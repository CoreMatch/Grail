// Package syncer 是镜像节点的同步引擎：只拉不推（D11）。
//
// 每次同步的顺序是硬约定：
//  1. 拉取增量批次（节点身份签名）；
//  2. 先验密钥环（本地信任锚 = 根公钥，拒绝序号回退，钉住根公钥）；
//  3. 再验选择状态文档（yank/宽限）；
//  4. 逐个验证版本清单签名（项目密钥取自密钥环）；
//  5. 对渠道策略覆盖的版本，优先把 URL 背后的字节抓下来落盘（D4）；
//     抓不动/超限才退回"只记地址"，并在汇总中显式报告；
//  6. 持久化游标，清理孤儿字节。
//
// 任何一步验证失败：整体显式失败，不做静默降级。
package syncer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"Grail/internal/client"
	"Grail/internal/config"
	"Grail/internal/model"
	"Grail/internal/signing"
	"Grail/internal/store"
)

// Summary 是一次同步的结果汇报。
type Summary struct {
	KeyringSeq   int64    `json:"keyring_seq"`
	StatesSeq    int64    `json:"states_seq"`
	Applied      int      `json:"applied"`
	Removed      int      `json:"removed"`
	BlobsFetched int      `json:"blobs_fetched"`
	BlobsPresent int      `json:"blobs_present"`
	BlobFailures []string `json:"blob_failures,omitempty"`
	Cursor       string   `json:"cursor"`
}

type cursorFile struct {
	Cursor string `json:"cursor"`
}

func cursorPath(dataDir string) string {
	return filepath.Join(dataDir, "mirror", "cursor.json")
}

func readCursor(dataDir string) string {
	var cf cursorFile
	data, err := os.ReadFile(cursorPath(dataDir))
	if err != nil {
		return ""
	}
	if err := json.Unmarshal(data, &cf); err != nil {
		return ""
	}
	return cf.Cursor
}

func writeCursor(dataDir, cursor string) error {
	path := cursorPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(cursorFile{Cursor: cursor})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RunOnce 执行一次完整同步。
func RunOnce(ctx context.Context, cfg *config.Config, creds *config.Credentials, st *store.Store, cl *client.Client) (*Summary, error) {
	if creds.RootPublicKey == "" {
		return nil, fmt.Errorf("mirror has no trust anchor: root_public_key missing in credentials")
	}
	anchor, err := signing.DecodePublicKey(creds.RootPublicKey)
	if err != nil {
		return nil, fmt.Errorf("trust anchor: %w", err)
	}

	changes, err := cl.SyncChanges(ctx, readCursor(cfg.Node.DataDir))
	if err != nil {
		return nil, fmt.Errorf("fetch sync changes: %w", err)
	}

	sum := &Summary{}

	// --- 1. 密钥环：锚点验签 + 钉住根公钥 + 拒绝序号回退 ---
	localKeyring := parseKeyring(st)
	if changes.Keyring != nil {
		var kr model.KeyringPayload
		if err := signing.VerifyEnvelope(changes.Keyring, anchor, &kr); err != nil {
			return nil, fmt.Errorf("keyring signature: %w", err)
		}
		if kr.Root.PublicKey != creds.RootPublicKey {
			return nil, fmt.Errorf("keyring root key does not match local trust anchor (possible rotation without re-pinning)")
		}
		if localKeyring != nil && kr.Seq <= localKeyring.Seq {
			// 序号不回退；等序/回退视为无更新（防回滚攻击）
		} else {
			if err := st.SetKeyring(changes.Keyring); err != nil {
				return nil, err
			}
			localKeyring = &kr
		}
	}
	if localKeyring == nil {
		return nil, fmt.Errorf("upstream served no keyring; cannot verify anything")
	}
	sum.KeyringSeq = localKeyring.Seq

	// --- 2. 选择状态：根公钥验签 + 序号前进 ---
	localStates := parseStates(st)
	if changes.States != nil {
		var sp model.StatesPayload
		if err := signing.VerifyEnvelope(changes.States, anchor, &sp); err != nil {
			return nil, fmt.Errorf("states signature: %w", err)
		}
		if localStates == nil || sp.Seq > localStates.Seq {
			if err := st.SetStates(changes.States); err != nil {
				return nil, err
			}
			localStates = &sp
		}
	}
	if localStates != nil {
		sum.StatesSeq = localStates.Seq
	}

	// --- 3. 版本清单：项目密钥验签后入库 ---
	var applied []*model.VersionManifest
	for i := range changes.Manifests {
		env := &changes.Manifests[i]
		var probe model.VersionManifest
		if err := json.Unmarshal(env.Payload, &probe); err != nil {
			return nil, fmt.Errorf("manifest payload: %w", err)
		}
		entry, ok := localKeyring.Projects[probe.Project]
		if !ok {
			return nil, fmt.Errorf("manifest for unregistered project %q", probe.Project)
		}
		pub, err := signing.DecodePublicKey(entry.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("project key %s: %w", probe.Project, err)
		}
		var m model.VersionManifest
		if err := signing.VerifyEnvelope(env, pub, &m); err != nil {
			return nil, fmt.Errorf("manifest signature %s/%s/%s: %w", m.Project, m.Channel, m.Version, err)
		}

		policy := cfg.ChannelPolicyOf(m.Channel)
		switch policy.Policy {
		case "none":
			continue
		case "subscribe":
			if !contains(policy.Projects, m.Project) {
				continue
			}
		}

		existing, err := st.GetVersion(m.Project, m.Channel, m.Version)
		if err != nil {
			return nil, err
		}
		if existing != nil && existing.Manifest.Seq == m.Seq {
			continue // 已有同版本，幂等跳过
		}
		rec := &store.VersionRecord{Envelope: env, Manifest: &m}
		if err := st.PutVersion(m.Project, m.Channel, m.Version, rec); err != nil {
			return nil, err
		}
		if _, err := st.AppendJournal("publish", model.VersionRef{Project: m.Project, Channel: m.Channel, Version: m.Version}); err != nil {
			return nil, err
		}
		applied = append(applied, &m)
		sum.Applied++
	}

	// --- 4. 移除通知 ---
	for _, ref := range changes.Removed {
		if err := st.DeleteVersion(ref.Project, ref.Channel, ref.Version); err != nil {
			return nil, err
		}
		if _, err := st.AppendJournal("remove", ref); err != nil {
			return nil, err
		}
		sum.Removed++
	}

	// --- 5. 状态收敛：按状态文档对齐本地版本的 yank/宽限标记 ---
	if localStates != nil {
		if err := applyStates(st, localStates); err != nil {
			return nil, err
		}
	}

	// --- 6. 字节抓取：优先落盘（D4），失败显式记录 ---
	maxBytes := cfg.EffectiveMaxArtifactBytes()
	for _, m := range applied {
		for _, res := range m.Resources {
			if st.HasBlob(res.Digest) {
				sum.BlobsPresent++
				continue
			}
			body, _, err := cl.FetchBlob(ctx, res.Digest)
			if err != nil {
				sum.BlobFailures = append(sum.BlobFailures,
					fmt.Sprintf("%s/%s/%s %s: fetch: %v", m.Project, m.Channel, m.Version, res.Digest, err))
				continue
			}
			if _, err := st.PutBlob(body, res.Digest, maxBytes); err != nil {
				body.Close()
				sum.BlobFailures = append(sum.BlobFailures,
					fmt.Sprintf("%s/%s/%s %s: store: %v", m.Project, m.Channel, m.Version, res.Digest, err))
				continue
			}
			body.Close()
			sum.BlobsFetched++
		}
	}

	// --- 7. 游标与孤儿字节 ---
	if err := writeCursor(cfg.Node.DataDir, changes.Cursor); err != nil {
		return nil, err
	}
	sum.Cursor = changes.Cursor
	if sum.Removed > 0 {
		if err := gcOrphanBlobs(st); err != nil {
			return nil, err
		}
	}
	return sum, nil
}

// RunEvery 按周期运行同步直到 ctx 取消；失败显式记录（由调用方提供日志）。
func RunEvery(ctx context.Context, interval time.Duration, once func(context.Context) error, logf func(string, ...any)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := once(ctx); err != nil && ctx.Err() == nil {
			logf("sync failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func parseKeyring(st *store.Store) *model.KeyringPayload {
	env := st.Keyring()
	if env == nil {
		return nil
	}
	var kr model.KeyringPayload
	if err := json.Unmarshal(env.Payload, &kr); err != nil {
		return nil
	}
	return &kr
}

func parseStates(st *store.Store) *model.StatesPayload {
	env := st.States()
	if env == nil {
		return nil
	}
	var sp model.StatesPayload
	if err := json.Unmarshal(env.Payload, &sp); err != nil {
		return nil
	}
	return &sp
}

// applyStates 把状态文档收敛到本地版本记录（未列入即清除标记）。
func applyStates(s *store.Store, sp *model.StatesPayload) error {
	yanked := make(map[model.VersionRef]model.StateEntry)
	for _, e := range sp.Yanked {
		yanked[model.VersionRef{Project: e.Project, Channel: e.Channel, Version: e.Version}] = e
	}
	grace := make(map[model.VersionRef]model.GraceEntry)
	for _, e := range sp.Grace {
		grace[model.VersionRef{Project: e.Project, Channel: e.Channel, Version: e.Version}] = e
	}

	all, err := s.AllVersions()
	if err != nil {
		return err
	}
	for _, rec := range all {
		ref := model.VersionRef{Project: rec.Manifest.Project, Channel: rec.Manifest.Channel, Version: rec.Manifest.Version}
		next := rec.State
		if e, ok := yanked[ref]; ok {
			next.Yanked = true
			next.YankAt = e.At
			next.Reason = e.Reason
		} else {
			next.Yanked = false
			next.YankAt = ""
			next.Reason = ""
		}
		if e, ok := grace[ref]; ok {
			next.Grace = true
			next.GraceAt = e.At
			next.RemoveAt = e.RemoveAt
		} else {
			next.Grace = false
			next.GraceAt = ""
			next.RemoveAt = ""
		}
		if next != rec.State {
			if err := s.SetVersionState(ref.Project, ref.Channel, ref.Version, next); err != nil {
				return err
			}
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func gcOrphanBlobs(st *store.Store) error {
	all, err := st.AllVersions()
	if err != nil {
		return err
	}
	referenced := make(map[string]bool)
	for _, rec := range all {
		for _, res := range rec.Manifest.Resources {
			referenced[res.Digest] = true
		}
	}
	blobs, err := st.AllBlobDigests()
	if err != nil {
		return err
	}
	for _, d := range blobs {
		if !referenced[d] {
			if err := st.DeleteBlob(d); err != nil {
				return err
			}
		}
	}
	return nil
}
