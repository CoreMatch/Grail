// Package server 的 Server 门面：持有配置、凭据与存储，
// 维护密钥环/状态文档的内存视图，并运行后台循环
// （原站：宽限期清扫；镜像：轮询同步）。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"Grail/internal/config"
	"Grail/internal/model"
	"Grail/internal/signing"
	"Grail/internal/store"
)

// Server 是节点 HTTP 面的承载体。
type Server struct {
	cfg       *config.Config
	creds     *config.Credentials
	credsPath string
	store     *store.Store

	mu       sync.Mutex
	keyring  *model.KeyringPayload
	states   *model.StatesPayload
	lastSync time.Time // 仅 mirror：最近一次成功同步

	// OnSyncOnce 由注入的镜像同步器执行一次同步（避免循环依赖）。
	// 返回错误时循环按周期重试，失败显式记录日志（不静默）。
	OnSyncOnce func(ctx context.Context) error
}

// New 组装 Server：装载密钥环与状态文档的本地视图。
// root 节点必须已有初始化产物（密钥环 + 根私钥），否则显式失败。
func New(cfg *config.Config, creds *config.Credentials, credsPath string, st *store.Store) (*Server, error) {
	s := &Server{cfg: cfg, creds: creds, credsPath: credsPath, store: st}

	if env := st.Keyring(); env != nil {
		var kr model.KeyringPayload
		if err := json.Unmarshal(env.Payload, &kr); err != nil {
			return nil, fmt.Errorf("parse keyring payload: %w", err)
		}
		s.keyring = &kr
	}
	if env := st.States(); env != nil {
		var sp model.StatesPayload
		if err := json.Unmarshal(env.Payload, &sp); err != nil {
			return nil, fmt.Errorf("parse states payload: %w", err)
		}
		s.states = &sp
	}

	if cfg.Node.Role == "root" {
		if s.keyring == nil {
			return nil, fmt.Errorf("root node not initialized: keyring missing (run `grail init` first)")
		}
		if creds.RootPrivateKey == "" {
			return nil, fmt.Errorf("root node requires root_private_key in credentials")
		}
	}
	return s, nil
}

// Store 暴露底层存储（测试用）。
func (s *Server) Store() *store.Store { return s.store }

// Tier 报告节点层级：原站 0，镜像 1（多层拓扑下每层只知自己与上级）。
func (s *Server) Tier() int {
	if s.cfg.Node.Role == "root" {
		return 0
	}
	return 1
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// --- 密钥环 / 状态文档（原站写路径） ---

func (s *Server) rootPrivateKey() ([]byte, error) {
	key, err := signing.DecodePrivateKey(s.creds.RootPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("root private key: %w", err)
	}
	return key, nil
}

// updateKeyring 变更密钥环：seq 递增、根密钥重签、原子落盘。
func (s *Server) updateKeyring(mutate func(*model.KeyringPayload)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keyring == nil {
		return fmt.Errorf("keyring not initialized")
	}
	next := *s.keyring
	next.Projects = make(map[string]model.KeyEntry, len(s.keyring.Projects))
	for k, v := range s.keyring.Projects {
		next.Projects[k] = v
	}
	mutate(&next)
	next.Seq = s.keyring.Seq + 1
	next.UpdatedAt = nowUTC()

	rootKey, err := s.rootPrivateKey()
	if err != nil {
		return err
	}
	env, err := signing.SignEnvelope(next, next.Root.KeyID, rootKey)
	if err != nil {
		return err
	}
	if err := s.store.SetKeyring(env); err != nil {
		return err
	}
	s.keyring = &next
	return nil
}

// updateStates 变更选择状态文档：seq 递增、根密钥重签、原子落盘。
func (s *Server) updateStates(mutate func(*model.StatesPayload)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states == nil {
		return fmt.Errorf("states document not initialized")
	}
	next := model.StatesPayload{
		Seq:    s.states.Seq + 1,
		Yanked: append([]model.StateEntry(nil), s.states.Yanked...),
		Grace:  append([]model.GraceEntry(nil), s.states.Grace...),
	}
	mutate(&next)
	next.UpdatedAt = nowUTC()

	rootKey, err := s.rootPrivateKey()
	if err != nil {
		return err
	}
	env, err := signing.SignEnvelope(next, s.keyring.Root.KeyID, rootKey)
	if err != nil {
		return err
	}
	if err := s.store.SetStates(env); err != nil {
		return err
	}
	s.states = &next
	return nil
}

// statesView 返回当前状态文档副本（读路径用）。
func (s *Server) statesView() *model.StatesPayload {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states == nil {
		return nil
	}
	cp := *s.states
	return &cp
}

func (s *Server) statesSeq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states == nil {
		return 0
	}
	return s.states.Seq
}

// projectKey 返回项目公钥（未登记返回错误）。
func (s *Server) projectEntry(project string) (model.KeyEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keyring == nil {
		return model.KeyEntry{}, fmt.Errorf("keyring not initialized")
	}
	e, ok := s.keyring.Projects[project]
	if !ok {
		return model.KeyEntry{}, fmt.Errorf("project not registered: %s", project)
	}
	return e, nil
}

// --- 后台循环 ---

// RunBackgroundLoops 启动后台循环直到 ctx 取消：
// root 跑宽限期清扫器；mirror 跑轮询同步（只拉不推，D11）。
func (s *Server) RunBackgroundLoops(ctx context.Context) {
	if s.cfg.Node.Role == "root" {
		go s.sweepLoop(ctx)
		return
	}
	if s.OnSyncOnce == nil {
		return
	}
	go func() {
		interval := time.Duration(s.cfg.EffectiveSyncInterval()) * time.Second
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := s.OnSyncOnce(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("grail: sync failed: %v", err) // 显式失败，不静默
			} else {
				s.mu.Lock()
				s.lastSync = time.Now()
				s.mu.Unlock()
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// sweepLoop 定期把宽限期满且无引用的版本物理移除（D15）。
func (s *Server) sweepLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.SweepExpiredGrace(); err != nil {
				log.Printf("grail: grace sweep failed: %v", err)
			}
		}
	}
}

// SweepExpiredGrace 执行一次宽限期清扫：
// 期满且无引用 → 物理移除（记录移除日志 + 孤儿字节清理）；
// 期满但仍有引用 → 保留并显式告警（拒绝清理，设计稿 11.3）。
func (s *Server) SweepExpiredGrace() error {
	st := s.statesView()
	if st == nil {
		return nil
	}
	now := time.Now().UTC()
	var due []model.GraceEntry
	for _, g := range st.Grace {
		removeAt, err := time.Parse(time.RFC3339, g.RemoveAt)
		if err != nil {
			continue
		}
		if !now.Before(removeAt) {
			due = append(due, g)
		}
	}
	if len(due) == 0 {
		return nil
	}

	removedAny := false
	for _, g := range due {
		ref := model.VersionRef{Project: g.Project, Channel: g.Channel, Version: g.Version}
		refs, err := s.store.ReferencedBy(ref)
		if err != nil {
			return err
		}
		if len(refs) > 0 {
			log.Printf("grail: grace expired for %s/%s/%s but still referenced by %d version(s); removal refused",
				g.Project, g.Channel, g.Version, len(refs))
			continue
		}
		if err := s.store.DeleteVersion(g.Project, g.Channel, g.Version); err != nil {
			return err
		}
		if _, err := s.store.AppendJournal("remove", ref); err != nil {
			return err
		}
		entry := g
		if err := s.updateStates(func(sp *model.StatesPayload) {
			out := sp.Grace[:0]
			for _, ge := range sp.Grace {
				if ge == entry {
					continue
				}
				out = append(out, ge)
			}
			sp.Grace = out
		}); err != nil {
			return err
		}
		removedAny = true
		log.Printf("grail: removed %s/%s/%s (grace period ended)", g.Project, g.Channel, g.Version)
	}

	if removedAny {
		return s.gcOrphanBlobs()
	}
	return nil
}

// gcOrphanBlobs 删除不再被任何版本引用的字节。
func (s *Server) gcOrphanBlobs() error {
	all, err := s.store.AllVersions()
	if err != nil {
		return err
	}
	referenced := make(map[string]bool)
	for _, rec := range all {
		for _, res := range rec.Manifest.Resources {
			referenced[res.Digest] = true
		}
	}
	blobs, err := s.store.AllBlobDigests()
	if err != nil {
		return err
	}
	for _, d := range blobs {
		if !referenced[d] {
			if err := s.store.DeleteBlob(d); err != nil {
				return err
			}
		}
	}
	return nil
}

// servingNode 组装响应里的服务节点自报家门块（不参与签名）。
func (s *Server) servingNode() model.ServingNode {
	s.mu.Lock()
	stale := false
	if s.cfg.Node.Role == "mirror" {
		interval := time.Duration(s.cfg.EffectiveSyncInterval()) * time.Second
		stale = s.lastSync.IsZero() || time.Since(s.lastSync) > 3*interval
	}
	s.mu.Unlock()
	return model.ServingNode{
		Tier:      s.Tier(),
		Offline:   false,
		StatesSeq: s.statesSeq(),
		Stale:     stale,
	}
}
