// Package store 是 Grail 节点的本地存储：内容寻址 blob 库 +
// 版本元数据 + 密钥环/状态文档 + 变更日志（journal）。
//
// 布局（<data>/ 下）：
//
//	node.json                          节点元信息（角色等）
//	keyring.env.json                   当前密钥环（签名信封）
//	states.env.json                    当前选择状态（签名信封：yank+宽限）
//	meta/<project>/<channel>/counter.json     渠道发布序号计数
//	meta/<project>/<channel>/v/<version>.json 版本记录（信封+本地状态+外部地址）
//	journal.jsonl                      变更日志（发布/移除，单调 id）
//	blobs/sha256/<前2位>/<其余>          内容寻址字节
//	nodes/<node-id>.json               已登记的下游节点身份
//
// 纪律：一切落盘走临时文件+原子改名；损坏可读性问题显式失败。
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"Grail/internal/model"
)

// ErrSizeCap 表示字节超过大小上限（兜底限制，D10）。
var ErrSizeCap = errors.New("blob exceeds size cap")

// DigestRe 校验 digest 形态：sha256:<64hex>。
var DigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// VersionRe 校验版本字符串：不透明标识符（D6），但必须 URL 安全——
// 它要进规范 URL 的路径段。这是唯一的形态约束，不解读任何数字语义。
var VersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Channels 是固定的三个渠道（D1）。
var Channels = []string{"ci", "candidate", "release"}

// ValidChannel 报告渠道是否合法。
func ValidChannel(c string) bool {
	return c == "ci" || c == "candidate" || c == "release"
}

// NodeMeta 是节点元信息。
type NodeMeta struct {
	Role    string `json:"role"` // root | mirror
	Name    string `json:"name"`
	Created string `json:"created"`
}

// VersionRecord 是一个版本的完整本地记录：
// 签名信封（原样转发）+ 解析出的清单 + 本地选择状态 + 外部地址表。
// 外部地址不进签名负载——消费方只见规范 URL（D10）。
type VersionRecord struct {
	Envelope  *model.Envelope        `json:"envelope"`
	Manifest  *model.VersionManifest `json:"manifest"`
	State     model.VersionState     `json:"state"`
	Externals map[string]string      `json:"externals,omitempty"` // digest -> external URL
}

// JournalEntry 是变更日志的一行。
type JournalEntry struct {
	ID   int64            `json:"id"`
	Type string           `json:"type"` // publish | remove
	Ref  model.VersionRef `json:"ref"`
}

// Store 是单进程内的存储门面（互斥保护；落盘原子）。
type Store struct {
	mu      sync.Mutex
	dataDir string
}

// Open 打开（或初始化）存储目录。
func Open(dataDir string) (*Store, error) {
	for _, sub := range []string{"meta", "blobs/sha256", "nodes"} {
		if err := os.MkdirAll(filepath.Join(dataDir, sub), 0o755); err != nil {
			return nil, fmt.Errorf("init store dir %s: %w", sub, err)
		}
	}
	return &Store{dataDir: dataDir}, nil
}

// DataDir 返回存储根目录。
func (s *Store) DataDir() string { return s.dataDir }

// --- 原子落盘 ---

func atomicWriteJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, data, 0o644)
}

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

// --- 节点元信息 ---

func (s *Store) nodeMetaPath() string { return filepath.Join(s.dataDir, "node.json") }

// NodeMeta 读取节点元信息（不存在返回零值）。
func (s *Store) NodeMeta() (*NodeMeta, error) {
	var m NodeMeta
	if err := readJSON(s.nodeMetaPath(), &m); err != nil {
		if os.IsNotExist(err) {
			return &NodeMeta{}, nil
		}
		return nil, err
	}
	return &m, nil
}

// SetNodeMeta 写入节点元信息。
func (s *Store) SetNodeMeta(m *NodeMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteJSON(s.nodeMetaPath(), m)
}

// --- blob 库 ---

// BlobPath 返回 digest 对应的落盘路径。
func (s *Store) BlobPath(digest string) string {
	hexPart := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(s.dataDir, "blobs", "sha256", hexPart[:2], hexPart[2:])
}

// HasBlob 报告字节是否已托管在本节点。
func (s *Store) HasBlob(digest string) bool {
	if !DigestRe.MatchString(digest) {
		return false
	}
	info, err := os.Stat(s.BlobPath(digest))
	return err == nil && info.Mode().IsRegular()
}

// PutBlob 流式写入字节：临时文件 + 全程哈希 + 校验期望 digest +
// 原子改名。大小超过 maxBytes（>0 时）立即中止并清理。
// 已存在的 digest 幂等成功。
func (s *Store) PutBlob(r io.Reader, expectDigest string, maxBytes int64) (int64, error) {
	if !DigestRe.MatchString(expectDigest) {
		return 0, fmt.Errorf("malformed digest %q", expectDigest)
	}
	if s.HasBlob(expectDigest) {
		info, err := os.Stat(s.BlobPath(expectDigest))
		if err != nil {
			return 0, err
		}
		return info.Size(), nil
	}

	destDir := filepath.Dir(s.BlobPath(expectDigest))
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(destDir, ".blob-*")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	h := sha256.New()
	var written int64
	if maxBytes > 0 {
		r = io.LimitReader(r, maxBytes+1)
	}
	written, err = io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		tmp.Close()
		return 0, fmt.Errorf("stream blob: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	if maxBytes > 0 && written > maxBytes {
		return 0, fmt.Errorf("%w: %d bytes > %d", ErrSizeCap, written, maxBytes)
	}
	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if got != expectDigest {
		return 0, fmt.Errorf("digest mismatch: declared %s, streamed %s", expectDigest, got)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return 0, err
	}
	if err := os.Rename(tmpName, s.BlobPath(expectDigest)); err != nil {
		return 0, err
	}
	return written, nil
}

// OpenBlob 打开已托管的字节。
func (s *Store) OpenBlob(digest string) (io.ReadCloser, int64, error) {
	if !DigestRe.MatchString(digest) {
		return nil, 0, fmt.Errorf("malformed digest %q", digest)
	}
	p := s.BlobPath(digest)
	info, err := os.Stat(p)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, 0, err
	}
	return f, info.Size(), nil
}

// DeleteBlob 删除一个字节（孤儿清理用）。
func (s *Store) DeleteBlob(digest string) error {
	if !DigestRe.MatchString(digest) {
		return fmt.Errorf("malformed digest %q", digest)
	}
	err := os.Remove(s.BlobPath(digest))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// AllBlobDigests 枚举本节点托管的全部 digest。
func (s *Store) AllBlobDigests() ([]string, error) {
	root := filepath.Join(s.dataDir, "blobs", "sha256")
	var out []string
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() || len(e.Name()) != 2 {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if f.IsDir() || strings.HasPrefix(f.Name(), ".") {
				continue
			}
			out = append(out, "sha256:"+e.Name()+f.Name())
		}
	}
	return out, nil
}

// --- 密钥环与状态文档 ---

func (s *Store) keyringPath() string { return filepath.Join(s.dataDir, "keyring.env.json") }
func (s *Store) statesPath() string  { return filepath.Join(s.dataDir, "states.env.json") }

// Keyring 返回当前密钥环信封（未初始化返回 nil）。
func (s *Store) Keyring() *model.Envelope {
	var env model.Envelope
	if err := readJSON(s.keyringPath(), &env); err != nil {
		return nil
	}
	return &env
}

// SetKeyring 原子替换密钥环信封。
func (s *Store) SetKeyring(env *model.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteJSON(s.keyringPath(), env)
}

// States 返回当前选择状态信封（未初始化返回 nil）。
func (s *Store) States() *model.Envelope {
	var env model.Envelope
	if err := readJSON(s.statesPath(), &env); err != nil {
		return nil
	}
	return &env
}

// SetStates 原子替换选择状态信封。
func (s *Store) SetStates(env *model.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteJSON(s.statesPath(), env)
}

// --- 版本记录 ---

func versionDir(dataDir, project, channel string) string {
	return filepath.Join(dataDir, "meta", project, channel)
}

func (s *Store) versionPath(project, channel, version string) string {
	return filepath.Join(versionDir(s.dataDir, project, channel), "v", version+".json")
}

func (s *Store) counterPath(project, channel string) string {
	return filepath.Join(versionDir(s.dataDir, project, channel), "counter.json")
}

// GetVersion 读取版本记录；不存在返回 (nil, nil)。
func (s *Store) GetVersion(project, channel, version string) (*VersionRecord, error) {
	var rec VersionRecord
	err := readJSON(s.versionPath(project, channel, version), &rec)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// PutVersion 写入版本记录（发布与同步共用）。
func (s *Store) PutVersion(project, channel, version string, rec *VersionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteJSON(s.versionPath(project, channel, version), rec)
}

// SetVersionState 只更新版本的选择状态。
func (s *Store) SetVersionState(project, channel, version string, st model.VersionState) error {
	rec, err := s.GetVersion(project, channel, version)
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("version not found: %s/%s/%s", project, channel, version)
	}
	rec.State = st
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteJSON(s.versionPath(project, channel, version), rec)
}

// DeleteVersion 物理删除版本记录（宽限期满后的移除）。
func (s *Store) DeleteVersion(project, channel, version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.versionPath(project, channel, version))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// ListVersions 按发布序号倒序返回渠道内的全部版本记录。
func (s *Store) ListVersions(project, channel string) ([]*VersionRecord, error) {
	dir := filepath.Join(versionDir(s.dataDir, project, channel), "v")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*VersionRecord
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		version := strings.TrimSuffix(e.Name(), ".json")
		rec, err := s.GetVersion(project, channel, version)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.Seq > out[j].Manifest.Seq })
	return out, nil
}

// AllVersions 枚举本节点持有的全部版本（孤儿清理与引用扫描用）。
func (s *Store) AllVersions() ([]*VersionRecord, error) {
	var out []*VersionRecord
	metaRoot := filepath.Join(s.dataDir, "meta")
	projects, err := os.ReadDir(metaRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	for _, p := range projects {
		if !p.IsDir() {
			continue
		}
		for _, ch := range Channels {
			recs, err := s.ListVersions(p.Name(), ch)
			if err != nil {
				return nil, err
			}
			out = append(out, recs...)
		}
	}
	return out, nil
}

// NextSeq 分配渠道内的下一个发布序号（单调递增）。
func (s *Store) NextSeq(project, channel string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var counter struct {
		Next int64 `json:"next"`
	}
	if err := readJSON(s.counterPath(project, channel), &counter); err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	counter.Next++
	if err := atomicWriteJSON(s.counterPath(project, channel), &counter); err != nil {
		return 0, err
	}
	return counter.Next, nil
}

// ReferencedBy 扫描血缘引用：哪些版本的 derived_from 指向 ref。
// 被引用的版本不可清理（设计稿 11.3）。
func (s *Store) ReferencedBy(ref model.VersionRef) ([]model.VersionRef, error) {
	all, err := s.AllVersions()
	if err != nil {
		return nil, err
	}
	var refs []model.VersionRef
	for _, rec := range all {
		df := rec.Manifest.Provenance.DerivedFrom
		if df == nil {
			continue
		}
		if df.Channel == ref.Channel && df.Version == ref.Version && rec.Manifest.Project == ref.Project {
			refs = append(refs, model.VersionRef{
				Project: rec.Manifest.Project,
				Channel: rec.Manifest.Channel,
				Version: rec.Manifest.Version,
			})
		}
	}
	return refs, nil
}

// --- 变更日志（journal） ---

func (s *Store) journalPath() string { return filepath.Join(s.dataDir, "journal.jsonl") }

// AppendJournal 追加一条变更并返回其 id。
func (s *Store) AppendJournal(typ string, ref model.VersionRef) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	last, err := s.lastJournalIDLocked()
	if err != nil {
		return 0, err
	}
	entry := JournalEntry{ID: last + 1, Type: typ, Ref: ref}
	line, err := json.Marshal(entry)
	if err != nil {
		return 0, err
	}
	f, err := os.OpenFile(s.journalPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return 0, err
	}
	if err := f.Sync(); err != nil {
		return 0, err
	}
	return entry.ID, nil
}

func (s *Store) lastJournalIDLocked() (int64, error) {
	entries, err := s.readJournalLocked()
	if err != nil {
		return 0, err
	}
	if len(entries) == 0 {
		return 0, nil
	}
	return entries[len(entries)-1].ID, nil
}

func (s *Store) readJournalLocked() ([]JournalEntry, error) {
	data, err := os.ReadFile(s.journalPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []JournalEntry
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e JournalEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("journal line %d: %w", i+1, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// JournalSince 返回 id > since 的变更与最新游标。
func (s *Store) JournalSince(since int64) ([]JournalEntry, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.readJournalLocked()
	if err != nil {
		return nil, "", err
	}
	var out []JournalEntry
	var last int64
	for _, e := range entries {
		last = e.ID
		if e.ID > since {
			out = append(out, e)
		}
	}
	return out, fmt.Sprintf("%d", last), nil
}

// --- 下游节点身份 ---

func (s *Store) nodePath(id string) string {
	return filepath.Join(s.dataDir, "nodes", id+".json")
}

// PutNode 登记/更新一个下游节点身份。
func (s *Store) PutNode(info *model.NodeInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteJSON(s.nodePath(info.NodeID), info)
}

// GetNode 读取一个下游节点身份。
func (s *Store) GetNode(id string) (*model.NodeInfo, error) {
	var info model.NodeInfo
	err := readJSON(s.nodePath(id), &info)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// DeleteNode 吊销一个下游节点身份（定向撤销）。
func (s *Store) DeleteNode(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.nodePath(id))
	if os.IsNotExist(err) {
		return fmt.Errorf("node not found: %s", id)
	}
	return err
}

// ListNodes 列出全部已登记节点。
func (s *Store) ListNodes() ([]*model.NodeInfo, error) {
	entries, err := os.ReadDir(filepath.Join(s.dataDir, "nodes"))
	if err != nil {
		return nil, err
	}
	var out []*model.NodeInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		info, err := s.GetNode(id)
		if err != nil {
			return nil, err
		}
		if info != nil {
			out = append(out, info)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out, nil
}
