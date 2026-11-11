package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"Grail/internal/client"
	"Grail/internal/config"
	"Grail/internal/model"
	"Grail/internal/server"
	"Grail/internal/signing"
	"Grail/internal/store"
	"Grail/internal/syncer"
)

func init() { gin.SetMode(gin.TestMode) }

func digestOf(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// rootFixture 是一个进程内原站：真实根密钥、真实密钥环与状态文档。
type rootFixture struct {
	srv       *server.Server
	ts        *httptest.Server
	store     *store.Store
	rootPubB64 string
}

func newRootFixture(t *testing.T) *rootFixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	rootEntry := model.KeyEntry{KeyID: "root-1", Alg: signing.Alg, PublicKey: signing.EncodeKey(pub), Created: "2026-11-12T00:00:00Z"}
	krEnv, err := signing.SignEnvelope(model.KeyringPayload{
		Seq: 1, UpdatedAt: "2026-11-12T00:00:00Z", Root: rootEntry,
		Projects: map[string]model.KeyEntry{},
	}, "root-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetKeyring(krEnv); err != nil {
		t.Fatal(err)
	}
	stEnv, err := signing.SignEnvelope(model.StatesPayload{
		Seq: 1, UpdatedAt: "2026-11-12T00:00:00Z",
		Yanked: []model.StateEntry{}, Grace: []model.GraceEntry{},
	}, "root-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetStates(stEnv); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNodeMeta(&store.NodeMeta{Role: "root", Name: "test-root"}); err != nil {
		t.Fatal(err)
	}

	creds := &config.Credentials{
		AdminToken:     "admin-tok",
		RootPrivateKey: signing.EncodeKey(priv),
		PublishTokens: []config.TokenEntry{
			{Name: "ci-bot", Token: "ci-tok", Channels: []string{"ci"}},
			{Name: "author", Token: "author-tok", Channels: []string{"candidate", "release"}},
		},
		ReadTokens: []config.TokenEntry{{Name: "reader", Token: "read-tok"}},
	}
	cfg := &config.Config{Node: config.NodeConfig{Role: "root", Public: true, DataDir: dir}}
	srv, err := server.New(cfg, creds, "", st)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.NewRouter(srv))
	t.Cleanup(ts.Close)
	return &rootFixture{srv: srv, ts: ts, store: st, rootPubB64: signing.EncodeKey(pub)}
}

func doJSON(t *testing.T, method, url, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func registerProject(t *testing.T, f *rootFixture, name string) {
	t.Helper()
	resp, body := doJSON(t, http.MethodPost, f.ts.URL+"/v1/admin/projects", "admin-tok", map[string]string{"name": name})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register project %s -> %d: %s", name, resp.StatusCode, body)
	}
}

func uploadBlob(t *testing.T, f *rootFixture, token string, data []byte) string {
	t.Helper()
	d := digestOf(data)
	req, _ := http.NewRequest(http.MethodPost, f.ts.URL+"/v1/blobs", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Grail-Digest", d)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload blob -> %d: %s", resp.StatusCode, body)
	}
	return d
}

func publish(t *testing.T, f *rootFixture, token, project, channel, version, digest string, size int64, prov model.Provenance) (*http.Response, []byte) {
	t.Helper()
	req := model.PublishRequest{
		Version: version,
		Resources: []model.PublishResource{{
			Name: project, Platform: "linux-amd64", Digest: digest, Size: size,
		}},
		Provenance: prov,
	}
	return doJSON(t, http.MethodPost,
		fmt.Sprintf("%s/v1/projects/%s/channels/%s/versions", f.ts.URL, project, channel), token, req)
}

// TestFullChain 覆盖：登记项目 → 上传 → 发布（血缘）→ 解析验签 → 规范 URL 取件
// → 重复发布拒绝 → 渠道读权限。
func TestFullChain(t *testing.T) {
	f := newRootFixture(t)
	registerProject(t, f, "demo")

	payload := []byte("demo artifact v1")
	d := uploadBlob(t, f, "author-tok", payload)

	prov := model.Provenance{
		Builder: "test", Commit: "a1b2c3d", SameContent: false,
		DerivedFrom: &model.DerivedFrom{Channel: "candidate", Version: "0.6", Note: "fix per feedback"},
	}
	resp, body := publish(t, f, "author-tok", "demo", "release", "0.6", d, int64(len(payload)), prov)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("publish -> %d: %s", resp.StatusCode, body)
	}

	// 重复发布同版本字符串：永久消耗，必须拒绝（D7）。
	resp, _ = publish(t, f, "author-tok", "demo", "release", "0.6", d, int64(len(payload)), prov)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("republish same version must be 400, got %d", resp.StatusCode)
	}

	// 解析 latest：release 公开，匿名可读。
	var rr model.ResolveResponse
	resp, body = doJSON(t, http.MethodGet, f.ts.URL+"/v1/projects/demo/channels/release/resolve?version=latest&platform=linux-amd64", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resolve -> %d: %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &rr); err != nil {
		t.Fatal(err)
	}
	if rr.Version != "0.6" || rr.ResolvedFrom != "latest" || len(rr.Resources) != 1 {
		t.Fatalf("resolve unexpected: %+v", rr)
	}

	// 端到端验签：锚点 → 密钥环 → 项目密钥 → 清单。
	anchor, err := signing.DecodePublicKey(f.rootPubB64)
	if err != nil {
		t.Fatal(err)
	}
	var krEnv model.Envelope
	resp, body = doJSON(t, http.MethodGet, f.ts.URL+"/v1/keyring", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keyring -> %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, &krEnv); err != nil {
		t.Fatal(err)
	}
	var kr model.KeyringPayload
	if err := signing.VerifyEnvelope(&krEnv, anchor, &kr); err != nil {
		t.Fatalf("keyring verify: %v", err)
	}
	entry := kr.Projects["demo"]
	projectPub, err := signing.DecodePublicKey(entry.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var env model.Envelope
	resp, body = doJSON(t, http.MethodGet, f.ts.URL+"/v1/projects/demo/channels/release/versions/0.6", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("version envelope -> %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	var manifest model.VersionManifest
	if err := signing.VerifyEnvelope(&env, projectPub, &manifest); err != nil {
		t.Fatalf("manifest verify: %v", err)
	}
	if manifest.Version != rr.Version || manifest.Seq != rr.Seq {
		t.Fatal("resolve/envelope mismatch")
	}

	// 规范取件 URL：200 直供 + digest 一致。
	resp, body = doJSON(t, http.MethodGet, f.ts.URL+"/demo/release/0.6/linux-amd64", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("canonical fetch -> %d: %s", resp.StatusCode, body)
	}
	if digestOf(body) != d {
		t.Fatal("canonical fetch digest mismatch")
	}

	// ci 渠道匿名读必须被拒（默认仅节点/读凭据可见）。
	resp, _ = doJSON(t, http.MethodGet, f.ts.URL+"/v1/projects/demo/channels/ci/resolve", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous ci read must be 401, got %d", resp.StatusCode)
	}
	// 读凭据可读 ci（空渠道返回 404 无可选版本，而非 401）。
	resp, _ = doJSON(t, http.MethodGet, f.ts.URL+"/v1/projects/demo/channels/ci/resolve", "read-tok", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("ci resolve with read token should be 404 (empty), got %d", resp.StatusCode)
	}

	// ci 令牌不得发布 release（渠道范围）。
	resp, _ = publish(t, f, "ci-tok", "demo", "release", "0.7", d, int64(len(payload)), prov)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ci token publishing release must be 401, got %d", resp.StatusCode)
	}
}

// TestYankAndGrace 覆盖：yank 即时不可选、宽限期默认跳过/钉住可用、
// 被引用版本拒绝清理。
func TestYankAndGrace(t *testing.T) {
	f := newRootFixture(t)
	registerProject(t, f, "demo")

	payload := []byte("demo artifact")
	d := uploadBlob(t, f, "author-tok", payload)
	prov := model.Provenance{}
	if resp, body := publish(t, f, "author-tok", "demo", "release", "0.6", d, int64(len(payload)), prov); resp.StatusCode != http.StatusOK {
		t.Fatalf("publish: %s", body)
	}

	// yank：latest 立刻选不中；钉住仍可取且带标记。
	resp, _ := doJSON(t, http.MethodPost, f.ts.URL+"/v1/projects/demo/channels/release/versions/0.6/yank", "admin-tok", map[string]string{"reason": "suspect"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("yank -> %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, http.MethodGet, f.ts.URL+"/v1/projects/demo/channels/release/resolve?version=latest", "", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("latest after yank must be 404, got %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, http.MethodGet, f.ts.URL+"/demo/release/0.6/linux-amd64", "", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Grail-Yanked") != "true" {
		t.Fatalf("pinned yanked fetch must be 200 + marker, got %d %q", resp.StatusCode, resp.Header.Get("X-Grail-Yanked"))
	}

	// unyank 恢复可选。
	if resp, _ := doJSON(t, http.MethodDelete, f.ts.URL+"/v1/projects/demo/channels/release/versions/0.6/yank", "admin-tok", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("unyank -> %d", resp.StatusCode)
	}
	if resp, _ := doJSON(t, http.MethodGet, f.ts.URL+"/v1/projects/demo/channels/release/resolve?version=latest", "", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("latest after unyank must be 200, got %d", resp.StatusCode)
	}

	// 宽限期：latest 跳过、钉住可用带标记。
	resp, _ = doJSON(t, http.MethodPost, f.ts.URL+"/v1/projects/demo/channels/release/versions/0.6/deprecate", "admin-tok", map[string]int64{"grace_seconds": 3600})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deprecate -> %d", resp.StatusCode)
	}
	if resp, _ := doJSON(t, http.MethodGet, f.ts.URL+"/v1/projects/demo/channels/release/resolve?version=latest", "", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("latest during grace must be 404, got %d", resp.StatusCode)
	}
	var rr model.ResolveResponse
	resp, body := doJSON(t, http.MethodGet, f.ts.URL+"/v1/projects/demo/channels/release/resolve?version=0.6", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pinned grace resolve -> %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, &rr); err != nil {
		t.Fatal(err)
	}
	if rr.Grace == nil || rr.Grace.RemoveAt == "" {
		t.Fatal("grace marker missing on pinned resolve")
	}

	// 被血缘引用的版本拒绝清理（409 + 引用清单）。
	if resp, body := publish(t, f, "author-tok", "demo", "candidate", "0.6", d, int64(len(payload)), prov); resp.StatusCode != http.StatusOK {
		t.Fatalf("publish candidate: %s", body)
	}
	provRelease := model.Provenance{DerivedFrom: &model.DerivedFrom{Channel: "candidate", Version: "0.6"}}
	payload2 := []byte("demo artifact rebuilt")
	d2 := uploadBlob(t, f, "author-tok", payload2)
	if resp, body := publish(t, f, "author-tok", "demo", "release", "1.0", d2, int64(len(payload2)), provRelease); resp.StatusCode != http.StatusOK {
		t.Fatalf("publish release 1.0: %s", body)
	}
	resp, body = doJSON(t, http.MethodPost, f.ts.URL+"/v1/projects/demo/channels/candidate/versions/0.6/deprecate", "admin-tok", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("deprecate referenced candidate must be 409, got %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "referenced_by") {
		t.Fatalf("409 must carry reference list: %s", body)
	}
}

// TestMirrorSync 覆盖：节点登记 → 真实同步（清单验签入库 + 字节真拉下来）
// → 镜像直供 → 未持有时 302 回上级。
func TestMirrorSync(t *testing.T) {
	f := newRootFixture(t)
	registerProject(t, f, "demo")
	payload := []byte("mirror sync payload")
	d := uploadBlob(t, f, "author-tok", payload)
	if resp, body := publish(t, f, "author-tok", "demo", "release", "0.6", d, int64(len(payload)), model.Provenance{}); resp.StatusCode != http.StatusOK {
		t.Fatalf("publish: %s", body)
	}

	// 登记下游节点（私钥只出现一次）。
	resp, body := doJSON(t, http.MethodPost, f.ts.URL+"/v1/admin/nodes", "admin-tok", model.RegisterNodeRequest{Name: "mirror-1"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register node -> %d: %s", resp.StatusCode, body)
	}
	var nodeResp model.RegisterNodeResponse
	if err := json.Unmarshal(body, &nodeResp); err != nil {
		t.Fatal(err)
	}
	nodeKey, err := signing.DecodePrivateKey(nodeResp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	// 组装镜像节点。
	mirrorDir := t.TempDir()
	mirrorStore, err := store.Open(mirrorDir)
	if err != nil {
		t.Fatal(err)
	}
	mirrorCfg := &config.Config{
		Node: config.NodeConfig{Role: "mirror", Public: true, DataDir: mirrorDir},
		Mirror: config.MirrorConfig{
			UpstreamBaseURL: f.ts.URL,
			Channels: map[string]config.ChannelPolicy{
				"release": {Policy: "full"},
			},
		},
	}
	mirrorCreds := &config.Credentials{
		NodeID:         "mirror-1",
		NodePrivateKey: nodeResp.PrivateKey,
		RootPublicKey:  f.rootPubB64,
	}
	cl := client.New(f.ts.URL).WithNodeIdentity("mirror-1", nodeKey)

	sum, err := syncer.RunOnce(context.Background(), mirrorCfg, mirrorCreds, mirrorStore, cl)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if sum.Applied != 1 || sum.BlobsFetched != 1 || len(sum.BlobFailures) != 0 {
		t.Fatalf("sync summary unexpected: %+v", sum)
	}
	if !mirrorStore.HasBlob(d) {
		t.Fatal("mirror did not store the bytes (must fetch, not just record URL)")
	}

	// 镜像直供（200）。
	mirrorSrv, err := server.New(mirrorCfg, mirrorCreds, "", mirrorStore)
	if err != nil {
		t.Fatal(err)
	}
	mts := httptest.NewServer(server.NewRouter(mirrorSrv))
	defer mts.Close()

	resp2, body2 := doJSON(t, http.MethodGet, mts.URL+"/demo/release/0.6/linux-amd64", "", nil)
	if resp2.StatusCode != http.StatusOK || digestOf(body2) != d {
		t.Fatalf("mirror canonical fetch -> %d digest=%s", resp2.StatusCode, digestOf(body2))
	}

	// 幂等：二次同步不重复计数。
	sum2, err := syncer.RunOnce(context.Background(), mirrorCfg, mirrorCreds, mirrorStore, cl)
	if err != nil {
		t.Fatal(err)
	}
	if sum2.Applied != 0 || sum2.BlobsFetched != 0 {
		t.Fatalf("second sync must be no-op: %+v", sum2)
	}

	// 删除本地字节后：302 回上级（跳链可追溯）。
	if err := mirrorStore.DeleteBlob(d); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, mts.URL+"/demo/release/0.6/linux-amd64", nil)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp3, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusFound {
		t.Fatalf("mirror without bytes must 302, got %d", resp3.StatusCode)
	}
	if loc := resp3.Header.Get("Location"); !strings.HasPrefix(loc, f.ts.URL+"/demo/release/0.6/linux-amd64") {
		t.Fatalf("redirect must point at upstream canonical URL, got %q", loc)
	}

	// 未登记节点不得同步。
	badCl := client.New(f.ts.URL).WithNodeIdentity("ghost", nodeKey)
	if _, err := badCl.SyncChanges(context.Background(), ""); err == nil {
		t.Fatal("unregistered node sync must fail")
	}
}

// TestMirrorRefusedWriteSurface 覆盖：镜像不承载发布/管理面（403）。
func TestMirrorRefusedWriteSurface(t *testing.T) {
	f := newRootFixture(t)
	registerProject(t, f, "demo")

	mirrorDir := t.TempDir()
	mirrorStore, err := store.Open(mirrorDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := mirrorStore.SetNodeMeta(&store.NodeMeta{Role: "mirror"}); err != nil {
		t.Fatal(err)
	}
	mirrorCfg := &config.Config{
		Node:   config.NodeConfig{Role: "mirror", Public: true, DataDir: mirrorDir},
		Mirror: config.MirrorConfig{UpstreamBaseURL: f.ts.URL},
	}
	mirrorSrv, err := server.New(mirrorCfg, &config.Credentials{}, "", mirrorStore)
	if err != nil {
		t.Fatal(err)
	}
	mts := httptest.NewServer(server.NewRouter(mirrorSrv))
	defer mts.Close()

	resp, _ := doJSON(t, http.MethodPost, mts.URL+"/v1/projects/demo/channels/release/versions", "author-tok", model.PublishRequest{Version: "0.6"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("publish on mirror must be 403, got %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, http.MethodPost, mts.URL+"/v1/admin/projects", "admin-tok", map[string]string{"name": "x"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin on mirror must be 403, got %d", resp.StatusCode)
	}
}
