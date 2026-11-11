// Grail 是 HA 生态的产物分发上游：原站 + 分级镜像的混合形态。
//
// 设计稿：GRAIL-DESIGN-20261112.md（R2 定稿）。
// 契约：HA-Contract docs/api/openapi/grail.yaml（METHOD+path 防漂移）。
//
// 子命令：
//   - init       初始化原站：生成根密钥、首个密钥环与状态文档、凭据模板
//   - server     启动节点（root 或 mirror，按配置）
//   - admin      原站管理：项目登记（项目密钥）、节点登记（节点身份）
//   - publish    发布产物：上传字节 + 登记版本（含血缘字段）
//   - resolve    解析版本清单并端到端验签
//   - sync       镜像节点执行一次同步（拉取，不推送）
//   - yank / unyank            撤销 / 撤销的撤销
//   - deprecate / undeprecate  宽限期 / 取消宽限
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"

	"Grail/internal/client"
	"Grail/internal/config"
	"Grail/internal/model"
	"Grail/internal/server"
	"Grail/internal/signing"
	"Grail/internal/store"
	"Grail/internal/syncer"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "server":
		err = cmdServer(args)
	case "admin":
		err = cmdAdmin(args)
	case "publish":
		err = cmdPublish(args)
	case "resolve":
		err = cmdResolve(args)
	case "sync":
		err = cmdSync(args)
	case "yank", "unyank", "deprecate", "undeprecate":
		err = cmdMaintenance(cmd, args)
	default:
		fmt.Fprintf(os.Stderr, "grail: 未知子命令 %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "grail: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `用法: grail <command> [flags]

命令:
  init          初始化原站（根密钥 + 密钥环 + 凭据模板）
  server        启动节点（--config --credentials）
  admin         原站管理（project add / node add / nodes / node rm）
  publish       发布产物
  resolve       解析并端到端验签
  sync          镜像同步一次
  yank          撤销版本          unyank       取消撤销
  deprecate     版本置入宽限期     undeprecate  取消宽限
`)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// --- init ---

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configPath := fs.String("config", "grail.yaml", "写入的节点配置文件")
	credsPath := fs.String("credentials", "credentials.json", "写入的凭据文件（0600）")
	dataDir := fs.String("data-dir", "./data", "数据目录")
	listen := fs.String("listen", config.DefaultListen, "监听地址")
	name := fs.String("name", "root", "节点名")
	public := fs.Bool("public", true, "公开节点：release 匿名可读")
	fs.Parse(args)

	st, err := store.Open(*dataDir)
	if err != nil {
		return err
	}
	if meta, _ := st.NodeMeta(); meta.Role == "root" {
		return fmt.Errorf("data dir %s already initialized as root; refusing to overwrite", *dataDir)
	}

	pub, priv, err := signing.GenerateKey()
	if err != nil {
		return err
	}
	rootEntry := model.KeyEntry{
		KeyID:     "root-1",
		Alg:       signing.Alg,
		PublicKey: signing.EncodeKey(pub),
		Created:   time.Now().UTC().Format(time.RFC3339),
	}
	keyring := model.KeyringPayload{
		Seq:       1,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Root:      rootEntry,
		Projects:  map[string]model.KeyEntry{},
	}
	keyringEnv, err := signing.SignEnvelope(keyring, rootEntry.KeyID, priv)
	if err != nil {
		return err
	}
	states := model.StatesPayload{
		Seq:       1,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Yanked:    []model.StateEntry{},
		Grace:     []model.GraceEntry{},
	}
	statesEnv, err := signing.SignEnvelope(states, rootEntry.KeyID, priv)
	if err != nil {
		return err
	}
	if err := st.SetKeyring(keyringEnv); err != nil {
		return err
	}
	if err := st.SetStates(statesEnv); err != nil {
		return err
	}
	if err := st.SetNodeMeta(&store.NodeMeta{Role: "root", Name: *name, Created: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		return err
	}

	adminToken, err := randomHex(32)
	if err != nil {
		return err
	}
	creds := &config.Credentials{
		AdminToken:     adminToken,
		RootPrivateKey: signing.EncodeKey(priv),
	}
	if err := config.SaveCredentials(*credsPath, creds); err != nil {
		return err
	}

	cfg := config.Config{Node: config.NodeConfig{
		Role: "root", Listen: *listen, Public: *public, DataDir: *dataDir,
	}}
	cfgData, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*configPath, cfgData, 0o644); err != nil {
		return err
	}

	fmt.Printf("root 初始化完成。\n")
	fmt.Printf("  配置:       %s\n", *configPath)
	fmt.Printf("  凭据:       %s（0600，含根私钥与管理令牌，绝不进仓库）\n", *credsPath)
	fmt.Printf("  根公钥:     %s\n", signing.EncodeKey(pub))
	fmt.Printf("  管理令牌:   %s（只出现这一次）\n", adminToken)
	fmt.Printf("下一步：登记项目密钥（admin project add）与下游节点（admin node add），然后 grail server。\n")
	return nil
}

// --- server ---

func cmdServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	configPath := fs.String("config", "grail.yaml", "节点配置")
	credsPath := fs.String("credentials", "credentials.json", "凭据文件")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	creds, err := config.LoadCredentials(*credsPath)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.Node.DataDir)
	if err != nil {
		return err
	}
	srv, err := server.New(cfg, creds, *credsPath, st)
	if err != nil {
		return err
	}

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	if cfg.Node.Role == "mirror" {
		nodeKey, err := signing.DecodePrivateKey(creds.NodePrivateKey)
		if err != nil || creds.NodeID == "" {
			return fmt.Errorf("mirror requires node_id + node_private_key in credentials (register via `grail admin node add` on the upper tier)")
		}
		cl := client.New(cfg.Mirror.UpstreamBaseURL).WithNodeIdentity(creds.NodeID, nodeKey)
		srv.OnSyncOnce = func(syncCtx context.Context) error {
			sum, err := syncer.RunOnce(syncCtx, cfg, creds, st, cl)
			if err != nil {
				return err
			}
			fmt.Printf("grail: sync ok: applied=%d removed=%d blobs_fetched=%d blobs_present=%d failures=%d cursor=%s\n",
				sum.Applied, sum.Removed, sum.BlobsFetched, sum.BlobsPresent, len(sum.BlobFailures), sum.Cursor)
			for _, f := range sum.BlobFailures {
				fmt.Printf("grail: blob not fetched (pointer-only fallback): %s\n", f)
			}
			return nil
		}
	}
	go srv.RunBackgroundLoops(ctx)

	gin.SetMode(gin.ReleaseMode)
	httpSrv := &http.Server{
		Addr:              cfg.Node.Listen,
		Handler:           server.NewRouter(srv),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	fmt.Printf("grail: role=%s public=%v listening on %s\n", cfg.Node.Role, cfg.Node.Public, cfg.Node.Listen)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// --- admin ---

func cmdAdmin(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: grail admin <project add|node add|nodes|node rm> ...")
	}
	fs := flag.NewFlagSet("admin", flag.ExitOnError)
	baseURL := fs.String("base-url", "", "Grail 节点地址")
	adminToken := fs.String("admin-token", "", "管理令牌")
	name := fs.String("name", "", "项目/节点名")
	channels := fs.String("channels", "", "节点可同步渠道（逗号分隔，空=全部）")
	id := fs.String("id", "", "节点 id（node rm）")
	// 位置参数（如 "project add"）在前，旗标在后：先切分再解析。
	split := 0
	for split < len(args) && !strings.HasPrefix(args[split], "-") {
		split++
	}
	sub := strings.Join(args[:split], " ")
	fs.Parse(args[split:])

	if *baseURL == "" || *adminToken == "" {
		return fmt.Errorf("--base-url 与 --admin-token 必填")
	}
	cl := client.New(*baseURL).WithBearer(*adminToken)
	ctx := context.Background()

	switch sub {
	case "project add":
		if *name == "" {
			return fmt.Errorf("--name 必填")
		}
		var out map[string]any
		if err := cl.PostJSON(ctx, "/v1/admin/projects", map[string]string{"name": *name}, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "node add":
		if *name == "" {
			return fmt.Errorf("--name 必填")
		}
		req := model.RegisterNodeRequest{Name: *name}
		if *channels != "" {
			req.Channels = strings.Split(*channels, ",")
		}
		var out model.RegisterNodeResponse
		if err := cl.PostJSON(ctx, "/v1/admin/nodes", req, &out); err != nil {
			return err
		}
		fmt.Printf("节点 %s 已登记。私钥只出现这一次：\n%s\n", out.NodeID, out.PrivateKey)
		return nil
	case "nodes":
		var out map[string]any
		if err := cl.GetJSON(ctx, "/v1/admin/nodes", nil, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "node rm":
		if *id == "" {
			return fmt.Errorf("--id 必填")
		}
		if err := cl.Delete(ctx, "/v1/admin/nodes/"+*id); err != nil {
			return err
		}
		fmt.Printf("节点 %s 已吊销。\n", *id)
		return nil
	default:
		return fmt.Errorf("未知 admin 子命令 %q（支持：project add / node add / nodes / node rm）", sub)
	}
}

// --- publish ---

type resourceFlag []string

func (r *resourceFlag) String() string     { return strings.Join(*r, " ") }
func (r *resourceFlag) Set(v string) error { *r = append(*r, v); return nil }

func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	baseURL := fs.String("base-url", "", "Grail 原站地址")
	token := fs.String("token", "", "发布令牌")
	project := fs.String("project", "", "项目名")
	channel := fs.String("channel", "", "渠道（ci|candidate|release）")
	version := fs.String("version", "", "版本字符串（不透明，渠道内永久消耗）")
	var locals, externals resourceFlag
	fs.Var(&locals, "resource", "本地资源 name:platform:/path（可重复）")
	fs.Var(&externals, "external", "外部资源 name,platform,url,sha256hex,size（可重复）")
	builder := fs.String("builder", "", "血缘：构建器标识")
	commit := fs.String("commit", "", "血缘：提交号")
	derivedChannel := fs.String("derived-channel", "", "血缘：来源渠道（通常 candidate）")
	derivedVersion := fs.String("derived-version", "", "血缘：来源版本")
	derivedNote := fs.String("derived-note", "", "血缘：反馈/修正摘要")
	sameContent := fs.Bool("same-content", false, "血缘：显式声明与来源版本同字节（D8，默认关闭）")
	fs.Parse(args)

	if *baseURL == "" || *token == "" || *project == "" || *channel == "" || *version == "" {
		return fmt.Errorf("--base-url --token --project --channel --version 必填")
	}
	if len(locals)+len(externals) == 0 {
		return fmt.Errorf("至少一个 --resource 或 --external")
	}

	cl := client.New(*baseURL).WithBearer(*token)
	ctx := context.Background()
	req := model.PublishRequest{Version: *version}

	for _, spec := range locals {
		parts := strings.SplitN(spec, ":", 3)
		if len(parts) != 3 {
			return fmt.Errorf("--resource 需要 name:platform:/path，得到 %q", spec)
		}
		name, platform, path := parts[0], parts[1], parts[2]
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		h := sha256.Sum256(data)
		digest := "sha256:" + hex.EncodeToString(h[:])
		if err := cl.UploadBlob(ctx, digest, bytes.NewReader(data)); err != nil {
			return fmt.Errorf("upload %s: %w", name, err)
		}
		req.Resources = append(req.Resources, model.PublishResource{
			Name: name, Platform: platform, Digest: digest, Size: int64(len(data)),
		})
	}
	for _, spec := range externals {
		// 逗号分隔，避免与 URL 内的冒号冲突：name,platform,url,sha256hex,size
		parts := strings.Split(spec, ",")
		if len(parts) != 5 {
			return fmt.Errorf("--external 需要 name,platform,url,sha256hex,size，得到 %q", spec)
		}
		size, err := strconv.ParseInt(parts[4], 10, 64)
		if err != nil {
			return fmt.Errorf("--external 大小解析失败: %q", spec)
		}
		digest := "sha256:" + strings.TrimPrefix(parts[3], "sha256:")
		req.Resources = append(req.Resources, model.PublishResource{
			Name: parts[0], Platform: parts[1], ExternalURL: parts[2],
			Digest: digest, Size: size,
		})
	}

	req.Provenance = model.Provenance{
		Builder: *builder, Commit: *commit,
		BuiltAt: time.Now().UTC().Format(time.RFC3339), SameContent: *sameContent,
	}
	if *derivedChannel != "" && *derivedVersion != "" {
		req.Provenance.DerivedFrom = &model.DerivedFrom{
			Channel: *derivedChannel, Version: *derivedVersion, Note: *derivedNote,
		}
	}

	var out map[string]any
	if err := cl.PostJSON(ctx, fmt.Sprintf("/v1/projects/%s/channels/%s/versions", *project, *channel), req, &out); err != nil {
		return err
	}
	return printJSON(out)
}

// --- resolve ---

func cmdResolve(args []string) error {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	baseURL := fs.String("base-url", "", "Grail 节点地址")
	token := fs.String("token", "", "读凭据（公开节点的 release 可省）")
	project := fs.String("project", "", "项目名")
	channel := fs.String("channel", "release", "渠道")
	version := fs.String("version", "latest", "版本（latest 或钉住）")
	platform := fs.String("platform", "", "平台过滤")
	rootKey := fs.String("root-key", "", "信任锚：根公钥 base64（或 @文件）")
	fs.Parse(args)

	if *baseURL == "" || *project == "" || *rootKey == "" {
		return fmt.Errorf("--base-url --project --root-key 必填")
	}
	anchorB64 := *rootKey
	if strings.HasPrefix(anchorB64, "@") {
		data, err := os.ReadFile(strings.TrimPrefix(anchorB64, "@"))
		if err != nil {
			return err
		}
		anchorB64 = strings.TrimSpace(string(data))
	}
	anchor, err := signing.DecodePublicKey(anchorB64)
	if err != nil {
		return fmt.Errorf("信任锚: %w", err)
	}

	cl := client.New(*baseURL)
	if *token != "" {
		cl.WithBearer(*token)
	}
	ctx := context.Background()

	// 1. 密钥环：锚点验签。
	var keyringEnv model.Envelope
	if err := cl.GetJSON(ctx, "/v1/keyring", nil, &keyringEnv); err != nil {
		return fmt.Errorf("fetch keyring: %w", err)
	}
	var kr model.KeyringPayload
	if err := signing.VerifyEnvelope(&keyringEnv, anchor, &kr); err != nil {
		return fmt.Errorf("keyring 验签失败: %w", err)
	}
	entry, ok := kr.Projects[*project]
	if !ok {
		return fmt.Errorf("密钥环中没有项目 %s", *project)
	}
	projectPub, err := signing.DecodePublicKey(entry.PublicKey)
	if err != nil {
		return err
	}

	// 2. 解析。
	q := map[string][]string{"version": {*version}}
	if *platform != "" {
		q["platform"] = []string{*platform}
	}
	var resp model.ResolveResponse
	if err := cl.GetJSON(ctx, fmt.Sprintf("/v1/projects/%s/channels/%s/resolve", *project, *channel), q, &resp); err != nil {
		return fmt.Errorf("resolve: %w", err)
	}

	// 3. 版本清单验签：取签名信封原文验证，再与解析结果对账。
	var env model.Envelope
	if err := cl.GetJSON(ctx, fmt.Sprintf("/v1/projects/%s/channels/%s/versions/%s", *project, *channel, resp.Version), nil, &env); err != nil {
		return fmt.Errorf("fetch manifest envelope: %w", err)
	}
	var manifest model.VersionManifest
	if err := signing.VerifyEnvelope(&env, projectPub, &manifest); err != nil {
		return fmt.Errorf("版本清单验签失败: %w", err)
	}
	if manifest.Version != resp.Version || manifest.Seq != resp.Seq {
		return fmt.Errorf("解析结果与签名清单不一致（中间节点可疑）")
	}

	fmt.Printf("验签通过：项目密钥 %s（密钥环 seq=%d，根锚点匹配）\n", entry.KeyID, kr.Seq)
	if resp.Yanked {
		fmt.Printf("警告：该版本已被 yank\n")
	}
	if resp.Grace != nil {
		fmt.Printf("警告：该版本处于宽限期，%s 移除\n", resp.Grace.RemoveAt)
	}
	out := map[string]any{
		"version": resp.Version, "seq": resp.Seq, "resolved_from": resp.ResolvedFrom,
		"provenance": resp.Provenance,
	}
	urls := make([]map[string]string, 0, len(resp.Resources))
	for _, res := range resp.Resources {
		urls = append(urls, map[string]string{
			"name": res.Name, "platform": res.Platform, "digest": res.Digest,
			"url": strings.TrimRight(*baseURL, "/") + res.URL,
		})
	}
	out["resources"] = urls
	return printJSON(out)
}

// --- sync ---

func cmdSync(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	configPath := fs.String("config", "grail.yaml", "节点配置")
	credsPath := fs.String("credentials", "credentials.json", "凭据文件")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Node.Role != "mirror" {
		return fmt.Errorf("sync 只用于 mirror 节点")
	}
	creds, err := config.LoadCredentials(*credsPath)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.Node.DataDir)
	if err != nil {
		return err
	}
	nodeKey, err := signing.DecodePrivateKey(creds.NodePrivateKey)
	if err != nil {
		return fmt.Errorf("node_private_key: %w", err)
	}
	cl := client.New(cfg.Mirror.UpstreamBaseURL).WithNodeIdentity(creds.NodeID, nodeKey)
	sum, err := syncer.RunOnce(context.Background(), cfg, creds, st, cl)
	if err != nil {
		return err
	}
	return printJSON(sum)
}

// --- yank / unyank / deprecate / undeprecate ---

func cmdMaintenance(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	baseURL := fs.String("base-url", "", "Grail 原站地址")
	adminToken := fs.String("admin-token", "", "管理令牌")
	project := fs.String("project", "", "项目名")
	channel := fs.String("channel", "", "渠道")
	version := fs.String("version", "", "版本")
	reason := fs.String("reason", "", "yank 原因")
	graceSeconds := fs.Int64("grace-seconds", 0, "宽限期秒数（默认 7 天）")
	fs.Parse(args)

	if *baseURL == "" || *adminToken == "" || *project == "" || *channel == "" || *version == "" {
		return fmt.Errorf("--base-url --admin-token --project --channel --version 必填")
	}
	cl := client.New(*baseURL).WithBearer(*adminToken)
	ctx := context.Background()
	base := fmt.Sprintf("/v1/projects/%s/channels/%s/versions/%s/", *project, *channel, *version)

	switch cmd {
	case "yank":
		return cl.PostJSON(ctx, base+"yank", map[string]string{"reason": *reason}, nil)
	case "unyank":
		return cl.Delete(ctx, base+"yank")
	case "deprecate":
		return cl.PostJSON(ctx, base+"deprecate", map[string]int64{"grace_seconds": *graceSeconds}, nil)
	case "undeprecate":
		return cl.Delete(ctx, base+"deprecate")
	}
	return fmt.Errorf("unknown maintenance command %q", cmd)
}

func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
