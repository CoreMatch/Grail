// 写侧处理函数：字节上传、发布、yank/宽限期维护、镜像同步、原站管理。
// 发布与维护面只在原站（镜像一律 403）。
package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"Grail/internal/config"
	"Grail/internal/httputil"
	"Grail/internal/model"
	"Grail/internal/signing"
	"Grail/internal/store"
)

var projectNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// --- 字节上传 ---

// handleBlobUpload 流式接收字节：声明 digest → 临时文件+全程哈希 →
// 匹配才原子落盘（大小上限中途强制）。发布前置步骤。
func (s *Server) handleBlobUpload(c *gin.Context) {
	if !s.requireOrigin(c) {
		return
	}
	if !s.requirePublishAny(c) {
		return
	}
	digest := c.GetHeader("X-Grail-Digest")
	if !store.DigestRe.MatchString(digest) {
		abort(c, http.StatusBadRequest, "X-Grail-Digest header (sha256:<64hex>) required")
		return
	}
	size, err := s.store.PutBlob(c.Request.Body, digest, s.cfg.EffectiveMaxArtifactBytes())
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, store.ErrSizeCap) {
			status = http.StatusRequestEntityTooLarge
		}
		abort(c, status, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"digest": digest, "size": size})
}

// requirePublishAny 放行任一发布令牌（blob 上传先于渠道归属）。
func (s *Server) requirePublishAny(c *gin.Context) bool {
	if len(s.creds.PublishTokens) == 0 || bearerOf(c) == "" ||
		!tokenMatchesAny(s.creds.PublishTokens, bearerOf(c)) {
		abort(c, http.StatusUnauthorized, "publish token required")
		return false
	}
	return true
}

// --- 发布 ---

// handlePublish 登记新版本（D5/D7/D13）：
// 版本字符串永久消耗；字节必须已在库或给出外部地址（原站按兜底限制摄取）；
// 项目密钥签名后指针可见。不做任何"移动指针"式操作。
func (s *Server) handlePublish(c *gin.Context) {
	project := c.Param("project")
	channel := c.Param("channel")
	if !store.ValidChannel(channel) {
		abort(c, http.StatusNotFound, "unknown channel")
		return
	}
	if !s.requireOrigin(c) {
		return
	}
	if !s.requirePublish(c, channel) {
		return
	}
	if _, err := s.projectEntry(project); err != nil {
		abort(c, http.StatusNotFound, err.Error())
		return
	}

	var req model.PublishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abort(c, http.StatusBadRequest, "parse publish request: "+err.Error())
		return
	}
	if !store.VersionRe.MatchString(req.Version) {
		abort(c, http.StatusBadRequest, "version string must match "+store.VersionRe.String())
		return
	}
	if len(req.Resources) == 0 {
		abort(c, http.StatusBadRequest, "at least one resource required")
		return
	}
	if existing, _ := s.store.GetVersion(project, channel, req.Version); existing != nil {
		abort(c, http.StatusBadRequest,
			fmt.Sprintf("version %q already published in %s/%s: version strings are permanently consumed (no republish, no reuse after yank)",
				req.Version, project, channel))
		return
	}

	maxBytes := s.cfg.EffectiveMaxArtifactBytes()
	resources := make([]model.Resource, 0, len(req.Resources))
	externals := make(map[string]string)
	type ingestionReport struct {
		Digest string `json:"digest"`
		State  string `json:"state"` // stored | external | failed
		Detail string `json:"detail,omitempty"`
	}
	var ingestions []ingestionReport

	for _, pr := range req.Resources {
		if !store.DigestRe.MatchString(pr.Digest) {
			abort(c, http.StatusBadRequest, "resource "+pr.Name+": malformed digest")
			return
		}
		if pr.Platform == "" || pr.Name == "" {
			abort(c, http.StatusBadRequest, "resource name and platform required")
			return
		}
		if pr.Size < 0 || (pr.Size > 0 && pr.Size > maxBytes) {
			abort(c, http.StatusBadRequest, "resource "+pr.Name+": declared size breaches size cap")
			return
		}

		switch {
		case pr.ExternalURL != "":
			// URL 型：先做 SSRF 硬校验，再尝试摄取落盘（D4/D10）。
			if _, err := httputil.ValidateExternalURL(pr.ExternalURL); err != nil {
				abort(c, http.StatusBadRequest, "resource "+pr.Name+": "+err.Error())
				return
			}
			if err := s.ingestExternal(c.Request.Context(), pr.ExternalURL, pr.Digest, maxBytes); err != nil {
				externals[pr.Digest] = pr.ExternalURL
				ingestions = append(ingestions, ingestionReport{Digest: pr.Digest, State: "external", Detail: err.Error()})
			} else {
				ingestions = append(ingestions, ingestionReport{Digest: pr.Digest, State: "stored"})
			}
		default:
			if !s.store.HasBlob(pr.Digest) {
				abort(c, http.StatusBadRequest,
					"resource "+pr.Name+": digest "+pr.Digest+" not in blob store (upload via POST /v1/blobs first, or declare external_url)")
				return
			}
			ingestions = append(ingestions, ingestionReport{Digest: pr.Digest, State: "stored"})
		}

		resources = append(resources, model.Resource{
			Name:     pr.Name,
			Platform: pr.Platform,
			Digest:   pr.Digest,
			Size:     pr.Size,
			URL:      fmt.Sprintf("/%s/%s/%s/%s", project, channel, req.Version, pr.Platform),
		})
	}

	seq, err := s.store.NextSeq(project, channel)
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	platforms := uniquePlatforms(resources)
	manifest := model.VersionManifest{
		Project:     project,
		Channel:     channel,
		Version:     req.Version,
		Seq:         seq,
		Platforms:   platforms,
		Resources:   resources,
		Provenance:  req.Provenance,
		PublishedAt: nowUTC(),
	}

	entry, err := s.projectEntry(project)
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	priv, err := signing.DecodePrivateKey(s.creds.ProjectPrivateKeys[project])
	if err != nil {
		abort(c, http.StatusInternalServerError, "project private key for "+project+": "+err.Error())
		return
	}
	env, err := signing.SignEnvelope(manifest, entry.KeyID, priv)
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}

	rec := &store.VersionRecord{
		Envelope:  env,
		Manifest:  &manifest,
		Externals: externals,
	}
	if err := s.store.PutVersion(project, channel, req.Version, rec); err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := s.store.AppendJournal("publish", model.VersionRef{Project: project, Channel: channel, Version: req.Version}); err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"project":   project,
		"channel":   channel,
		"version":   req.Version,
		"seq":       seq,
		"signature": env.Signature,
		"ingestion": ingestions,
	})
}

func uniquePlatforms(resources []model.Resource) []string {
	seen := make(map[string]bool)
	var out []string
	for _, res := range resources {
		if !seen[res.Platform] {
			seen[res.Platform] = true
			out = append(out, res.Platform)
		}
	}
	return out
}

// ingestExternal 抓取外部字节落盘：不带任何凭据、重定向经 SSRF 守卫、
// 大小上限、digest 校验。失败返回错误（调用方降级为 302 外部）。
func (s *Server) ingestExternal(ctx context.Context, rawURL, expectDigest string, maxBytes int64) error {
	client := &http.Client{
		Timeout:       10 * time.Minute,
		CheckRedirect: httputil.SafeRedirectPolicy(),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch external: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch external: GET %s -> %d", rawURL, resp.StatusCode)
	}
	if _, err := s.store.PutBlob(resp.Body, expectDigest, maxBytes); err != nil {
		return fmt.Errorf("ingest external: %w", err)
	}
	return nil
}

// --- yank / 宽限期 ---

func refOf(c *gin.Context) model.VersionRef {
	return model.VersionRef{
		Project: c.Param("project"),
		Channel: c.Param("channel"),
		Version: c.Param("version"),
	}
}

func (s *Server) handleYank(c *gin.Context) {
	if !s.requireOrigin(c) || !s.requireAdmin(c) {
		return
	}
	ref := refOf(c)
	rec, err := s.store.GetVersion(ref.Project, ref.Channel, ref.Version)
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil {
		abort(c, http.StatusNotFound, "unknown version")
		return
	}
	if rec.State.Yanked {
		c.JSON(http.StatusOK, gin.H{"already": true})
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)

	if err := s.updateStates(func(sp *model.StatesPayload) {
		sp.Yanked = append(sp.Yanked, model.StateEntry{
			Project: ref.Project, Channel: ref.Channel, Version: ref.Version,
			At: nowUTC(), Reason: body.Reason,
		})
	}); err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	st := rec.State
	st.Yanked = true
	st.YankAt = nowUTC()
	st.Reason = body.Reason
	if err := s.store.SetVersionState(ref.Project, ref.Channel, ref.Version, st); err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"yanked": true})
}

func (s *Server) handleUnyank(c *gin.Context) {
	if !s.requireOrigin(c) || !s.requireAdmin(c) {
		return
	}
	ref := refOf(c)
	rec, err := s.store.GetVersion(ref.Project, ref.Channel, ref.Version)
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil {
		abort(c, http.StatusNotFound, "unknown version")
		return
	}
	if err := s.updateStates(func(sp *model.StatesPayload) {
		out := sp.Yanked[:0]
		for _, e := range sp.Yanked {
			if e.Project == ref.Project && e.Channel == ref.Channel && e.Version == ref.Version {
				continue
			}
			out = append(out, e)
		}
		sp.Yanked = out
	}); err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	st := rec.State
	st.Yanked = false
	st.YankAt = ""
	st.Reason = ""
	if err := s.store.SetVersionState(ref.Project, ref.Channel, ref.Version, st); err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"yanked": false})
}

// handleDeprecate 把版本置入宽限期（D15）。
// 被引用的版本拒绝清理：返回 409 与引用清单（设计稿 11.3）。
func (s *Server) handleDeprecate(c *gin.Context) {
	if !s.requireOrigin(c) || !s.requireAdmin(c) {
		return
	}
	ref := refOf(c)
	rec, err := s.store.GetVersion(ref.Project, ref.Channel, ref.Version)
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil {
		abort(c, http.StatusNotFound, "unknown version")
		return
	}
	if rec.State.Grace {
		c.JSON(http.StatusOK, gin.H{"already": true, "remove_at": rec.State.RemoveAt})
		return
	}

	refs, err := s.store.ReferencedBy(ref)
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	if len(refs) > 0 {
		c.JSON(http.StatusConflict, gin.H{
			"error":         "version is referenced by lineage; cleanup refused",
			"referenced_by": refs,
		})
		return
	}

	var body struct {
		GraceSeconds int64 `json:"grace_seconds"`
	}
	_ = c.ShouldBindJSON(&body)
	if body.GraceSeconds <= 0 {
		body.GraceSeconds = 7 * 24 * 3600 // 默认 7 天宽限
	}
	removeAt := time.Now().UTC().Add(time.Duration(body.GraceSeconds) * time.Second).Format(time.RFC3339)

	if err := s.updateStates(func(sp *model.StatesPayload) {
		sp.Grace = append(sp.Grace, model.GraceEntry{
			Project: ref.Project, Channel: ref.Channel, Version: ref.Version,
			At: nowUTC(), RemoveAt: removeAt,
		})
	}); err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	st := rec.State
	st.Grace = true
	st.GraceAt = nowUTC()
	st.RemoveAt = removeAt
	if err := s.store.SetVersionState(ref.Project, ref.Channel, ref.Version, st); err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"grace": true, "remove_at": removeAt})
}

func (s *Server) handleCancelDeprecate(c *gin.Context) {
	if !s.requireOrigin(c) || !s.requireAdmin(c) {
		return
	}
	ref := refOf(c)
	rec, err := s.store.GetVersion(ref.Project, ref.Channel, ref.Version)
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil {
		abort(c, http.StatusNotFound, "unknown version")
		return
	}
	if !rec.State.Grace {
		abort(c, http.StatusNotFound, "version not in grace")
		return
	}
	if err := s.updateStates(func(sp *model.StatesPayload) {
		out := sp.Grace[:0]
		for _, e := range sp.Grace {
			if e.Project == ref.Project && e.Channel == ref.Channel && e.Version == ref.Version {
				continue
			}
			out = append(out, e)
		}
		sp.Grace = out
	}); err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	st := rec.State
	st.Grace = false
	st.GraceAt = ""
	st.RemoveAt = ""
	if err := s.store.SetVersionState(ref.Project, ref.Channel, ref.Version, st); err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"grace": false})
}

// --- 镜像同步（只拉不推，D11） ---

func (s *Server) handleSyncChanges(c *gin.Context) {
	info, ok := s.verifyNodeIdentity(c, "")
	if !ok {
		abort(c, http.StatusUnauthorized, "registered node identity required")
		return
	}
	var since int64
	if q := c.Query("since"); q != "" {
		if v, err := strconv.ParseInt(q, 10, 64); err == nil {
			since = v
		}
	}
	entries, cursor, err := s.store.JournalSince(since)
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}

	var manifests []model.Envelope
	var removed []model.VersionRef
	for _, e := range entries {
		if !nodeChannelAllowed(info.Channels, e.Ref.Channel) {
			continue
		}
		switch e.Type {
		case "publish":
			rec, err := s.store.GetVersion(e.Ref.Project, e.Ref.Channel, e.Ref.Version)
			if err != nil {
				abort(c, http.StatusInternalServerError, err.Error())
				return
			}
			if rec != nil {
				manifests = append(manifests, *rec.Envelope)
			}
		case "remove":
			removed = append(removed, e.Ref)
		}
	}

	out := model.SyncChanges{
		Cursor:    cursor,
		Keyring:   s.store.Keyring(),
		States:    s.store.States(),
		Manifests: manifests,
		Removed:   removed,
	}
	c.JSON(http.StatusOK, out)
}

// --- 原站管理 ---

func (s *Server) handleAdminRegisterProject(c *gin.Context) {
	if !s.requireOrigin(c) || !s.requireAdmin(c) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || !projectNameRe.MatchString(body.Name) {
		abort(c, http.StatusBadRequest, "project name must match "+projectNameRe.String())
		return
	}
	if _, err := s.projectEntry(body.Name); err == nil {
		abort(c, http.StatusConflict, "project already registered: "+body.Name)
		return
	}

	pub, priv, err := signing.GenerateKey()
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	keyID := body.Name + "-1"
	if err := s.updateKeyring(func(kr *model.KeyringPayload) {
		kr.Projects[body.Name] = model.KeyEntry{
			KeyID:     keyID,
			Alg:       signing.Alg,
			PublicKey: signing.EncodeKey(pub),
			Created:   nowUTC(),
		}
	}); err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	// 项目私钥只落在原站凭据文件（0600），绝不出服务端。
	if s.creds.ProjectPrivateKeys == nil {
		s.creds.ProjectPrivateKeys = make(map[string]string)
	}
	s.creds.ProjectPrivateKeys[body.Name] = signing.EncodeKey(priv)
	if s.credsPath != "" {
		if err := config.SaveCredentials(s.credsPath, s.creds); err != nil {
			abort(c, http.StatusInternalServerError, "persist project key: "+err.Error())
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"project":    body.Name,
		"key_id":     keyID,
		"public_key": signing.EncodeKey(pub),
	})
}

func (s *Server) handleAdminRegisterNode(c *gin.Context) {
	if !s.requireOrigin(c) || !s.requireAdmin(c) {
		return
	}
	var req model.RegisterNodeRequest
	if err := c.ShouldBindJSON(&req); err != nil || !projectNameRe.MatchString(req.Name) {
		abort(c, http.StatusBadRequest, "node name must match "+projectNameRe.String())
		return
	}
	if existing, _ := s.store.GetNode(req.Name); existing != nil {
		abort(c, http.StatusConflict, "node already registered: "+req.Name)
		return
	}
	pub, priv, err := signing.GenerateKey()
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	info := &model.NodeInfo{
		NodeID:    req.Name,
		PublicKey: signing.EncodeKey(pub),
		Channels:  req.Channels,
		Created:   nowUTC(),
	}
	if err := s.store.PutNode(info); err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	// 私钥只在登记响应中出现一次（运维交接点）。
	c.JSON(http.StatusOK, model.RegisterNodeResponse{
		NodeID:     req.Name,
		PublicKey:  signing.EncodeKey(pub),
		PrivateKey: signing.EncodeKey(priv),
		Channels:   req.Channels,
	})
}

func (s *Server) handleAdminListNodes(c *gin.Context) {
	if !s.requireOrigin(c) || !s.requireAdmin(c) {
		return
	}
	nodes, err := s.store.ListNodes()
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"nodes": nodes})
}

func (s *Server) handleAdminDeleteNode(c *gin.Context) {
	if !s.requireOrigin(c) || !s.requireAdmin(c) {
		return
	}
	if err := s.store.DeleteNode(c.Param("node")); err != nil {
		abort(c, http.StatusNotFound, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked": c.Param("node")})
}
