// 读侧处理函数：健康探测、信任分发（密钥环/状态）、解析、规范取件 URL。
package server

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"Grail/internal/model"
	"Grail/internal/store"
)

func (s *Server) handleHealthz(c *gin.Context) {
	meta, _ := s.store.NodeMeta()
	c.JSON(http.StatusOK, gin.H{
		"node": meta.Name,
		"role": s.cfg.Node.Role,
		"time": nowUTC(),
		"tier": s.Tier(),
	})
}

func (s *Server) handleKeyring(c *gin.Context) {
	env := s.store.Keyring()
	if env == nil {
		abort(c, http.StatusNotFound, "keyring not initialized on this node")
		return
	}
	c.JSON(http.StatusOK, env)
}

func (s *Server) handleRevocations(c *gin.Context) {
	env := s.store.States()
	if env == nil {
		abort(c, http.StatusNotFound, "states document not initialized on this node")
		return
	}
	c.JSON(http.StatusOK, env)
}

// versionSummary 是版本列表的条目。
type versionSummary struct {
	Version     string           `json:"version"`
	Seq         int64            `json:"seq"`
	Yanked      bool             `json:"yanked"`
	Grace       *model.GraceInfo `json:"grace"`
	PublishedAt string           `json:"published_at"`
}

func (s *Server) handleListVersions(c *gin.Context) {
	project := c.Param("project")
	channel := c.Param("channel")
	if !store.ValidChannel(channel) {
		abort(c, http.StatusNotFound, "unknown channel")
		return
	}
	if !s.requireRead(c, channel) {
		return
	}
	recs, err := s.store.ListVersions(project, channel)
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	includeAll := c.Query("include_unselectable") == "true"
	limit := 50
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 && v <= 500 {
		limit = v
	}
	var cursorSeq int64
	if cur := c.Query("cursor"); cur != "" {
		if v, err := strconv.ParseInt(cur, 10, 64); err == nil {
			cursorSeq = v
		}
	}

	out := make([]versionSummary, 0, limit)
	for _, rec := range recs { // 已按 seq 倒序
		if cursorSeq > 0 && rec.Manifest.Seq >= cursorSeq {
			continue
		}
		if !includeAll && !rec.State.Selectable() {
			continue
		}
		sum := versionSummary{
			Version:     rec.Manifest.Version,
			Seq:         rec.Manifest.Seq,
			Yanked:      rec.State.Yanked,
			PublishedAt: rec.Manifest.PublishedAt,
		}
		if rec.State.Grace {
			sum.Grace = &model.GraceInfo{RemoveAt: rec.State.RemoveAt}
		}
		out = append(out, sum)
		if len(out) >= limit {
			break
		}
	}
	var next string
	if len(out) == limit {
		next = strconv.FormatInt(out[len(out)-1].Seq, 10)
	}
	c.JSON(http.StatusOK, gin.H{"versions": out, "next_cursor": next})
}

// hasPlatform 报告版本是否携带目标平台（或平台无关资源）。
func hasPlatform(rec *store.VersionRecord, platform string) bool {
	if platform == "" {
		return true
	}
	for _, res := range rec.Manifest.Resources {
		if res.Platform == platform || res.Platform == "any" {
			return true
		}
	}
	return false
}

// filterResources 按平台过滤资源（保留精确匹配与 any）。
func filterResources(resources []model.Resource, platform string) []model.Resource {
	if platform == "" {
		return resources
	}
	var out []model.Resource
	for _, res := range resources {
		if res.Platform == platform || res.Platform == "any" {
			out = append(out, res)
		}
	}
	return out
}

func (s *Server) handleResolve(c *gin.Context) {
	project := c.Param("project")
	channel := c.Param("channel")
	if !store.ValidChannel(channel) {
		abort(c, http.StatusNotFound, "unknown channel")
		return
	}
	if !s.requireRead(c, channel) {
		return
	}
	version := c.DefaultQuery("version", "latest")
	platform := c.Query("platform")

	var rec *store.VersionRecord
	var resolvedFrom string
	if version == "latest" {
		recs, err := s.store.ListVersions(project, channel)
		if err != nil {
			abort(c, http.StatusInternalServerError, err.Error())
			return
		}
		for _, r := range recs { // seq 倒序
			// latest 跳过 yank 与宽限期版本（设计稿 10.1）
			if !r.State.Selectable() {
				continue
			}
			if !hasPlatform(r, platform) {
				continue
			}
			rec = r
			break
		}
		if rec == nil {
			abort(c, http.StatusNotFound, "no selectable version in "+project+"/"+channel+
				" (all yanked/in grace, or none match platform)")
			return
		}
		resolvedFrom = "latest"
	} else {
		var err error
		rec, err = s.store.GetVersion(project, channel, version)
		if err != nil {
			abort(c, http.StatusInternalServerError, err.Error())
			return
		}
		if rec == nil {
			abort(c, http.StatusNotFound, "unknown version "+version)
			return
		}
		resolvedFrom = "pinned"
	}

	resp := model.ResolveResponse{
		Project:      project,
		Channel:      channel,
		Version:      rec.Manifest.Version,
		Seq:          rec.Manifest.Seq,
		Yanked:       rec.State.Yanked,
		ResolvedFrom: resolvedFrom,
		Platforms:    rec.Manifest.Platforms,
		Resources:    filterResources(rec.Manifest.Resources, platform),
		Provenance:   rec.Manifest.Provenance,
		Signature:    rec.Envelope.Signature,
		ServingNode:  s.servingNode(),
	}
	if rec.State.Grace {
		resp.Grace = &model.GraceInfo{RemoveAt: rec.State.RemoveAt}
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) handleGetVersion(c *gin.Context) {
	project := c.Param("project")
	channel := c.Param("channel")
	version := c.Param("version")
	if !store.ValidChannel(channel) {
		abort(c, http.StatusNotFound, "unknown channel")
		return
	}
	if !s.requireRead(c, channel) {
		return
	}
	rec, err := s.store.GetVersion(project, channel, version)
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil {
		abort(c, http.StatusNotFound, "unknown version "+version)
		return
	}
	c.JSON(http.StatusOK, rec.Envelope)
}

// handleCanonical 是规范取件 URL（D10）：
// 本节点托管字节 → 200 直供；否则 302（原站转外部地址，镜像转上级）。
// yank/宽限标记以响应头显式随行。
func (s *Server) handleCanonical(c *gin.Context) {
	project := c.Param("project")
	channel := c.Param("channel")
	version := c.Param("version")
	platform := c.Param("platform")
	if !store.ValidChannel(channel) {
		abort(c, http.StatusNotFound, "unknown channel")
		return
	}
	if !s.requireRead(c, channel) {
		return
	}
	rec, err := s.store.GetVersion(project, channel, version)
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil {
		abort(c, http.StatusNotFound, "unknown version")
		return
	}
	var res *model.Resource
	for i := range rec.Manifest.Resources {
		if rec.Manifest.Resources[i].Platform == platform || rec.Manifest.Resources[i].Platform == "any" {
			res = &rec.Manifest.Resources[i]
			break
		}
	}
	if res == nil {
		abort(c, http.StatusNotFound, "no resource for platform "+platform)
		return
	}
	if rec.State.Yanked {
		c.Header("X-Grail-Yanked", "true")
	}
	if rec.State.Grace {
		c.Header("X-Grail-Grace", rec.State.RemoveAt)
	}

	if s.store.HasBlob(res.Digest) {
		f, size, err := s.store.OpenBlob(res.Digest)
		if err != nil {
			abort(c, http.StatusInternalServerError, err.Error())
			return
		}
		defer f.Close()
		c.Header("X-Grail-Digest", res.Digest)
		c.DataFromReader(http.StatusOK, size, "application/octet-stream", f, nil)
		return
	}

	if s.cfg.Node.Role == "root" {
		if ext := rec.Externals[res.Digest]; ext != "" {
			c.Redirect(http.StatusFound, ext)
			return
		}
		abort(c, http.StatusNotFound, "bytes not available on origin (no blob, no external)")
		return
	}
	// 镜像未持有字节：转上级节点的对应规范 URL（设计稿 8.5）。
	c.Redirect(http.StatusFound, s.cfg.Mirror.UpstreamBaseURL+c.Request.URL.Path)
}

// handleBlobGet 以节点身份提供内容寻址字节（镜像同步用）。
func (s *Server) handleBlobGet(c *gin.Context) {
	if !s.requireNode(c, "") {
		return
	}
	digest := c.Param("digest")
	if !store.DigestRe.MatchString(digest) {
		abort(c, http.StatusNotFound, "malformed digest")
		return
	}
	if !s.store.HasBlob(digest) {
		abort(c, http.StatusNotFound, "blob not stored on this node")
		return
	}
	f, size, err := s.store.OpenBlob(digest)
	if err != nil {
		abort(c, http.StatusInternalServerError, err.Error())
		return
	}
	defer f.Close()
	c.DataFromReader(http.StatusOK, size, "application/octet-stream", f, nil)
}
