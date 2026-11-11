// Package server 承载 Grail 节点的全部 HTTP 面。
//
// 本文件是 HA-Contract 业务 API 防漂移校验（check-business-api-drift.sh）
// 的路由来源文件：全部路由必须在这里注册，且与
// HA-Contract docs/api/openapi/grail.yaml 保持 METHOD+path 双向一致。
//
// 路由分四族：
//   - 规范取件 URL（对外唯一取件入口，D10）：GET /{project}/{channel}/{version}/{platform}
//   - 只读解析面（/v1/keyring、/v1/revocations、/v1/projects/...）
//   - 发布与维护面（POST /v1/blobs、POST .../versions、yank、deprecate、admin）
//   - 镜像同步面（GET /v1/sync/changes，节点身份鉴权）
package server

import (
	"github.com/gin-gonic/gin"
)

// NewRouter 组装节点的完整路由表（处理函数全部挂在 Server 上）。
func NewRouter(s *Server) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	// --- 健康探测 ---
	r.GET("/healthz", s.handleHealthz)

	// --- 规范取件 URL：对外唯一暴露的取件入口 ---
	// 本节点托管字节时 200 直供；否则 302（外部地址或上级节点对应 URL）。
	r.GET("/:project/:channel/:version/:platform", s.handleCanonical)
	r.HEAD("/:project/:channel/:version/:platform", s.handleCanonical)

	// --- 信任与状态分发 ---
	r.GET("/v1/keyring", s.handleKeyring)
	r.GET("/v1/revocations", s.handleRevocations)

	// --- 只读解析 ---
	r.GET("/v1/projects/:project/channels/:channel/versions", s.handleListVersions)
	r.GET("/v1/projects/:project/channels/:channel/resolve", s.handleResolve)
	r.GET("/v1/projects/:project/channels/:channel/versions/:version", s.handleGetVersion)

	// --- 字节（内容寻址）：上传供发布用；下载供镜像同步用 ---
	r.GET("/v1/blobs/:digest", s.handleBlobGet)
	r.HEAD("/v1/blobs/:digest", s.handleBlobGet)
	r.POST("/v1/blobs", s.handleBlobUpload)

	// --- 发布 ---
	r.POST("/v1/projects/:project/channels/:channel/versions", s.handlePublish)

	// --- 撤销与宽限期（维护面） ---
	r.POST("/v1/projects/:project/channels/:channel/versions/:version/yank", s.handleYank)
	r.DELETE("/v1/projects/:project/channels/:channel/versions/:version/yank", s.handleUnyank)
	r.POST("/v1/projects/:project/channels/:channel/versions/:version/deprecate", s.handleDeprecate)
	r.DELETE("/v1/projects/:project/channels/:channel/versions/:version/deprecate", s.handleCancelDeprecate)

	// --- 镜像同步（节点身份） ---
	r.GET("/v1/sync/changes", s.handleSyncChanges)

	// --- 原站管理 ---
	r.POST("/v1/admin/projects", s.handleAdminRegisterProject)
	r.POST("/v1/admin/nodes", s.handleAdminRegisterNode)
	r.GET("/v1/admin/nodes", s.handleAdminListNodes)
	r.DELETE("/v1/admin/nodes/:node", s.handleAdminDeleteNode)

	return r
}
