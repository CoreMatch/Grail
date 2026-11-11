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
	"net/http"

	"github.com/gin-gonic/gin"
)

// NewRouter 组装节点的完整路由表。骨架期所有处理函数返回 501；
// 实现落地后逐个替换（路由表本身是契约面，先行冻结）。
func NewRouter() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	// --- 健康探测 ---
	r.GET("/healthz", notImplemented)

	// --- 规范取件 URL：对外唯一暴露的取件入口 ---
	// 本节点托管字节时 200 直供；否则 302（外部地址或上级节点对应 URL）。
	r.GET("/:project/:channel/:version/:platform", notImplemented)
	r.HEAD("/:project/:channel/:version/:platform", notImplemented)

	// --- 信任与状态分发 ---
	r.GET("/v1/keyring", notImplemented)
	r.GET("/v1/revocations", notImplemented)

	// --- 只读解析 ---
	r.GET("/v1/projects/:project/channels/:channel/versions", notImplemented)
	r.GET("/v1/projects/:project/channels/:channel/resolve", notImplemented)
	r.GET("/v1/projects/:project/channels/:channel/versions/:version", notImplemented)

	// --- 字节（内容寻址）：上传供发布用；下载供镜像同步用 ---
	r.GET("/v1/blobs/:digest", notImplemented)
	r.HEAD("/v1/blobs/:digest", notImplemented)
	r.POST("/v1/blobs", notImplemented)

	// --- 发布 ---
	r.POST("/v1/projects/:project/channels/:channel/versions", notImplemented)

	// --- 撤销与宽限期（维护面） ---
	r.POST("/v1/projects/:project/channels/:channel/versions/:version/yank", notImplemented)
	r.DELETE("/v1/projects/:project/channels/:channel/versions/:version/yank", notImplemented)
	r.POST("/v1/projects/:project/channels/:channel/versions/:version/deprecate", notImplemented)
	r.DELETE("/v1/projects/:project/channels/:channel/versions/:version/deprecate", notImplemented)

	// --- 镜像同步（节点身份） ---
	r.GET("/v1/sync/changes", notImplemented)

	// --- 原站管理 ---
	r.POST("/v1/admin/projects", notImplemented)
	r.POST("/v1/admin/nodes", notImplemented)
	r.GET("/v1/admin/nodes", notImplemented)
	r.DELETE("/v1/admin/nodes/:node", notImplemented)

	return r
}

// notImplemented 是骨架期占位：契约面已冻结，实现未落地。
func notImplemented(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "not implemented in skeleton",
		"path":  c.FullPath(),
	})
}
