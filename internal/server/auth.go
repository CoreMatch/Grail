// 鉴权分层（D12）：
//
//   - 读身份（"谁能看"）：release 在公开节点匿名可读；ci/candidate
//     需读凭据或节点身份。
//   - 节点身份（"谁能在下级建镜像"）：登记过密钥对的下游节点，
//     请求按 nodeID|timestamp|method|path 签名，窗口 ±300s。
//
// 两套身份不可合并：持读凭据不获得同步权，持节点身份不自动扩大读范围
// （节点可同步的渠道在登记时声明）。
package server

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"Grail/internal/config"
	"Grail/internal/model"
	"Grail/internal/signing"
)

const nodeSigWindow = 300 * time.Second

func bearerOf(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if len(h) > 7 && h[:7] == "Bearer " {
		return h[7:]
	}
	return ""
}

func tokenMatches(entries []config.TokenEntry, token, channel string) bool {
	for _, e := range entries {
		if subtle.ConstantTimeCompare([]byte(e.Token), []byte(token)) != 1 {
			continue
		}
		if len(e.Channels) == 0 {
			return true
		}
		for _, ch := range e.Channels {
			if ch == channel {
				return true
			}
		}
	}
	return false
}

// tokenMatchesAny 只验令牌本身（不看渠道范围）。
func tokenMatchesAny(entries []config.TokenEntry, token string) bool {
	for _, e := range entries {
		if subtle.ConstantTimeCompare([]byte(e.Token), []byte(token)) == 1 {
			return true
		}
	}
	return false
}

// requireAdmin 校验管理令牌；失败回 401。
func (s *Server) requireAdmin(c *gin.Context) bool {
	if s.creds.AdminToken == "" ||
		subtle.ConstantTimeCompare([]byte(s.creds.AdminToken), []byte(bearerOf(c))) != 1 {
		abort(c, http.StatusUnauthorized, "admin token required")
		return false
	}
	return true
}

// requireOrigin 要求本节点是原站（发布/管理/维护面只在原站）。
func (s *Server) requireOrigin(c *gin.Context) bool {
	if s.cfg.Node.Role != "root" {
		abort(c, http.StatusForbidden, "this node is a mirror: publish/maintenance is served by the origin")
		return false
	}
	return true
}

// requirePublish 校验发布令牌的渠道范围。
func (s *Server) requirePublish(c *gin.Context, channel string) bool {
	if !tokenMatches(s.creds.PublishTokens, bearerOf(c), channel) {
		abort(c, http.StatusUnauthorized, "publish token required for channel "+channel)
		return false
	}
	return true
}

// requireRead 按渠道读规则放行（读凭据或节点身份；release 在公开节点匿名）。
func (s *Server) requireRead(c *gin.Context, channel string) bool {
	if channel == "release" && s.cfg.Node.Public {
		return true
	}
	if tokenMatches(s.creds.ReadTokens, bearerOf(c), channel) {
		return true
	}
	if _, ok := s.verifyNodeIdentity(c, channel); ok {
		return true
	}
	abort(c, http.StatusUnauthorized, "channel "+channel+" requires read credentials")
	return false
}

// requireNode 仅放行持有效节点身份且渠道权限覆盖的请求。
func (s *Server) requireNode(c *gin.Context, channel string) bool {
	if _, ok := s.verifyNodeIdentity(c, channel); !ok {
		abort(c, http.StatusUnauthorized, "registered node identity required")
		return false
	}
	return true
}

// verifyNodeIdentity 验证节点签名并核对渠道权限；失败返回 ok=false
// （调用方决定是否已回 401——此处不重复写响应）。
func (s *Server) verifyNodeIdentity(c *gin.Context, channel string) (info *model.NodeInfo, ok bool) {
	id := c.GetHeader("X-Grail-Node-Id")
	tsStr := c.GetHeader("X-Grail-Timestamp")
	sigB64 := c.GetHeader("X-Grail-Signature")
	if id == "" || tsStr == "" || sigB64 == "" {
		return nil, false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return nil, false
	}
	d := time.Since(time.Unix(ts, 0))
	if d > nodeSigWindow || d < -nodeSigWindow {
		return nil, false
	}
	info, err = s.store.GetNode(id)
	if err != nil || info == nil {
		return nil, false
	}
	pub, err := signing.DecodePublicKey(info.PublicKey)
	if err != nil {
		return nil, false
	}
	msg := id + "\n" + tsStr + "\n" + c.Request.Method + "\n" + c.Request.URL.Path
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || !ed25519.Verify(pub, []byte(msg), sig) {
		return nil, false
	}
	if channel != "" && !nodeChannelAllowed(info.Channels, channel) {
		return nil, false
	}
	return info, true
}

func nodeChannelAllowed(channels []string, channel string) bool {
	if len(channels) == 0 {
		return true
	}
	for _, ch := range channels {
		if ch == channel {
			return true
		}
	}
	return false
}

func abort(c *gin.Context, status int, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"error": msg})
}

func abortf(c *gin.Context, status int, format string, args ...any) {
	abort(c, status, fmt.Sprintf(format, args...))
}
