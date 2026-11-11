// Package httputil 承载抓取外部字节时的兜底防护（D10）：
// 拒绝指向内网地址的重定向（防 SSRF）。
package httputil

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
)

// IsPrivateHost 报告 host（域名或 IP）是否解析到任何内网/环回/
// 链路本地地址。域名会先解析出全部 IP 再逐个判断。
func IsPrivateHost(host string) bool {
	if host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return isPrivateIP(ip)
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		// 解析不了按不可信处理：兜底限制宁可拦下
		return true
	}
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return true
		}
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// SafeRedirectPolicy 产出重定向策略：最多 5 跳；任何一跳指向内网地址
// 都显式失败（原始请求目标由调用方在发起前自行校验）。
func SafeRedirectPolicy() func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects (>5)")
		}
		if IsPrivateHost(req.URL.Hostname()) {
			return fmt.Errorf("refusing redirect to internal address %q (SSRF guard)", req.URL.Host)
		}
		return nil
	}
}

// ValidateExternalURL 校验登记/抓取的外部 URL：
// 仅 http/https，且主机不得指向内网（发布时登记的硬校验）。
func ValidateExternalURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse external url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("external url scheme must be http/https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("external url has no host")
	}
	if IsPrivateHost(u.Hostname()) {
		return nil, fmt.Errorf("external url host %q resolves to an internal address (refused)", u.Host)
	}
	return u, nil
}
