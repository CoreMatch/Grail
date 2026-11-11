// Package client 是 Grail 的 HTTP 客户端：镜像同步、发布、解析等
// 命令行子命令共用。节点身份请求按约定签名：
//
//	X-Grail-Node-Id / X-Grail-Timestamp / X-Grail-Signature
//	签名消息 = nodeID "\n" timestamp "\n" METHOD "\n" path（不含 query）
//	时间窗口 ±300s（与生态内既有约定一致）
package client

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"Grail/internal/model"
)

// Client 是面向单个 Grail 节点的客户端。
// NodeID+NodeKey 与 Bearer 二选一（或都空 = 匿名读公开渠道）。
type Client struct {
	BaseURL string
	HTTP    *http.Client
	NodeID  string
	NodeKey ed25519.PrivateKey
	Bearer  string
}

// New 构造客户端。
func New(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 10 * time.Minute},
	}
}

// WithNodeIdentity 设置节点身份（镜像同步/内部 blob 拉取用）。
func (c *Client) WithNodeIdentity(nodeID string, key ed25519.PrivateKey) *Client {
	c.NodeID = nodeID
	c.NodeKey = key
	return c
}

// WithBearer 设置令牌（发布/管理/读凭据用）。
func (c *Client) WithBearer(token string) *Client {
	c.Bearer = token
	return c
}

// Do 发起请求：按配置附加节点签名或 Bearer 令牌。
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body io.Reader, headers http.Header) (*http.Response, error) {
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if c.NodeKey != nil && c.NodeID != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		msg := c.NodeID + "\n" + ts + "\n" + method + "\n" + path
		sig := ed25519.Sign(c.NodeKey, []byte(msg))
		req.Header.Set("X-Grail-Node-Id", c.NodeID)
		req.Header.Set("X-Grail-Timestamp", ts)
		req.Header.Set("X-Grail-Signature", base64.StdEncoding.EncodeToString(sig))
	} else if c.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}
	return c.HTTP.Do(req)
}

// GetJSON 发起 GET 并把响应体解析到 out；非 2xx 返回带响应片的错误。
func (c *Client) GetJSON(ctx context.Context, path string, query url.Values, out any) error {
	resp, err := c.Do(ctx, http.MethodGet, path, query, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errorFromResponse(resp)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// PostJSON 发起 POST（JSON 请求体）并解析响应。
func (c *Client) PostJSON(ctx context.Context, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(data))
	}
	headers := http.Header{}
	if in != nil {
		headers.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(ctx, http.MethodPost, path, nil, body, headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errorFromResponse(resp)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Delete 发起 DELETE。
func (c *Client) Delete(ctx context.Context, path string) error {
	resp, err := c.Do(ctx, http.MethodDelete, path, nil, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errorFromResponse(resp)
	}
	return nil
}

// SyncChanges 拉取同步增量（节点身份）。
func (c *Client) SyncChanges(ctx context.Context, since string) (*model.SyncChanges, error) {
	q := url.Values{}
	if since != "" {
		q.Set("since", since)
	}
	var out model.SyncChanges
	if err := c.GetJSON(ctx, "/v1/sync/changes", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FetchBlob 以节点身份拉取内容寻址字节（调用方负责校验 digest）。
func (c *Client) FetchBlob(ctx context.Context, digest string) (io.ReadCloser, int64, error) {
	resp, err := c.Do(ctx, http.MethodGet, "/v1/blobs/"+digest, nil, nil, nil)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, 0, errorFromResponse(resp)
	}
	return resp.Body, resp.ContentLength, nil
}

// UploadBlob 上传字节（发布前置步骤），声明期望 digest。
func (c *Client) UploadBlob(ctx context.Context, digest string, r io.Reader) error {
	headers := http.Header{}
	headers.Set("X-Grail-Digest", digest)
	headers.Set("Content-Type", "application/octet-stream")
	resp, err := c.Do(ctx, http.MethodPost, "/v1/blobs", nil, r, headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errorFromResponse(resp)
	}
	return nil
}

func errorFromResponse(resp *http.Response) error {
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("%s %s -> %d: %s", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, strings.TrimSpace(string(snippet)))
}
