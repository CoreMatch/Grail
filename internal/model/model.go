// Package model 定义 Grail 的全部线上结构（契约形状见
// HA-Contract docs/api/openapi/grail.yaml）。
//
// 规范化约定：所有被签名的负载（payload）都通过固定结构体的
// encoding/json 序列化产生——Go 对 struct 按字段声明顺序、对 map 按
// 键排序输出，序列化结果确定，签名即对该字节序列计算。
package model

import "encoding/json"

// Signature 是对负载规范化 JSON 的 Ed25519 签名。
type Signature struct {
	KeyID string `json:"key_id"`
	Alg   string `json:"alg"` // 恒为 ed25519
	Value string `json:"value"`
}

// Envelope 是一份被签名的文档：payload 是被签名的规范化 JSON 原文，
// 验签方必须且只能使用这里的字节验签，不得重新序列化。
type Envelope struct {
	Payload   json.RawMessage `json:"payload"`
	Signature Signature       `json:"signature"`
}

// KeyEntry 是密钥环中的一把公钥。
type KeyEntry struct {
	KeyID     string `json:"key_id"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
	Created   string `json:"created"`
}

// KeyringPayload 是根密钥签署的密钥环负载：
// 单调序号 + 根公钥 + 项目→公钥映射（D9：每项目一把独立密钥）。
type KeyringPayload struct {
	Seq       int64               `json:"seq"`
	UpdatedAt string              `json:"updated_at"`
	Root      KeyEntry            `json:"root"`
	Projects  map[string]KeyEntry `json:"projects"`
}

// StateEntry 记录一次 yank（撤销）。
type StateEntry struct {
	Project string `json:"project"`
	Channel string `json:"channel"`
	Version string `json:"version"`
	At      string `json:"at"`
	Reason  string `json:"reason,omitempty"`
}

// GraceEntry 记录一个进入宽限期的版本（D15）。
type GraceEntry struct {
	Project  string `json:"project"`
	Channel  string `json:"channel"`
	Version  string `json:"version"`
	At       string `json:"at"`
	RemoveAt string `json:"remove_at"`
}

// StatesPayload 是根密钥签署的选择状态负载：
// yank 列表 + 宽限期列表，随同步分发（镜像据此跳过/标记版本）。
type StatesPayload struct {
	Seq       int64        `json:"seq"`
	UpdatedAt string       `json:"updated_at"`
	Yanked    []StateEntry `json:"yanked"`
	Grace     []GraceEntry `json:"grace"`
}

// Resource 是一个可交付文件。消费方只见一个 URL（规范 URL）；
// 字节实际在哪一层是该节点的内部事务（D10）。
type Resource struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
	Digest   string `json:"digest"` // sha256:<64hex>
	Size     int64  `json:"size"`
	URL      string `json:"url"` // 本节点上的规范 URL 路径
}

// DerivedFrom 是血缘指针：本版本从哪个 candidate 版本的反馈/修正中重建而来。
type DerivedFrom struct {
	Channel string `json:"channel"`
	Version string `json:"version"`
	Digest  string `json:"digest,omitempty"`
	Note    string `json:"note,omitempty"`
}

// Provenance 是血缘记录，随版本清单一起被签名。
// SameContent 为显式声明（默认 false）：本版本与来源 candidate 字节相同
// （D8 边缘情况，需显式开启）。
type Provenance struct {
	Builder     string       `json:"builder,omitempty"`
	Commit      string       `json:"commit,omitempty"`
	BuiltAt     string       `json:"built_at,omitempty"`
	SameContent bool         `json:"same_content"`
	DerivedFrom *DerivedFrom `json:"derived_from,omitempty"`
}

// VersionManifest 是发布版本的签名负载（项目密钥签署）。
// 注意：版本号是不透明标识符（D6），任何解析/选择逻辑不得解读其数字。
type VersionManifest struct {
	Project     string     `json:"project"`
	Channel     string     `json:"channel"`
	Version     string     `json:"version"`
	Seq         int64      `json:"seq"` // 渠道内发布序号（排序与 latest 的唯一依据）
	Platforms   []string   `json:"platforms"`
	Resources   []Resource `json:"resources"`
	Provenance  Provenance `json:"provenance"`
	PublishedAt string     `json:"published_at"`
}

// VersionRef 唯一标识一个版本。
type VersionRef struct {
	Project string `json:"project"`
	Channel string `json:"channel"`
	Version string `json:"version"`
}

// GraceInfo 是解析响应中的宽限期标记。
type GraceInfo struct {
	RemoveAt string `json:"remove_at"`
}

// ServingNode 是服务节点自报家门块：仅用于排障，不参与签名，
// 下游不得将其作为信任输入。
type ServingNode struct {
	Tier      int   `json:"tier"`
	Offline   bool  `json:"offline"`
	StatesSeq int64 `json:"states_seq"`
	Stale     bool  `json:"stale"`
}

// ResolveResponse 是解析结果：签名清单字段 + 选择性标记 + 服务节点块。
type ResolveResponse struct {
	Project      string      `json:"project"`
	Channel      string      `json:"channel"`
	Version      string      `json:"version"`
	Seq          int64       `json:"seq"`
	Yanked       bool        `json:"yanked"`
	Grace        *GraceInfo  `json:"grace"`
	ResolvedFrom string      `json:"resolved_from"` // latest | pinned
	Platforms    []string    `json:"platforms"`
	Resources    []Resource  `json:"resources"`
	Provenance   Provenance  `json:"provenance"`
	Signature    Signature   `json:"signature"`
	ServingNode  ServingNode `json:"serving_node"`
}

// SyncChanges 是镜像同步的增量批次（只拉不推，D11）。
// Keyring/States 为当前值（有变化时携带）；Manifests 是 since 之后的
// 发布；Removed 是物理移除通知。
type SyncChanges struct {
	Cursor    string       `json:"cursor"`
	Keyring   *Envelope    `json:"keyring,omitempty"`
	States    *Envelope    `json:"states,omitempty"`
	Manifests []Envelope   `json:"manifests"`
	Removed   []VersionRef `json:"removed,omitempty"`
}

// PublishResource 是发布请求中的单个资源。
// Digest 必填；字节要么已上传至 blob 库，要么给出 ExternalURL 由原站
// 按兜底限制尝试摄取（失败则降级为 302 外部地址）。
type PublishResource struct {
	Name        string `json:"name"`
	Platform    string `json:"platform"`
	Digest      string `json:"digest"`
	Size        int64  `json:"size"`
	ExternalURL string `json:"external_url,omitempty"`
}

// PublishRequest 是发布版本的请求体。
type PublishRequest struct {
	Version    string            `json:"version"`
	Resources  []PublishResource `json:"resources"`
	Provenance Provenance        `json:"provenance"`
}

// RegisterNodeRequest 登记一个下游节点身份（D12：镜像同步必须节点身份）。
type RegisterNodeRequest struct {
	Name     string   `json:"name"`
	Channels []string `json:"channels,omitempty"` // 空 = 全部渠道
}

// RegisterNodeResponse 返回节点身份；私钥只在此响应中出现一次。
type RegisterNodeResponse struct {
	NodeID     string   `json:"node_id"`
	PublicKey  string   `json:"public_key"`
	PrivateKey string   `json:"private_key"`
	Channels   []string `json:"channels"`
}

// NodeInfo 是节点身份的公开视图（仅公钥与渠道权限）。
type NodeInfo struct {
	NodeID    string   `json:"node_id"`
	PublicKey string   `json:"public_key"`
	Channels  []string `json:"channels"`
	Created   string   `json:"created"`
}

// VersionState 是版本的选择状态（本地元数据，不进签名负载；
// yank 与宽限的正交语义见设计稿第 11 节）。
type VersionState struct {
	Yanked   bool   `json:"yanked"`
	YankAt   string `json:"yank_at,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Grace    bool   `json:"grace"`
	GraceAt  string `json:"grace_at,omitempty"`
	RemoveAt string `json:"remove_at,omitempty"`
}

// Selectable 报告版本是否进入 latest 选择：
// 被 yank 或处于宽限期的版本一律跳过（设计稿 10.1）。
func (st VersionState) Selectable() bool {
	return !st.Yanked && !st.Grace
}
