// Package config 装载节点配置（YAML）与凭据（JSON，0600）。
//
// 纪律（与生态一致）：凭据只存在于本地凭据文件，绝不进仓库、
// 绝不进任何对外响应；配置为空时保持明确的默认行为。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/goccy/go-yaml"
)

// 默认值。
const (
	DefaultListen             = "127.0.0.1:2780"
	DefaultMaxArtifactBytes   = int64(1) << 30 // 1 GiB
	DefaultSyncIntervalSecond = 60
)

// Config 是节点配置。
type Config struct {
	Node   NodeConfig   `yaml:"node"`
	Mirror MirrorConfig `yaml:"mirror"`
}

// NodeConfig 是节点自身参数。
type NodeConfig struct {
	// Role 为 root（原站）或 mirror（下级镜像）。
	Role    string `yaml:"role"`
	Listen  string `yaml:"listen"`
	Public  bool   `yaml:"public"` // 公开节点：release 匿名可读
	DataDir string `yaml:"data_dir"`
	Limits  Limits `yaml:"limits"`
}

// Limits 是兜底限制（D10：消费方默认信任上游，节点单方执行）。
type Limits struct {
	// MaxArtifactBytes 为单产物大小上限；0 = 用默认值 1 GiB。
	MaxArtifactBytes int64 `yaml:"max_artifact_bytes"`
}

// MirrorConfig 仅 mirror 角色使用。
type MirrorConfig struct {
	UpstreamBaseURL     string                   `yaml:"upstream_base_url"`
	SyncIntervalSeconds int                      `yaml:"sync_interval_seconds"`
	Channels            map[string]ChannelPolicy `yaml:"channels"`
}

// ChannelPolicy 是单渠道的镜像策略。
type ChannelPolicy struct {
	// Policy: full（全量）| subscribe（按项目订阅）| none（不镜像）。
	Policy   string   `yaml:"policy"`
	Projects []string `yaml:"projects,omitempty"`
}

// EffectiveMaxArtifactBytes 返回生效的大小上限。
func (c *Config) EffectiveMaxArtifactBytes() int64 {
	if c.Node.Limits.MaxArtifactBytes > 0 {
		return c.Node.Limits.MaxArtifactBytes
	}
	return DefaultMaxArtifactBytes
}

// EffectiveSyncInterval 返回生效的同步周期（秒）。
func (c *Config) EffectiveSyncInterval() int {
	if c.Mirror.SyncIntervalSeconds > 0 {
		return c.Mirror.SyncIntervalSeconds
	}
	return DefaultSyncIntervalSecond
}

// ChannelPolicyOf 返回渠道策略；未声明时：release=full，其余=none。
func (c *Config) ChannelPolicyOf(channel string) ChannelPolicy {
	if p, ok := c.Mirror.Channels[channel]; ok {
		return p
	}
	if channel == "release" {
		return ChannelPolicy{Policy: "full"}
	}
	return ChannelPolicy{Policy: "none"}
}

// Validate 校验配置的基本一致性（显式失败，不静默纠正）。
func (c *Config) Validate() error {
	switch c.Node.Role {
	case "root", "mirror":
	default:
		return fmt.Errorf("node.role must be root or mirror, got %q", c.Node.Role)
	}
	if c.Node.DataDir == "" {
		return fmt.Errorf("node.data_dir is required")
	}
	if c.Node.Role == "mirror" {
		if c.Mirror.UpstreamBaseURL == "" {
			return fmt.Errorf("mirror.upstream_base_url is required for role=mirror")
		}
	}
	for ch, p := range c.Mirror.Channels {
		switch p.Policy {
		case "full", "subscribe", "none":
		default:
			return fmt.Errorf("mirror.channels.%s.policy must be full|subscribe|none, got %q", ch, p.Policy)
		}
	}
	return nil
}

// Load 读取并校验配置文件。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.Node.Listen == "" {
		cfg.Node.Listen = DefaultListen
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// TokenEntry 是一个命名令牌及其渠道范围（空 = 全部渠道）。
type TokenEntry struct {
	Name     string   `json:"name"`
	Token    string   `json:"token"`
	Channels []string `json:"channels,omitempty"`
}

// Credentials 是节点凭据（0600，绝不进仓库）。
//
// root 节点：AdminToken + RootPrivateKey + ProjectPrivateKeys；
// mirror 节点：NodeID + NodePrivateKey + RootPublicKey（信任锚）；
// 读/发布令牌按需。
type Credentials struct {
	AdminToken         string            `json:"admin_token,omitempty"`
	RootPrivateKey     string            `json:"root_private_key,omitempty"`
	ProjectPrivateKeys map[string]string `json:"project_private_keys,omitempty"`
	NodeID             string            `json:"node_id,omitempty"`
	NodePrivateKey     string            `json:"node_private_key,omitempty"`
	RootPublicKey      string            `json:"root_public_key,omitempty"`
	PublishTokens      []TokenEntry      `json:"publish_tokens,omitempty"`
	ReadTokens         []TokenEntry      `json:"read_tokens,omitempty"`
}

// LoadCredentials 读取凭据文件；路径为空或文件不存在返回空凭据，
// 由调用方按 fail-closed 语义处理。
func LoadCredentials(path string) (*Credentials, error) {
	creds := &Credentials{}
	if path == "" {
		return creds, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return creds, nil
		}
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	if err := json.Unmarshal(data, creds); err != nil {
		return nil, fmt.Errorf("parse credentials %s: %w", path, err)
	}
	return creds, nil
}

// SaveCredentials 原子写入凭据文件（0600，目录 0700）。
func SaveCredentials(path string, creds *Credentials) error {
	if path == "" {
		return fmt.Errorf("credentials path is empty")
	}
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
