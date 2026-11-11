// Package signing 承载 Grail 的签名机制：Ed25519（标准库），
// 签的是负载的规范化 JSON（见 model 包约定）。
//
// 信任链（设计稿第 7 节）：
//
//	本地信任锚（根公钥） → 验证密钥环 → 按项目取公钥 → 验证版本清单 → digest → 字节
//
// 镜像不持有任何发布密钥、不重签任何东西（7.2）。
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"Grail/internal/model"
)

// Alg 是当前唯一的签名算法标识。
const Alg = "ed25519"

// GenerateKey 生成一对 Ed25519 密钥（原始字节）。
func GenerateKey() (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return pub, priv, nil
}

// EncodeKey 将密钥编码为 base64（进文档/凭据文件的形态）。
func EncodeKey(k []byte) string { return base64.StdEncoding.EncodeToString(k) }

// DecodePublicKey 解析 base64 公钥并校验长度。
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key size %d, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// DecodePrivateKey 解析 base64 私钥并校验长度。
func DecodePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key size %d, want %d", len(b), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b), nil
}

// SignEnvelope 序列化负载结构体并用私钥签名，产出签名信封。
// 负载的规范化 JSON 以返回信封中的 Payload 字节为准。
func SignEnvelope(payload any, keyID string, priv ed25519.PrivateKey) (*model.Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	sig := ed25519.Sign(priv, raw)
	return &model.Envelope{
		Payload: raw,
		Signature: model.Signature{
			KeyID: keyID,
			Alg:   Alg,
			Value: base64.StdEncoding.EncodeToString(sig),
		},
	}, nil
}

// VerifyEnvelope 用公钥验证信封签名，并把负载反序列化到 out。
// 验签只使用信封内的 Payload 字节（绝不重新序列化）。
func VerifyEnvelope(env *model.Envelope, pub ed25519.PublicKey, out any) error {
	if env == nil {
		return fmt.Errorf("nil envelope")
	}
	if env.Signature.Alg != Alg {
		return fmt.Errorf("unsupported signature alg %q", env.Signature.Alg)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature.Value)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, env.Payload, sig) {
		return fmt.Errorf("signature verification failed (key %s)", env.Signature.KeyID)
	}
	if out != nil {
		if err := json.Unmarshal(env.Payload, out); err != nil {
			return fmt.Errorf("unmarshal payload: %w", err)
		}
	}
	return nil
}
