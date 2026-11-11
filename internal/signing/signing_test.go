package signing

import (
	"testing"

	"Grail/internal/model"
)

func TestEnvelopeRoundtrip(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	payload := model.KeyringPayload{Seq: 1, UpdatedAt: "2026-11-12T00:00:00Z"}
	env, err := SignEnvelope(payload, "root-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	var got model.KeyringPayload
	if err := VerifyEnvelope(env, pub, &got); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Seq != 1 {
		t.Fatalf("seq = %d, want 1", got.Seq)
	}
}

func TestEnvelopeTamperDetected(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := SignEnvelope(model.StatesPayload{Seq: 1}, "root-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	// 篡改 payload 字节：验签必须失败。
	env.Payload[len(env.Payload)-2] ^= 0xff
	if err := VerifyEnvelope(env, pub, nil); err == nil {
		t.Fatal("tampered payload verified — signature check is broken")
	}
}

func TestEnvelopeWrongKeyRejected(t *testing.T) {
	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := SignEnvelope(model.StatesPayload{Seq: 1}, "root-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnvelope(env, otherPub, nil); err == nil {
		t.Fatal("wrong key verified — signature check is broken")
	}
}

func TestKeyCodecRoundtrip(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub2, err := DecodePublicKey(EncodeKey(pub))
	if err != nil {
		t.Fatal(err)
	}
	priv2, err := DecodePrivateKey(EncodeKey(priv))
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(pub2) || !priv.Equal(priv2) {
		t.Fatal("key codec roundtrip mismatch")
	}
}
