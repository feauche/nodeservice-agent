package proto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestEnvelopeRoundtrip(t *testing.T) {
	env, err := New(MsgHello, Hello{ServerID: "0192c000-0000-7000-8000-000000000001", Pubkey: "AAAA", Version: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if env.V != Version {
		t.Fatalf("v = %d", env.V)
	}
	if _, err := uuid.Parse(env.ID); err != nil {
		t.Fatalf("id не uuid: %v", err)
	}
	// Схема панели (z.iso.datetime) требует UTC с суффиксом Z.
	if !strings.HasSuffix(env.TS, "Z") {
		t.Fatalf("ts не UTC: %s", env.TS)
	}
	if _, err := time.Parse(time.RFC3339, env.TS); err != nil {
		t.Fatalf("ts не RFC3339: %v", err)
	}

	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var back Envelope
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	hello, err := Decode[Hello](back)
	if err != nil {
		t.Fatal(err)
	}
	if hello.Version != "v1" || hello.Pubkey != "AAAA" {
		t.Fatalf("payload потерян: %+v", hello)
	}
}

func TestDecodeWithoutPayload(t *testing.T) {
	if _, err := Decode[Hello](Envelope{Type: MsgHello}); err == nil {
		t.Fatal("ожидалась ошибка про пустой payload")
	}
}

func TestSignNonce(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("nonce-32-bytes-of-random-data!!!")
	sigB64, err := SignNonce(priv, base64.StdEncoding.EncodeToString(nonce))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, nonce, sig) {
		t.Fatal("подпись не проходит проверку")
	}
	// Подписываются сырые байты, а не base64-строка.
	if ed25519.Verify(pub, []byte(base64.StdEncoding.EncodeToString(nonce)), sig) {
		t.Fatal("подписана base64-строка вместо сырых байт")
	}
}

func TestSignNonceBadBase64(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	if _, err := SignNonce(priv, "не base64!!!"); err == nil {
		t.Fatal("ожидалась ошибка про base64")
	}
}
