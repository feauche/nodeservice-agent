package vpnprobe

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestParseVLESSReality(t *testing.T) {
	publicKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	r, err := parseVLESS("vless://11111111-1111-1111-1111-111111111111@203.0.113.7:443?security=reality&type=tcp&sni=cdn.example.com&fp=chrome&pbk=" + publicKey + "&sid=abcd&flow=xtls-rprx-vision#node")
	if err != nil {
		t.Fatal(err)
	}
	if r.address != "203.0.113.7" || r.port != 443 || r.serverName != "cdn.example.com" || r.publicKey != publicKey {
		t.Fatalf("route = %+v", r)
	}
	config, err := xrayConfig(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := serialConfig(config)
	if err != nil || decoded == nil {
		t.Fatalf("xray config: %v", err)
	}
	instance, err := start(config)
	if err != nil {
		t.Fatalf("xray start: %v", err)
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("xray close: %v", err)
	}
}

func TestParseVLESSRejectsDiagnosticTLSAndUnsupportedTransport(t *testing.T) {
	for _, link := range []string{
		"https://example.com",
		"vless://id@example.com:443?security=tls&sni=example.com",
		"vless://id@example.com:443?security=reality&sni=example.com&pbk=x&type=quic",
	} {
		if _, err := parseVLESS(link); err == nil {
			t.Fatalf("accepted %q", link)
		}
	}
}

func TestParseHysteria2AndBuildXrayConfig(t *testing.T) {
	r, err := parseRoute("hy2://secret%3Avalue@hy.example.com:30443?sni=cdn.example.com&obfs=salamander&obfs-password=mask-secret#node")
	if err != nil {
		t.Fatal(err)
	}
	if r.protocol != "hysteria2" || r.address != "hy.example.com" || r.port != 30443 || r.auth != "secret:value" {
		t.Fatalf("route = %+v", r)
	}
	config, err := xrayConfig(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serialConfig(config); err != nil {
		t.Fatalf("xray config: %v", err)
	}
	instance, err := start(config)
	if err != nil {
		t.Fatalf("xray start: %v", err)
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("xray close: %v", err)
	}
}

func TestHysteria2RejectsMissingAuthAndInsecureTLS(t *testing.T) {
	if _, err := parseHysteria2("hysteria2://hy.example.com:443?sni=cdn.example.com"); err == nil {
		t.Fatal("accepted route without auth")
	}
	r, err := parseHysteria2("hysteria2://secret@hy.example.com:443?sni=cdn.example.com&insecure=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xrayConfig(r); err == nil {
		t.Fatal("accepted insecure TLS route")
	}
	pinned, err := parseHysteria2("hysteria2://secret@hy.example.com:443?sni=cdn.example.com&insecure=1&pinSHA256=8f4d05d6e67f22c1f5f5d4ce32f998cff17d44ce35cb47e4b1b2e1de92974fe1")
	if err != nil {
		t.Fatal(err)
	}
	config, err := xrayConfig(pinned)
	if err != nil {
		t.Fatalf("pinned route: %v", err)
	}
	if _, err := serialConfig(config); err != nil {
		t.Fatalf("pinned xray config: %v", err)
	}
}

// Small wrapper keeps the test focused on whether xray accepts our generated config.
func serialConfig(raw []byte) (any, error) {
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return decoded.Build()
}
