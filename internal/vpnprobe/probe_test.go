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

// Small wrapper keeps the test focused on whether xray accepts our generated config.
func serialConfig(raw []byte) (any, error) {
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return decoded.Build()
}
