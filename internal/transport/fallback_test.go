package transport

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/feauche/nodeservice-agent/internal/proto"
	"github.com/feauche/nodeservice-agent/internal/state"
)

func TestPulseEndpoint(t *testing.T) {
	got, err := pulseEndpoint("wss://agents.example.net/api/agent/v1/ws")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://agents.example.net/api/agent/v1/pulse" {
		t.Fatalf("pulse URL = %q", got)
	}
}

func TestSendPulseSignsExactPayload(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	var received proto.PulseRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/agent/v1/pulse" {
			t.Errorf("не тот запрос: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		signature, _ := base64.StdEncoding.DecodeString(received.Signature)
		if !ed25519.Verify(pub, []byte(proto.PulseSigningText(received)), signature) {
			t.Error("подпись HTTPS pulse не сошлась")
		}
		_ = json.NewEncoder(w).Encode(proto.Welcome{
			ServerName:       "kz-1",
			HeartbeatSeconds: 10,
			MetricsSeconds:   10,
			WsURLs:           []string{"wss://one.test/api/agent/v1/ws", "wss://two.test/api/agent/v1/ws"},
		})
	}))
	defer srv.Close()

	c := New(Config{
		State:   &state.State{ServerID: testServerID},
		Version: "v0.7.0",
		Log:     zerolog.Nop(),
	})
	welcome, err := c.sendPulse(
		t.Context(),
		key,
		srv.URL+"/api/agent/v1/pulse",
		"ws"+strings.TrimPrefix(srv.URL, "http")+"/api/agent/v1/ws",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if welcome.ServerName != "kz-1" || len(welcome.WsURLs) != 2 {
		t.Fatalf("welcome = %+v", welcome)
	}
	var payload proto.PulsePayload
	if err := json.Unmarshal([]byte(received.Payload), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Route == "" || received.ServerID != testServerID || received.Version != "v0.7.0" {
		t.Fatalf("pulse = %+v", received)
	}
}

func TestApplyWelcomePersistsRoutes(t *testing.T) {
	dir := t.TempDir()
	st := &state.State{
		ServerID:   testServerID,
		WsURL:      "wss://old.test/api/agent/v1/ws",
		WsURLs:     []string{"wss://old.test/api/agent/v1/ws"},
		PrivKeyB64: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize)),
	}
	c := New(Config{State: st, StateDir: dir, Log: zerolog.Nop()})
	c.applyWelcome(&proto.Welcome{WsURLs: []string{
		"wss://one.test/api/agent/v1/ws",
		"wss://two.test/api/agent/v1/ws",
	}})

	loaded, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Endpoints(); len(got) != 2 || got[0] != "wss://one.test/api/agent/v1/ws" {
		t.Fatalf("маршруты не сохранились: %v", got)
	}
}

func TestRunUsesHTTPSWhenWebSocketUpgradeIsRejected(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	seen := make(chan struct{})
	var once sync.Once
	var wsURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/v1/ws":
			http.Error(w, "upgrade запрещён прокси", http.StatusForbidden)
		case "/api/agent/v1/pulse":
			var pulse proto.PulseRequest
			if err := json.NewDecoder(r.Body).Decode(&pulse); err != nil {
				t.Error(err)
				return
			}
			sig, _ := base64.StdEncoding.DecodeString(pulse.Signature)
			if !ed25519.Verify(pub, []byte(proto.PulseSigningText(pulse)), sig) {
				t.Error("подпись fallback-запроса не сошлась")
				http.Error(w, "bad signature", http.StatusUnauthorized)
				return
			}
			once.Do(func() { close(seen) })
			_ = json.NewEncoder(w).Encode(proto.Welcome{
				ServerName:       "kz-1",
				HeartbeatSeconds: 10,
				MetricsSeconds:   0,
				WsURLs:           []string{wsURL},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	wsURL = "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/agent/v1/ws"
	st := &state.State{
		ServerID:   testServerID,
		WsURL:      wsURL,
		WsURLs:     []string{wsURL},
		PrivKeyB64: base64.StdEncoding.EncodeToString(key.Seed()),
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- New(Config{State: st, Version: "v0.7.0", Log: zerolog.Nop()}).Run(ctx) }()
	select {
	case <-seen:
		cancel()
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("после отказа WebSocket агент не перешёл на HTTPS")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run после отмены: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run не остановился после отмены")
	}
}
