package enroll

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnrollOK(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/enroll" || r.Method != http.MethodPost {
			t.Errorf("не тот запрос: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["token"] != "nse_test-token" {
			t.Errorf("token = %q", body["token"])
		}
		if body["pubkey"] != base64.StdEncoding.EncodeToString(pub) {
			t.Errorf("pubkey = %q", body["pubkey"])
		}
		if body["version"] != "v0.5.0" {
			t.Errorf("version = %q", body["version"])
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"serverId":   "0192c000-0000-7000-8000-000000000001",
			"serverName": "de-fra-01",
			"wsUrl":      "ws://example/api/agent/v1/ws",
		})
	}))
	defer srv.Close()

	res, err := Enroll(t.Context(), srv.URL+"/", "nse_test-token", pub, "v0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if res.ServerName != "de-fra-01" || res.WsURL == "" {
		t.Fatalf("res = %+v", res)
	}
}

func TestEnrollRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"title":"Доступ запрещён","status":403,"detail":"Токен истёк или уже использован."}`))
	}))
	defer srv.Close()

	_, err := Enroll(t.Context(), srv.URL, "nse_dead", pub, "dev")
	if err == nil {
		t.Fatal("ожидался отказ")
	}
	want := "энроллмент отклонён (HTTP 403): Токен истёк или уже использован."
	if err.Error() != want {
		t.Fatalf("текст ошибки: %q", err.Error())
	}
}
