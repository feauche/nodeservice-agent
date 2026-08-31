package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/lumaxdev/nodeservice-agent/internal/proto"
)

const testServerID = "0192c000-0000-7000-8000-000000000001"

// fakePanel поднимает WS-сервер, играющий роль панели: challenge → проверка подписи → welcome/error.
func fakePanel(t *testing.T, acceptAuth bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		var hello proto.Envelope
		if err := wsjson.Read(ctx, conn, &hello); err != nil {
			t.Errorf("hello: %v", err)
			return
		}
		h, err := proto.Decode[proto.Hello](hello)
		if err != nil || h.ServerID != testServerID {
			t.Errorf("hello payload: %+v, %v", h, err)
			return
		}
		pub, _ := base64.StdEncoding.DecodeString(h.Pubkey)

		nonce := make([]byte, 32)
		_, _ = rand.Read(nonce)
		env, _ := proto.New(proto.MsgChallenge, proto.Challenge{Nonce: base64.StdEncoding.EncodeToString(nonce)})
		_ = wsjson.Write(ctx, conn, env)

		var auth proto.Envelope
		if err := wsjson.Read(ctx, conn, &auth); err != nil {
			t.Errorf("auth: %v", err)
			return
		}
		a, _ := proto.Decode[proto.Auth](auth)
		sig, _ := base64.StdEncoding.DecodeString(a.Signature)

		if acceptAuth && ed25519.Verify(pub, nonce, sig) {
			env, _ = proto.New(proto.MsgWelcome, proto.Welcome{ServerName: "de-fra-01", HeartbeatSeconds: 10, MetricsSeconds: 10})
		} else {
			env, _ = proto.New(proto.MsgError, proto.ErrorPayload{Code: proto.ErrCodeAuthFailed, Message: "подпись не сошлась"})
		}
		_ = wsjson.Write(ctx, conn, env)
	}))
}

func dial(t *testing.T, srv *httptest.Server) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(t.Context(), wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestHandshakeOK(t *testing.T) {
	srv := fakePanel(t, true)
	defer srv.Close()
	_, key, _ := ed25519.GenerateKey(nil)

	conn := dial(t, srv)
	defer conn.Close(websocket.StatusNormalClosure, "")

	w, err := Handshake(t.Context(), conn, testServerID, key, "v-test")
	if err != nil {
		t.Fatal(err)
	}
	if w.ServerName != "de-fra-01" || w.HeartbeatSeconds != 10 {
		t.Fatalf("welcome: %+v", w)
	}
}

func TestHandshakeAuthRejected(t *testing.T) {
	srv := fakePanel(t, false)
	defer srv.Close()
	_, key, _ := ed25519.GenerateKey(nil)

	conn := dial(t, srv)
	defer conn.Close(websocket.StatusNormalClosure, "")

	_, err := Handshake(t.Context(), conn, testServerID, key, "v-test")
	if !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("ожидал ErrAuthRejected, получил %v", err)
	}
}
