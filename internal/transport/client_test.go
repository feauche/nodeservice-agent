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
	"github.com/rs/zerolog"

	"github.com/feauche/nodeservice-agent/internal/proto"
	"github.com/feauche/nodeservice-agent/internal/state"
)

func TestFirstLoopErrorSendFailureCancelsBlockedRead(t *testing.T) {
	readStarted := make(chan struct{})
	readStopped := make(chan struct{})
	sendFailed := errors.New("heartbeat: network changed")

	err := firstLoopError(
		t.Context(),
		func(ctx context.Context) error {
			close(readStarted)
			<-ctx.Done()
			close(readStopped)
			return ctx.Err()
		},
		func(context.Context) error {
			<-readStarted
			return sendFailed
		},
	)
	if !errors.Is(err, sendFailed) {
		t.Fatalf("ожидал ошибку отправки, получил %v", err)
	}
	select {
	case <-readStopped:
	case <-time.After(time.Second):
		t.Fatal("ошибка отправки не остановила зависшее чтение")
	}
}

type failingPinger struct{ err error }

func (p failingPinger) Ping(context.Context) error { return p.err }

func TestPingLoopBreaksFrozenConnection(t *testing.T) {
	want := errors.New("path frozen")
	err := pingLoop(t.Context(), failingPinger{err: want}, time.Millisecond, time.Second)
	if !errors.Is(err, want) {
		t.Fatalf("pingLoop() = %v", err)
	}
}

func TestRunStopsWhenEveryRouteRejectsDeletedServer(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/agent/v1/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, acceptErr := websocket.Accept(w, r, nil)
		if acceptErr != nil {
			t.Error(acceptErr)
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		var hello proto.Envelope
		if readErr := wsjson.Read(r.Context(), conn, &hello); readErr != nil {
			t.Error(readErr)
			return
		}
		env, _ := proto.New(proto.MsgError, proto.ErrorPayload{
			Code:    proto.ErrCodeUnknownServer,
			Message: "сервер удалён",
		})
		_ = wsjson.Write(r.Context(), conn, env)
	})
	mux.HandleFunc("/api/agent/v1/pulse", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unknown server", http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	endpoint := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/agent/v1/ws"
	st := &state.State{
		ServerID:   testServerID,
		WsURL:      endpoint,
		WsURLs:     []string{endpoint},
		PrivKeyB64: base64.StdEncoding.EncodeToString(key.Seed()),
	}

	err = New(Config{State: st, Version: "v-test", Log: zerolog.Nop()}).Run(t.Context())
	if !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("удалённый сервер должен остановить агент, получено: %v", err)
	}
}
