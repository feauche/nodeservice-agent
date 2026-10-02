package transport

import (
	"context"
	"errors"
	"testing"
	"time"
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
