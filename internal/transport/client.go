// Package transport — исходящее WebSocket-соединение с панелью:
// рукопожатие hello → challenge → auth → welcome, затем heartbeat и метрики.
// Обрыв связи лечится переподключением с экспоненциальным backoff (cap 60 c + jitter);
// отказ аутентификации — фатален: без новой привязки переподключаться бессмысленно.
package transport

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/rs/zerolog"

	"github.com/feauche/nodeservice-agent/internal/metrics"
	"github.com/feauche/nodeservice-agent/internal/proto"
	"github.com/feauche/nodeservice-agent/internal/state"
)

// ErrAuthRejected — панель не признала агента (ключ не совпал или сервер удалён).
var ErrAuthRejected = errors.New("панель отвергла агента")

// Config — всё, что нужно клиенту.
type Config struct {
	State   *state.State
	Version string
	Log     zerolog.Logger
}

// Client держит цикл подключений.
type Client struct {
	cfg Config
	col *metrics.Collector
}

func New(cfg Config) *Client {
	return &Client{cfg: cfg, col: metrics.NewCollector()}
}

// Run крутит подключения до отмены контекста или фатального отказа аутентификации.
func (c *Client) Run(ctx context.Context) error {
	key, err := c.cfg.State.Key()
	if err != nil {
		return err
	}

	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = time.Second
	bo.MaxInterval = 60 * time.Second
	bo.RandomizationFactor = 0.4

	for {
		established, err := c.session(ctx, key)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, ErrAuthRejected) {
			return err
		}
		if established {
			bo.Reset()
		}
		wait := bo.NextBackOff()
		if wait <= 0 {
			wait = time.Second
		}
		c.cfg.Log.Warn().Err(err).Str("повтор_через", wait.Round(time.Second).String()).
			Msg("связь с панелью потеряна — переподключаюсь")
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// session — одно подключение: рукопожатие и рабочие циклы до обрыва.
func (c *Client) session(ctx context.Context, key ed25519.PrivateKey) (established bool, err error) {
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	conn, _, err := websocket.Dial(dialCtx, c.cfg.State.WsURL, nil)
	cancel()
	if err != nil {
		return false, fmt.Errorf("подключение: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "завершение")
	conn.SetReadLimit(1 << 20)

	welcome, err := Handshake(ctx, conn, c.cfg.State.ServerID, key, c.cfg.Version)
	if err != nil {
		return false, err
	}
	c.cfg.Log.Info().
		Str("сервер", welcome.ServerName).
		Int("heartbeat_с", welcome.HeartbeatSeconds).
		Int("метрики_с", welcome.MetricsSeconds).
		Msg("агент на связи с панелью")

	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	sendErr := make(chan error, 1)
	go func() { sendErr <- c.sendLoop(sctx, conn, welcome) }()

	readErr := c.readLoop(sctx, conn)
	scancel()
	<-sendErr
	return true, readErr
}

// Handshake выполняет hello → challenge → auth → welcome. Вынесен отдельно для тестов.
func Handshake(
	ctx context.Context,
	conn *websocket.Conn,
	serverID string,
	key ed25519.PrivateKey,
	version string,
) (*proto.Welcome, error) {
	hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	pub := key.Public().(ed25519.PublicKey)
	err := write(hctx, conn, proto.MsgHello, proto.Hello{
		ServerID: serverID,
		Pubkey:   base64.StdEncoding.EncodeToString(pub),
		Version:  version,
	})
	if err != nil {
		return nil, fmt.Errorf("hello: %w", err)
	}

	env, err := read(hctx, conn)
	if err != nil {
		return nil, err
	}
	if env.Type == proto.MsgError {
		return nil, asError(env)
	}
	if env.Type != proto.MsgChallenge {
		return nil, fmt.Errorf("ожидал challenge, пришло %q", env.Type)
	}
	ch, err := proto.Decode[proto.Challenge](env)
	if err != nil {
		return nil, err
	}
	sig, err := proto.SignNonce(key, ch.Nonce)
	if err != nil {
		return nil, err
	}
	if err := write(hctx, conn, proto.MsgAuth, proto.Auth{Signature: sig}); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	env, err = read(hctx, conn)
	if err != nil {
		return nil, err
	}
	switch env.Type {
	case proto.MsgWelcome:
		w, err := proto.Decode[proto.Welcome](env)
		if err != nil {
			return nil, err
		}
		return &w, nil
	case proto.MsgError:
		return nil, asError(env)
	default:
		return nil, fmt.Errorf("ожидал welcome, пришло %q", env.Type)
	}
}

// sendLoop шлёт heartbeat и (если включены в настройках) метрики.
func (c *Client) sendLoop(ctx context.Context, conn *websocket.Conn, w *proto.Welcome) error {
	hb := time.NewTicker(time.Duration(w.HeartbeatSeconds) * time.Second)
	defer hb.Stop()
	var metricsC <-chan time.Time
	if w.MetricsSeconds > 0 {
		mt := time.NewTicker(time.Duration(w.MetricsSeconds) * time.Second)
		defer mt.Stop()
		metricsC = mt.C
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-hb.C:
			if err := write(ctx, conn, proto.MsgHeartbeat, struct{}{}); err != nil {
				return err
			}
		case <-metricsC:
			m, warn := c.col.Collect(ctx)
			if warn != nil {
				c.cfg.Log.Debug().Err(warn).Msg("часть метрик недоступна")
			}
			if err := write(ctx, conn, proto.MsgMetrics, m); err != nil {
				return err
			}
		}
	}
}

// readLoop слушает панель: error-сообщения и будущие команды (v1 их игнорирует).
func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn) error {
	for {
		env, err := read(ctx, conn)
		if err != nil {
			return err
		}
		switch env.Type {
		case proto.MsgError:
			err := asError(env)
			if errors.Is(err, ErrAuthRejected) {
				return err
			}
			c.cfg.Log.Warn().Err(err).Msg("панель сообщила об ошибке")
		default:
			c.cfg.Log.Debug().Str("тип", env.Type).Msg("сообщение панели пропущено (эта версия его не знает)")
		}
	}
}

func write(ctx context.Context, conn *websocket.Conn, msgType string, payload any) error {
	env, err := proto.New(msgType, payload)
	if err != nil {
		return err
	}
	return wsjson.Write(ctx, conn, env)
}

func read(ctx context.Context, conn *websocket.Conn) (proto.Envelope, error) {
	var env proto.Envelope
	if err := wsjson.Read(ctx, conn, &env); err != nil {
		return env, fmt.Errorf("чтение: %w", err)
	}
	if env.V != proto.Version {
		return env, fmt.Errorf("протокол v%d не поддерживается (агент знает v%d)", env.V, proto.Version)
	}
	return env, nil
}

// asError превращает error-конверт панели в go-ошибку; отказы аутентификации фатальны.
func asError(env proto.Envelope) error {
	p, err := proto.Decode[proto.ErrorPayload](env)
	if err != nil {
		return err
	}
	if p.Code == proto.ErrCodeAuthFailed || p.Code == proto.ErrCodeUnknownServer {
		return fmt.Errorf("%w: %s", ErrAuthRejected, p.Message)
	}
	return fmt.Errorf("панель: %s (%s)", p.Message, p.Code)
}
