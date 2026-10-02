// Package transport — исходящее WebSocket-соединение с панелью:
// рукопожатие hello → challenge → auth → welcome, затем heartbeat и метрики.
// Обрыв связи лечится переподключением с экспоненциальным backoff (cap 60 c + jitter);
// отказ одного маршрута, включая аутентификацию, не останавливает службу: конфигурацию панели могут
// восстановить, а другой маршрут уже может вести к исправному экземпляру.
package transport

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
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
	State    *state.State
	StateDir string
	Version  string
	Log      zerolog.Logger
}

// Client держит цикл подключений.
type Client struct {
	cfg Config
	col *metrics.Collector
}

func New(cfg Config) *Client {
	return &Client{cfg: cfg, col: metrics.NewCollector()}
}

// Run крутит WebSocket и запасные HTTPS-подключения до отмены контекста.
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
		var lastErr error
		endpoints := c.cfg.State.Endpoints()
		attempts, rejected := 0, 0
		for _, endpoint := range endpoints {
			attempts++
			established, sessionErr := c.session(ctx, key, endpoint)
			if ctx.Err() != nil {
				return nil
			}
			if established {
				bo.Reset()
			}
			lastErr = sessionErr
			if errors.Is(sessionErr, ErrAuthRejected) {
				rejected++
			}
			c.cfg.Log.Warn().Err(sessionErr).Str("маршрут", endpoint).
				Msg("WebSocket недоступен — пробую следующий маршрут")
		}

		// Обычный HTTPS проходит через прокси, которые запрещают WebSocket Upgrade. Проверяем каждый
		// маршрут и, если нашли рабочий, держим heartbeat и метрики до следующей попытки WebSocket.
		for _, endpoint := range endpoints {
			attempts++
			established, fallbackErr := c.fallbackSession(ctx, key, endpoint)
			if ctx.Err() != nil {
				return nil
			}
			if established {
				bo.Reset()
			}
			lastErr = fallbackErr
			if errors.Is(fallbackErr, ErrAuthRejected) {
				rejected++
			}
			if errors.Is(fallbackErr, errRetryWebSocket) {
				lastErr = nil
				break
			}
			c.cfg.Log.Warn().Err(fallbackErr).Str("маршрут", endpoint).
				Msg("запасной HTTPS недоступен — пробую следующий маршрут")
		}
		if lastErr == nil {
			continue
		}
		// Все независимые входы и оба транспорта получили окончательный отказ. Это не обрыв сети:
		// сервер удалён из панели либо ключ отозван. Завершаемся специальной ошибкой, чтобы systemd
		// не создавал бесконечный цикл и тысячи одинаковых записей в Журнале.
		if attempts > 0 && rejected == attempts {
			return ErrAuthRejected
		}
		wait := bo.NextBackOff()
		if wait <= 0 {
			wait = time.Second
		}
		c.cfg.Log.Warn().Err(lastErr).Str("повтор_через", wait.Round(time.Second).String()).
			Msg("все маршруты к панели недоступны — повторяю")
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// session — одно подключение: рукопожатие и рабочие циклы до обрыва.
func (c *Client) session(
	ctx context.Context,
	key ed25519.PrivateKey,
	endpoint string,
) (established bool, err error) {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	conn, _, err := websocket.Dial(dialCtx, endpoint, nil)
	cancel()
	if err != nil {
		return false, fmt.Errorf("подключение: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "завершение")
	conn.SetReadLimit(1 << 20)

	welcome, err := Handshake(ctx, conn, c.cfg.State.ServerID, key, c.cfg.Version, endpoint)
	if err != nil {
		return false, err
	}
	c.cfg.Log.Info().
		Str("сервер", welcome.ServerName).
		Str("маршрут", endpoint).
		Str("транспорт", "WebSocket").
		Int("heartbeat_с", welcome.HeartbeatSeconds).
		Int("метрики_с", welcome.MetricsSeconds).
		Msg("агент на связи с панелью")
	c.applyWelcome(welcome)

	// Смена IP или маршрута часто первой ломает запись heartbeat, пока чтение из старого TCP-сокета ещё
	// висит. Ждать только readLoop нельзя: агент оставался в старом соединении до перезапуска службы.
	// Любая из двух сторон завершила работу — отменяем вторую и сразу начинаем новый сеанс.
	sessionErr := firstLoopError(
		ctx,
		func(loopCtx context.Context) error { return c.readLoop(loopCtx, conn) },
		func(loopCtx context.Context) error { return c.sendLoop(loopCtx, conn, welcome) },
	)
	return true, sessionErr
}

/** Сохранить новый список маршрутов, присланный панелью, не меняя ключ и привязку. */
func (c *Client) applyWelcome(welcome *proto.Welcome) {
	if len(welcome.WsURLs) == 0 || slices.Equal(c.cfg.State.Endpoints(), welcome.WsURLs) {
		return
	}
	c.cfg.State.SetEndpoints(welcome.WsURLs)
	if c.cfg.StateDir == "" {
		return
	}
	if err := state.Save(c.cfg.StateDir, c.cfg.State); err != nil {
		c.cfg.Log.Warn().Err(err).Msg("не удалось сохранить новый список маршрутов")
		return
	}
	c.cfg.Log.Info().Int("маршрутов", len(c.cfg.State.Endpoints())).Msg("список маршрутов к панели обновлён")
}

// firstLoopError запускает чтение и отправку вместе; первая ошибка отменяет соседний цикл.
func firstLoopError(
	parent context.Context,
	readLoop func(context.Context) error,
	sendLoop func(context.Context) error,
) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	errs := make(chan error, 2)
	go func() { errs <- readLoop(ctx) }()
	go func() { errs <- sendLoop(ctx) }()
	err := <-errs
	cancel()
	return err
}

// Handshake выполняет hello → challenge → auth → welcome. Вынесен отдельно для тестов.
func Handshake(
	ctx context.Context,
	conn *websocket.Conn,
	serverID string,
	key ed25519.PrivateKey,
	version string,
	route string,
) (*proto.Welcome, error) {
	hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	pub := key.Public().(ed25519.PublicKey)
	err := write(hctx, conn, proto.MsgHello, proto.Hello{
		ServerID: serverID,
		Pubkey:   base64.StdEncoding.EncodeToString(pub),
		Version:  version,
		Route:    route,
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
