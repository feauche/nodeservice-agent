package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/feauche/nodeservice-agent/internal/proto"
)

const fallbackBeforeWebSocketRetry = time.Minute

var errRetryWebSocket = errors.New("пора снова проверить WebSocket")

// fallbackSession держит heartbeat и метрики обычными HTTPS POST, затем периодически отдаёт управление
// основному циклу, чтобы тот снова попробовал более экономичный постоянный WebSocket.
func (c *Client) fallbackSession(
	ctx context.Context,
	key ed25519.PrivateKey,
	wsEndpoint string,
) (established bool, err error) {
	pulseURL, err := pulseEndpoint(wsEndpoint)
	if err != nil {
		return false, err
	}
	welcome, err := c.sendPulse(ctx, key, pulseURL, wsEndpoint, nil)
	if err != nil {
		return false, err
	}
	c.applyWelcome(welcome)
	c.cfg.Log.Info().
		Str("сервер", welcome.ServerName).
		Str("маршрут", pulseURL).
		Str("транспорт", "HTTPS").
		Msg("агент на связи с панелью через запасной канал")

	heartbeatEvery := time.Duration(welcome.HeartbeatSeconds) * time.Second
	if heartbeatEvery <= 0 {
		heartbeatEvery = 10 * time.Second
	}
	heartbeat := time.NewTicker(heartbeatEvery)
	defer heartbeat.Stop()
	retryWs := time.NewTimer(fallbackBeforeWebSocketRetry)
	defer retryWs.Stop()
	nextMetrics := time.Now().Add(time.Duration(welcome.MetricsSeconds) * time.Second)

	for {
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case <-retryWs.C:
			return true, errRetryWebSocket
		case <-heartbeat.C:
			var snapshot *proto.Metrics
			if welcome.MetricsSeconds > 0 && !time.Now().Before(nextMetrics) {
				collected, warn := c.col.Collect(ctx)
				if warn != nil {
					c.cfg.Log.Debug().Err(warn).Msg("часть метрик недоступна")
				}
				snapshot = collected
				nextMetrics = time.Now().Add(time.Duration(welcome.MetricsSeconds) * time.Second)
			}
			fresh, pulseErr := c.sendPulse(ctx, key, pulseURL, wsEndpoint, snapshot)
			if pulseErr != nil {
				return true, pulseErr
			}
			welcome = fresh
			c.applyWelcome(welcome)
		}
	}
}

func pulseEndpoint(wsEndpoint string) (string, error) {
	u, err := url.Parse(wsEndpoint)
	if err != nil {
		return "", fmt.Errorf("адрес маршрута: %w", err)
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	default:
		return "", fmt.Errorf("адрес маршрута: схема %q не поддерживается", u.Scheme)
	}
	u.Path = strings.TrimSuffix(u.Path, "/ws") + "/pulse"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func (c *Client) sendPulse(
	ctx context.Context,
	key ed25519.PrivateKey,
	endpoint string,
	route string,
	metrics *proto.Metrics,
) (*proto.Welcome, error) {
	payload, err := json.Marshal(proto.PulsePayload{Metrics: metrics, Route: route})
	if err != nil {
		return nil, err
	}
	reqBody := proto.PulseRequest{
		V:        proto.Version,
		ServerID: c.cfg.State.ServerID,
		Version:  c.cfg.Version,
		ID:       uuid.NewString(),
		TS:       time.Now().UTC().Format(time.RFC3339),
		Payload:  string(payload),
	}
	reqBody.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(key, []byte(proto.PulseSigningText(reqBody))),
	)
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTPS pulse: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("HTTPS pulse: ответ: %w", err)
	}
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: HTTPS %d", ErrAuthRejected, res.StatusCode)
	}
	if res.StatusCode != http.StatusOK {
		detail := strings.TrimSpace(string(body))
		if len(detail) > 300 {
			detail = detail[:300] + "…"
		}
		return nil, fmt.Errorf("HTTPS pulse: HTTP %d: %s", res.StatusCode, detail)
	}
	var welcome proto.Welcome
	if err := json.Unmarshal(body, &welcome); err != nil {
		return nil, fmt.Errorf("HTTPS pulse: ответ панели не разобрался: %w", err)
	}
	if welcome.ServerName == "" || welcome.HeartbeatSeconds <= 0 {
		return nil, errors.New("HTTPS pulse: ответ панели неполный")
	}
	return &welcome, nil
}
