// Package proto — конверт и сообщения протокола агент↔панель, версия 1.
// Источник правды — panel/packages/shared/src/agent-protocol.ts: изменения формата
// сначала попадают туда и в docs, затем зеркалятся здесь.
package proto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Version — версия протокола в поле v конверта.
const Version = 1

// Типы сообщений v1 (AGENT_MSG в shared-контракте).
const (
	MsgHello     = "hello"
	MsgAuth      = "auth"
	MsgHeartbeat = "heartbeat"
	MsgMetrics   = "metrics"
	MsgChallenge = "challenge"
	MsgWelcome   = "welcome"
	MsgError     = "error"
)

// Коды error-сообщения панели, после которых переподключаться бессмысленно.
const (
	ErrCodeAuthFailed    = "auth-failed"
	ErrCodeUnknownServer = "unknown-server"
)

// Envelope — версионированный конверт {v, type, id, ts, payload}.
type Envelope struct {
	V       int             `json:"v"`
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	TS      string          `json:"ts"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// New упаковывает payload в конверт с новым id и текущим временем (UTC, RFC3339 — как требует схема панели).
func New(msgType string, payload any) (Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("payload %q: %w", msgType, err)
	}
	return Envelope{
		V:       Version,
		Type:    msgType,
		ID:      uuid.NewString(),
		TS:      time.Now().UTC().Format(time.RFC3339),
		Payload: raw,
	}, nil
}

// Decode разбирает payload конверта в нужный тип.
func Decode[T any](env Envelope) (T, error) {
	var out T
	if len(env.Payload) == 0 {
		return out, fmt.Errorf("сообщение %q без payload", env.Type)
	}
	if err := json.Unmarshal(env.Payload, &out); err != nil {
		return out, fmt.Errorf("payload %q: %w", env.Type, err)
	}
	return out, nil
}

/* ---------- агент → панель ---------- */

// Hello — первое сообщение после подключения: кто я.
type Hello struct {
	ServerID string `json:"serverId"`
	Pubkey   string `json:"pubkey"`
	Version  string `json:"version"`
}

// Auth — подпись nonce из challenge.
type Auth struct {
	Signature string `json:"signature"`
}

// Metrics — снимок метрик; ключи 1-в-1 с agentMetricsSchema.
type Metrics struct {
	CPUPct         float64 `json:"cpuPct"`
	Load1          float64 `json:"load1"`
	MemUsedMb      int64   `json:"memUsedMb"`
	MemTotalMb     int64   `json:"memTotalMb"`
	DiskUsedMb     int64   `json:"diskUsedMb"`
	DiskTotalMb    int64   `json:"diskTotalMb"`
	NetRxBps       float64 `json:"netRxBps"`
	NetTxBps       float64 `json:"netTxBps"`
	NetRxPps       float64 `json:"netRxPps"`
	NetTxPps       float64 `json:"netTxPps"`
	ConntrackCount *int64  `json:"conntrackCount"`
	UptimeSec      int64   `json:"uptimeSec"`
}

/* ---------- панель → агент ---------- */

// Challenge — nonce (base64), который агент подписывает своим ключом.
type Challenge struct {
	Nonce string `json:"nonce"`
}

// Welcome — успешная аутентификация и параметры работы из настроек «Автопроверки».
type Welcome struct {
	ServerName       string `json:"serverName"`
	HeartbeatSeconds int    `json:"heartbeatSeconds"`
	MetricsSeconds   int    `json:"metricsSeconds"`
}

// ErrorPayload — ошибка протокола или аутентификации от панели.
type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// SignNonce подписывает СЫРЫЕ байты nonce (после base64-декода) ключом агента.
func SignNonce(key ed25519.PrivateKey, nonceB64 string) (string, error) {
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return "", fmt.Errorf("nonce не base64: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, nonce)), nil
}
