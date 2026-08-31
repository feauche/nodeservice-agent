// Package enroll — обмен одноразового токена на привязку агента (HTTP, до WebSocket).
package enroll

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Result — ответ панели: к какому серверу привязан агент и куда подключаться.
type Result struct {
	ServerID   string `json:"serverId"`
	ServerName string `json:"serverName"`
	WsURL      string `json:"wsUrl"`
}

type request struct {
	Token    string `json:"token"`
	Pubkey   string `json:"pubkey"`
	Version  string `json:"version"`
	Hostname string `json:"hostname,omitempty"`
}

// problem — тело ошибки панели (application/problem+json).
type problem struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// Enroll выполняет POST {panel}/api/agent/v1/enroll и возвращает привязку.
func Enroll(
	ctx context.Context,
	panelURL, token string,
	pub ed25519.PublicKey,
	version string,
) (*Result, error) {
	hostname, _ := os.Hostname()
	body, err := json.Marshal(request{
		Token:    token,
		Pubkey:   base64.StdEncoding.EncodeToString(pub),
		Version:  version,
		Hostname: hostname,
	})
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(panelURL, "/") + "/api/agent/v1/enroll"
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("панель недоступна: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		var p problem
		_ = json.Unmarshal(raw, &p)
		msg := p.Detail
		if msg == "" {
			msg = p.Title
		}
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		return nil, fmt.Errorf("энроллмент отклонён (HTTP %d): %s", res.StatusCode, msg)
	}

	var out Result
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("ответ панели не разобрался: %w", err)
	}
	if out.ServerID == "" || out.WsURL == "" {
		return nil, fmt.Errorf("ответ панели неполный: %s", strings.TrimSpace(string(raw)))
	}
	return &out, nil
}
