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
	ServerID   string   `json:"serverId"`
	ServerName string   `json:"serverName"`
	WsURL      string   `json:"wsUrl"`
	WsURLs     []string `json:"wsUrls,omitempty"`
}

// Endpoints поддерживает и новый список, и один адрес от старой панели.
func (r *Result) Endpoints() []string {
	urls := append([]string(nil), r.WsURLs...)
	urls = append(urls, r.WsURL)
	seen := make(map[string]struct{}, len(urls))
	out := make([]string, 0, len(urls))
	for _, value := range urls {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
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

// FirstAvailable выполняет первичную привязку через первый доступный вход. Резервные маршруты нужны
// именно здесь: до успешного enroll у агента ещё нет state.json и он не может получить их от панели.
func FirstAvailable(
	ctx context.Context,
	panelURLs []string,
	token string,
	pub ed25519.PublicKey,
	version string,
) (*Result, string, error) {
	if len(panelURLs) == 0 {
		return nil, "", fmt.Errorf("не задан ни один адрес панели")
	}
	errorsByURL := make([]string, 0, len(panelURLs))
	for _, panelURL := range panelURLs {
		res, err := Enroll(ctx, panelURL, token, pub, version)
		if err == nil {
			return res, panelURL, nil
		}
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		errorsByURL = append(errorsByURL, fmt.Sprintf("%s: %v", panelURL, err))
	}
	return nil, "", fmt.Errorf("регистрация не прошла ни через один вход: %s", strings.Join(errorsByURL, "; "))
}
