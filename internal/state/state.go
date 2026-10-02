// Package state — привязка агента к панели: ключ ed25519 и адреса.
// Файл state.json лежит в каталоге состояния (по умолчанию /var/lib/nodeservice-agent),
// права 0600 — приватный ключ никуда больше не попадает.
package state

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// State — всё, что нужно агенту после энроллмента.
type State struct {
	PanelURL   string `json:"panelUrl"`
	ServerID   string `json:"serverId"`
	ServerName string `json:"serverName"`
	// WsURL оставлен для совместимости с агентами до v0.7.0; равен первому элементу WsURLs.
	WsURL  string   `json:"wsUrl"`
	WsURLs []string `json:"wsUrls,omitempty"`
	// PrivKeyB64 — base64 seed (32 байта) приватного ключа ed25519.
	PrivKeyB64 string `json:"privateKey"`
}

// Key восстанавливает приватный ключ из seed.
func (s *State) Key() (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(s.PrivKeyB64)
	if err != nil {
		return nil, fmt.Errorf("ключ в состоянии не base64: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ключ в состоянии: %d байт вместо %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func path(dir string) string { return filepath.Join(dir, "state.json") }

// Load читает состояние; (nil, nil) — агент ещё не привязан.
func Load(dir string) (*State, error) {
	raw, err := os.ReadFile(path(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("state.json повреждён: %w", err)
	}
	if st.WsURL == "" && len(st.WsURLs) > 0 {
		st.WsURL = st.WsURLs[0]
	}
	if st.ServerID == "" || st.WsURL == "" || st.PrivKeyB64 == "" {
		return nil, errors.New("state.json неполный — удали его и привяжи агента заново токеном")
	}
	st.SetEndpoints(append(st.WsURLs, st.WsURL))
	return &st, nil
}

// Endpoints возвращает основной и запасные WebSocket-адреса без повторов.
func (s *State) Endpoints() []string {
	return append([]string(nil), s.WsURLs...)
}

// SetEndpoints обновляет список, сохраняя старое поле WsURL для обратной совместимости.
func (s *State) SetEndpoints(urls []string) {
	seen := make(map[string]struct{}, len(urls))
	next := make([]string, 0, len(urls))
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		u, err := url.Parse(raw)
		if raw == "" || err != nil || u.Host == "" || (u.Scheme != "ws" && u.Scheme != "wss") {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		next = append(next, raw)
		if len(next) == 5 {
			break
		}
	}
	if len(next) == 0 && s.WsURL != "" {
		next = []string{s.WsURL}
	}
	s.WsURLs = next
	if len(next) > 0 {
		s.WsURL = next[0]
	}
}

// Save атомарно пишет состояние (tmp + rename), права 0600.
func Save(dir string, st *State) error {
	st.SetEndpoints(append(st.WsURLs, st.WsURL))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path(dir) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path(dir))
}
