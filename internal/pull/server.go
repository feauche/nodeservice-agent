// Package pull exposes the agent to the panel over a small authenticated HTTPS API.
package pull

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"

	"github.com/feauche/nodeservice-agent/internal/metrics"
	"github.com/feauche/nodeservice-agent/internal/state"
	"github.com/feauche/nodeservice-agent/internal/vpnprobe"
)

const (
	CertFile = "pull-cert.pem"
	KeyFile  = "pull-key.pem"
)

type snapshot struct {
	ServerID string `json:"serverId"`
	Version  string `json:"version"`
	Metrics  any    `json:"metrics,omitempty"`
}

// EnsureCertificate creates the per-agent TLS identity once and returns the certificate DER as base64.
func EnsureCertificate(dir string) (string, error) {
	certPath, keyPath := filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)
	if raw, err := os.ReadFile(certPath); err == nil {
		block, _ := pem.Decode(raw)
		if block != nil && block.Type == "CERTIFICATE" {
			if _, parseErr := x509.ParseCertificate(block.Bytes); parseErr == nil {
				// Проверяем и сам ключ, и совпадение пары. Обрыв прошлого обновления не
				// должен оставить агент с вечно негодной парой cert/key.
				if _, pairErr := tls.LoadX509KeyPair(certPath, keyPath); pairErr == nil {
					return base64.StdEncoding.EncodeToString(block.Bytes), nil
				}
			}
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("TLS-ключ: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("серийный номер TLS: %w", err)
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "nodeservice-agent"},
		DNSNames:     []string{"nodeservice-agent"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		return "", fmt.Errorf("TLS-сертификат: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("TLS-ключ: %w", err)
	}
	if err := writeSecret(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})); err != nil {
		return "", err
	}
	if err := writeSecret(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func writeSecret(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type Config struct {
	State    *state.PullState
	StateDir string
	PanelURL string
	Version  string
	Log      zerolog.Logger
	// Probe is replaced in tests; production uses the in-process Xray probe.
	Probe func(context.Context, string, vpnprobe.Request) vpnprobe.Result
}

func authorized(r *http.Request, accessKey string) bool {
	want := "Bearer " + accessKey
	got := r.Header.Get("Authorization")
	return len(got) == len(want) && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// Run serves the snapshot and one strictly typed VPN probe. TLS pins the agent identity; Bearer authenticates the panel.
func Run(ctx context.Context, cfg Config) error {
	collector := metrics.NewCollector()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, cfg.State.AccessKey) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		out := snapshot{ServerID: cfg.State.ServerID, Version: cfg.Version}
		if r.URL.Query().Get("metrics") != "0" {
			m, warn := collector.Collect(r.Context())
			if warn != nil {
				cfg.Log.Debug().Err(warn).Msg("часть метрик недоступна")
			}
			out.Metrics = m
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	probe := cfg.Probe
	if probe == nil {
		probe = vpnprobe.Run
	}
	// Несколько нод могут просесть одновременно. Четыре короткие пробы не создают очередь на весь парк,
	// но защищают хост от десятков одновременных экземпляров Xray.
	probeSlot := make(chan struct{}, 4)
	mux.HandleFunc("POST /v1/vpn-probe", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, cfg.State.AccessKey) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		select {
		case probeSlot <- struct{}{}:
			defer func() { <-probeSlot }()
		default:
			http.Error(w, "probe already running", http.StatusTooManyRequests)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 12<<10)
		var input vpnprobe.Request
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil || len(input.Link) > 8192 || len(input.Token) < 32 || len(input.Token) > 200 {
			http.Error(w, "invalid probe request", http.StatusBadRequest)
			return
		}
		probeCtx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		result := probe(probeCtx, cfg.PanelURL, input)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(result)
	})
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.State.Port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	done := make(chan error, 1)
	go func() {
		done <- server.ListenAndServeTLS(filepath.Join(cfg.StateDir, CertFile), filepath.Join(cfg.StateDir, KeyFile))
	}()
	cfg.Log.Info().Int("порт", cfg.State.Port).Str("сервер", cfg.State.ServerName).
		Msg("агент ждёт защищённые запросы панели")
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
