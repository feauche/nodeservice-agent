package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/lumaxdev/nodeservice-agent/internal/enroll"
	"github.com/lumaxdev/nodeservice-agent/internal/state"
	"github.com/lumaxdev/nodeservice-agent/internal/transport"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func newRunCmd() *cobra.Command {
	var panelURL, token, stateDir string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Запустить агента (первый запуск с --token привязывает его к панели)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			log := newLogger()

			st, err := state.Load(stateDir)
			if err != nil {
				return fmt.Errorf("состояние агента: %w", err)
			}
			if st == nil {
				// Первый запуск: генерируем ключ и меняем одноразовый токен на привязку.
				if panelURL == "" || token == "" {
					return errors.New(
						"первый запуск: нужны --panel-url и --token (или NODESERVICE_PANEL_URL / NODESERVICE_TOKEN)",
					)
				}
				st, err = enrollFirstRun(cmd.Context(), log, panelURL, token, stateDir)
				if err != nil {
					return err
				}
			} else if token != "" {
				log.Info().Msg("состояние уже есть — токен игнорирую (для перепривязки удали state.json)")
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			client := transport.New(transport.Config{State: st, Version: version, Log: log})
			if err := client.Run(ctx); err != nil {
				log.Error().Err(err).Msg("агент остановлен")
				return err
			}
			log.Info().Msg("агент остановлен по сигналу")
			return nil
		},
	}
	cmd.Flags().StringVar(&panelURL, "panel-url", os.Getenv("NODESERVICE_PANEL_URL"),
		"адрес панели, например https://panel.example.com")
	cmd.Flags().StringVar(&token, "token", os.Getenv("NODESERVICE_TOKEN"),
		"одноразовый токен подключения (нужен только при первом запуске)")
	cmd.Flags().StringVar(&stateDir, "state-dir", envOr("NODESERVICE_STATE_DIR", "/var/lib/nodeservice-agent"),
		"каталог состояния агента (ключ и привязка)")
	return cmd
}

func enrollFirstRun(
	ctx context.Context,
	log zerolog.Logger,
	panelURL, token, stateDir string,
) (*state.State, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("генерация ключа: %w", err)
	}
	key := ed25519.NewKeyFromSeed(seed)

	res, err := enroll.Enroll(ctx, panelURL, token, key.Public().(ed25519.PublicKey), version)
	if err != nil {
		return nil, err
	}
	st := &state.State{
		PanelURL:   panelURL,
		ServerID:   res.ServerID,
		ServerName: res.ServerName,
		WsURL:      res.WsURL,
		PrivKeyB64: base64.StdEncoding.EncodeToString(seed),
	}
	if err := state.Save(stateDir, st); err != nil {
		return nil, fmt.Errorf("сохранение состояния: %w", err)
	}
	log.Info().Str("сервер", res.ServerName).Msg("агент привязан к панели, ключ зафиксирован")
	return st, nil
}

func newLogger() zerolog.Logger {
	cw := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.TimeOnly,
		NoColor:    !term.IsTerminal(int(os.Stderr.Fd())),
	}
	return zerolog.New(cw).With().Timestamp().Logger()
}
