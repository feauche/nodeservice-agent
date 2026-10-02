package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/feauche/nodeservice-agent/internal/pull"
	"github.com/feauche/nodeservice-agent/internal/state"
)

func newConfigurePullCmd() *cobra.Command {
	var stateDir, serverID, serverName string
	var port int
	var accessKeyStdin bool
	cmd := &cobra.Command{
		Use:    "configure-pull",
		Short:  "Настроить входящий HTTPS-канал панели",
		Hidden: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			if port < 10000 || port > 65535 {
				return errors.New("порт агента должен быть пятизначным: 10000–65535")
			}
			if serverID == "" || serverName == "" {
				return errors.New("нужны идентификатор и имя сервера")
			}
			if !accessKeyStdin {
				return errors.New("ключ доступа принимается только через stdin")
			}
			key, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil && key == "" {
				return fmt.Errorf("чтение ключа доступа: %w", err)
			}
			key = strings.TrimSpace(key)
			if len(key) < 32 {
				return errors.New("ключ доступа слишком короткий")
			}
			st, err := state.Load(stateDir)
			if err != nil {
				// Полная настройка pull не зависит от старой привязки и чинит повреждённый state.json.
				st = &state.State{}
			}
			if st == nil {
				st = &state.State{}
			}
			st.Pull = &state.PullState{Port: port, AccessKey: key, ServerID: serverID, ServerName: serverName}
			if err := state.Save(stateDir, st); err != nil {
				return fmt.Errorf("сохранение настройки: %w", err)
			}
			cert, err := pull.EnsureCertificate(stateDir)
			if err != nil {
				return err
			}
			fmt.Printf("NODESERVICE_PULL_CERT=%s\n", cert)
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", envOr("NODESERVICE_STATE_DIR", "/var/lib/nodeservice-agent"), "каталог состояния")
	cmd.Flags().StringVar(&serverID, "server-id", "", "идентификатор сервера")
	cmd.Flags().StringVar(&serverName, "server-name", "", "имя сервера")
	cmd.Flags().IntVar(&port, "port", 0, "порт HTTPS")
	cmd.Flags().BoolVar(&accessKeyStdin, "access-key-stdin", false, "прочитать ключ доступа из stdin")
	return cmd
}
