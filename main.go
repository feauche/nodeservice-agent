// Агент NodeService: метрики и heartbeat ноды. Новые установки обслуживаются
// входящим HTTPS-каналом, который опрашивает панель; старый WebSocket совместим.
package main

import (
	"errors"
	"os"

	"github.com/feauche/nodeservice-agent/internal/transport"
	"github.com/spf13/cobra"
)

const authRejectedExitCode = 78

// version подменяется при сборке: -ldflags "-X main.version=v0.5.0".
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		if errors.Is(err, transport.ErrAuthRejected) {
			os.Exit(authRejectedExitCode)
		}
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:          "nodeservice-agent",
		Short:        "Агент NodeService: heartbeat и метрики ноды",
		SilenceUsage: true,
	}
	root.AddCommand(newRunCmd(), newVersionCmd(), newConfigurePullCmd())
	return root
}
