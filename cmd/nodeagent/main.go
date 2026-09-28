// Command nodeagent is the data plane: it runs on an exit server, supervises a local
// xray-core process, and keeps it in sync with the panel.
//
// It is PID 1 in the node container and Xray is its child. That is deliberate: one
// process supervises the core, so there is exactly one thing that knows whether the node
// is serving, and stopping the container stops both.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xraypanel/panel/internal/agent"
	"github.com/xraypanel/panel/internal/agent/link"
	"github.com/xraypanel/panel/internal/agent/stats"
	"github.com/xraypanel/panel/internal/agent/store"
	"github.com/xraypanel/panel/internal/agent/supervisor"
	"github.com/xraypanel/panel/internal/logging"
)

// Build metadata, set with -ldflags at release time.
var (
	version = "dev"
	commit  = "none"
)

// shutdownBudget is how long the core gets to stop cleanly when the agent is asked to
// exit. Beyond it the process is killed: a container stuck shutting down is worse than
// an abrupt one.
const shutdownBudget = 20 * time.Second

const usage = `nodeagent - Xray data plane

Usage:
  nodeagent run        Supervise xray and stay connected to the panel (default)
  nodeagent version    Print build information

Configuration is read from the environment:

  NODE_PANEL_ADDR          host:port of the panel's node port (required)
  NODE_CA_PIN              the panel authority's public-key pin (required)
  NODE_ENROLLMENT_TOKEN    single-use token, needed only until this node is enrolled
  NODE_DATA_DIR            where identity and configuration live (default /var/lib/xraypanel-node)
  NODE_XRAY_BINARY         the xray executable (default /usr/local/bin/xray)
  NODE_HEARTBEAT_INTERVAL  fallback interval until the panel states one (default 30s)
  NODE_RECONNECT_MIN       first reconnect delay (default 1s)
  NODE_RECONNECT_MAX       longest reconnect delay (default 1m)
  NODE_STATS_INTERVAL      how often the core's traffic counters are read (default 30s)
  NODE_STATS_STRATEGY      delta|reset; delta keeps the core authoritative (default delta)
  NODE_LOG_LEVEL           debug|info|warn|error (default info)
  NODE_LOG_FORMAT          json|text (default json)

All three of address, pin and token come from the panel when an operator mints an
enrollment token. The pin is what lets this node verify the panel before it sends the
token, so it is required even after enrollment.
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	command := "run"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	switch command {
	case "version":
		fmt.Printf("nodeagent %s (commit %s)\n", version, commit)
		return nil
	case "help", "-h", "--help":
		_, _ = os.Stdout.WriteString(usage)
		return nil
	case "run":
	default:
		_, _ = os.Stdout.WriteString(usage)
		return fmt.Errorf("unknown command %q", command)
	}

	cfg, err := agent.LoadConfig()
	if err != nil {
		return err
	}

	logger := logging.New(os.Stdout, logging.Options{
		Level:  cfg.LogLevel,
		Format: cfg.LogFormat,
	})

	logger.Info("starting node agent",
		slog.String("version", version),
		slog.String("commit", commit),
		slog.String("panel", cfg.PanelAddr),
		slog.String("data_dir", cfg.DataDir),
		slog.String("xray", cfg.XrayBinary))

	state, err := store.Open(cfg.StorePath())
	if err != nil {
		return err
	}
	defer func() {
		if err := state.Close(); err != nil {
			logger.Error("closing the local store failed", slog.Any("error", err))
		}
	}()

	sup, err := supervisor.New(supervisor.Config{
		Binary:     cfg.XrayBinary,
		ConfigPath: cfg.ConfigPath(),
		Logger:     logger,
	})
	if err != nil {
		return err
	}

	node, err := link.New(link.Config{
		PanelAddr:       cfg.PanelAddr,
		CAPin:           cfg.CAPin,
		EnrollmentToken: cfg.EnrollmentToken,
		AgentVersion:    version,
		Hostname:        cfg.Hostname,
		Logger:          logger,
		ReconnectMin:    cfg.ReconnectMin,
		ReconnectMax:    cfg.ReconnectMax,
		Heartbeat:       cfg.HeartbeatInterval,
		StatsInterval:   cfg.StatsInterval,
		StatsStrategy:   stats.Mode(cfg.StatsStrategy),
	}, state, sup)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runErr := node.Run(ctx)

	// The core is stopped on the way out whatever happened, including a configuration
	// error: leaving an orphaned Xray behind would mean the next agent cannot bind its
	// ports, which looks like a broken node.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
	defer cancel()

	if err := sup.Close(shutdownCtx); err != nil {
		logger.Error("stopping xray was not clean", slog.Any("error", err))
	}

	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return runErr
	}

	logger.Info("node agent stopped")
	return nil
}
