// Package agent holds the node agent's configuration.
//
// Separate from the panel's config package because the two processes share nothing: the
// agent has no database, no secret key, and no HTTP surface, and a single configuration
// type covering both would invite a node to be handed a database URL.
package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xraypanel/panel/internal/agent/stats"
	"github.com/xraypanel/panel/internal/pki"
)

// Defaults. The paths are inside the container's volume, so that an agent restart — or a
// container replacement — finds its identity and its configuration where it left them.
const (
	DefaultDataDir    = "/var/lib/xraypanel-node"
	DefaultXrayBinary = "/usr/local/bin/xray"

	storeFileName  = "agent.db"
	configFileName = "config.json"
)

// Config is the agent's fully validated configuration.
type Config struct {
	PanelAddr       string
	CAPin           string
	EnrollmentToken string

	DataDir    string
	XrayBinary string

	LogLevel  string
	LogFormat string

	HeartbeatInterval time.Duration
	ReconnectMin      time.Duration
	ReconnectMax      time.Duration

	// StatsInterval is how often the core's traffic counters are read. Shorter means
	// finer-grained billing and more work; longer means more traffic at risk if the core
	// restarts, since the traffic between a restart and the last poll is the part that
	// cannot be recovered (ADR-008).
	StatsInterval time.Duration

	// StatsStrategy is "delta" or "reset". Delta reads counters without zeroing them and
	// computes differences, which is what makes a crash cost nothing. Reset is the escape
	// hatch for an installation where that misbehaves, and it loses whatever was read but
	// not yet reported.
	StatsStrategy string

	// Hostname is reported to the panel for the operator's benefit, nothing more.
	Hostname string
}

// StorePath is where the local state lives.
func (c *Config) StorePath() string { return filepath.Join(c.DataDir, storeFileName) }

// ConfigPath is where the Xray configuration is written.
func (c *Config) ConfigPath() string { return filepath.Join(c.DataDir, configFileName) }

// LoadConfig reads the agent's configuration from the environment.
func LoadConfig() (*Config, error) { return LoadConfigFrom(os.LookupEnv) }

// LoadConfigFrom reads the configuration from an arbitrary lookup, collecting every
// problem rather than stopping at the first: an operator bringing up a node fixes the
// whole file in one pass instead of one restart per typo.
func LoadConfigFrom(lookup func(string) (string, bool)) (*Config, error) {
	var problems []string

	str := func(key, def string) string {
		value, ok := lookup(key)
		if !ok {
			return def
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return def
		}
		return value
	}

	duration := func(key string, def, minVal, maxVal time.Duration) time.Duration {
		raw := str(key, "")
		if raw == "" {
			return def
		}
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: must be a duration such as 30s, got %q", key, raw))
			return def
		}
		if parsed < minVal || parsed > maxVal {
			problems = append(problems, fmt.Sprintf("%s: must be between %s and %s, got %s",
				key, minVal, maxVal, parsed))
			return def
		}
		return parsed
	}

	enum := func(key, def string, allowed ...string) string {
		value := str(key, def)
		if !slices.Contains(allowed, value) {
			problems = append(problems, fmt.Sprintf("%s: must be one of %s, got %q",
				key, strings.Join(allowed, "|"), value))
			return def
		}
		return value
	}

	hostname, _ := os.Hostname()

	cfg := &Config{
		PanelAddr:       str("NODE_PANEL_ADDR", ""),
		CAPin:           str("NODE_CA_PIN", ""),
		EnrollmentToken: str("NODE_ENROLLMENT_TOKEN", ""),

		DataDir:    str("NODE_DATA_DIR", DefaultDataDir),
		XrayBinary: str("NODE_XRAY_BINARY", DefaultXrayBinary),

		LogLevel:  enum("NODE_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		LogFormat: enum("NODE_LOG_FORMAT", "json", "json", "text"),

		HeartbeatInterval: duration("NODE_HEARTBEAT_INTERVAL", 30*time.Second, 5*time.Second, 10*time.Minute),
		ReconnectMin:      duration("NODE_RECONNECT_MIN", time.Second, 100*time.Millisecond, time.Minute),
		ReconnectMax:      duration("NODE_RECONNECT_MAX", time.Minute, time.Second, time.Hour),

		// The ceiling is an hour because deltas are attributed to the hour they were
		// observed in: polling less often than that would put traffic in the wrong hour.
		StatsInterval: duration("NODE_STATS_INTERVAL", 30*time.Second, time.Second, time.Hour),
		StatsStrategy: enum("NODE_STATS_STRATEGY", string(stats.ModeDelta),
			string(stats.ModeDelta), string(stats.ModeReset)),

		Hostname: str("NODE_HOSTNAME", hostname),
	}

	if cfg.PanelAddr == "" {
		problems = append(problems, "NODE_PANEL_ADDR: is required (host:port of the panel's node port)")
	} else if err := validateAddr(cfg.PanelAddr); err != nil {
		problems = append(problems, "NODE_PANEL_ADDR: "+err.Error())
	}

	// The pin is required even when the node is already enrolled. It costs nothing to
	// keep and it is what makes a re-enrollment safe: an agent that dropped the pin
	// after enrolling would have to trust whoever answers next time.
	switch {
	case cfg.CAPin == "":
		problems = append(problems, "NODE_CA_PIN: is required; it is issued together with the "+
			"enrollment token and is what lets this node verify the panel")
	default:
		normalized, err := pki.NormalizePin(cfg.CAPin)
		if err != nil {
			problems = append(problems, "NODE_CA_PIN: "+err.Error())
		} else {
			cfg.CAPin = normalized
		}
	}

	if cfg.ReconnectMax < cfg.ReconnectMin {
		problems = append(problems, fmt.Sprintf(
			"NODE_RECONNECT_MAX: must not be shorter than NODE_RECONNECT_MIN (%s < %s)",
			cfg.ReconnectMax, cfg.ReconnectMin))
	}

	if len(problems) > 0 {
		slices.Sort(problems)
		return nil, fmt.Errorf("invalid configuration (%d problem(s)):\n  - %s",
			len(problems), strings.Join(problems, "\n  - "))
	}
	return cfg, nil
}

// validateAddr checks a host:port the agent will dial.
func validateAddr(addr string) error {
	host, port, found := strings.Cut(addr, ":")
	if !found {
		return errors.New("must include a port, as host:port")
	}
	if strings.TrimSpace(host) == "" {
		return errors.New("must include a host")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("port %q is not between 1 and 65535", port)
	}
	return nil
}
