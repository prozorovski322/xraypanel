package agent

import (
	"strings"
	"testing"
	"time"
)

// A node is configured once, by hand, over SSH, by somebody who is also setting up the
// panel. Every problem has to be reported at once and in terms of the variable that
// caused it, because the alternative is one restart per typo on a machine they are not
// looking at.

func lookupFrom(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

// validPin is a syntactically valid SHA-256 pin.
const validPin = "6026c176aa9024fea1b4b1503a0fd5a64189638f1d68c4ab246eff896788e33d"

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := LoadConfigFrom(lookupFrom(map[string]string{
		"NODE_PANEL_ADDR": "panel.example.com:8443",
		"NODE_CA_PIN":     validPin,
	}))
	if err != nil {
		t.Fatalf("LoadConfigFrom: %v", err)
	}

	if cfg.DataDir != DefaultDataDir || cfg.XrayBinary != DefaultXrayBinary {
		t.Errorf("paths are %q and %q", cfg.DataDir, cfg.XrayBinary)
	}
	if cfg.HeartbeatInterval != 30*time.Second {
		t.Errorf("heartbeat default is %s", cfg.HeartbeatInterval)
	}
	if cfg.LogFormat != "json" {
		// A node's log is read through docker, where JSON is what a collector expects.
		t.Errorf("log format default is %q, want json", cfg.LogFormat)
	}
	if cfg.StorePath() != DefaultDataDir+"/agent.db" && !strings.HasSuffix(cfg.StorePath(), "agent.db") {
		t.Errorf("store path is %q", cfg.StorePath())
	}
	if !strings.HasSuffix(cfg.ConfigPath(), "config.json") {
		t.Errorf("config path is %q", cfg.ConfigPath())
	}
}

func TestLoadConfigRequiresAnAddressAndAPin(t *testing.T) {
	_, err := LoadConfigFrom(lookupFrom(map[string]string{}))
	if err == nil {
		t.Fatal("a configuration with no panel address was accepted")
	}

	message := err.Error()
	for _, expected := range []string{"NODE_PANEL_ADDR", "NODE_CA_PIN"} {
		if !strings.Contains(message, expected) {
			t.Errorf("the report does not mention %s:\n%s", expected, message)
		}
	}

	// Both problems in one report, not one per restart.
	if !strings.Contains(message, "2 problem(s)") {
		t.Errorf("problems are not reported together:\n%s", message)
	}
}

// The pin is required even for a node that is already enrolled. An agent that forgot it
// would have to trust whoever answers the next time it re-enrols.
func TestLoadConfigRejectsAnUnusablePin(t *testing.T) {
	for name, pin := range map[string]string{
		"too short":    "abc",
		"not hex":      strings.Repeat("z", 64),
		"with colons":  "60:26:c1:76",
		"whole sha512": strings.Repeat("a", 128),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfigFrom(lookupFrom(map[string]string{
				"NODE_PANEL_ADDR": "panel:8443",
				"NODE_CA_PIN":     pin,
			}))
			if err == nil {
				t.Fatal("an unusable pin was accepted")
			}
			if !strings.Contains(err.Error(), "NODE_CA_PIN") {
				t.Errorf("the report does not name the variable: %v", err)
			}
		})
	}
}

// A pin is accepted in whatever case it was pasted in, and stored in one form so that
// comparisons later cannot fail on capitalisation.
func TestPinIsNormalised(t *testing.T) {
	cfg, err := LoadConfigFrom(lookupFrom(map[string]string{
		"NODE_PANEL_ADDR": "panel:8443",
		"NODE_CA_PIN":     "  " + strings.ToUpper(validPin) + "  ",
	}))
	if err != nil {
		t.Fatalf("LoadConfigFrom: %v", err)
	}
	if cfg.CAPin != validPin {
		t.Errorf("pin is %q, want %q", cfg.CAPin, validPin)
	}
}

func TestLoadConfigValidatesTheAddress(t *testing.T) {
	for name, addr := range map[string]string{
		"no port":           "panel.example.com",
		"no host":           ":8443",
		"port too high":     "panel:70000",
		"port not a number": "panel:https",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfigFrom(lookupFrom(map[string]string{
				"NODE_PANEL_ADDR": addr,
				"NODE_CA_PIN":     validPin,
			}))
			if err == nil {
				t.Fatalf("%q was accepted as a panel address", addr)
			}
		})
	}
}

func TestLoadConfigValidatesDurations(t *testing.T) {
	_, err := LoadConfigFrom(lookupFrom(map[string]string{
		"NODE_PANEL_ADDR":         "panel:8443",
		"NODE_CA_PIN":             validPin,
		"NODE_HEARTBEAT_INTERVAL": "not a duration",
	}))
	if err == nil || !strings.Contains(err.Error(), "NODE_HEARTBEAT_INTERVAL") {
		t.Fatalf("an unparseable duration was accepted: %v", err)
	}

	// Out of range is reported as such rather than silently clamped: an operator who
	// asked for a heartbeat every day meant something, and it was not this.
	_, err = LoadConfigFrom(lookupFrom(map[string]string{
		"NODE_PANEL_ADDR":         "panel:8443",
		"NODE_CA_PIN":             validPin,
		"NODE_HEARTBEAT_INTERVAL": "24h",
	}))
	if err == nil || !strings.Contains(err.Error(), "NODE_HEARTBEAT_INTERVAL") {
		t.Fatalf("an out-of-range duration was accepted: %v", err)
	}
}

// A reconnect ceiling below the floor would make the backoff nonsense, and it is the kind
// of thing that only shows up when a panel goes down.
func TestReconnectBoundsMustBeOrdered(t *testing.T) {
	_, err := LoadConfigFrom(lookupFrom(map[string]string{
		"NODE_PANEL_ADDR":    "panel:8443",
		"NODE_CA_PIN":        validPin,
		"NODE_RECONNECT_MIN": "30s",
		"NODE_RECONNECT_MAX": "5s",
	}))
	if err == nil || !strings.Contains(err.Error(), "NODE_RECONNECT_MAX") {
		t.Fatalf("reversed reconnect bounds were accepted: %v", err)
	}
}

func TestLoadConfigValidatesEnums(t *testing.T) {
	_, err := LoadConfigFrom(lookupFrom(map[string]string{
		"NODE_PANEL_ADDR": "panel:8443",
		"NODE_CA_PIN":     validPin,
		"NODE_LOG_LEVEL":  "verbose",
	}))
	if err == nil || !strings.Contains(err.Error(), "NODE_LOG_LEVEL") {
		t.Fatalf("an unknown log level was accepted: %v", err)
	}
}

// An empty value means "unset", not "set to the empty string", which is what an operator
// almost always intends when a line is left blank in an env file.
func TestEmptyValuesFallBackToDefaults(t *testing.T) {
	cfg, err := LoadConfigFrom(lookupFrom(map[string]string{
		"NODE_PANEL_ADDR":  "panel:8443",
		"NODE_CA_PIN":      validPin,
		"NODE_DATA_DIR":    "   ",
		"NODE_XRAY_BINARY": "",
	}))
	if err != nil {
		t.Fatalf("LoadConfigFrom: %v", err)
	}
	if cfg.DataDir != DefaultDataDir || cfg.XrayBinary != DefaultXrayBinary {
		t.Errorf("blank values did not fall back: %q, %q", cfg.DataDir, cfg.XrayBinary)
	}
}
