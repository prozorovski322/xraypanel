package config

import (
	"strings"
	"testing"
	"time"
)

// validEnv is the smallest environment that must load cleanly. Tests copy it and
// mutate one key, so a new required variable breaks every test at once, which is
// exactly the signal we want.
func validEnv() map[string]string {
	return map[string]string{
		"DATABASE_URL":     "postgres://panel:secret@localhost:5432/panel?sslmode=disable",
		"PANEL_SECRET_KEY": strings.Repeat("ab", 32), // 64 hex chars = 32 bytes
	}
}

func lookupFrom(env map[string]string) LookupFunc {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

func loadWith(t *testing.T, mutate func(env map[string]string)) (*Config, error) {
	t.Helper()
	env := validEnv()
	if mutate != nil {
		mutate(env)
	}
	return LoadFrom(lookupFrom(env))
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := loadWith(t, nil)
	if err != nil {
		t.Fatalf("expected the minimal environment to load, got: %v", err)
	}

	if cfg.Env != EnvDev {
		t.Errorf("Env = %q, want %q", cfg.Env, EnvDev)
	}
	if cfg.IsProd() {
		t.Error("IsProd() = true for the default environment")
	}
	if cfg.Log.Format != "text" {
		t.Errorf("Log.Format = %q, want text in dev", cfg.Log.Format)
	}
	if cfg.HTTP.Addr != ":8080" {
		t.Errorf("HTTP.Addr = %q, want :8080", cfg.HTTP.Addr)
	}
	if cfg.GRPC.Addr != ":8443" {
		t.Errorf("GRPC.Addr = %q, want :8443", cfg.GRPC.Addr)
	}
	if len(cfg.SecretKey) != 32 {
		t.Errorf("len(SecretKey) = %d, want 32", len(cfg.SecretKey))
	}
	if cfg.BillingLocation != time.UTC {
		t.Errorf("BillingLocation = %v, want UTC", cfg.BillingLocation)
	}
	if cfg.Auth.SecureCookies {
		t.Error("Auth.SecureCookies = true, want false by default in dev")
	}
	if cfg.Bootstrap.Enabled() {
		t.Error("Bootstrap.Enabled() = true with no bootstrap variables set")
	}
}

func TestProdDefaults(t *testing.T) {
	cfg, err := loadWith(t, func(env map[string]string) {
		env["APP_ENV"] = EnvProd
	})
	if err != nil {
		t.Fatalf("prod environment failed to load: %v", err)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Log.Format = %q, want json in prod", cfg.Log.Format)
	}
	if !cfg.Auth.SecureCookies {
		t.Error("Auth.SecureCookies = false, want true by default in prod")
	}
}

// TestSecretKeyEncodings pins the accepted encodings: an operator should be able
// to paste whatever `openssl rand` or `head -c 32 | base64` produced.
func TestSecretKeyEncodings(t *testing.T) {
	cases := map[string]string{
		"hex":            strings.Repeat("0f", 32),
		"base64 std":     "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"base64 raw url": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := loadWith(t, func(env map[string]string) {
				env["PANEL_SECRET_KEY"] = value
			})
			if err != nil {
				t.Fatalf("PANEL_SECRET_KEY=%s rejected: %v", name, err)
			}
			if len(cfg.SecretKey) != 32 {
				t.Errorf("len(SecretKey) = %d, want 32", len(cfg.SecretKey))
			}
		})
	}
}

// TestValidationErrors is the real point of this package: a bad environment must
// fail startup with a message naming the offending variable.
func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(env map[string]string)
		wantKey string
	}{
		{
			name:    "missing database url",
			mutate:  func(env map[string]string) { delete(env, "DATABASE_URL") },
			wantKey: "DATABASE_URL",
		},
		{
			name:    "empty database url counts as missing",
			mutate:  func(env map[string]string) { env["DATABASE_URL"] = "   " },
			wantKey: "DATABASE_URL",
		},
		{
			name:    "database url with wrong scheme",
			mutate:  func(env map[string]string) { env["DATABASE_URL"] = "mysql://localhost/panel" },
			wantKey: "DATABASE_URL",
		},
		{
			name:    "missing secret key",
			mutate:  func(env map[string]string) { delete(env, "PANEL_SECRET_KEY") },
			wantKey: "PANEL_SECRET_KEY",
		},
		{
			name:    "short secret key is not stretched",
			mutate:  func(env map[string]string) { env["PANEL_SECRET_KEY"] = "tooshort" },
			wantKey: "PANEL_SECRET_KEY",
		},
		{
			name:    "unknown environment",
			mutate:  func(env map[string]string) { env["APP_ENV"] = "staging" },
			wantKey: "APP_ENV",
		},
		{
			name:    "unparsable duration",
			mutate:  func(env map[string]string) { env["AUTH_ACCESS_TTL"] = "15 minutes" },
			wantKey: "AUTH_ACCESS_TTL",
		},
		{
			name:    "duration out of range",
			mutate:  func(env map[string]string) { env["AUTH_ACCESS_TTL"] = "1s" },
			wantKey: "AUTH_ACCESS_TTL",
		},
		{
			name:    "listen address without port",
			mutate:  func(env map[string]string) { env["HTTP_ADDR"] = "localhost" },
			wantKey: "HTTP_ADDR",
		},
		{
			name:    "listen port out of range",
			mutate:  func(env map[string]string) { env["HTTP_ADDR"] = ":70000" },
			wantKey: "HTTP_ADDR",
		},
		{
			name:    "non-integer conn count",
			mutate:  func(env map[string]string) { env["DB_MAX_CONNS"] = "many" },
			wantKey: "DB_MAX_CONNS",
		},
		{
			name: "min conns above max conns",
			mutate: func(env map[string]string) {
				env["DB_MIN_CONNS"] = "20"
				env["DB_MAX_CONNS"] = "10"
			},
			wantKey: "DB_MIN_CONNS",
		},
		{
			name: "refresh ttl not longer than access ttl",
			mutate: func(env map[string]string) {
				env["AUTH_ACCESS_TTL"] = "2h"
				env["AUTH_REFRESH_TTL"] = "1h"
			},
			wantKey: "AUTH_REFRESH_TTL",
		},
		{
			name: "http and grpc on the same address",
			mutate: func(env map[string]string) {
				env["HTTP_ADDR"] = ":9000"
				env["GRPC_ADDR"] = ":9000"
			},
			wantKey: "GRPC_ADDR",
		},
		{
			name:    "invalid timezone",
			mutate:  func(env map[string]string) { env["BILLING_TIMEZONE"] = "Mars/Olympus" },
			wantKey: "BILLING_TIMEZONE",
		},
		{
			name:    "invalid cidr in trusted proxies",
			mutate:  func(env map[string]string) { env["HTTP_TRUSTED_PROXIES"] = "10.0.0.1" },
			wantKey: "HTTP_TRUSTED_PROXIES",
		},
		{
			name:    "non-boolean flag",
			mutate:  func(env map[string]string) { env["AUTH_SECURE_COOKIES"] = "yes please" },
			wantKey: "AUTH_SECURE_COOKIES",
		},
		{
			name:    "bootstrap username without password",
			mutate:  func(env map[string]string) { env["BOOTSTRAP_ADMIN_USERNAME"] = "root" },
			wantKey: "BOOTSTRAP_ADMIN_PASSWORD",
		},
		{
			name:    "bootstrap password without username",
			mutate:  func(env map[string]string) { env["BOOTSTRAP_ADMIN_PASSWORD"] = "correct-horse" },
			wantKey: "BOOTSTRAP_ADMIN_USERNAME",
		},
		{
			name: "bootstrap password too short",
			mutate: func(env map[string]string) {
				env["BOOTSTRAP_ADMIN_USERNAME"] = "root"
				env["BOOTSTRAP_ADMIN_PASSWORD"] = "short"
			},
			wantKey: "BOOTSTRAP_ADMIN_PASSWORD",
		},
		{
			name: "insecure cookies rejected in prod",
			mutate: func(env map[string]string) {
				env["APP_ENV"] = EnvProd
				env["AUTH_SECURE_COOKIES"] = "false"
			},
			wantKey: "AUTH_SECURE_COOKIES",
		},
		{
			name: "debug logging rejected in prod",
			mutate: func(env map[string]string) {
				env["APP_ENV"] = EnvProd
				env["LOG_LEVEL"] = "debug"
			},
			wantKey: "LOG_LEVEL",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadWith(t, tc.mutate)
			if err == nil {
				t.Fatalf("expected a validation error mentioning %s, got a valid config", tc.wantKey)
			}
			if cfg != nil {
				t.Error("a failed load must return a nil config, not a partially built one")
			}
			if !strings.Contains(err.Error(), tc.wantKey) {
				t.Errorf("error does not mention %s:\n%v", tc.wantKey, err)
			}
		})
	}
}

// TestReportsEveryProblemAtOnce is the behaviour that makes a broken .env a
// one-pass fix instead of one restart per typo.
func TestReportsEveryProblemAtOnce(t *testing.T) {
	_, err := loadWith(t, func(env map[string]string) {
		delete(env, "DATABASE_URL")
		delete(env, "PANEL_SECRET_KEY")
		env["APP_ENV"] = "staging"
		env["HTTP_ADDR"] = "nope"
	})
	if err == nil {
		t.Fatal("expected validation to fail")
	}

	for _, key := range []string{"DATABASE_URL", "PANEL_SECRET_KEY", "APP_ENV", "HTTP_ADDR"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error omits %s, so the operator would have to restart to find it:\n%v", key, err)
		}
	}
}

// TestBlankValuesFallBackToDefaults pins the "FOO= means unset" rule, which is
// how a commented-out line in a .env file behaves in practice.
func TestBlankValuesFallBackToDefaults(t *testing.T) {
	cfg, err := loadWith(t, func(env map[string]string) {
		env["HTTP_ADDR"] = ""
		env["LOG_LEVEL"] = "  "
		env["DB_MAX_CONNS"] = ""
	})
	if err != nil {
		t.Fatalf("blank optional values should fall back to defaults, got: %v", err)
	}
	if cfg.HTTP.Addr != ":8080" {
		t.Errorf("HTTP.Addr = %q, want the default :8080", cfg.HTTP.Addr)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("Log.Level = %q, want the default info", cfg.Log.Level)
	}
	if cfg.DB.MaxConns != 10 {
		t.Errorf("DB.MaxConns = %d, want the default 10", cfg.DB.MaxConns)
	}
}
