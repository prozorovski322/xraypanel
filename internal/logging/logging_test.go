package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func newTestLogger(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return New(&buf, Options{Level: "debug", Format: "json"}), &buf
}

// decode reads the single JSON record the logger produced.
func decode(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("logger produced no output")
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatalf("output is not valid JSON (%v): %s", err, line)
	}
	return record
}

func TestRedactsSensitiveKeys(t *testing.T) {
	keys := []string{
		"password",
		"Password",
		"password_hash",
		"passwordHash",
		"totp_secret",
		"refresh_token",
		"authorization",
		"cookie",
		"private_key",
		"api_key",
		"apiKey",
		"database_url",
		"dsn",
		"ss_psk",
	}

	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			logger, buf := newTestLogger(t)
			logger.Info("test", slog.String(key, "hunter2-the-actual-value"))

			out := buf.String()
			if strings.Contains(out, "hunter2-the-actual-value") {
				t.Errorf("value leaked for key %q: %s", key, out)
			}
			if !strings.Contains(out, Redacted) {
				t.Errorf("no redaction marker for key %q: %s", key, out)
			}
		})
	}
}

// TestKeepsSafeKeys is the other half of the contract: over-redaction makes logs
// useless exactly when someone is debugging a handshake.
func TestKeepsSafeKeys(t *testing.T) {
	keys := []string{
		"public_key",
		"key_prefix",
		"totp_enabled",
		"api_key_name",
		"username",
		"node_id",
		"remote_addr",
		"xray_version",
	}

	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			logger, buf := newTestLogger(t)
			logger.Info("test", slog.String(key, "visible-value"))

			out := buf.String()
			if !strings.Contains(out, "visible-value") {
				t.Errorf("key %q was redacted but carries nothing secret: %s", key, out)
			}
		})
	}
}

// TestRedactsInsideGroups guards the accidental-leak path: a nested struct logged
// as a group must be walked, not trusted.
func TestRedactsInsideGroups(t *testing.T) {
	logger, buf := newTestLogger(t)
	logger.Info("login",
		slog.Group("admin",
			slog.String("username", "root"),
			slog.String("password", "leaky"),
			slog.Group("session", slog.String("refresh_token", "also-leaky")),
		),
	)

	out := buf.String()
	if strings.Contains(out, "leaky") {
		t.Errorf("a secret inside a group reached the log: %s", out)
	}
	if !strings.Contains(out, "root") {
		t.Errorf("non-secret group attribute was dropped: %s", out)
	}
}

func TestSecretWrapperNeverPrints(t *testing.T) {
	logger, buf := newTestLogger(t)

	// A deliberately innocuous key name: the wrapper must hide the value even
	// when key-name redaction would not have fired.
	logger.Info("test", slog.Any("harmless_field", Wrap("top-secret-value")))

	out := buf.String()
	if strings.Contains(out, "top-secret-value") {
		t.Errorf("Secret leaked through slog: %s", out)
	}
	if !strings.Contains(out, Redacted) {
		t.Errorf("Secret did not render as %s: %s", Redacted, out)
	}
}

func TestSecretStringerDoesNotLeak(t *testing.T) {
	s := Wrap("top-secret-value")
	if got := s.String(); got != Redacted {
		t.Errorf("String() = %q, want %q", got, Redacted)
	}
	if got := s.Reveal(); got != "top-secret-value" {
		t.Errorf("Reveal() = %q, want the original value", got)
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, Options{Level: "warn", Format: "json"})

	logger.Info("should be dropped")
	if buf.Len() != 0 {
		t.Errorf("info record passed a warn-level logger: %s", buf.String())
	}

	logger.Warn("should be kept")
	if buf.Len() == 0 {
		t.Error("warn record was dropped by a warn-level logger")
	}
}

func TestUnknownLevelFallsBackToInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, Options{Level: "chatty", Format: "json"})

	logger.Debug("dropped")
	if buf.Len() != 0 {
		t.Error("debug record passed a logger that should have fallen back to info")
	}

	logger.Info("kept")
	record := decode(t, &buf)
	if record["msg"] != "kept" {
		t.Errorf("msg = %v, want %q", record["msg"], "kept")
	}
}

func TestTextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, Options{Level: "info", Format: "text"})
	logger.Info("hello", slog.String("password", "leaky"))

	out := buf.String()
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("text format produced JSON: %s", out)
	}
	if strings.Contains(out, "leaky") {
		t.Errorf("text format skipped redaction: %s", out)
	}
}

func TestRedactDSN(t *testing.T) {
	t.Run("masks the password", func(t *testing.T) {
		got := RedactDSN("postgres://panel:supersecret@db.internal:5432/panel?sslmode=require")
		if strings.Contains(got, "supersecret") {
			t.Errorf("password survived redaction: %s", got)
		}
		for _, want := range []string{"://panel:", "db.internal:5432", "/panel", "sslmode=require"} {
			if !strings.Contains(got, want) {
				t.Errorf("RedactDSN dropped %q, which an operator needs: %s", want, got)
			}
		}
	})

	t.Run("passwordless dsn is unchanged", func(t *testing.T) {
		const dsn = "postgres://db.internal:5432/panel"
		if got := RedactDSN(dsn); got != dsn {
			t.Errorf("RedactDSN(%q) = %q, want it unchanged", dsn, got)
		}
	})

	t.Run("empty stays empty", func(t *testing.T) {
		if got := RedactDSN(""); got != "" {
			t.Errorf("RedactDSN(\"\") = %q, want empty", got)
		}
	})

	t.Run("unparsable dsn is not echoed", func(t *testing.T) {
		got := RedactDSN("postgres://user:pw@ho st:5432/db")
		if strings.Contains(got, "pw") {
			t.Errorf("an unparsable DSN was echoed with its password: %s", got)
		}
	})
}

func TestIsSensitiveKeyNormalizesSeparators(t *testing.T) {
	for _, key := range []string{"refresh-token", "refresh.token", "refresh token", "RefreshToken"} {
		if !IsSensitiveKey(key) {
			t.Errorf("IsSensitiveKey(%q) = false, want true", key)
		}
	}
	for _, key := range []string{"public-key", "public.key", "PublicKey"} {
		if IsSensitiveKey(key) {
			t.Errorf("IsSensitiveKey(%q) = true, want false", key)
		}
	}
}
