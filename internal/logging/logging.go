// Package logging builds the process logger and keeps secrets out of it.
//
// Redaction here is a safety net, not a licence to log secrets: code should pass
// [Secret] or an already-masked value. The net exists because the expensive leaks
// are the accidental ones, where a whole struct gets logged years after someone
// added a password field to it.
package logging

import (
	"io"
	"log/slog"
	"net/url"
	"strings"
)

// Redacted replaces every value that redaction decides not to print.
const Redacted = "[REDACTED]"

// sensitiveSubstrings marks an attribute key as secret-bearing. Matching is on a
// lowercased key, so "PasswordHash" and "password_hash" both match.
var sensitiveSubstrings = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"credential",
	"authorization",
	"cookie",
	"session",
	"private",
	"dsn",
	"database_url",
	"apikey",
	"api_key",
	"totp",
	"psk",
}

// safeKeys are keys that match a sensitive substring but carry nothing secret.
// Without this list the redactor eats exactly the fields an operator needs while
// debugging a failing node handshake.
var safeKeys = map[string]struct{}{
	"public_key":       {},
	"publickey":        {},
	"key_prefix":       {},
	"keyprefix":        {},
	"token_hash":       {},
	"tokenhash":        {},
	"session_count":    {},
	"sessioncount":     {},
	"secret_version":   {},
	"secretversion":    {},
	"api_key_id":       {},
	"apikeyid":         {},
	"api_key_name":     {},
	"apikeyname":       {},
	"private_net":      {},
	"privatenet":       {},
	"totp_enabled":     {},
	"totpenabled":      {},
	"password_algo":    {},
	"passwordalgo":     {},
	"cookie_secure":    {},
	"cookiesecure":     {},
	"session_ttl":      {},
	"sessionttl":       {},
	"token_ttl":        {},
	"tokenttl":         {},
	"tokens_revoked":   {},
	"tokensrevoked":    {},
	"secret_key_bytes": {},
	"secretkeybytes":   {},
}

// Options configures the process logger.
type Options struct {
	// Level is one of debug, info, warn, error. An unknown value falls back to
	// info rather than failing: config validation already rejects bad values,
	// and a logger that refuses to exist makes every other error invisible.
	Level string
	// Format is json or text. Anything else means json.
	Format string
	// AddSource attaches file:line to every record. Useful in dev, noisy in prod.
	AddSource bool
}

// New builds a logger writing to w.
func New(w io.Writer, opts Options) *slog.Logger {
	handlerOpts := &slog.HandlerOptions{
		Level:       parseLevel(opts.Level),
		AddSource:   opts.AddSource,
		ReplaceAttr: redactAttr,
	}

	var handler slog.Handler
	if strings.EqualFold(opts.Format, "text") {
		handler = slog.NewTextHandler(w, handlerOpts)
	} else {
		handler = slog.NewJSONHandler(w, handlerOpts)
	}
	return slog.New(handler)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// redactAttr masks secret-bearing attributes anywhere in the record, including
// inside groups.
func redactAttr(_ []string, a slog.Attr) slog.Attr {
	// Resolve LogValuer first so a Secret renders as its own placeholder and is
	// not re-inspected as a struct.
	a.Value = a.Value.Resolve()

	if a.Value.Kind() == slog.KindGroup {
		return a
	}
	if IsSensitiveKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	return a
}

// IsSensitiveKey reports whether an attribute key should have its value masked.
func IsSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(normalized)

	if _, ok := safeKeys[normalized]; ok {
		return false
	}
	if _, ok := safeKeys[strings.ReplaceAll(normalized, "_", "")]; ok {
		return false
	}

	for _, needle := range sensitiveSubstrings {
		if strings.Contains(normalized, needle) {
			return true
		}
	}
	return false
}

// Secret wraps a value so it never reaches the log, whatever the attribute is
// called. Prefer this over trusting key-name redaction.
type Secret[T any] struct{ value T }

// Wrap hides v from logs while keeping it usable through [Secret.Reveal].
func Wrap[T any](v T) Secret[T] { return Secret[T]{value: v} }

// Reveal returns the wrapped value.
func (s Secret[T]) Reveal() T { return s.value }

// LogValue implements [slog.LogValuer].
func (s Secret[T]) LogValue() slog.Value { return slog.StringValue(Redacted) }

// String implements [fmt.Stringer] so an accidental %v or %s does not leak
// either.
func (s Secret[T]) String() string { return Redacted }

// RedactDSN masks the password in a database URL so the rest stays greppable.
// A DSN that cannot be parsed is reported as unparsable rather than echoed: an
// unparsable DSN is exactly the case where the password is in an odd position.
func RedactDSN(dsn string) string {
	if dsn == "" {
		return ""
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return "[UNPARSABLE DSN]"
	}
	// url.URL.Redacted replaces the userinfo password with a fixed placeholder
	// and leaves host, port, database and query parameters intact, which is the
	// part an operator actually needs to see.
	return u.Redacted()
}
