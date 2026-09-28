package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// LookupFunc resolves an environment variable. It mirrors os.LookupEnv so tests
// can supply a map instead of mutating the real process environment.
type LookupFunc func(key string) (string, bool)

// loader reads typed values out of the environment and accumulates every problem
// it finds. Accumulating rather than failing on the first error means an operator
// fixes a broken .env in one pass instead of one restart per typo.
type loader struct {
	lookup LookupFunc
	errs   []error
}

func newLoader(lookup LookupFunc) *loader {
	return &loader{lookup: lookup}
}

// raw returns the trimmed value and whether it was present and non-empty. An
// empty string counts as absent: "FOO=" in a .env file means "unset", not "set
// to the empty string", which is what an operator almost always intends.
func (l *loader) raw(key string) (string, bool) {
	v, ok := l.lookup(key)
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	return v, true
}

func (l *loader) errf(key, format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf("%s: %s", key, fmt.Sprintf(format, args...)))
}

func (l *loader) str(key, def string) string {
	if v, ok := l.raw(key); ok {
		return v
	}
	return def
}

func (l *loader) required(key string) string {
	v, ok := l.raw(key)
	if !ok {
		l.errf(key, "is required")
		return ""
	}
	return v
}

func (l *loader) enum(key, def string, allowed ...string) string {
	v := l.str(key, def)
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	l.errf(key, "must be one of %s, got %q", strings.Join(allowed, "|"), v)
	return def
}

func (l *loader) intVal(key string, def, minVal, maxVal int) int {
	v, ok := l.raw(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		l.errf(key, "must be an integer, got %q", v)
		return def
	}
	if n < minVal || n > maxVal {
		l.errf(key, "must be between %d and %d, got %d", minVal, maxVal, n)
		return def
	}
	return n
}

func (l *loader) boolVal(key string, def bool) bool {
	v, ok := l.raw(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		l.errf(key, "must be a boolean (true|false|1|0), got %q", v)
		return def
	}
	return b
}

func (l *loader) duration(key string, def, minVal, maxVal time.Duration) time.Duration {
	v, ok := l.raw(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		l.errf(key, "must be a duration such as 30s, 15m or 24h, got %q", v)
		return def
	}
	if d < minVal || d > maxVal {
		l.errf(key, "must be between %s and %s, got %s", minVal, maxVal, d)
		return def
	}
	return d
}

// listenAddr validates a "host:port" or ":port" listen address.
func (l *loader) listenAddr(key, def string) string {
	v := l.str(key, def)
	_, port, err := net.SplitHostPort(v)
	if err != nil {
		l.errf(key, "must be a listen address such as :8080 or 127.0.0.1:8080, got %q", v)
		return def
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		l.errf(key, "port must be between 1 and 65535, got %q", port)
		return def
	}
	return v
}

// key32 decodes a 32-byte secret from hex or from any base64 variant. A shorter
// value is rejected outright rather than stretched or padded: silently accepting
// a weak key here would weaken every secret stored in the database.
func (l *loader) key32(key string) []byte {
	v, ok := l.raw(key)
	if !ok {
		l.errf(key, "is required (32 bytes as 64 hex chars, or base64)")
		return nil
	}
	decoders := []func(string) ([]byte, error){
		hex.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}
	for _, decode := range decoders {
		if b, err := decode(v); err == nil && len(b) == 32 {
			return b
		}
	}
	l.errf(key, "must decode to exactly 32 bytes from hex or base64")
	return nil
}

func (l *loader) location(key, def string) *time.Location {
	v := l.str(key, def)
	loc, err := time.LoadLocation(v)
	if err != nil {
		l.errf(key, "must be an IANA timezone such as UTC or Europe/Moscow, got %q", v)
		return time.UTC
	}
	return loc
}

// dnsNameList parses a comma-separated list of DNS names for a certificate.
//
// Validated rather than passed through, because an invalid name in a certificate
// request fails at issuance — that is, at startup, with a message about x509 rather
// than about the variable that caused it.
func (l *loader) dnsNameList(key, def string) []string {
	v := l.str(key, def)
	if v == "" {
		return nil
	}

	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !isDNSName(part) {
			l.errf(key, "%q is not a valid DNS name", part)
			continue
		}
		out = append(out, part)
	}
	return out
}

// isDNSName accepts the conservative subset of RFC 1123 that certificates use: labels
// of letters, digits and hyphens, no leading or trailing hyphen, no empty label.
func isDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
	}
	return true
}

// cidrList parses a comma-separated list of CIDR blocks.
func (l *loader) cidrList(key, def string) []net.IPNet {
	v := l.str(key, def)
	if v == "" {
		return nil
	}
	var out []net.IPNet
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, network, err := net.ParseCIDR(part)
		if err != nil {
			l.errf(key, "%q is not a valid CIDR block", part)
			continue
		}
		out = append(out, *network)
	}
	return out
}
