package httpapi

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// realIP replaces r.RemoteAddr with the client address taken from
// X-Forwarded-For, but only when the immediate peer is one of the trusted
// networks.
//
// chi's own RealIP middleware trusts the header unconditionally. That is the
// wrong default here: this address feeds login throttling and the audit trail, so
// letting any client set it would let an attacker spread brute-force attempts
// across an unlimited number of fabricated addresses and forge audit entries.
func realIP(trusted []net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(trusted) > 0 {
				if ip := forwardedFor(r, trusted); ip != "" {
					r.RemoteAddr = net.JoinHostPort(ip, "0")
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func forwardedFor(r *http.Request, trusted []net.IPNet) string {
	peer := peerIP(r.RemoteAddr)
	if peer == nil || !containsIP(trusted, peer) {
		return ""
	}

	header := r.Header.Get("X-Forwarded-For")
	if header == "" {
		return ""
	}

	// Walk right to left, skipping addresses contributed by our own proxies. The
	// first untrusted hop is the closest thing to a real client we can prove.
	parts := strings.Split(header, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := net.ParseIP(strings.TrimSpace(parts[i]))
		if candidate == nil {
			return ""
		}
		if !containsIP(trusted, candidate) {
			return candidate.String()
		}
	}
	return ""
}

func peerIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(host)
}

func containsIP(networks []net.IPNet, ip net.IP) bool {
	for i := range networks {
		if networks[i].Contains(ip) {
			return true
		}
	}
	return false
}

// requestLogger logs one record per request.
func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Health probes would otherwise dominate the log at one record every
			// few seconds and bury everything worth reading.
			if isProbe(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			attrs := []slog.Attr{
				slog.String("method", r.Method),
				// Path only, and with the subscription token cut out: the token is a
				// bearer credential, and a log is read by more people than it should be.
				slog.String("path", redactPath(r.URL.Path)),
				slog.Int("status", ww.Status()),
				slog.Int("bytes", ww.BytesWritten()),
				slog.Duration("duration", time.Since(start)),
				slog.String("remote_addr", r.RemoteAddr),
				slog.String("request_id", middleware.GetReqID(r.Context())),
			}

			level := slog.LevelInfo
			switch {
			case ww.Status() >= http.StatusInternalServerError:
				level = slog.LevelError
			case ww.Status() >= http.StatusBadRequest:
				level = slog.LevelWarn
			}

			logger.LogAttrs(r.Context(), level, "http request", attrs...)
		})
	}
}

// redactPath replaces the token in a /sub/{token} path.
func redactPath(path string) string {
	rest, found := strings.CutPrefix(path, pathSubscription)
	if !found {
		return path
	}
	if _, tail, hasTail := strings.Cut(rest, "/"); hasTail {
		return pathSubscription + "[token]/" + tail
	}
	return pathSubscription + "[token]"
}

func isProbe(path string) bool {
	return path == pathHealthz || path == pathReadyz
}
