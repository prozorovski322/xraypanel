package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/xraypanel/panel/internal/auth"
)

// principalContextKey is unexported so nothing outside this package can inject a
// principal into a request context. Authentication has exactly one entry point.
type principalContextKey struct{}

type authMiddleware struct {
	svc    *auth.Service
	logger *slog.Logger
}

// requireAuth authenticates a request from either an access token or an API key.
//
// Both arrive in the Authorization header, and which one it is is decided by the
// value's own shape rather than by a separate header: a caller cannot choose to be
// validated as the other kind.
func (m *authMiddleware) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		credential, ok := bearerCredential(r)
		if !ok {
			// WWW-Authenticate is what tells a well-behaved client this was an
			// authentication problem and not an authorisation one.
			w.Header().Set("WWW-Authenticate", `Bearer realm="xraypanel"`)
			writeError(w, r, http.StatusUnauthorized, codeUnauthorized, "")
			return
		}

		principal, err := m.resolve(r.Context(), credential)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="xraypanel"`)
			writeError(w, r, http.StatusUnauthorized, codeInvalidToken, "")
			return
		}

		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireScope gates a route behind a capability.
//
// It runs after requireAuth and treats a missing principal as a denial rather than
// trusting that the middleware was wired up. A route that is accidentally mounted
// without requireAuth then returns 401 instead of running unauthenticated.
func (m *authMiddleware) requireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := principalFrom(r.Context())
			if principal == nil {
				writeError(w, r, http.StatusUnauthorized, codeUnauthorized, "")
				return
			}
			if !principal.Can(scope) {
				m.logger.InfoContext(r.Context(), "request denied for want of a scope",
					slog.String("actor", principal.Label()),
					slog.String("required_scope", scope),
					slog.String("path", r.URL.Path))
				writeError(w, r, http.StatusForbidden, codeForbidden,
					"this credential does not carry the "+scope+" scope")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// resolve picks the credential kind from its shape.
func (m *authMiddleware) resolve(ctx context.Context, credential string) (*auth.Principal, error) {
	// An API key is recognisable by its own marker, so the two kinds never compete
	// for the same parse.
	if _, _, err := auth.ParseAPIKey(credential); err == nil {
		return m.svc.AuthenticateAPIKey(ctx, credential)
	}
	return m.svc.Authenticate(ctx, credential)
}

// bearerCredential extracts the credential from the Authorization header.
func bearerCredential(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}

	scheme, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return "", false
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	return value, true
}

// principalFrom returns the authenticated caller, or nil.
//
// Handlers behind requireAuth can rely on it being non-nil, but they are written to
// tolerate nil anyway: a handler that panics when middleware is missing turns a
// wiring mistake into a crash instead of a 401.
func principalFrom(ctx context.Context) *auth.Principal {
	principal, _ := ctx.Value(principalContextKey{}).(*auth.Principal)
	return principal
}
