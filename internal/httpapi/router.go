// Package httpapi wires the panel's HTTP surface: the admin REST API, the public
// subscription endpoint, and the health probes.
package httpapi

import (
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/xraypanel/panel/internal/auth"
	"github.com/xraypanel/panel/internal/postgres/listbuilder"
	"github.com/xraypanel/panel/internal/ratelimit"
	"github.com/xraypanel/panel/internal/service"
)

// requestTimeout bounds any single request. Long-running work belongs in a
// background worker, not in a handler holding a connection open.
const requestTimeout = 30 * time.Second

// Deps are the collaborators the router needs. It grows one field per milestone;
// keeping it explicit means a handler cannot quietly reach for a global.
type Deps struct {
	Logger         *slog.Logger
	DB             Pinger
	Auth           *auth.Service
	Service        *service.Service
	Pool           listbuilder.Querier
	Version        string
	TrustedProxies []net.IPNet

	// Nodes is the live control-stream registry. It may be nil: the HTTP surface is
	// useful without a node server, and the handlers that read it say "not connected"
	// rather than refusing.
	Nodes NodeRegistry

	// SecureCookies sets the Secure attribute on the refresh cookie. Configuration
	// forces it on in production.
	SecureCookies bool
	RefreshTTL    time.Duration
	LoginLockout  time.Duration

	// SubscriptionLimiter bounds requests to the public subscription endpoint per client.
	// Nil turns the limit off, which only tests should want.
	SubscriptionLimiter *ratelimit.Limiter
}

// NewRouter builds the panel's HTTP handler.
func NewRouter(deps Deps) http.Handler {
	health := &healthHandler{
		db:      deps.DB,
		logger:  deps.Logger,
		version: deps.Version,
	}

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(realIP(deps.TrustedProxies))
	r.Use(requestLogger(deps.Logger))
	// Recoverer sits after the logger so a panic still produces a request record.
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(requestTimeout))
	r.Use(securityHeaders)

	r.Get(pathHealthz, health.handleHealthz)
	r.Get(pathReadyz, health.handleReadyz)

	// The public subscription needs no authentication, only the service that resolves it.
	if deps.Service != nil {
		subscriptions := &subscriptionHandler{
			svc:     deps.Service,
			logger:  deps.Logger,
			limiter: deps.SubscriptionLimiter,
		}
		subscriptions.routes(r)
	}

	// The auth service is absent in tests that only exercise the probes, so the
	// authenticated surface is mounted only when it is wired up. Mounting routes
	// backed by a nil service would turn a missing dependency into a panic on the
	// first request rather than an obvious gap at startup.
	if deps.Auth != nil {
		authHandlers := &authHandler{
			svc:           deps.Auth,
			logger:        deps.Logger,
			secureCookies: deps.SecureCookies,
			refreshTTL:    deps.RefreshTTL,
			lockout:       deps.LoginLockout,
		}
		mw := &authMiddleware{svc: deps.Auth, logger: deps.Logger}

		crud := &crudHandler{
			svc:    deps.Service,
			logger: deps.Logger,
			pool:   deps.Pool,
			nodes:  deps.Nodes,
		}

		r.Route("/api/v1", func(r chi.Router) {
			authHandlers.routes(r, mw)

			// The resource surface needs the service layer as well as authentication, so
			// it is mounted only when both are wired. A route backed by a nil service
			// would turn a missing dependency into a panic on the first request.
			if deps.Service != nil {
				crud.routes(r, mw)
				crud.resourceRoutes(r, mw)
				crud.webhookRoutes(r, mw)
				crud.overviewRoutes(r, mw)
			}
		})
	}

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusNotFound, codeNotFound, "")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusMethodNotAllowed, codeBadRequest, "method not allowed")
	})

	return r
}

// securityHeaders sets the headers that cost nothing and remove whole classes of
// mistake.
//
// The API serves JSON only, so a restrictive default is safe here in a way it would
// not be for a page that loads assets; the frontend is served separately with its
// own policy.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		// Stops a browser from second-guessing Content-Type and executing a JSON
		// response as script.
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		// Nothing here is meant to be embedded or to load anything.
		header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
