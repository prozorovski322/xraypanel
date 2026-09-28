package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// Probe paths. They are excluded from the request log.
const (
	pathHealthz = "/healthz"
	pathReadyz  = "/readyz"
)

// readinessTimeout caps how long a readiness check may block. A probe that hangs
// is worse than one that fails: an orchestrator waiting on it cannot act.
const readinessTimeout = 3 * time.Second

// Pinger is the part of a database pool that readiness needs.
type Pinger interface {
	Ping(ctx context.Context) error
}

type healthHandler struct {
	db      Pinger
	logger  *slog.Logger
	version string
}

// healthResponse is the body of both probes.
type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
}

// handleHealthz answers liveness: the process is running and can serve HTTP.
//
// It deliberately does not touch the database. Liveness that depends on a
// dependency turns a database blip into a restart loop, which makes the outage
// longer rather than shorter.
func (h *healthHandler) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok", Version: h.version})
}

// handleReadyz answers readiness: the panel can actually do its job, which means
// the database is reachable.
func (h *healthHandler) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
	defer cancel()

	if err := h.db.Ping(ctx); err != nil {
		h.logger.WarnContext(ctx, "readiness check failed", slog.Any("error", err))
		// The reason is logged, not returned: an unauthenticated endpoint should
		// not describe internal topology.
		writeJSON(w, http.StatusServiceUnavailable, healthResponse{
			Status: "unavailable",
			Error:  "database unreachable",
		})
		return
	}

	writeJSON(w, http.StatusOK, healthResponse{Status: "ok", Version: h.version})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// The response is a small fixed struct, so an encoding error can only mean the
	// connection is already gone; there is nothing useful left to report.
	_ = json.NewEncoder(w).Encode(body)
}
