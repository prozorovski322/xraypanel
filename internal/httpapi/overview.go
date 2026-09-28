package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xraypanel/panel/internal/auth"
	"github.com/xraypanel/panel/internal/service"
)

func (h *crudHandler) overviewRoutes(r chi.Router, mw *authMiddleware) {
	r.Route("/audit", func(r chi.Router) {
		r.Use(mw.requireAuth)
		r.With(mw.requireScope(auth.ScopeAuditRead)).Get("/", h.listAudit)
	})
	r.Route("/stats", func(r chi.Router) {
		r.Use(mw.requireAuth)
		r.With(mw.requireScope(auth.ScopeStatsRead)).Get("/summary", h.statsSummary)
	})
}

// --- audit ---

type auditEntryResponse struct {
	ID         int64           `json:"id"`
	At         string          `json:"at"`
	ActorType  string          `json:"actor_type"`
	ActorID    *int64          `json:"actor_id"`
	ActorLabel string          `json:"actor_label"`
	Action     string          `json:"action"`
	EntityType string          `json:"entity_type"`
	EntityID   *string         `json:"entity_id"`
	IP         string          `json:"ip,omitempty"`
	Diff       json.RawMessage `json:"diff,omitempty"`
}

type auditPageResponse struct {
	Items []auditEntryResponse `json:"items"`

	// NextBefore is what to pass as before for the next page, absent on the last one.
	NextBefore *int64 `json:"next_before,omitempty"`
}

func (h *crudHandler) listAudit(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	q := service.AuditQuery{
		EntityType: optionalString(query.Get("entity_type")),
		EntityID:   optionalString(query.Get("entity_id")),
		Action:     optionalString(query.Get("action")),
		ActorType:  optionalString(query.Get("actor_type")),
	}

	if raw := query.Get("before"); raw != "" {
		before, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || before <= 0 {
			writeError(w, r, http.StatusBadRequest, codeBadRequest, "before must be a positive entry id")
			return
		}
		q.BeforeID = &before
	}
	if raw := query.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit <= 0 {
			writeError(w, r, http.StatusBadRequest, codeBadRequest, "limit must be a positive integer")
			return
		}
		q.Limit = limit
	}

	entries, next, err := h.svc.SearchAudit(r.Context(), q)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}

	page := auditPageResponse{Items: make([]auditEntryResponse, 0, len(entries)), NextBefore: next}
	for _, entry := range entries {
		page.Items = append(page.Items, auditEntryResponse{
			ID:         entry.ID,
			At:         entry.At.Format(time.RFC3339),
			ActorType:  entry.ActorType,
			ActorID:    entry.ActorID,
			ActorLabel: entry.ActorLabel,
			Action:     entry.Action,
			EntityType: entry.EntityType,
			EntityID:   entry.EntityID,
			IP:         entry.IP,
			Diff:       entry.Diff,
		})
	}
	writeJSON(w, http.StatusOK, page)
}

// optionalString treats an empty query parameter as absent, which is what a form that
// submits an unselected filter sends.
func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// --- summary ---

type trafficTotalsResponse struct {
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
	Since    string `json:"since"`
}

type statsSummaryResponse struct {
	Users         map[string]int64      `json:"users"`
	Nodes         map[string]int64      `json:"nodes"`
	OnlineUsers   int64                 `json:"online_users"`
	OnlineWindowS int64                 `json:"online_window_seconds"`
	TrafficToday  trafficTotalsResponse `json:"traffic_today"`
	TrafficMonth  trafficTotalsResponse `json:"traffic_month"`
}

func (h *crudHandler) statsSummary(w http.ResponseWriter, r *http.Request) {
	overview, err := h.svc.Overview(r.Context())
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}

	writeJSON(w, http.StatusOK, statsSummaryResponse{
		Users:         overview.UsersByStatus,
		Nodes:         overview.NodesByStatus,
		OnlineUsers:   overview.OnlineUsers,
		OnlineWindowS: int64(overview.OnlineWindow / time.Second),
		TrafficToday: trafficTotalsResponse{
			Uplink:   overview.TrafficToday.Uplink,
			Downlink: overview.TrafficToday.Downlink,
			Since:    overview.TodaySince.Format(time.RFC3339),
		},
		TrafficMonth: trafficTotalsResponse{
			Uplink:   overview.TrafficThisMonth.Uplink,
			Downlink: overview.TrafficThisMonth.Downlink,
			Since:    overview.MonthSince.Format(time.RFC3339),
		},
	})
}
