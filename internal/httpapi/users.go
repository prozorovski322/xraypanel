package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/auth"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
	"github.com/xraypanel/panel/internal/postgres/listbuilder"
	"github.com/xraypanel/panel/internal/service"
	"github.com/xraypanel/panel/internal/sublink"
)

// maxCRUDBodyBytes caps admin request bodies. Larger than the auth limit because an
// inbound's extra settings and a node's config patch are legitimately chunky, and small
// enough that a malformed request cannot make the panel allocate without bound.
const maxCRUDBodyBytes = 256 << 10

// idempotencyHeader is the header a client sends to make a create or renew safe to retry.
const idempotencyHeader = "Idempotency-Key"

type crudHandler struct {
	svc    *service.Service
	logger *slog.Logger
	pool   listbuilder.Querier

	// nodes is the live connection registry, nil when this process runs no gRPC
	// server. Handlers report "not connected" rather than failing in that case.
	nodes NodeRegistry
}

// --- request bodies ---

type createUserRequest struct {
	Username      string  `json:"username"`
	TrafficLimit  int64   `json:"traffic_limit"`
	ResetStrategy string  `json:"reset_strategy"`
	ExpiresAt     *string `json:"expires_at"`
	Note          string  `json:"note"`
	TelegramID    *int64  `json:"telegram_id"`
	GroupIDs      []int64 `json:"group_ids"`
}

type updateUserRequest struct {
	Username      *string `json:"username"`
	Status        *string `json:"status"`
	TrafficLimit  *int64  `json:"traffic_limit"`
	ResetStrategy *string `json:"reset_strategy"`
	Note          *string `json:"note"`
	TelegramID    *int64  `json:"telegram_id"`

	// ExpiresAt distinguishes absent, a value, and an explicit null that clears the
	// expiry, which is how "never expires" is requested.
	ExpiresAt optional[string] `json:"expires_at"`
}

type renewUserRequest struct {
	ExtendBy     string `json:"extend_by"`
	ResetTraffic bool   `json:"reset_traffic"`
	TrafficLimit *int64 `json:"traffic_limit"`
}

type setGroupsRequest struct {
	GroupIDs []int64 `json:"group_ids"`
}

type bulkStatusRequest struct {
	UserIDs []int64 `json:"user_ids"`
	Status  string  `json:"status"`
}

// --- response bodies ---

type userResponse struct {
	ID              int64  `json:"id"`
	Username        string `json:"username"`
	Status          string `json:"status"`
	TrafficLimit    int64  `json:"traffic_limit"`
	TrafficUsed     int64  `json:"traffic_used"`
	TrafficLifetime int64  `json:"traffic_lifetime"`
	ResetStrategy   string `json:"reset_strategy"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	Note            string `json:"note"`
	TelegramID      *int64 `json:"telegram_id,omitempty"`
	OnlineAt        string `json:"online_at,omitempty"`
	CreatedAt       string `json:"created_at"`

	// SubscriptionURL is the only place a credential is returned, and only for a single
	// user read. It is absent from listings: an endpoint that returns every user's
	// subscription token turns one careless log line into a breach.
	SubscriptionToken string `json:"subscription_token,omitempty"`
}

type userListResponse struct {
	Items  []userListItem `json:"items"`
	Total  int64          `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
}

type userListItem struct {
	ID              int64  `json:"id"`
	Username        string `json:"username"`
	Status          string `json:"status"`
	TrafficLimit    int64  `json:"traffic_limit"`
	TrafficUsed     int64  `json:"traffic_used"`
	TrafficLifetime int64  `json:"traffic_lifetime"`
	ResetStrategy   string `json:"reset_strategy"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	Note            string `json:"note"`
	TelegramID      *int64 `json:"telegram_id,omitempty"`
	OnlineAt        string `json:"online_at,omitempty"`
	SubFetchedAt    string `json:"sub_fetched_at,omitempty"`
	CreatedAt       string `json:"created_at"`
	GroupCount      int64  `json:"group_count"`
}

// --- routes ---

func (h *crudHandler) routes(r chi.Router, mw *authMiddleware) {
	r.Route("/users", func(r chi.Router) {
		r.Use(mw.requireAuth)

		r.With(mw.requireScope(auth.ScopeUsersRead)).Get("/", h.listUsers)
		r.With(mw.requireScope(auth.ScopeUsersWrite)).Post("/", h.createUser)
		r.With(mw.requireScope(auth.ScopeUsersWrite)).Post("/bulk/status", h.bulkStatus)

		r.Route("/{id}", func(r chi.Router) {
			r.With(mw.requireScope(auth.ScopeUsersRead)).Get("/", h.getUser)
			r.With(mw.requireScope(auth.ScopeUsersRead)).Get("/subscription", h.getUserSubscription)
			r.With(mw.requireScope(auth.ScopeUsersRead)).Get("/traffic", h.userTraffic)
			r.With(mw.requireScope(auth.ScopeUsersWrite)).Patch("/", h.updateUser)
			r.With(mw.requireScope(auth.ScopeUsersWrite)).Delete("/", h.deleteUser)
			r.With(mw.requireScope(auth.ScopeUsersWrite)).Post("/renew", h.renewUser)
			r.With(mw.requireScope(auth.ScopeUsersWrite)).Post("/reset-traffic", h.resetTraffic)
			r.With(mw.requireScope(auth.ScopeUsersWrite)).Post("/rotate-credentials", h.rotateCredentials)
			r.With(mw.requireScope(auth.ScopeUsersWrite)).Put("/groups", h.setUserGroups)
		})
	})
}

// --- handlers ---

func (h *crudHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	filter := listbuilder.UserFilter{
		Search: query.Get("search"),
		Sort:   query.Get("sort"),
		Desc:   strings.EqualFold(query.Get("order"), "desc"),
	}

	if statuses := query["status"]; len(statuses) > 0 {
		filter.Statuses = statuses
	}
	if raw := query.Get("group_id"); raw != "" {
		groupID, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, codeBadRequest, "group_id must be an integer")
			return
		}
		filter.GroupID = &groupID
	}
	if raw := query.Get("expiring_before"); raw != "" {
		moment, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, codeBadRequest,
				"expiring_before must be an RFC3339 timestamp")
			return
		}
		filter.ExpiringBefore = &moment
	}
	if raw := query.Get("over_quota"); raw != "" {
		filter.OverQuota = raw == "1" || strings.EqualFold(raw, "true")
	}
	if raw := query.Get("has_telegram"); raw != "" {
		value := raw == "1" || strings.EqualFold(raw, "true")
		filter.HasTelegram = &value
	}

	var err error
	if filter.Limit, err = intQuery(query.Get("limit"), 0); err != nil {
		writeError(w, r, http.StatusBadRequest, codeBadRequest, "limit must be an integer")
		return
	}
	if filter.Offset, err = intQuery(query.Get("offset"), 0); err != nil {
		writeError(w, r, http.StatusBadRequest, codeBadRequest, "offset must be an integer")
		return
	}

	page, err := listbuilder.ListUsers(r.Context(), h.pool, filter)
	if err != nil {
		// An unknown sort column is the caller's mistake, and the message lists the ones
		// that work rather than making them guess.
		if strings.Contains(err.Error(), "cannot sort by") {
			writeError(w, r, http.StatusBadRequest, codeBadRequest,
				"sort must be one of "+strings.Join(listbuilder.SortColumns(), ", "))
			return
		}
		writeServiceError(w, r, h.logger, err)
		return
	}

	items := make([]userListItem, 0, len(page.Rows))
	for _, row := range page.Rows {
		items = append(items, userListItem{
			ID:              row.ID,
			Username:        row.Username,
			Status:          row.Status,
			TrafficLimit:    row.TrafficLimit,
			TrafficUsed:     row.TrafficUsed,
			TrafficLifetime: row.TrafficLifetime,
			ResetStrategy:   row.ResetStrategy,
			ExpiresAt:       formatOptionalTime(row.ExpiresAt),
			Note:            row.Note,
			TelegramID:      row.TelegramID,
			OnlineAt:        formatOptionalTime(row.OnlineAt),
			SubFetchedAt:    formatOptionalTime(row.SubFetchedAt),
			CreatedAt:       row.CreatedAt.UTC().Format(time.RFC3339),
			GroupCount:      row.GroupCount,
		})
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = listbuilder.DefaultLimit
	}
	writeJSON(w, http.StatusOK, userListResponse{
		Items: items, Total: page.Total, Limit: limit, Offset: filter.Offset,
	})
}

func (h *crudHandler) createUser(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req createUserRequest
	if !decodeBody(w, r, body, &req) {
		return
	}

	in := service.CreateUserInput{
		Username:      req.Username,
		TrafficLimit:  req.TrafficLimit,
		ResetStrategy: req.ResetStrategy,
		Note:          req.Note,
		TelegramID:    req.TelegramID,
		GroupIDs:      req.GroupIDs,
	}
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		moment, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, codeBadRequest,
				"expires_at must be an RFC3339 timestamp")
			return
		}
		in.ExpiresAt = &moment
	}

	actor := actorFrom(r)

	response, err := h.svc.Idempotent(r.Context(), r.Header.Get(idempotencyHeader),
		service.ScopeUserCreate, body,
		func(ctx context.Context) (service.StoredResponse, error) {
			user, err := h.svc.CreateUser(ctx, actor, in)
			if err != nil {
				return service.StoredResponse{}, err
			}
			encoded, err := json.Marshal(newUserResponse(user, true))
			if err != nil {
				return service.StoredResponse{}, err
			}
			return service.StoredResponse{StatusCode: http.StatusCreated, Body: encoded}, nil
		})
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}

	writeStored(w, response)
}

func (h *crudHandler) getUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	user, err := h.svc.GetUser(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, newUserResponse(user, true))
}

// getUserSubscription returns the resolved endpoints for a user, as the admin UI shows
// them. It is the same resolution the public subscription endpoint will use.
func (h *crudHandler) getUserSubscription(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	user, err := h.svc.GetUser(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}

	sub, err := h.svc.BuildSubscription(r.Context(), user)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}

	links, err := sublink.RenderPlainLinks(sub)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"subscription_token": user.ShortUuid,
		"links":              links,
		"user_info":          sub.UserInfo.UserInfoHeader(),
	})
}

func (h *crudHandler) updateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req updateUserRequest
	if !decodeBody(w, r, body, &req) {
		return
	}

	in := service.UpdateUserInput{
		Username:      req.Username,
		Status:        req.Status,
		TrafficLimit:  req.TrafficLimit,
		ResetStrategy: req.ResetStrategy,
		Note:          req.Note,
		TelegramID:    req.TelegramID,
	}

	if req.ExpiresAt.Present() {
		in.SetExpiry = true
		// A nil value is an explicit null, which clears the expiry.
		if value := req.ExpiresAt.Value(); value != nil && *value != "" {
			moment, err := time.Parse(time.RFC3339, *value)
			if err != nil {
				writeError(w, r, http.StatusBadRequest, codeBadRequest,
					"expires_at must be an RFC3339 timestamp or null")
				return
			}
			in.ExpiresAt = &moment
		}
	}

	user, err := h.svc.UpdateUser(r.Context(), actorFrom(r), id, in)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, newUserResponse(user, false))
}

func (h *crudHandler) renewUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req renewUserRequest
	if !decodeBody(w, r, body, &req) {
		return
	}

	actor := actorFrom(r)
	in := service.RenewUserInput{
		ExtendBy:     req.ExtendBy,
		ResetTraffic: req.ResetTraffic,
		TrafficLimit: req.TrafficLimit,
	}

	response, err := h.svc.Idempotent(r.Context(), r.Header.Get(idempotencyHeader),
		service.ScopeUserRenew, append(body, []byte(strconv.FormatInt(id, 10))...),
		func(ctx context.Context) (service.StoredResponse, error) {
			user, err := h.svc.RenewUser(ctx, actor, id, in)
			if err != nil {
				return service.StoredResponse{}, err
			}
			encoded, err := json.Marshal(newUserResponse(user, false))
			if err != nil {
				return service.StoredResponse{}, err
			}
			return service.StoredResponse{StatusCode: http.StatusOK, Body: encoded}, nil
		})
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeStored(w, response)
}

func (h *crudHandler) resetTraffic(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	user, err := h.svc.ResetUserTraffic(r.Context(), actorFrom(r), id)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, newUserResponse(user, false))
}

func (h *crudHandler) rotateCredentials(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	user, err := h.svc.RotateUserCredentials(r.Context(), actorFrom(r), id)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	// The new subscription token is included: the caller just asked for a new one and has
	// no other way to learn it.
	writeJSON(w, http.StatusOK, newUserResponse(user, true))
}

func (h *crudHandler) setUserGroups(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req setGroupsRequest
	if !decodeBody(w, r, body, &req) {
		return
	}

	if err := h.svc.SetUserGroups(r.Context(), actorFrom(r), id, req.GroupIDs); err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *crudHandler) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.svc.DeleteUser(r.Context(), actorFrom(r), id); err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *crudHandler) bulkStatus(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req bulkStatusRequest
	if !decodeBody(w, r, body, &req) {
		return
	}

	affected, err := h.svc.SetUsersStatus(r.Context(), actorFrom(r), req.UserIDs, req.Status)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"affected": affected})
}

// --- helpers ---

func newUserResponse(user *dbgen.User, includeToken bool) userResponse {
	response := userResponse{
		ID:              user.ID,
		Username:        user.Username,
		Status:          string(user.Status),
		TrafficLimit:    user.TrafficLimit,
		TrafficUsed:     user.TrafficUsed,
		TrafficLifetime: user.TrafficLifetime,
		ResetStrategy:   string(user.ResetStrategy),
		ExpiresAt:       formatOptionalTime(user.ExpiresAt),
		Note:            user.Note,
		TelegramID:      user.TelegramID,
		OnlineAt:        formatOptionalTime(user.OnlineAt),
		CreatedAt:       user.CreatedAt.UTC().Format(time.RFC3339),
	}
	if includeToken {
		response.SubscriptionToken = user.ShortUuid
	}
	return response
}

// readBody reads and size-limits the request body.
//
// The bytes are kept because idempotency hashes them: reading the body twice is not
// possible, and hashing a re-encoded struct would make the hash depend on field ordering.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	limited := http.MaxBytesReader(w, r.Body, maxCRUDBodyBytes)

	body, err := io.ReadAll(limited)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, r, http.StatusRequestEntityTooLarge, codeBadRequest, "request body is too large")
			return nil, false
		}
		writeError(w, r, http.StatusBadRequest, codeBadRequest, "could not read the request body")
		return nil, false
	}
	return body, true
}

// decodeBody unmarshals a body that readBody already captured, rejecting unknown fields.
func decodeBody(w http.ResponseWriter, r *http.Request, body []byte, dst any) bool {
	if len(body) == 0 {
		writeError(w, r, http.StatusBadRequest, codeBadRequest, "request body is required")
		return false
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		writeError(w, r, http.StatusBadRequest, codeBadRequest,
			"request body must be valid JSON with no unknown fields: "+err.Error())
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, r, http.StatusBadRequest, codeBadRequest, "id must be a positive integer")
		return 0, false
	}
	return id, true
}

func intQuery(raw string, fallback int) (int, error) {
	if raw == "" {
		return fallback, nil
	}
	return strconv.Atoi(raw)
}

// writeStored replays a stored idempotent response, or a fresh one.
func writeStored(w http.ResponseWriter, response service.StoredResponse) {
	status := response.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(response.Body)
}

// actorFrom builds the audit actor from the authenticated principal.
func actorFrom(r *http.Request) audit.Actor {
	principal := principalFrom(r.Context())
	ip := clientIP(r)

	actor := audit.Actor{Label: principal.Label()}
	if ip.IsValid() {
		actor.IP = &ip
	}

	switch {
	case principal == nil:
		actor.Type = audit.ActorSystem
	case principal.IsAdmin:
		actor.Type = audit.ActorAdmin
		id := principal.AdminID
		actor.ID = &id
	case principal.IsAPIKey:
		actor.Type = audit.ActorAPIKey
		id := principal.APIKeyID
		actor.ID = &id
	default:
		actor.Type = audit.ActorSystem
	}
	return actor
}
