package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xraypanel/panel/internal/auth"
	"github.com/xraypanel/panel/internal/service"
)

// Webhook endpoints sit behind their own scopes: an endpoint receives a stream of events about
// every user, and the ability to point that stream somewhere is worth granting on purpose.
// An API key has it only if it was created with it; a viewer can list and not change.

type webhookRequest struct {
	URL     *string   `json:"url"`
	Events  *[]string `json:"events"`
	Secret  *string   `json:"secret"`
	Enabled *bool     `json:"enabled"`
}

type webhookResponse struct {
	ID        int64    `json:"id"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	Enabled   bool     `json:"enabled"`
	CreatedAt string   `json:"created_at"`

	// Secret appears exactly once: in the answer to a create that asked the panel to
	// generate it. It cannot be read back afterwards.
	Secret string `json:"secret,omitempty"`
}

func webhookResponseOf(endpoint *service.WebhookEndpoint) webhookResponse {
	return webhookResponse{
		ID:        endpoint.ID,
		URL:       endpoint.URL,
		Events:    endpoint.Events,
		Enabled:   endpoint.Enabled,
		CreatedAt: endpoint.CreatedAt.Format(time.RFC3339),
		Secret:    endpoint.Secret,
	}
}

func (h *crudHandler) webhookRoutes(r chi.Router, mw *authMiddleware) {
	r.Route("/webhooks", func(r chi.Router) {
		r.Use(mw.requireAuth)

		r.With(mw.requireScope(auth.ScopeWebhooksRead)).Get("/", h.listWebhooks)
		r.With(mw.requireScope(auth.ScopeWebhooksWrite)).Post("/", h.createWebhook)
		r.With(mw.requireScope(auth.ScopeWebhooksWrite)).Patch("/{id}", h.updateWebhook)
		r.With(mw.requireScope(auth.ScopeWebhooksWrite)).Delete("/{id}", h.deleteWebhook)
	})
}

func (h *crudHandler) listWebhooks(w http.ResponseWriter, r *http.Request) {
	endpoints, err := h.svc.ListWebhookEndpoints(r.Context())
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}

	out := make([]webhookResponse, 0, len(endpoints))
	for i := range endpoints {
		out = append(out, webhookResponseOf(&endpoints[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *crudHandler) createWebhook(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req webhookRequest
	if !decodeBody(w, r, body, &req) {
		return
	}

	in := service.CreateWebhookEndpointInput{Enabled: true}
	if req.URL != nil {
		in.URL = *req.URL
	}
	if req.Events != nil {
		in.Events = *req.Events
	}
	if req.Secret != nil {
		in.Secret = *req.Secret
	}
	if req.Enabled != nil {
		in.Enabled = *req.Enabled
	}

	endpoint, err := h.svc.CreateWebhookEndpoint(r.Context(), actorFrom(r), in)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusCreated, webhookResponseOf(endpoint))
}

func (h *crudHandler) updateWebhook(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req webhookRequest
	if !decodeBody(w, r, body, &req) {
		return
	}
	if req.Secret != nil {
		// Rotating a secret is deleting the endpoint and creating it again, which makes the
		// moment the old secret stops working explicit to whoever does it.
		writeError(w, r, http.StatusBadRequest, codeBadRequest,
			"the secret cannot be changed; delete the endpoint and create it again")
		return
	}

	endpoint, err := h.svc.UpdateWebhookEndpoint(r.Context(), actorFrom(r), id, service.UpdateWebhookEndpointInput{
		URL:     req.URL,
		Events:  req.Events,
		Enabled: req.Enabled,
	})
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, webhookResponseOf(endpoint))
}

func (h *crudHandler) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.svc.DeleteWebhookEndpoint(r.Context(), actorFrom(r), id); err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
