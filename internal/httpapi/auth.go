package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xraypanel/panel/internal/auth"
)

// refreshCookieName is scoped to the auth path, so the refresh token is not
// attached to every other request the SPA makes. A cookie that travels with
// requests that never need it is a cookie with a larger attack surface than it has
// to have.
const (
	refreshCookieName = "xp_refresh"
	refreshCookiePath = "/api/v1/auth"
)

// maxAuthBodyBytes caps request bodies on the unauthenticated endpoints. Without it
// an anonymous caller can make the panel allocate as much as they like.
const maxAuthBodyBytes = 16 << 10

type authHandler struct {
	svc           *auth.Service
	logger        *slog.Logger
	secureCookies bool
	refreshTTL    time.Duration
	lockout       time.Duration
}

// --- request and response bodies ---

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type mfaRequest struct {
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type totpConfirmRequest struct {
	Code string `json:"code"`
}

type totpDisableRequest struct {
	Password string `json:"password"`
}

type createAPIKeyRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresAt *string  `json:"expires_at"`
}

// loginResponse is what a successful login returns.
//
// The refresh token is absent on purpose: it travels only in an httpOnly cookie, so
// JavaScript in the page can never read it. The access token is returned in the body
// for the SPA to hold in memory.
type loginResponse struct {
	MFARequired bool   `json:"mfa_required,omitempty"`
	MFAToken    string `json:"mfa_token,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	Username    string `json:"username,omitempty"`
	Role        string `json:"role,omitempty"`
}

type meResponse struct {
	Kind     string   `json:"kind"`
	Username string   `json:"username,omitempty"`
	Role     string   `json:"role,omitempty"`
	Name     string   `json:"name,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`

	// TOTPEnabled is set for administrators only; an API key has no second factor.
	TOTPEnabled *bool `json:"totp_enabled,omitempty"`
}

type totpEnrollResponse struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

type apiKeyResponse struct {
	ID         int64    `json:"id"`
	Name       string   `json:"name"`
	Prefix     string   `json:"prefix"`
	Scopes     []string `json:"scopes"`
	CreatedAt  string   `json:"created_at"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	LastUsedAt string   `json:"last_used_at,omitempty"`
	RevokedAt  string   `json:"revoked_at,omitempty"`

	// Key is the plaintext, present only in the response that creates it. It
	// cannot be retrieved later because only its hash is stored.
	Key string `json:"key,omitempty"`
}

// --- routes ---

func (h *authHandler) routes(r chi.Router, mw *authMiddleware) {
	r.Route("/auth", func(r chi.Router) {
		r.Post("/login", h.handleLogin)
		r.Post("/login/mfa", h.handleLoginMFA)
		r.Post("/refresh", h.handleRefresh)
		r.Post("/logout", h.handleLogout)

		r.Group(func(r chi.Router) {
			r.Use(mw.requireAuth)
			r.Get("/me", h.handleMe)
			r.Post("/logout-all", h.handleLogoutAll)
			r.Post("/password", h.handleChangePassword)
			r.Post("/totp/enroll", h.handleTOTPEnroll)
			r.Post("/totp/confirm", h.handleTOTPConfirm)
			r.Post("/totp/disable", h.handleTOTPDisable)
		})
	})

	r.Route("/api-keys", func(r chi.Router) {
		r.Use(mw.requireAuth)
		r.With(mw.requireScope(auth.ScopeAdminsRead)).Get("/", h.handleListAPIKeys)
		r.With(mw.requireScope(auth.ScopeAdminsWrite)).Post("/", h.handleCreateAPIKey)
		r.With(mw.requireScope(auth.ScopeAdminsWrite)).Delete("/{id}", h.handleRevokeAPIKey)
	})
}

// --- handlers ---

func (h *authHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, r, http.StatusBadRequest, codeBadRequest, "username and password are required")
		return
	}

	result, err := h.svc.Login(r.Context(), auth.LoginInput{
		Username:  req.Username,
		Password:  req.Password,
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		h.writeAuthError(w, r, err)
		return
	}

	h.writeLoginResult(w, r, result)
}

func (h *authHandler) handleLoginMFA(w http.ResponseWriter, r *http.Request) {
	var req mfaRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.MFAToken == "" || req.Code == "" {
		writeError(w, r, http.StatusBadRequest, codeBadRequest, "mfa_token and code are required")
		return
	}

	result, err := h.svc.CompleteMFA(r.Context(), auth.CompleteMFAInput{
		MFAToken:  req.MFAToken,
		Code:      strings.TrimSpace(req.Code),
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		h.writeAuthError(w, r, err)
		return
	}

	h.writeLoginResult(w, r, result)
}

func (h *authHandler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if !h.checkSameOrigin(w, r) {
		return
	}

	cookie, err := r.Cookie(refreshCookieName)
	if err != nil || cookie.Value == "" {
		writeError(w, r, http.StatusUnauthorized, codeInvalidToken, "")
		return
	}

	result, err := h.svc.Refresh(r.Context(), auth.RefreshInput{
		RefreshToken: cookie.Value,
		IP:           clientIP(r),
		UserAgent:    r.UserAgent(),
	})
	if err != nil {
		// The cookie is cleared on any failure. Leaving a token the server has
		// rejected in the browser only produces a loop of failing refreshes.
		h.clearRefreshCookie(w)
		h.writeAuthError(w, r, err)
		return
	}

	h.writeLoginResult(w, r, result)
}

func (h *authHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(refreshCookieName); err == nil && cookie.Value != "" {
		if err := h.svc.Logout(r.Context(), cookie.Value); err != nil {
			h.logger.WarnContext(r.Context(), "logout failed", slog.Any("error", err))
		}
	}
	// Always clears the cookie and always succeeds: the caller asked to be logged
	// out, and after this they are.
	h.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *authHandler) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	adminID, ok := principalFrom(r.Context()).Admin()
	if !ok {
		writeError(w, r, http.StatusForbidden, codeForbidden, "only an administrator can do this")
		return
	}

	if err := h.svc.LogoutEverywhere(r.Context(), adminID); err != nil {
		h.writeAuthError(w, r, err)
		return
	}
	h.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *authHandler) handleMe(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	if principal == nil {
		writeError(w, r, http.StatusUnauthorized, codeUnauthorized, "")
		return
	}

	resp := meResponse{}
	if principal.IsAdmin {
		resp.Kind = "admin"
		resp.Username = principal.Username
		resp.Role = principal.Role

		// Read fresh rather than carried in the token: the account screen offers to enable or
		// disable 2FA, and a stale answer would offer the wrong one.
		if adminID, ok := principal.Admin(); ok {
			enabled, err := h.svc.TOTPEnabled(r.Context(), adminID)
			if err != nil {
				h.logger.ErrorContext(r.Context(), "could not read the 2FA state", slog.Any("error", err))
				writeError(w, r, http.StatusInternalServerError, codeInternal, "")
				return
			}
			resp.TOTPEnabled = &enabled
		}
	} else {
		resp.Kind = "api_key"
		resp.Name = principal.APIKeyName
		resp.Scopes = principal.Scopes
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *authHandler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	adminID, ok := principalFrom(r.Context()).Admin()
	if !ok {
		writeError(w, r, http.StatusForbidden, codeForbidden, "only an administrator can do this")
		return
	}

	var req changePasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if err := h.svc.ChangePassword(r.Context(), adminID, req.CurrentPassword, req.NewPassword); err != nil {
		h.writeAuthError(w, r, err)
		return
	}

	// Every session was just revoked, including this one.
	h.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *authHandler) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	adminID, ok := principalFrom(r.Context()).Admin()
	if !ok {
		writeError(w, r, http.StatusForbidden, codeForbidden, "only an administrator can do this")
		return
	}

	enrollment, err := h.svc.BeginTOTPEnrollment(r.Context(), adminID)
	if err != nil {
		h.writeAuthError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, totpEnrollResponse{
		Secret: enrollment.Secret,
		URI:    enrollment.URI,
	})
}

func (h *authHandler) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	adminID, ok := principalFrom(r.Context()).Admin()
	if !ok {
		writeError(w, r, http.StatusForbidden, codeForbidden, "only an administrator can do this")
		return
	}

	var req totpConfirmRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if err := h.svc.ConfirmTOTPEnrollment(r.Context(), adminID, strings.TrimSpace(req.Code)); err != nil {
		h.writeAuthError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *authHandler) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	adminID, ok := principalFrom(r.Context()).Admin()
	if !ok {
		writeError(w, r, http.StatusForbidden, codeForbidden, "only an administrator can do this")
		return
	}

	var req totpDisableRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if err := h.svc.DisableTOTP(r.Context(), adminID, req.Password); err != nil {
		h.writeAuthError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *authHandler) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.svc.ListAPIKeys(r.Context())
	if err != nil {
		h.writeAuthError(w, r, err)
		return
	}

	out := make([]apiKeyResponse, 0, len(keys))
	for _, k := range keys {
		out = append(out, apiKeyResponse{
			ID:         k.ID,
			Name:       k.Name,
			Prefix:     k.KeyPrefix,
			Scopes:     k.Scopes,
			CreatedAt:  k.CreatedAt.UTC().Format(time.RFC3339),
			ExpiresAt:  formatOptionalTime(k.ExpiresAt),
			LastUsedAt: formatOptionalTime(k.LastUsedAt),
			RevokedAt:  formatOptionalTime(k.RevokedAt),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *authHandler) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req createAPIKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	in := auth.CreateAPIKeyInput{Name: req.Name, Scopes: req.Scopes}

	if adminID, ok := principalFrom(r.Context()).Admin(); ok {
		in.CreatedBy = &adminID
	}

	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, codeBadRequest,
				"expires_at must be an RFC3339 timestamp")
			return
		}
		in.ExpiresAt = &expires
	}

	generated, key, err := h.svc.CreateAPIKey(r.Context(), in)
	if err != nil {
		if errors.Is(err, auth.ErrWeakPassword) || strings.Contains(err.Error(), "unknown scope") {
			writeError(w, r, http.StatusUnprocessableEntity, codeUnprocessable, err.Error())
			return
		}
		h.writeAuthError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, apiKeyResponse{
		ID:        key.ID,
		Name:      key.Name,
		Prefix:    key.KeyPrefix,
		Scopes:    key.Scopes,
		CreatedAt: key.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt: formatOptionalTime(key.ExpiresAt),
		Key:       generated.Plaintext,
	})
}

func (h *authHandler) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, codeBadRequest, "id must be an integer")
		return
	}

	if err := h.svc.RevokeAPIKey(r.Context(), id); err != nil {
		h.writeAuthError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

func (h *authHandler) writeLoginResult(w http.ResponseWriter, r *http.Request, result *auth.LoginResult) {
	if result.MFARequired {
		// No refresh cookie yet: the password step alone must not produce a session.
		writeJSON(w, http.StatusOK, loginResponse{
			MFARequired: true,
			MFAToken:    result.MFAToken,
		})
		return
	}

	h.setRefreshCookie(w, result.Tokens.RefreshToken, result.Tokens.RefreshExpiresAt)
	writeJSON(w, http.StatusOK, loginResponse{
		AccessToken: result.Tokens.AccessToken,
		ExpiresAt:   result.Tokens.AccessExpiresAt.UTC().Format(time.RFC3339),
		Username:    result.Username,
		Role:        result.Role,
	})
}

func (h *authHandler) setRefreshCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:  refreshCookieName,
		Value: token,
		Path:  refreshCookiePath,
		// HttpOnly keeps the token out of reach of any script on the page, which is
		// the whole reason the access token is the one handed to JavaScript.
		HttpOnly: true,
		Secure:   h.secureCookies,
		// Strict rather than Lax: this cookie is only ever needed on a request the
		// SPA makes to its own origin, and Strict is what stops it riding along on a
		// cross-site request.
		SameSite: http.SameSiteStrictMode,
		Expires:  expires.UTC(),
		MaxAge:   int(time.Until(expires).Seconds()),
	})
}

func (h *authHandler) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     refreshCookiePath,
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// checkSameOrigin rejects a cross-site refresh.
//
// SameSite=Strict already keeps the cookie off cross-site requests in any current
// browser, so this is a second line rather than the only one. It only fires when an
// Origin header is present, because a same-origin request from an older client may
// not send one at all, and refusing those would break the SPA rather than protect it.
func (h *authHandler) checkSameOrigin(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	parsed, err := url.Parse(origin)
	if err != nil {
		writeError(w, r, http.StatusForbidden, codeForbidden, "invalid origin")
		return false
	}
	if !strings.EqualFold(parsed.Host, r.Host) {
		h.logger.WarnContext(r.Context(), "cross-origin refresh attempt rejected",
			slog.String("origin", origin), slog.String("host", r.Host))
		writeError(w, r, http.StatusForbidden, codeForbidden, "cross-origin request rejected")
		return false
	}
	return true
}

// decodeJSON reads a JSON body with a size limit and rejects unknown fields.
//
// Rejecting unknown fields turns a misspelled field into a visible error instead of
// a silently ignored one, which for a password-change request is the difference
// between a clear failure and a password that did not change.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	body := http.MaxBytesReader(w, r.Body, maxAuthBodyBytes)

	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		message := "request body must be valid JSON"
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			message = "request body is too large"
		}
		writeError(w, r, http.StatusBadRequest, codeBadRequest, message)
		return false
	}

	// A second value in the stream means the client sent something other than one
	// object, which is worth refusing rather than partially honouring.
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, codeBadRequest,
			"request body must contain exactly one JSON object")
		return false
	}

	return true
}

// clientIP extracts the caller's address. RemoteAddr has already been corrected by
// the realIP middleware, which only trusts configured proxies.
func clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func formatOptionalTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
