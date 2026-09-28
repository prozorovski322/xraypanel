package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/xraypanel/panel/internal/auth"
	"github.com/xraypanel/panel/internal/service"
)

// ErrorBody is the shape of every error response.
//
// Code is a stable machine-readable token; Message is for a human and is only
// filled in where the detail is safe to disclose. RequestID lets an operator find
// the matching log line, which is how a caller gets a real explanation for the
// cases where the response deliberately says little.
type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// Error codes returned to clients.
const (
	codeInvalidCredentials = "invalid_credentials"
	codeInvalidCode        = "invalid_code"
	codeInvalidToken       = "invalid_token"
	codeTooManyAttempts    = "too_many_attempts"
	codeForbidden          = "forbidden"
	codeUnauthorized       = "unauthorized"
	codeBadRequest         = "bad_request"
	codeConflict           = "conflict"
	codeUnprocessable      = "unprocessable"
	codeNotFound           = "not_found"
	codeInternal           = "internal_error"

	codeIdempotencyMismatch = "idempotency_mismatch"
	codeIdempotencyInFlight = "idempotency_in_flight"
)

// writeServiceError maps a service error onto a response.
//
// Unlike the authentication errors below, these messages are returned to the caller.
// A validation failure, a duplicate name or a port collision are all facts about the
// caller's own request, and withholding them would only make the API harder to use
// without protecting anything.
func writeServiceError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, service.ErrNotFound):
		writeError(w, r, http.StatusNotFound, codeNotFound, cleanServiceMessage(err))

	case errors.Is(err, service.ErrConflict):
		writeError(w, r, http.StatusConflict, codeConflict, cleanServiceMessage(err))

	case errors.Is(err, service.ErrInUse):
		writeError(w, r, http.StatusConflict, codeConflict, cleanServiceMessage(err))

	case errors.Is(err, service.ErrPortConflict):
		// 409 rather than 422: nothing about the request is malformed, the target is
		// simply occupied, and the message names the other inbound.
		writeError(w, r, http.StatusConflict, codeConflict, cleanServiceMessage(err))

	case errors.Is(err, service.ErrValidation):
		writeError(w, r, http.StatusUnprocessableEntity, codeUnprocessable, cleanServiceMessage(err))

	case errors.Is(err, service.ErrIdempotencyMismatch):
		// 422, because reusing a key with a different body is a client bug rather than a
		// conflict to be retried.
		writeError(w, r, http.StatusUnprocessableEntity, codeIdempotencyMismatch,
			"that Idempotency-Key was already used with a different request body")

	case errors.Is(err, service.ErrIdempotencyInFlight):
		// 409 with Retry-After: the answer exists shortly, it just does not yet.
		w.Header().Set("Retry-After", "1")
		writeError(w, r, http.StatusConflict, codeIdempotencyInFlight,
			"an identical request is still being processed")

	default:
		logger.ErrorContext(r.Context(), "unhandled service error",
			slog.String("path", r.URL.Path),
			slog.String("request_id", middleware.GetReqID(r.Context())),
			slog.Any("error", err))
		writeError(w, r, http.StatusInternalServerError, codeInternal, "")
	}
}

// cleanServiceMessage strips the internal sentinel prefix from a service error.
//
// The sentinels read "service: validation failed: ..." which is useful in a log and noise
// in an API response.
func cleanServiceMessage(err error) string {
	message := err.Error()
	for _, prefix := range []string{
		"service: validation failed: ",
		"service: not found: ",
		"service: conflict: ",
		"service: still in use: ",
		"service: port already used on that node: ",
	} {
		if strings.HasPrefix(message, prefix) {
			return strings.TrimPrefix(message, prefix)
		}
	}
	return message
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, ErrorBody{
		Code:      code,
		Message:   message,
		RequestID: middleware.GetReqID(r.Context()),
	})
}

// writeAuthError maps a service error onto a response.
//
// Several distinct failures collapse onto one response on purpose. A caller must
// not be able to tell a missing account from a wrong password, a disabled account
// from either, or a replayed TOTP code from an incorrect one: each of those
// distinctions is a free oracle. The real reason is logged with the request id.
func (h *authHandler) writeAuthError(w http.ResponseWriter, r *http.Request, err error) {
	logger := h.logger.With(
		slog.String("request_id", middleware.GetReqID(r.Context())),
		slog.String("path", r.URL.Path),
	)

	switch {
	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrAccountDisabled):
		logger.InfoContext(r.Context(), "login rejected", slog.Any("reason", err))
		writeError(w, r, http.StatusUnauthorized, codeInvalidCredentials, "")

	case errors.Is(err, auth.ErrTOTPInvalid), errors.Is(err, auth.ErrTOTPReplayed):
		// A replay is logged at warning level: it means someone is submitting a
		// code they observed rather than one they generated.
		level := slog.LevelInfo
		if errors.Is(err, auth.ErrTOTPReplayed) {
			level = slog.LevelWarn
		}
		logger.LogAttrs(r.Context(), level, "totp rejected", slog.Any("reason", err))
		writeError(w, r, http.StatusUnauthorized, codeInvalidCode, "")

	case errors.Is(err, auth.ErrSessionReplayed):
		logger.WarnContext(r.Context(), "refresh token replayed; all sessions revoked")
		writeError(w, r, http.StatusUnauthorized, codeInvalidToken,
			"session revoked, sign in again")

	case errors.Is(err, auth.ErrInvalidToken):
		logger.InfoContext(r.Context(), "token rejected", slog.Any("reason", err))
		writeError(w, r, http.StatusUnauthorized, codeInvalidToken, "")

	case errors.Is(err, auth.ErrThrottled):
		logger.WarnContext(r.Context(), "login throttled")
		w.Header().Set("Retry-After", strconv.Itoa(int(h.lockout/time.Second)))
		writeError(w, r, http.StatusTooManyRequests, codeTooManyAttempts,
			"too many attempts, try again later")

	case errors.Is(err, auth.ErrForbidden):
		writeError(w, r, http.StatusForbidden, codeForbidden, "")

	case errors.Is(err, auth.ErrTOTPRequired):
		writeError(w, r, http.StatusUnauthorized, codeInvalidCredentials, "")

	// These are safe to describe: they are about the caller's own request, not
	// about whether some other account exists.
	case errors.Is(err, auth.ErrWeakPassword):
		writeError(w, r, http.StatusUnprocessableEntity, codeUnprocessable, err.Error())

	case errors.Is(err, auth.ErrUsernameTaken):
		writeError(w, r, http.StatusConflict, codeConflict, "username already taken")

	case errors.Is(err, auth.ErrTOTPAlreadyEnabled):
		writeError(w, r, http.StatusConflict, codeConflict, "two-factor authentication is already enabled")

	case errors.Is(err, auth.ErrTOTPNotEnrolled):
		writeError(w, r, http.StatusConflict, codeConflict, "two-factor authentication is not set up")

	default:
		// An unexpected error is logged in full and reported as nothing.
		logger.ErrorContext(r.Context(), "unhandled authentication error", slog.Any("error", err))
		writeError(w, r, http.StatusInternalServerError, codeInternal, "")
	}
}
