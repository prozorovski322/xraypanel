//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xraypanel/panel/internal/auth"
	"github.com/xraypanel/panel/internal/httpapi"
)

// newServer builds the real router over the test environment's service.
func (e *env) newServer() http.Handler {
	return httpapi.NewRouter(httpapi.Deps{
		Logger:        slog.New(slog.NewJSONHandler(io.Discard, nil)),
		DB:            e.pool,
		Auth:          e.svc,
		Service:       e.res,
		Pool:          e.pool,
		Version:       "test",
		SecureCookies: false, // the test transport is plain HTTP
		RefreshTTL:    e.cfg.RefreshTTL,
		LoginLockout:  e.cfg.LoginLockout,
	})
}

type apiCall struct {
	method  string
	path    string
	body    any
	bearer  string
	cookies []*http.Cookie
	headers map[string]string
}

func (e *env) do(handler http.Handler, call apiCall) *httptest.ResponseRecorder {
	e.t.Helper()

	var reader io.Reader
	if call.body != nil {
		switch v := call.body.(type) {
		case string:
			reader = strings.NewReader(v)
		default:
			encoded, err := json.Marshal(v)
			if err != nil {
				e.t.Fatalf("marshal request body: %v", err)
			}
			reader = bytes.NewReader(encoded)
		}
	}

	req := httptest.NewRequest(call.method, call.path, reader)
	req.RemoteAddr = "203.0.113.5:44444"
	if call.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if call.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+call.bearer)
	}
	for _, c := range call.cookies {
		req.AddCookie(c)
	}
	for k, v := range call.headers {
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeInto(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("response is not valid JSON (%v): %s", err, rec.Body.String())
	}
}

func refreshCookieFrom(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "xp_refresh" {
			return c
		}
	}
	t.Fatalf("no refresh cookie in the response: %v", rec.Result().Cookies())
	return nil
}

// TestLoginOverHTTPKeepsRefreshTokenOutOfTheBody is the shape the SPA depends on:
// the access token is readable by JavaScript, the refresh token never is.
func TestLoginOverHTTPKeepsRefreshTokenOutOfTheBody(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(testUsername, testPassword)
	server := e.newServer()

	rec := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/auth/login",
		body: map[string]string{"username": testUsername, "password": testPassword},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		AccessToken string `json:"access_token"`
		Role        string `json:"role"`
	}
	decodeInto(t, rec, &body)
	if body.AccessToken == "" {
		t.Error("no access token in the body")
	}
	if body.Role != auth.RoleSuperadmin {
		t.Errorf("role = %q, want %q", body.Role, auth.RoleSuperadmin)
	}

	cookie := refreshCookieFrom(t, rec)
	if cookie.Value == "" {
		t.Error("the refresh cookie is empty")
	}
	if strings.Contains(rec.Body.String(), cookie.Value) {
		t.Error("the refresh token also appears in the response body, defeating HttpOnly")
	}
	if !cookie.HttpOnly {
		t.Error("the refresh cookie is not HttpOnly, so any script on the page can read it")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", cookie.SameSite)
	}
	if cookie.Path != "/api/v1/auth" {
		t.Errorf("cookie path = %q, want it scoped to the auth routes", cookie.Path)
	}
}

func TestAuthenticatedRouteRequiresBearer(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(testUsername, testPassword)
	server := e.newServer()

	rec := e.do(server, apiCall{method: http.MethodGet, path: "/api/v1/auth/me"})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("no WWW-Authenticate header on a 401")
	}

	for _, bearer := range []string{"garbage", "a.b.c"} {
		rec := e.do(server, apiCall{method: http.MethodGet, path: "/api/v1/auth/me", bearer: bearer})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("bearer %q: status = %d, want 401", bearer, rec.Code)
		}
	}
}

func TestLoginRefreshMeLogoutOverHTTP(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(testUsername, testPassword)
	server := e.newServer()

	login := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/auth/login",
		body: map[string]string{"username": testUsername, "password": testPassword},
	})
	var loginBody struct {
		AccessToken string `json:"access_token"`
	}
	decodeInto(t, login, &loginBody)
	cookie := refreshCookieFrom(t, login)

	me := e.do(server, apiCall{
		method: http.MethodGet, path: "/api/v1/auth/me", bearer: loginBody.AccessToken,
	})
	if me.Code != http.StatusOK {
		t.Fatalf("/me status = %d, want 200: %s", me.Code, me.Body.String())
	}
	var meBody struct {
		Kind     string `json:"kind"`
		Username string `json:"username"`
	}
	decodeInto(t, me, &meBody)
	if meBody.Kind != "admin" || meBody.Username != testUsername {
		t.Errorf("/me returned %+v", meBody)
	}

	e.clock.Advance(1e9) // one second, so the reissued token differs
	refresh := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/auth/refresh",
		cookies: []*http.Cookie{cookie},
	})
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, want 200: %s", refresh.Code, refresh.Body.String())
	}
	rotated := refreshCookieFrom(t, refresh)
	if rotated.Value == cookie.Value {
		t.Error("the refresh cookie was not rotated")
	}

	logout := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/auth/logout",
		cookies: []*http.Cookie{rotated},
	})
	if logout.Code != http.StatusNoContent {
		t.Errorf("logout status = %d, want 204", logout.Code)
	}
	// The cookie must be cleared, not merely ignored.
	if cleared := refreshCookieFrom(t, logout); cleared.MaxAge >= 0 {
		t.Errorf("logout did not expire the cookie: MaxAge = %d", cleared.MaxAge)
	}
}

// TestRefreshRejectsCrossOrigin covers the second line of CSRF defence behind
// SameSite=Strict.
func TestRefreshRejectsCrossOrigin(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(testUsername, testPassword)
	server := e.newServer()

	login := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/auth/login",
		body: map[string]string{"username": testUsername, "password": testPassword},
	})
	cookie := refreshCookieFrom(t, login)

	rec := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/auth/refresh",
		cookies: []*http.Cookie{cookie},
		headers: map[string]string{"Origin": "https://evil.example.com"},
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin refresh status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

// TestAPIKeyWithInsufficientScopeGets403 is the stated acceptance criterion for this
// milestone.
func TestAPIKeyWithInsufficientScopeGets403(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()

	readOnly, _, err := e.svc.CreateAPIKey(context.Background(), auth.CreateAPIKeyInput{
		Name:   "reader",
		Scopes: []string{auth.ScopeAdminsRead},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	// admins:read is enough to list.
	list := e.do(server, apiCall{
		method: http.MethodGet, path: "/api/v1/api-keys", bearer: readOnly.Plaintext,
	})
	if list.Code != http.StatusOK {
		t.Errorf("list with admins:read status = %d, want 200: %s", list.Code, list.Body.String())
	}

	// admins:write is not granted, so creating must be refused.
	create := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/api-keys", bearer: readOnly.Plaintext,
		body: map[string]any{"name": "escalation", "scopes": []string{auth.ScopeUsersWrite}},
	})
	if create.Code != http.StatusForbidden {
		t.Fatalf("create with admins:read status = %d, want 403: %s", create.Code, create.Body.String())
	}

	var errBody httpapi.ErrorBody
	decodeInto(t, create, &errBody)
	if errBody.Code != "forbidden" {
		t.Errorf("error code = %q, want forbidden", errBody.Code)
	}
	if !strings.Contains(errBody.Message, auth.ScopeAdminsWrite) {
		t.Errorf("the message does not name the missing scope: %q", errBody.Message)
	}
}

// TestViewerCannotWrite is the role-based half of the same check.
func TestViewerCannotWrite(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()

	if _, err := e.svc.CreateAdmin(context.Background(), auth.CreateAdminInput{
		Username: "watcher",
		Password: testPassword,
		Role:     auth.RoleViewer,
	}); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}

	login := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/auth/login",
		body: map[string]string{"username": "watcher", "password": testPassword},
	})
	var body struct {
		AccessToken string `json:"access_token"`
	}
	decodeInto(t, login, &body)

	rec := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/api-keys", bearer: body.AccessToken,
		body: map[string]any{"name": "nope", "scopes": []string{}},
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("viewer creating an api key: status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

func TestAPIKeyCreateReturnsPlaintextOnceOnly(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)
	_ = adminID
	server := e.newServer()

	login := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/auth/login",
		body: map[string]string{"username": testUsername, "password": testPassword},
	})
	var loginBody struct {
		AccessToken string `json:"access_token"`
	}
	decodeInto(t, login, &loginBody)

	create := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/api-keys", bearer: loginBody.AccessToken,
		body: map[string]any{"name": "ci", "scopes": []string{auth.ScopeUsersRead}},
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201: %s", create.Code, create.Body.String())
	}
	var created struct {
		ID  int64  `json:"id"`
		Key string `json:"key"`
	}
	decodeInto(t, create, &created)
	if created.Key == "" {
		t.Fatal("the creation response did not carry the plaintext key")
	}

	list := e.do(server, apiCall{
		method: http.MethodGet, path: "/api/v1/api-keys", bearer: loginBody.AccessToken,
	})
	if strings.Contains(list.Body.String(), created.Key) {
		t.Error("the listing exposes the plaintext key")
	}

	del := e.do(server, apiCall{
		method: http.MethodDelete, path: "/api/v1/api-keys/" + itoa(created.ID),
		bearer: loginBody.AccessToken,
	})
	if del.Code != http.StatusNoContent {
		t.Errorf("delete status = %d, want 204: %s", del.Code, del.Body.String())
	}
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	return string(digits)
}

// TestUnknownFieldIsRejected keeps a misspelled field from being silently ignored,
// which on a password change is the difference between a clear failure and a
// password that did not change.
func TestUnknownFieldIsRejected(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(testUsername, testPassword)
	server := e.newServer()

	rec := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/auth/login",
		body: `{"username":"root","password":"correct horse battery staple","remember":true}`,
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an unknown field: %s", rec.Code, rec.Body.String())
	}
}

func TestOversizedBodyIsRejected(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()

	huge := `{"username":"` + strings.Repeat("a", 32<<10) + `","password":"x"}`
	rec := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/auth/login", body: huge,
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an oversized body", rec.Code)
	}
}

// TestLoginResponsesDoNotDistinguishFailures keeps the response from acting as an
// account oracle.
func TestLoginResponsesDoNotDistinguishFailures(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(testUsername, testPassword)
	server := e.newServer()

	wrongPassword := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/auth/login",
		body: map[string]string{"username": testUsername, "password": "wrong"},
	})
	unknownUser := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/auth/login",
		body: map[string]string{"username": "ghost", "password": "wrong"},
	})

	if wrongPassword.Code != unknownUser.Code {
		t.Errorf("status differs: %d vs %d", wrongPassword.Code, unknownUser.Code)
	}

	var a, b httpapi.ErrorBody
	decodeInto(t, wrongPassword, &a)
	decodeInto(t, unknownUser, &b)
	if a.Code != b.Code {
		t.Errorf("error code differs: %q vs %q", a.Code, b.Code)
	}
	if a.Message != b.Message {
		t.Errorf("message differs: %q vs %q", a.Message, b.Message)
	}
}

func TestThrottledLoginReturns429WithRetryAfter(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(testUsername, testPassword)
	server := e.newServer()

	for i := 0; i < e.cfg.LoginMaxAttempts; i++ {
		e.do(server, apiCall{
			method: http.MethodPost, path: "/api/v1/auth/login",
			body: map[string]string{"username": testUsername, "password": "wrong"},
		})
	}

	rec := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/auth/login",
		body: map[string]string{"username": testUsername, "password": testPassword},
	})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After header on a 429")
	}
}
