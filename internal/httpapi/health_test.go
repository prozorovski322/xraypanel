package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubPinger struct {
	err    error
	called int
}

func (s *stubPinger) Ping(context.Context) error {
	s.called++
	return s.err
}

func newTestRouter(t *testing.T, db Pinger) http.Handler {
	t.Helper()
	return NewRouter(Deps{
		Logger:  slog.New(slog.NewJSONHandler(io.Discard, nil)),
		DB:      db,
		Version: "test-version",
	})
}

func do(t *testing.T, handler http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func decodeHealth(t *testing.T, rec *httptest.ResponseRecorder) healthResponse {
	t.Helper()
	var body healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON (%v): %s", err, rec.Body.String())
	}
	return body
}

// TestHealthzIgnoresDatabase pins the liveness contract: depending on the database
// here would turn a database blip into a restart loop.
func TestHealthzIgnoresDatabase(t *testing.T) {
	db := &stubPinger{err: errors.New("database is down")}
	rec := do(t, newTestRouter(t, db), http.MethodGet, pathHealthz)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d even with the database down", rec.Code, http.StatusOK)
	}
	if db.called != 0 {
		t.Errorf("healthz pinged the database %d time(s), want 0", db.called)
	}
	if body := decodeHealth(t, rec); body.Status != "ok" {
		t.Errorf("status field = %q, want ok", body.Status)
	}
}

func TestReadyzOK(t *testing.T) {
	db := &stubPinger{}
	rec := do(t, newTestRouter(t, db), http.MethodGet, pathReadyz)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if db.called != 1 {
		t.Errorf("readyz pinged the database %d time(s), want 1", db.called)
	}
	body := decodeHealth(t, rec)
	if body.Status != "ok" {
		t.Errorf("status field = %q, want ok", body.Status)
	}
	if body.Version != "test-version" {
		t.Errorf("version = %q, want test-version", body.Version)
	}
}

// TestReadyzFailsWhenDatabaseIsDown is the M1 acceptance criterion: readiness must
// actually go red, not merely log.
func TestReadyzFailsWhenDatabaseIsDown(t *testing.T) {
	db := &stubPinger{err: errors.New("dial tcp 10.0.0.5:5432: connection refused")}
	rec := do(t, newTestRouter(t, db), http.MethodGet, pathReadyz)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	body := decodeHealth(t, rec)
	if body.Status == "ok" {
		t.Error("readiness reported ok while the database was unreachable")
	}

	// An unauthenticated probe must not describe internal topology.
	if strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Errorf("readiness response leaked the database address: %s", rec.Body.String())
	}
}

func TestProbesAreNotCached(t *testing.T) {
	for _, path := range []string{pathHealthz, pathReadyz} {
		t.Run(path, func(t *testing.T) {
			rec := do(t, newTestRouter(t, &stubPinger{}), http.MethodGet, path)
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
			if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
		})
	}
}

func TestUnknownRouteReturnsJSON(t *testing.T) {
	rec := do(t, newTestRouter(t, &stubPinger{}), http.MethodGet, "/no/such/path")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var body ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not an ErrorBody: %v", err)
	}
	if body.Code != codeNotFound {
		t.Errorf("code = %q, want %q", body.Code, codeNotFound)
	}
}

// TestSecurityHeaders pins the headers that remove whole classes of mistake for
// free; losing one silently is the kind of regression nothing else would catch.
func TestSecurityHeaders(t *testing.T) {
	rec := do(t, newTestRouter(t, &stubPinger{}), http.MethodGet, pathHealthz)

	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
}

// TestAuthRoutesAbsentWithoutService documents the wiring choice: a router built
// without an auth service must not expose routes backed by a nil dependency.
func TestAuthRoutesAbsentWithoutService(t *testing.T) {
	handler := newTestRouter(t, &stubPinger{})

	for _, path := range []string{"/api/v1/auth/me", "/api/v1/api-keys"} {
		rec := do(t, handler, http.MethodGet, path)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want %d when no auth service is wired", path, rec.Code, http.StatusNotFound)
		}
	}
}

func TestMethodNotAllowed(t *testing.T) {
	rec := do(t, newTestRouter(t, &stubPinger{}), http.MethodPost, pathHealthz)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
