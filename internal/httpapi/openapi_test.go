package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	yaml "go.yaml.in/yaml/v3"

	"github.com/xraypanel/panel/internal/auth"
	"github.com/xraypanel/panel/internal/service"
)

// TestOpenAPIMatchesTheRouter is a drift guard.
//
// A hand-maintained specification rots: a route is added, the file is not touched, and the
// document quietly starts describing a different API than the one running. Since the spec
// is meant to be the contract other tools generate clients from, that is worse than having
// no spec at all.
//
// So the router is walked and compared against the file in both directions: an undocumented
// route fails, and so does a documented path that no longer exists.
func TestOpenAPIMatchesTheRouter(t *testing.T) {
	router := routerForSpecComparison(t)

	implemented := map[string]bool{}
	err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		implemented[method+" "+normalizeRoute(route)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk routes: %v", err)
	}

	documented := loadSpecOperations(t)

	// A comparison of two sets can pass because both are empty, or because normalisation
	// collapsed every route onto one string. Neither would catch anything, so the sizes are
	// asserted before the contents.
	const minimumRoutes = 30
	if len(implemented) < minimumRoutes {
		t.Fatalf("walked only %d routes, expected at least %d; route collection is broken, "+
			"so the comparison below proves nothing", len(implemented), minimumRoutes)
	}
	if len(documented) < minimumRoutes {
		t.Fatalf("parsed only %d operations from the spec, expected at least %d",
			len(documented), minimumRoutes)
	}

	var undocumented, missing []string

	for route := range implemented {
		if !documented[route] {
			undocumented = append(undocumented, route)
		}
	}
	for route := range documented {
		if !implemented[route] {
			missing = append(missing, route)
		}
	}

	sort.Strings(undocumented)
	sort.Strings(missing)

	if len(undocumented) > 0 {
		t.Errorf("routes with no entry in api/openapi.yaml:\n  %s", strings.Join(undocumented, "\n  "))
	}
	if len(missing) > 0 {
		t.Errorf("api/openapi.yaml documents routes that do not exist:\n  %s", strings.Join(missing, "\n  "))
	}
}

// routerForSpecComparison builds the full route tree.
//
// The services are zero values: only their being non-nil decides which routes are mounted,
// and no handler runs during a walk.
func routerForSpecComparison(t *testing.T) chi.Router {
	t.Helper()

	handler := NewRouter(Deps{
		Logger:  slog.New(slog.NewJSONHandler(io.Discard, nil)),
		DB:      &stubPinger{},
		Auth:    &auth.Service{},
		Service: &service.Service{},
		Version: "test",
	})

	router, ok := handler.(chi.Router)
	if !ok {
		t.Fatalf("NewRouter returned %T, which cannot be walked", handler)
	}
	return router
}

// normalizeRoute makes a chi route comparable to an OpenAPI path.
//
// chi reports a trailing slash for a subrouter mounted at its own root, and OpenAPI does
// not use one.
func normalizeRoute(route string) string {
	route = strings.ReplaceAll(route, "/*/", "/")
	route = strings.TrimSuffix(route, "/*")
	if route != "/" {
		route = strings.TrimSuffix(route, "/")
	}
	if route == "" {
		route = "/"
	}
	return route
}

// specDocument is the slice of OpenAPI this test needs.
type specDocument struct {
	Paths map[string]map[string]any `yaml:"paths"`
}

// loadSpecOperations reads the documented method and path pairs.
//
// Paths are rebased onto the server prefix, since the document declares `/api/v1` as the
// server and the probes override it with `/`.
func loadSpecOperations(t *testing.T) map[string]bool {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read api/openapi.yaml: %v", err)
	}

	var document specDocument
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("api/openapi.yaml is not valid YAML: %v", err)
	}
	if len(document.Paths) == 0 {
		t.Fatal("api/openapi.yaml declares no paths")
	}

	methods := map[string]string{
		"get": http.MethodGet, "post": http.MethodPost, "put": http.MethodPut,
		"patch": http.MethodPatch, "delete": http.MethodDelete,
		"head": http.MethodHead, "options": http.MethodOptions,
	}

	operations := map[string]bool{}
	for path, item := range document.Paths {
		for key, operation := range item {
			method, isMethod := methods[strings.ToLower(key)]
			if !isMethod {
				continue
			}

			full := path
			// The health probes declare their own server of "/" because they live outside
			// the versioned prefix.
			if !operationOverridesServer(operation) {
				full = "/api/v1" + path
			}
			operations[method+" "+normalizeRoute(full)] = true
		}
	}
	return operations
}

// operationOverridesServer reports whether an operation declares its own servers list.
func operationOverridesServer(operation any) bool {
	asMap, ok := operation.(map[string]any)
	if !ok {
		return false
	}
	_, has := asMap["servers"]
	return has
}

// TestOpenAPIErrorCodesMatchTheCode keeps the documented enum honest. A client switching on
// a code that the panel never sends, or missing one it does, is a client that mishandles a
// real failure.
func TestOpenAPIErrorCodesMatchTheCode(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read api/openapi.yaml: %v", err)
	}

	emitted := []string{
		codeInvalidCredentials, codeInvalidCode, codeInvalidToken, codeTooManyAttempts,
		codeForbidden, codeUnauthorized, codeBadRequest, codeConflict, codeUnprocessable,
		codeNotFound, codeInternal, codeIdempotencyMismatch, codeIdempotencyInFlight,
		codeRateLimited,
	}

	for _, code := range emitted {
		if !strings.Contains(string(raw), code) {
			t.Errorf("error code %q is emitted by the panel but absent from api/openapi.yaml", code)
		}
	}
}

// TestOpenAPIScopesMatchTheCode does the same for scopes, which are what an operator picks
// from when minting a key.
func TestOpenAPIScopesMatchTheCode(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read api/openapi.yaml: %v", err)
	}

	for _, scope := range auth.AllScopes {
		if !strings.Contains(string(raw), scope) {
			t.Errorf("scope %q exists in the code but is absent from api/openapi.yaml", scope)
		}
	}
}
