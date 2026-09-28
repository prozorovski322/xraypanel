//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/xraypanel/panel/internal/auth"
	"github.com/xraypanel/panel/internal/httpapi"
	"github.com/xraypanel/panel/internal/service"
)

// adminToken creates a superadmin and returns a usable access token.
func (e *env) adminToken(handler http.Handler) string {
	e.t.Helper()

	e.createAdmin("root", testPassword)

	login := e.do(handler, apiCall{
		method: http.MethodPost, path: "/api/v1/auth/login",
		body: map[string]string{"username": "root", "password": testPassword},
	})
	if login.Code != http.StatusOK {
		e.t.Fatalf("login failed: %d %s", login.Code, login.Body.String())
	}

	var body struct {
		AccessToken string `json:"access_token"`
	}
	decodeInto(e.t, login, &body)
	return body.AccessToken
}

// TestCreateUserOverHTTPIsIdempotent exercises the header a retrying client actually sends.
func TestCreateUserOverHTTPIsIdempotent(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	token := e.adminToken(server)

	call := apiCall{
		method: http.MethodPost, path: "/api/v1/users", bearer: token,
		body:    map[string]any{"username": "alice", "traffic_limit": 1073741824},
		headers: map[string]string{"Idempotency-Key": "abc-123"},
	}

	first := e.do(server, call)
	if first.Code != http.StatusCreated {
		t.Fatalf("first: status = %d, want 201: %s", first.Code, first.Body.String())
	}

	second := e.do(server, call)
	if second.Code != http.StatusCreated {
		t.Fatalf("retry: status = %d, want 201: %s", second.Code, second.Body.String())
	}

	// Byte-identical, not merely equivalent: a client comparing bytes or verifying a
	// signature over the body must see one answer to one request.
	if first.Body.String() != second.Body.String() {
		t.Errorf("the retry returned a different body:\n first: %s\nsecond: %s",
			first.Body.String(), second.Body.String())
	}

	count, err := e.q.CountUsers(context.Background())
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if count != 1 {
		t.Errorf("got %d users, want 1", count)
	}
}

func TestIdempotencyKeyReuseOverHTTPIs422(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	token := e.adminToken(server)

	first := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/users", bearer: token,
		body:    map[string]any{"username": "alice"},
		headers: map[string]string{"Idempotency-Key": "same-key"},
	})
	if first.Code != http.StatusCreated {
		t.Fatalf("first: %d %s", first.Code, first.Body.String())
	}

	second := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/users", bearer: token,
		body:    map[string]any{"username": "bob"},
		headers: map[string]string{"Idempotency-Key": "same-key"},
	})
	if second.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %s", second.Code, second.Body.String())
	}

	var body httpapi.ErrorBody
	decodeInto(t, second, &body)
	if body.Code != "idempotency_mismatch" {
		t.Errorf("code = %q, want idempotency_mismatch", body.Code)
	}
}

// TestUserEndpointsEnforceScopes is the authorisation half: reading and writing users are
// different capabilities, and a read-only credential must not be able to create one.
func TestUserEndpointsEnforceScopes(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	ctx := context.Background()

	readOnly, _, err := e.svc.CreateAPIKey(ctx, auth.CreateAPIKeyInput{
		Name: "reader", Scopes: []string{auth.ScopeUsersRead},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	writer, _, err := e.svc.CreateAPIKey(ctx, auth.CreateAPIKeyInput{
		Name: "writer", Scopes: []string{auth.ScopeUsersWrite},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	cases := []struct {
		name string
		key  string
		call apiCall
		want int
	}{
		{
			name: "read-only key lists users",
			key:  readOnly.Plaintext,
			call: apiCall{method: http.MethodGet, path: "/api/v1/users"},
			want: http.StatusOK,
		},
		{
			name: "read-only key cannot create",
			key:  readOnly.Plaintext,
			call: apiCall{method: http.MethodPost, path: "/api/v1/users", body: map[string]any{"username": "x"}},
			want: http.StatusForbidden,
		},
		{
			name: "write key creates",
			key:  writer.Plaintext,
			call: apiCall{method: http.MethodPost, path: "/api/v1/users", body: map[string]any{"username": "created"}},
			want: http.StatusCreated,
		},
		{
			name: "write key also reads, because write implies read",
			key:  writer.Plaintext,
			call: apiCall{method: http.MethodGet, path: "/api/v1/users"},
			want: http.StatusOK,
		},
		{
			name: "users key cannot touch nodes",
			key:  writer.Plaintext,
			call: apiCall{method: http.MethodGet, path: "/api/v1/nodes"},
			want: http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			call := tc.call
			call.bearer = tc.key
			rec := e.do(server, call)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestViewerCannotWriteResources is the role-based half.
func TestViewerCannotWriteResources(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()

	if _, err := e.svc.CreateAdmin(context.Background(), auth.CreateAdminInput{
		Username: "watcher", Password: testPassword, Role: auth.RoleViewer,
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

	reads := []string{"/api/v1/users", "/api/v1/inbounds", "/api/v1/nodes", "/api/v1/groups"}
	for _, path := range reads {
		rec := e.do(server, apiCall{method: http.MethodGet, path: path, bearer: body.AccessToken})
		if rec.Code != http.StatusOK {
			t.Errorf("viewer GET %s: status = %d, want 200: %s", path, rec.Code, rec.Body.String())
		}
	}

	writes := []apiCall{
		{method: http.MethodPost, path: "/api/v1/users", body: map[string]any{"username": "x"}},
		{method: http.MethodPost, path: "/api/v1/nodes", body: map[string]any{"name": "n", "address": "a"}},
		{method: http.MethodPost, path: "/api/v1/groups", body: map[string]any{"name": "g"}},
	}
	for _, call := range writes {
		call.bearer = body.AccessToken
		rec := e.do(server, call)
		if rec.Code != http.StatusForbidden {
			t.Errorf("viewer %s %s: status = %d, want 403: %s",
				call.method, call.path, rec.Code, rec.Body.String())
		}
	}
}

func TestListUsersRejectsBadQueryParameters(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	token := e.adminToken(server)

	cases := map[string]string{
		"unknown sort column": "/api/v1/users?sort=password_hash",
		"non-numeric limit":   "/api/v1/users?limit=lots",
		"non-numeric offset":  "/api/v1/users?offset=x",
		"bad group id":        "/api/v1/users?group_id=abc",
		"bad timestamp":       "/api/v1/users?expiring_before=tomorrow",
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			rec := e.do(server, apiCall{method: http.MethodGet, path: path, bearer: token})
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestPortConflictIsA409WithAUsefulMessage is what an operator sees when they make the one
// mistake this validation exists for.
func TestPortConflictIsA409WithAUsefulMessage(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	token := e.adminToken(server)
	ctx := context.Background()

	node, err := e.res.CreateNode(ctx, testActor(), service.CreateNodeInput{
		Name: "de-1", Address: "de1.example.com", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	for _, tag := range []string{"first", "second"} {
		if _, err := e.res.CreateInbound(ctx, testActor(), service.CreateInboundInput{
			Tag: tag, Protocol: "vless", Transport: "tcp", Security: "none",
			ListenPort: 8443, Enabled: true,
		}); err != nil {
			t.Fatalf("CreateInbound %s: %v", tag, err)
		}
	}

	first, err := e.q.GetInboundByTag(ctx, "first")
	if err != nil {
		t.Fatalf("GetInboundByTag: %v", err)
	}
	second, err := e.q.GetInboundByTag(ctx, "second")
	if err != nil {
		t.Fatalf("GetInboundByTag: %v", err)
	}

	attach := func(inboundID int64) *httptest.ResponseRecorder {
		return e.do(server, apiCall{
			method: http.MethodPut, bearer: token,
			path: "/api/v1/nodes/" + strconv.FormatInt(node.ID, 10) +
				"/inbounds/" + strconv.FormatInt(inboundID, 10),
		})
	}

	if rec := attach(first.ID); rec.Code != http.StatusNoContent {
		t.Fatalf("first attach: %d %s", rec.Code, rec.Body.String())
	}

	rec := attach(second.ID)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
	}

	var body httpapi.ErrorBody
	decodeInto(t, rec, &body)
	if !strings.Contains(body.Message, "first") {
		t.Errorf("the message does not name the occupying inbound: %q", body.Message)
	}
	if !strings.Contains(body.Message, "8443") {
		t.Errorf("the message does not name the port: %q", body.Message)
	}
}

// TestNodeConfigNeedsWriteScope covers a read that is really a secret: the generated
// configuration carries every user's credentials and the Reality private key.
func TestNodeConfigNeedsWriteScope(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	ctx := context.Background()

	scenario := e.buildScenario(t)

	reader, _, err := e.svc.CreateAPIKey(ctx, auth.CreateAPIKeyInput{
		Name: "node reader", Scopes: []string{auth.ScopeNodesRead},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	writer, _, err := e.svc.CreateAPIKey(ctx, auth.CreateAPIKeyInput{
		Name: "node writer", Scopes: []string{auth.ScopeNodesWrite},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	path := "/api/v1/nodes/" + strconv.FormatInt(scenario.nodeID, 10) + "/config"

	if rec := e.do(server, apiCall{method: http.MethodGet, path: path, bearer: reader.Plaintext}); rec.Code != http.StatusForbidden {
		t.Errorf("nodes:read could read the generated config: status = %d", rec.Code)
	}

	rec := e.do(server, apiCall{method: http.MethodGet, path: path, bearer: writer.Plaintext})
	if rec.Code != http.StatusOK {
		t.Fatalf("nodes:write could not read the config: %d %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		StructuralHash string          `json:"structural_hash"`
		Config         json.RawMessage `json:"config"`
	}
	decodeInto(t, rec, &payload)
	if payload.StructuralHash == "" {
		t.Error("no structural hash in the response")
	}
	if !strings.Contains(string(payload.Config), "privateKey") {
		t.Error("the config carries no reality private key, so resolution did not decrypt it")
	}
}
