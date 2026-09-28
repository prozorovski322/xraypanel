//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xraypanel/panel/internal/auth"
)

func TestAPIKeyAuthenticatesAndCarriesScopes(t *testing.T) {
	e := newEnv(t)

	generated, key, err := e.svc.CreateAPIKey(context.Background(), auth.CreateAPIKeyInput{
		Name:   "ci",
		Scopes: []string{auth.ScopeUsersRead, auth.ScopeStatsRead},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if generated.Plaintext == "" {
		t.Fatal("no plaintext key was returned")
	}
	if key.KeyPrefix != generated.Prefix {
		t.Errorf("stored prefix %q does not match the key %q", key.KeyPrefix, generated.Prefix)
	}

	principal, err := e.svc.AuthenticateAPIKey(context.Background(), generated.Plaintext)
	if err != nil {
		t.Fatalf("AuthenticateAPIKey: %v", err)
	}
	if !principal.IsAPIKey || principal.IsAdmin {
		t.Error("an API key resolved to something other than an api-key principal")
	}
	if !principal.Can(auth.ScopeUsersRead) {
		t.Error("the key cannot use a scope it was granted")
	}
	if principal.Can(auth.ScopeUsersWrite) {
		t.Error("the key can use a scope it was not granted")
	}
}

// TestAPIKeyPlaintextIsNotRecoverable is the property that makes storing only a hash
// worth doing: a database dump must not hand over working credentials.
func TestAPIKeyPlaintextIsNotRecoverable(t *testing.T) {
	e := newEnv(t)

	generated, _, err := e.svc.CreateAPIKey(context.Background(), auth.CreateAPIKeyInput{
		Name:   "ci",
		Scopes: []string{auth.ScopeUsersRead},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	keys, err := e.svc.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("ListAPIKeys returned %d keys, want 1", len(keys))
	}

	// Render the whole row, not just the hash column: the point is that the
	// plaintext is nowhere in the table, including in a field someone might add later.
	var row string
	if err := e.pool.QueryRow(context.Background(),
		`SELECT api_keys::text FROM api_keys`).Scan(&row); err != nil {
		t.Fatalf("read stored row: %v", err)
	}
	if row == "" {
		t.Fatal("no row was stored")
	}
	if strings.Contains(row, generated.Plaintext) {
		t.Error("the plaintext key is recoverable from the database")
	}

	// The secret half must not be there either, in case only the prefix was hashed.
	secret := generated.Plaintext[len(generated.Plaintext)-32:]
	if strings.Contains(row, secret) {
		t.Error("the key secret is stored in clear")
	}
}

func TestAPIKeyRevocationTakesEffect(t *testing.T) {
	e := newEnv(t)

	generated, key, err := e.svc.CreateAPIKey(context.Background(), auth.CreateAPIKeyInput{
		Name:   "ci",
		Scopes: []string{auth.ScopeUsersRead},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if _, err := e.svc.AuthenticateAPIKey(context.Background(), generated.Plaintext); err != nil {
		t.Fatalf("AuthenticateAPIKey: %v", err)
	}

	if err := e.svc.RevokeAPIKey(context.Background(), key.ID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	if _, err := e.svc.AuthenticateAPIKey(context.Background(), generated.Plaintext); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("a revoked key still authenticates: err = %v", err)
	}

	// Revoking twice is not an error: the caller wanted it gone and it is.
	if err := e.svc.RevokeAPIKey(context.Background(), key.ID); err != nil {
		t.Errorf("revoking an already revoked key: %v", err)
	}
}

func TestAPIKeyExpiryTakesEffect(t *testing.T) {
	e := newEnv(t)

	expires := e.clock.Now().Add(time.Hour)
	generated, _, err := e.svc.CreateAPIKey(context.Background(), auth.CreateAPIKeyInput{
		Name:      "temporary",
		Scopes:    []string{auth.ScopeUsersRead},
		ExpiresAt: &expires,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if _, err := e.svc.AuthenticateAPIKey(context.Background(), generated.Plaintext); err != nil {
		t.Fatalf("AuthenticateAPIKey before expiry: %v", err)
	}

	e.clock.Advance(2 * time.Hour)
	if _, err := e.svc.AuthenticateAPIKey(context.Background(), generated.Plaintext); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("an expired key still authenticates: err = %v", err)
	}
}

func TestCreateAPIKeyRejectsBadInput(t *testing.T) {
	e := newEnv(t)

	if _, _, err := e.svc.CreateAPIKey(context.Background(), auth.CreateAPIKeyInput{
		Name:   "",
		Scopes: []string{auth.ScopeUsersRead},
	}); err == nil {
		t.Error("an unnamed key was accepted")
	}

	if _, _, err := e.svc.CreateAPIKey(context.Background(), auth.CreateAPIKeyInput{
		Name:   "typo",
		Scopes: []string{"users:delete"},
	}); err == nil {
		t.Error("an unknown scope was accepted")
	}

	past := e.clock.Now().Add(-time.Hour)
	if _, _, err := e.svc.CreateAPIKey(context.Background(), auth.CreateAPIKeyInput{
		Name:      "already expired",
		Scopes:    []string{auth.ScopeUsersRead},
		ExpiresAt: &past,
	}); err == nil {
		t.Error("a key expiring in the past was accepted")
	}
}

// TestScopelessKeyCanDoNothing pins the safe default for a half-finished creation
// request.
func TestScopelessKeyCanDoNothing(t *testing.T) {
	e := newEnv(t)

	generated, _, err := e.svc.CreateAPIKey(context.Background(), auth.CreateAPIKeyInput{
		Name: "no scopes",
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	principal, err := e.svc.AuthenticateAPIKey(context.Background(), generated.Plaintext)
	if err != nil {
		t.Fatalf("AuthenticateAPIKey: %v", err)
	}
	for _, scope := range auth.AllScopes {
		if principal.Can(scope) {
			t.Errorf("a key with no scopes was allowed %q", scope)
		}
	}
}

// TestAccessTokenIsNotAnAPIKey and its converse keep the two credential kinds from
// being interchangeable at the service boundary.
func TestCredentialKindsAreNotInterchangeable(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(testUsername, testPassword)

	session, err := e.login(testUsername, testPassword, "203.0.113.200")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	generated, _, err := e.svc.CreateAPIKey(context.Background(), auth.CreateAPIKeyInput{
		Name:   "ci",
		Scopes: []string{auth.ScopeUsersRead},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	if _, err := e.svc.AuthenticateAPIKey(context.Background(), session.Tokens.AccessToken); err == nil {
		t.Error("an access token was accepted as an API key")
	}
	if _, err := e.svc.Authenticate(context.Background(), generated.Plaintext); err == nil {
		t.Error("an API key was accepted as an access token")
	}
}
