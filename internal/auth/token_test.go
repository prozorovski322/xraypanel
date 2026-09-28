package auth

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testSigner(t *testing.T) *TokenSigner {
	t.Helper()
	signer, err := NewTokenSigner(bytes.Repeat([]byte{0x2a}, 32), 15*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenSigner: %v", err)
	}
	return signer
}

// atTime pins the signer's clock so expiry can be tested without sleeping.
func atTime(s *TokenSigner, moment time.Time) *TokenSigner {
	clone := *s
	clone.now = func() time.Time { return moment }
	return &clone
}

func TestNewTokenSignerRejectsBadInput(t *testing.T) {
	if _, err := NewTokenSigner(bytes.Repeat([]byte{1}, 16), time.Minute); err == nil {
		t.Error("accepted a short master key")
	}
	if _, err := NewTokenSigner(bytes.Repeat([]byte{1}, 32), 0); err == nil {
		t.Error("accepted a zero access ttl")
	}
}

func TestAccessTokenRoundTrip(t *testing.T) {
	signer := testSigner(t)

	token, expires, err := signer.IssueAccessToken(42, RoleAdmin, time.Time{})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if !expires.After(time.Now()) {
		t.Errorf("expiry %s is not in the future", expires)
	}

	claims, err := signer.ParseAccessToken(token)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	if claims.Subject != "42" {
		t.Errorf("Subject = %q, want 42", claims.Subject)
	}
	if claims.Role != RoleAdmin {
		t.Errorf("Role = %q, want %q", claims.Role, RoleAdmin)
	}
	if claims.IssuedAt == nil {
		t.Error("IssuedAt is nil, so tokens_valid_from could never be enforced")
	}
}

// TestSeparateKeysPerPurpose is the property that makes a forgotten type check a
// signature failure rather than a privilege escalation.
func TestSeparateKeysPerPurpose(t *testing.T) {
	signer := testSigner(t)

	access, _, err := signer.IssueAccessToken(1, RoleAdmin, time.Time{})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	mfa, _, err := signer.IssueMFAToken(1)
	if err != nil {
		t.Fatalf("IssueMFAToken: %v", err)
	}

	if _, err := signer.ParseAccessToken(mfa); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("an MFA ticket was accepted as an access token: err = %v", err)
	}
	if _, err := signer.ParseMFAToken(access); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("an access token was accepted as an MFA ticket: err = %v", err)
	}
}

func TestAccessTokenRejectsWrongKey(t *testing.T) {
	issuer := testSigner(t)
	other, err := NewTokenSigner(bytes.Repeat([]byte{0x2b}, 32), 15*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenSigner: %v", err)
	}

	token, _, err := issuer.IssueAccessToken(1, RoleAdmin, time.Time{})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	if _, err := other.ParseAccessToken(token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a token signed with a different master key was accepted: err = %v", err)
	}
}

func TestAccessTokenExpires(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	signer := atTime(testSigner(t), base)

	token, _, err := signer.IssueAccessToken(1, RoleAdmin, time.Time{})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	// Still valid just before expiry, accounting for the validation leeway.
	fresh := atTime(signer, base.Add(14*time.Minute))
	if _, err := fresh.ParseAccessToken(token); err != nil {
		t.Errorf("token rejected before it expired: %v", err)
	}

	stale := atTime(signer, base.Add(16*time.Minute))
	if _, err := stale.ParseAccessToken(token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired token accepted: err = %v", err)
	}
}

func TestMFATokenExpiresSooner(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	signer := atTime(testSigner(t), base)

	token, expires, err := signer.IssueMFAToken(7)
	if err != nil {
		t.Fatalf("IssueMFAToken: %v", err)
	}
	if got := expires.Sub(base); got != mfaTokenTTL {
		t.Errorf("mfa ttl = %s, want %s", got, mfaTokenTTL)
	}

	later := atTime(signer, base.Add(mfaTokenTTL+time.Minute))
	if _, err := later.ParseMFAToken(token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired mfa ticket accepted: err = %v", err)
	}

	adminID, err := signer.ParseMFAToken(token)
	if err != nil {
		t.Fatalf("ParseMFAToken: %v", err)
	}
	if adminID != 7 {
		t.Errorf("admin id = %d, want 7", adminID)
	}
}

// TestRejectsUnsignedToken covers the classic alg confusion attack: a token that
// declares "none" and carries no signature must never be accepted.
func TestRejectsUnsignedToken(t *testing.T) {
	signer := testSigner(t)

	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "1",
			Issuer:    tokenIssuer,
			Audience:  jwt.ClaimStrings{purposeAccess},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Role: RoleSuperadmin,
	}

	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("could not build the unsigned token for the test: %v", err)
	}

	if _, err := signer.ParseAccessToken(unsigned); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("an alg=none token was accepted: err = %v", err)
	}
}

func TestRejectsTamperedToken(t *testing.T) {
	signer := testSigner(t)

	token, _, err := signer.IssueAccessToken(1, RoleViewer, time.Time{})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected three JWT segments, got %d", len(parts))
	}

	// Flip a character in the payload; the signature must no longer match.
	payload := []byte(parts[1])
	payload[0] ^= 0x01
	tampered := parts[0] + "." + string(payload) + "." + parts[2]

	if _, err := signer.ParseAccessToken(tampered); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a tampered token was accepted: err = %v", err)
	}
}

func TestRejectsGarbage(t *testing.T) {
	signer := testSigner(t)

	for _, raw := range []string{"", "not.a.token", "a.b", strings.Repeat("x", 500)} {
		if _, err := signer.ParseAccessToken(raw); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("ParseAccessToken(%q) err = %v, want ErrInvalidToken", raw, err)
		}
		if _, err := signer.ParseMFAToken(raw); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("ParseMFAToken(%q) err = %v, want ErrInvalidToken", raw, err)
		}
	}
}

// TestRejectsNonNumericSubject guards the boundary between a token claim and a
// database identifier.
func TestRejectsNonNumericSubject(t *testing.T) {
	signer := testSigner(t)

	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "root",
			Issuer:    tokenIssuer,
			Audience:  jwt.ClaimStrings{purposeAccess},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Role: RoleSuperadmin,
	}

	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(signer.accessKey)
	if err != nil {
		t.Fatalf("could not sign the test token: %v", err)
	}

	if _, err := signer.ParseAccessToken(forged); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a token whose subject is not an id was accepted: err = %v", err)
	}
}
