package auth

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/xraypanel/panel/internal/crypto"
)

const (
	tokenIssuer = "xraypanel"

	// Token purposes, used both as the HKDF label and as the audience claim.
	//
	// They get separate signing keys rather than a shared key plus a type claim.
	// With one key, forgetting to check the type once turns a half-authenticated
	// MFA ticket into a full access token. With two, that mistake produces a
	// signature failure instead of a privilege escalation.
	purposeAccess = "jwt.access"
	purposeMFA    = "jwt.mfa"

	// mfaTokenTTL bounds the gap between passing the password step and passing the
	// second factor. Long enough for someone to open their authenticator, short
	// enough that a stolen ticket is worthless.
	mfaTokenTTL = 5 * time.Minute

	// clockLeeway tolerates small clock differences between the panel and a client
	// checking expiry. It applies to validation only, never to issuing.
	clockLeeway = 30 * time.Second
)

// TokenSigner issues and verifies the panel's own tokens.
type TokenSigner struct {
	accessKey []byte
	mfaKey    []byte
	accessTTL time.Duration
	now       func() time.Time
}

// AccessClaims is the payload of an access token.
type AccessClaims struct {
	jwt.RegisteredClaims
	Role string `json:"role"`
}

// MFAClaims is the payload of the ticket issued between the password step and the
// TOTP step.
type MFAClaims struct {
	jwt.RegisteredClaims
}

// NewTokenSigner derives the signing keys from the panel master key.
//
// Deriving rather than configuring separately means an operator manages one
// secret, and the access and MFA keys remain independent of the key that encrypts
// database columns.
func NewTokenSigner(masterKey []byte, accessTTL time.Duration) (*TokenSigner, error) {
	accessKey, err := crypto.DeriveKey(masterKey, purposeAccess, 32)
	if err != nil {
		return nil, fmt.Errorf("auth: derive access key: %w", err)
	}
	mfaKey, err := crypto.DeriveKey(masterKey, purposeMFA, 32)
	if err != nil {
		return nil, fmt.Errorf("auth: derive mfa key: %w", err)
	}
	if accessTTL <= 0 {
		return nil, errors.New("auth: access token ttl must be positive")
	}

	return &TokenSigner{
		accessKey: accessKey,
		mfaKey:    mfaKey,
		accessTTL: accessTTL,
		now:       time.Now,
	}, nil
}

// IssueAccessToken signs an access token for an administrator.
//
// The issued-at claim is load bearing: it is compared against the administrator's
// tokens_valid_from on every request, which is what lets a password change or a
// "sign out everywhere" take effect before the token would otherwise expire.
//
// notBefore is that administrator's current tokens_valid_from, and iat is never
// stamped earlier than it. Without that floor a login immediately after an
// invalidation would hand back a token that fails on first use: the mark is rounded
// up to the next whole second while iat is truncated down, so the fresh token would
// look older than the invalidation it came after. Raising iat to the mark keeps
// previously issued tokens rejected while making the new one usable at once.
func (s *TokenSigner) IssueAccessToken(adminID int64, role string, notBefore time.Time) (string, time.Time, error) {
	issuedAt := s.now().UTC().Truncate(time.Second)
	if issuedAt.Before(notBefore) {
		issuedAt = notBefore.UTC()
	}
	expiresAt := issuedAt.Add(s.accessTTL)

	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(adminID, 10),
			Issuer:    tokenIssuer,
			Audience:  jwt.ClaimStrings{purposeAccess},
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		Role: role,
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.accessKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: sign access token: %w", err)
	}
	return signed, expiresAt, nil
}

// ParseAccessToken verifies an access token and returns its claims.
//
// It performs only the checks that need no database: signature, algorithm, issuer,
// audience and expiry. Whether the administrator still exists, is still active,
// and has not invalidated their tokens is checked by the service, because a token
// that is cryptographically perfect can still belong to a disabled account.
func (s *TokenSigner) ParseAccessToken(raw string) (*AccessClaims, error) {
	claims := &AccessClaims{}
	if err := s.parse(raw, claims, s.accessKey, purposeAccess); err != nil {
		return nil, err
	}
	if claims.IssuedAt == nil {
		return nil, fmt.Errorf("%w: missing iat", ErrInvalidToken)
	}
	if _, err := strconv.ParseInt(claims.Subject, 10, 64); err != nil {
		return nil, fmt.Errorf("%w: subject is not an admin id", ErrInvalidToken)
	}
	return claims, nil
}

// IssueMFAToken signs the ticket handed out after a correct password when a second
// factor is still outstanding.
func (s *TokenSigner) IssueMFAToken(adminID int64) (string, time.Time, error) {
	issuedAt := s.now().UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(mfaTokenTTL)

	claims := MFAClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(adminID, 10),
			Issuer:    tokenIssuer,
			Audience:  jwt.ClaimStrings{purposeMFA},
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.mfaKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: sign mfa token: %w", err)
	}
	return signed, expiresAt, nil
}

// ParseMFAToken verifies an MFA ticket and returns the administrator it belongs to.
func (s *TokenSigner) ParseMFAToken(raw string) (int64, error) {
	claims := &MFAClaims{}
	if err := s.parse(raw, claims, s.mfaKey, purposeMFA); err != nil {
		return 0, err
	}
	adminID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: subject is not an admin id", ErrInvalidToken)
	}
	return adminID, nil
}

// AccessTTL reports the configured access token lifetime.
func (s *TokenSigner) AccessTTL() time.Duration { return s.accessTTL }

// SetClock overrides the signer's clock. It exists so a test can issue and validate
// tokens at a controlled instant; production never calls it.
func (s *TokenSigner) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func (s *TokenSigner) parse(raw string, claims jwt.Claims, key []byte, audience string) error {
	_, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) {
		return key, nil
	},
		// Pinning the algorithm is what closes the "alg": "none" and
		// RSA-public-key-as-HMAC-secret confusion attacks.
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(tokenIssuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(clockLeeway),
		jwt.WithTimeFunc(s.now),
	)
	if err != nil {
		// The underlying reason is wrapped for the log but collapsed into one
		// sentinel, so a handler cannot accidentally tell a caller which check
		// failed.
		return fmt.Errorf("%w: %v", ErrInvalidToken, err) //nolint:errorlint // collapsed on purpose, see above
	}
	return nil
}
