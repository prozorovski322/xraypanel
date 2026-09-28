package auth

import (
	"fmt"
	"strings"

	"github.com/xraypanel/panel/internal/crypto"
)

// API key layout: xpk_<prefix>_<secret>
//
// The visible prefix exists so a leaked key can be identified and revoked without
// anyone having to paste the whole secret into a chat window to ask "is this one
// ours?". It is stored in clear and shown in the UI; only the full key is hashed.
//
// The "xpk_" marker makes keys greppable in logs and recognisable to secret
// scanners, which is the difference between a leak found by tooling and a leak
// found by an incident.
const (
	apiKeyMarker       = "xpk"
	apiKeyPrefixLength = 10
	apiKeySecretLength = 32
)

// GeneratedAPIKey is the result of minting a key. The plaintext exists only here
// and in the HTTP response that carries it; the database gets the hash.
type GeneratedAPIKey struct {
	// Plaintext is the full key, shown to the operator exactly once.
	Plaintext string
	// Prefix is the public fragment stored for display.
	Prefix string
	// Hash is what goes in the database.
	Hash []byte
}

// GenerateAPIKey mints a new API key.
func GenerateAPIKey() (*GeneratedAPIKey, error) {
	prefix, err := crypto.RandomID(apiKeyPrefixLength)
	if err != nil {
		return nil, fmt.Errorf("auth: generate api key prefix: %w", err)
	}
	secret, err := crypto.RandomID(apiKeySecretLength)
	if err != nil {
		return nil, fmt.Errorf("auth: generate api key secret: %w", err)
	}

	plaintext := apiKeyMarker + "_" + prefix + "_" + secret

	return &GeneratedAPIKey{
		Plaintext: plaintext,
		Prefix:    prefix,
		// The whole key is hashed, not just the secret part. Hashing only the
		// secret would let a key be presented with someone else's prefix and still
		// authenticate, which would make the prefix useless for attributing a leak.
		Hash: crypto.HashToken(plaintext),
	}, nil
}

// ParseAPIKey checks the shape of a presented key and returns its prefix and hash.
//
// Shape is validated before any database work so that garbage in an Authorization
// header costs a string comparison rather than a query. It is not a security
// boundary: the hash lookup is.
func ParseAPIKey(presented string) (prefix string, hash []byte, err error) {
	presented = strings.TrimSpace(presented)

	parts := strings.Split(presented, "_")
	if len(parts) != 3 || parts[0] != apiKeyMarker {
		return "", nil, ErrInvalidToken
	}
	if len(parts[1]) != apiKeyPrefixLength || len(parts[2]) != apiKeySecretLength {
		return "", nil, ErrInvalidToken
	}

	return parts[1], crypto.HashToken(presented), nil
}

// ValidateScopes rejects unknown scopes.
//
// An unknown scope is refused rather than dropped: a key created with a typo would
// otherwise appear in the UI as granting something it does not grant, and the
// mistake would only surface as a confusing 403 much later.
func ValidateScopes(scopes []string) error {
	for _, s := range scopes {
		if !IsKnownScope(s) {
			return fmt.Errorf("auth: unknown scope %q", s)
		}
	}
	return nil
}
