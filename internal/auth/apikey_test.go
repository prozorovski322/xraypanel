package auth

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/xraypanel/panel/internal/crypto"
)

func TestGenerateAPIKeyShape(t *testing.T) {
	key, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	if !strings.HasPrefix(key.Plaintext, apiKeyMarker+"_") {
		t.Errorf("key does not carry the %q marker, so secret scanners will miss it: %s",
			apiKeyMarker, key.Plaintext)
	}
	parts := strings.Split(key.Plaintext, "_")
	if len(parts) != 3 {
		t.Fatalf("key has %d segments, want 3: %s", len(parts), key.Plaintext)
	}
	if len(parts[1]) != apiKeyPrefixLength {
		t.Errorf("prefix length = %d, want %d", len(parts[1]), apiKeyPrefixLength)
	}
	if len(parts[2]) != apiKeySecretLength {
		t.Errorf("secret length = %d, want %d", len(parts[2]), apiKeySecretLength)
	}
	if key.Prefix != parts[1] {
		t.Errorf("Prefix = %q but the key carries %q", key.Prefix, parts[1])
	}
	if len(key.Hash) != 32 {
		t.Errorf("hash length = %d, want 32", len(key.Hash))
	}
	if bytes.Contains(key.Hash, []byte(parts[2])) {
		t.Error("the hash contains the secret verbatim")
	}
}

func TestGenerateAPIKeyIsUnique(t *testing.T) {
	const iterations = 200
	seen := make(map[string]struct{}, iterations)

	for i := 0; i < iterations; i++ {
		key, err := GenerateAPIKey()
		if err != nil {
			t.Fatalf("GenerateAPIKey: %v", err)
		}
		if _, dup := seen[key.Plaintext]; dup {
			t.Fatalf("duplicate key after %d draws", i+1)
		}
		seen[key.Plaintext] = struct{}{}
	}
}

func TestParseAPIKeyRoundTrip(t *testing.T) {
	key, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	prefix, hash, err := ParseAPIKey(key.Plaintext)
	if err != nil {
		t.Fatalf("ParseAPIKey: %v", err)
	}
	if prefix != key.Prefix {
		t.Errorf("prefix = %q, want %q", prefix, key.Prefix)
	}
	if !bytes.Equal(hash, key.Hash) {
		t.Error("ParseAPIKey produced a different hash than GenerateAPIKey, so lookup would always miss")
	}
}

func TestParseAPIKeyIgnoresSurroundingWhitespace(t *testing.T) {
	key, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	// A key pasted out of a terminal often carries a trailing newline.
	_, hash, err := ParseAPIKey("  " + key.Plaintext + "\n")
	if err != nil {
		t.Fatalf("ParseAPIKey: %v", err)
	}
	if !bytes.Equal(hash, key.Hash) {
		t.Error("whitespace changed the hash")
	}
}

// TestHashCoversWholeKey is the property that makes the prefix trustworthy for
// attributing a leak: a key presented with a different prefix must not authenticate.
func TestHashCoversWholeKey(t *testing.T) {
	key, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	parts := strings.Split(key.Plaintext, "_")
	swapped := apiKeyMarker + "_" + strings.Repeat("a", apiKeyPrefixLength) + "_" + parts[2]

	_, hash, err := ParseAPIKey(swapped)
	if err != nil {
		t.Fatalf("ParseAPIKey: %v", err)
	}
	if bytes.Equal(hash, key.Hash) {
		t.Error("the same secret under a different prefix produced the same hash")
	}
}

func TestParseAPIKeyRejectsMalformed(t *testing.T) {
	valid, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	parts := strings.Split(valid.Plaintext, "_")

	cases := map[string]string{
		"empty":             "",
		"no marker":         strings.Join(parts[1:], "_"),
		"wrong marker":      "ghp_" + parts[1] + "_" + parts[2],
		"too few segments":  apiKeyMarker + "_" + parts[1],
		"too many segments": valid.Plaintext + "_extra",
		"short prefix":      apiKeyMarker + "_abc_" + parts[2],
		"short secret":      apiKeyMarker + "_" + parts[1] + "_abc",
		"just the marker":   apiKeyMarker,
		"bearer token":      "Bearer " + valid.Plaintext,
	}

	for name, presented := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseAPIKey(presented); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("err = %v, want ErrInvalidToken", err)
			}
		})
	}
}

func TestValidateScopes(t *testing.T) {
	if err := ValidateScopes(nil); err != nil {
		t.Errorf("an empty scope set is valid and means no access: %v", err)
	}
	if err := ValidateScopes([]string{ScopeUsersRead, ScopeNodesWrite}); err != nil {
		t.Errorf("known scopes rejected: %v", err)
	}

	for _, scopes := range [][]string{
		{"users:delete"},
		{ScopeUsersRead, "typo:read"},
		{""},
		{"USERS:READ"},
	} {
		if err := ValidateScopes(scopes); err == nil {
			t.Errorf("ValidateScopes(%v) accepted an unknown scope", scopes)
		}
	}
}

// TestAPIKeyHashMatchesCryptoHelper pins that storage and lookup use the same
// hashing, which is the kind of mismatch that produces "the key is right but
// authentication fails".
func TestAPIKeyHashMatchesCryptoHelper(t *testing.T) {
	key, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if !bytes.Equal(key.Hash, crypto.HashToken(key.Plaintext)) {
		t.Error("GenerateAPIKey does not hash with crypto.HashToken")
	}
}
