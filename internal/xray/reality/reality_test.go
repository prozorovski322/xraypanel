package reality

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	pair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Unpadded base64url is what `xray x25519` prints and what the client reads. A
	// padded or standard-alphabet key looks fine in Go and is rejected by the client.
	for name, encoded := range map[string]string{"private": pair.PrivateKey, "public": pair.PublicKey} {
		if strings.ContainsAny(encoded, "=+/") {
			t.Errorf("%s key is not unpadded base64url: %q", name, encoded)
		}
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Errorf("%s key does not decode as base64url: %v", name, err)
			continue
		}
		if len(raw) != keySize {
			t.Errorf("%s key decodes to %d bytes, want %d", name, len(raw), keySize)
		}
	}

	if pair.PrivateKey == pair.PublicKey {
		t.Error("the two halves of the key pair are identical")
	}
}

func TestGenerateKeyPairIsUnique(t *testing.T) {
	const iterations = 100
	seen := make(map[string]struct{}, iterations)

	for i := 0; i < iterations; i++ {
		pair, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		if _, dup := seen[pair.PrivateKey]; dup {
			t.Fatalf("duplicate private key after %d draws", i+1)
		}
		seen[pair.PrivateKey] = struct{}{}
	}
}

func TestPublicKeyForRecoversTheSameHalf(t *testing.T) {
	pair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	derived, err := PublicKeyFor(pair.PrivateKey)
	if err != nil {
		t.Fatalf("PublicKeyFor: %v", err)
	}
	if derived != pair.PublicKey {
		t.Errorf("PublicKeyFor = %q, want %q", derived, pair.PublicKey)
	}
}

// TestDecodeKeyAcceptsEveryBase64Variant covers keys pasted from other tools, which
// differ only in padding and alphabet and are the same key.
func TestDecodeKeyAcceptsEveryBase64Variant(t *testing.T) {
	pair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(pair.PrivateKey)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	variants := map[string]string{
		"raw url":   base64.RawURLEncoding.EncodeToString(raw),
		"url":       base64.URLEncoding.EncodeToString(raw),
		"raw std":   base64.RawStdEncoding.EncodeToString(raw),
		"std":       base64.StdEncoding.EncodeToString(raw),
		"padded ws": "  " + base64.StdEncoding.EncodeToString(raw) + "\n",
	}

	for name, encoded := range variants {
		derived, err := PublicKeyFor(encoded)
		if err != nil {
			t.Errorf("%s: PublicKeyFor: %v", name, err)
			continue
		}
		if derived != pair.PublicKey {
			t.Errorf("%s: derived a different public key", name)
		}
	}
}

func TestPublicKeyForRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"empty":      "",
		"whitespace": "   ",
		"not base64": "!!!!not-base64!!!!",
		"too short":  base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		"too long":   base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	}
	for name, key := range cases {
		if _, err := PublicKeyFor(key); err == nil {
			t.Errorf("%s: PublicKeyFor accepted %q", name, key)
		}
	}
}

// TestValidateKeyPairCatchesMismatch is the case worth being explicit about: an
// inbound built from a private key with somebody else's public key starts cleanly
// and rejects every client, with nothing in the logs to say why.
func TestValidateKeyPairCatchesMismatch(t *testing.T) {
	first, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	second, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	if err := ValidateKeyPair(first.PrivateKey, first.PublicKey); err != nil {
		t.Errorf("a matching pair was rejected: %v", err)
	}
	if err := ValidateKeyPair(first.PrivateKey, second.PublicKey); err == nil {
		t.Error("a mismatched pair was accepted")
	}
	if err := ValidateKeyPair(first.PrivateKey, "not-a-key"); err == nil {
		t.Error("an unparsable public key was accepted")
	}
}

func TestGenerateShortIDs(t *testing.T) {
	ids, err := GenerateShortIDs(DefaultShortIDCount)
	if err != nil {
		t.Fatalf("GenerateShortIDs: %v", err)
	}
	if len(ids) != DefaultShortIDCount {
		t.Fatalf("got %d ids, want %d", len(ids), DefaultShortIDCount)
	}

	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if len(id) != shortIDMaxBytes*2 {
			t.Errorf("id %q is %d hex digits, want %d", id, len(id), shortIDMaxBytes*2)
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Errorf("id %q is not hexadecimal", id)
		}
		if _, dup := seen[id]; dup {
			t.Errorf("id %q was generated twice", id)
		}
		seen[id] = struct{}{}
		if id == "" {
			t.Error("an empty short id was generated, which would accept clients that send none")
		}
	}

	if err := ValidateShortIDs(ids); err != nil {
		t.Errorf("generated ids fail their own validation: %v", err)
	}

	for _, count := range []int{0, -1, 65} {
		if _, err := GenerateShortIDs(count); err == nil {
			t.Errorf("GenerateShortIDs(%d) did not fail", count)
		}
	}
}

func TestValidateShortID(t *testing.T) {
	valid := []string{"ab", "abcd", "0123456789abcdef", "00", "ffffffffffffffff"}
	for _, id := range valid {
		if err := ValidateShortID(id); err != nil {
			t.Errorf("ValidateShortID(%q) = %v, want nil", id, err)
		}
	}

	invalid := map[string]string{
		"empty":          "",
		"odd length":     "abc",
		"too long":       "0123456789abcdef00",
		"not hex":        "zzzz",
		"uppercase ok?":  "GG",
		"with separator": "ab:cd",
	}
	for name, id := range invalid {
		if err := ValidateShortID(id); err == nil {
			t.Errorf("%s: ValidateShortID(%q) accepted it", name, id)
		}
	}
}

func TestValidateShortIDsRejectsDuplicatesAndEmptyList(t *testing.T) {
	if err := ValidateShortIDs(nil); err == nil {
		t.Error("an empty list was accepted")
	}
	if err := ValidateShortIDs([]string{"abcd", "abcd"}); err == nil {
		t.Error("a duplicate id was accepted")
	}
	if err := ValidateShortIDs([]string{"abcd", ""}); err == nil {
		t.Error("an empty id inside the list was accepted")
	}
}

func TestValidateDest(t *testing.T) {
	valid := []string{
		"www.example.com:443",
		"example.com:8443",
		"1.2.3.4:443",
		"[2001:db8::1]:443",
	}
	for _, dest := range valid {
		if err := ValidateDest(dest); err != nil {
			t.Errorf("ValidateDest(%q) = %v, want nil", dest, err)
		}
	}

	invalid := map[string]string{
		"empty":             "",
		"no port":           "www.example.com",
		"port zero":         "www.example.com:0",
		"port too high":     "www.example.com:70000",
		"port not a number": "www.example.com:https",
		"no host":           ":443",
		"scheme":            "https://www.example.com:443",
	}
	for name, dest := range invalid {
		if err := ValidateDest(dest); err == nil {
			t.Errorf("%s: ValidateDest(%q) accepted it", name, dest)
		}
	}
}

func TestValidateServerNames(t *testing.T) {
	if err := ValidateServerNames([]string{"www.example.com", "example.com"}); err != nil {
		t.Errorf("valid names rejected: %v", err)
	}

	invalid := map[string][]string{
		"empty list":  nil,
		"empty name":  {"www.example.com", ""},
		"with port":   {"www.example.com:443"},
		"with scheme": {"https://www.example.com"},
		"with space":  {"www example com"},
	}
	for name, names := range invalid {
		if err := ValidateServerNames(names); err == nil {
			t.Errorf("%s: ValidateServerNames(%v) accepted it", name, names)
		}
	}
}
