package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func testKey(t *testing.T, fill byte) []byte {
	t.Helper()
	return bytes.Repeat([]byte{fill}, KeySize)
}

func newTestCipher(t *testing.T, fill byte) *Cipher {
	t.Helper()
	c, err := NewCipher(testKey(t, fill))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func TestNewCipherRejectsWrongKeySize(t *testing.T) {
	for _, size := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := NewCipher(bytes.Repeat([]byte{0x01}, size)); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("NewCipher with a %d-byte key: err = %v, want ErrInvalidKeySize", size, err)
		}
	}
}

func TestCipherRoundTrip(t *testing.T) {
	c := newTestCipher(t, 0x11)

	cases := map[string][]byte{
		"empty":     {},
		"short":     []byte("x"),
		"pem-ish":   []byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"),
		"binary":    {0x00, 0xff, 0x7f, 0x80, 0x00},
		"non-ascii": []byte("пароль"),
	}

	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			sealed, err := c.Encrypt(plaintext, "test.purpose")
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			// Only meaningful for plaintexts long enough that a coincidental
			// match in the nonce is not plausible.
			if len(plaintext) >= 4 && bytes.Contains(sealed, plaintext) {
				t.Error("plaintext appears verbatim in the ciphertext")
			}

			opened, err := c.Decrypt(sealed, "test.purpose")
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(opened, plaintext) {
				t.Errorf("round trip changed the value: got %q, want %q", opened, plaintext)
			}
		})
	}
}

// TestPurposeIsDomainSeparation is the property that makes copying a value between
// two encrypted columns a loud failure rather than a silent success.
func TestPurposeIsDomainSeparation(t *testing.T) {
	c := newTestCipher(t, 0x22)

	sealed, err := c.Encrypt([]byte("ca-private-key"), "pki.ca_key")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := c.Decrypt(sealed, "reality.private_key"); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("decrypting under a different purpose: err = %v, want ErrDecryptFailed", err)
	}
	if _, err := c.Decrypt(sealed, "pki.ca_key"); err != nil {
		t.Errorf("decrypting under the original purpose failed: %v", err)
	}
}

func TestEmptyPurposeRejected(t *testing.T) {
	c := newTestCipher(t, 0x33)

	if _, err := c.Encrypt([]byte("x"), ""); err == nil {
		t.Error("Encrypt accepted an empty purpose")
	}
	sealed, err := c.Encrypt([]byte("x"), "p")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := c.Decrypt(sealed, ""); err == nil {
		t.Error("Decrypt accepted an empty purpose")
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	sealed, err := newTestCipher(t, 0x44).Encrypt([]byte("secret"), "p")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := newTestCipher(t, 0x45).Decrypt(sealed, "p"); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("err = %v, want ErrDecryptFailed", err)
	}
}

func TestDecryptRejectsTampering(t *testing.T) {
	c := newTestCipher(t, 0x55)
	sealed, err := c.Encrypt([]byte("secret value"), "p")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip one bit at each position in turn; every position is authenticated.
	for i := range sealed {
		tampered := bytes.Clone(sealed)
		tampered[i] ^= 0x01

		_, err := c.Decrypt(tampered, "p")
		if err == nil {
			t.Fatalf("flipping a bit at offset %d went undetected", i)
		}
	}
}

func TestDecryptRejectsMalformedInput(t *testing.T) {
	c := newTestCipher(t, 0x66)

	cases := map[string][]byte{
		"nil":          nil,
		"empty":        {},
		"version only": {cipherVersion},
		"truncated":    bytes.Repeat([]byte{cipherVersion}, 8),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := c.Decrypt(input, "p"); !errors.Is(err, ErrMalformedCiphertext) {
				t.Errorf("err = %v, want ErrMalformedCiphertext", err)
			}
		})
	}
}

func TestDecryptRejectsUnknownVersion(t *testing.T) {
	c := newTestCipher(t, 0x77)
	sealed, err := c.Encrypt([]byte("secret"), "p")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	sealed[0] = 0xfe
	if _, err := c.Decrypt(sealed, "p"); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("err = %v, want ErrUnsupportedVersion", err)
	}
}

// TestNonceIsFresh catches the classic GCM failure: reusing a nonce under one key
// breaks confidentiality outright.
func TestNonceIsFresh(t *testing.T) {
	c := newTestCipher(t, 0x88)

	const iterations = 200
	seen := make(map[string]struct{}, iterations)
	for i := 0; i < iterations; i++ {
		sealed, err := c.Encrypt([]byte("identical plaintext"), "p")
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		nonce := string(sealed[1 : 1+12])
		if _, dup := seen[nonce]; dup {
			t.Fatalf("nonce repeated after %d encryptions", i+1)
		}
		seen[nonce] = struct{}{}
	}
}

func TestEncryptStringRoundTrip(t *testing.T) {
	c := newTestCipher(t, 0x99)

	sealed, err := c.EncryptString("тайна", "p")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	got, err := c.DecryptString(sealed, "p")
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if got != "тайна" {
		t.Errorf("got %q, want %q", got, "тайна")
	}
}

func TestDeriveKey(t *testing.T) {
	master := testKey(t, 0xaa)

	jwt1, err := DeriveKey(master, "jwt.signing", 32)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	jwt2, err := DeriveKey(master, "jwt.signing", 32)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if !bytes.Equal(jwt1, jwt2) {
		t.Error("DeriveKey is not deterministic, so tokens would not survive a restart")
	}

	other, err := DeriveKey(master, "webhook.signing", 32)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if bytes.Equal(jwt1, other) {
		t.Error("different purposes produced the same key, so they are not independent")
	}

	if bytes.Equal(jwt1, master) {
		t.Error("derived key equals the master key")
	}

	if _, err := DeriveKey(master, "", 32); err == nil {
		t.Error("DeriveKey accepted an empty purpose")
	}
	if _, err := DeriveKey(testKey(t, 0xbb)[:16], "p", 32); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("err = %v, want ErrInvalidKeySize", err)
	}
	for _, size := range []int{0, -1, 2048} {
		if _, err := DeriveKey(master, "p", size); err == nil {
			t.Errorf("DeriveKey accepted size %d", size)
		}
	}
}

// --- passwords ---

// testParams keeps Argon2 cheap so the suite stays fast. Production cost lives in
// DefaultArgon2Params and is asserted separately.
func testParams() Argon2Params {
	p := DefaultArgon2Params()
	p.Memory = 8 * 1024
	p.Iterations = 1
	return p
}

func TestHashPasswordFormat(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple", testParams())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Errorf("unexpected hash prefix: %s", hash)
	}
	if parts := strings.Split(hash, "$"); len(parts) != 6 {
		t.Errorf("hash has %d fields, want 6: %s", len(parts), hash)
	}
	if strings.Contains(hash, "correct horse") {
		t.Errorf("hash contains the password: %s", hash)
	}
}

func TestHashPasswordIsSalted(t *testing.T) {
	first, err := HashPassword("same password", testParams())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	second, err := HashPassword("same password", testParams())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if first == second {
		t.Error("two hashes of the same password are identical, so the salt is not random")
	}
}

func TestVerifyPassword(t *testing.T) {
	const password = "correct horse battery staple"
	hash, err := HashPassword(password, testParams())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	match, _, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !match {
		t.Error("the correct password did not verify")
	}

	for _, wrong := range []string{
		"",
		"Correct horse battery staple",
		"correct horse battery stapl",
		"correct horse battery staple ",
		"совсем другой",
	} {
		match, _, err := VerifyPassword(wrong, hash)
		if err != nil {
			t.Fatalf("VerifyPassword(%q): %v", wrong, err)
		}
		if match {
			t.Errorf("wrong password %q verified", wrong)
		}
	}
}

func TestVerifyPasswordFlagsWeakHashForRehash(t *testing.T) {
	weak := testParams() // below DefaultArgon2Params
	hash, err := HashPassword("password one two three", weak)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	match, needsRehash, err := VerifyPassword("password one two three", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !match {
		t.Fatal("password did not verify")
	}
	if !needsRehash {
		t.Error("a hash weaker than the current defaults was not flagged for rehash")
	}
}

func TestVerifyPasswordAtCurrentParamsNeedsNoRehash(t *testing.T) {
	// Uses production parameters on purpose: this is the only test that pays the
	// real cost, and it pins that the defaults do not flag themselves.
	hash, err := HashPassword("password one two three", DefaultArgon2Params())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	match, needsRehash, err := VerifyPassword("password one two three", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !match {
		t.Fatal("password did not verify")
	}
	if needsRehash {
		t.Error("a hash at current defaults was flagged for rehash, so every login would rehash")
	}
}

// TestVerifyPasswordRejectsMalformedHash separates "the stored row is broken" from
// "the password is wrong". Conflating them would report a corrupt row to the user
// as invalid credentials and hide a real problem.
func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	cases := map[string]string{
		"empty":               "",
		"not phc":             "plaintext-password",
		"too few fields":      "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA",
		"wrong algorithm":     "$argon2i$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaA",
		"bcrypt":              "$2y$10$abcdefghijklmnopqrstuv",
		"missing memory cost": "$argon2id$v=19$t=3,p=2$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaA",
		"zero memory cost":    "$argon2id$v=19$m=0,t=3,p=2$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaA",
		"unknown cost param":  "$argon2id$v=19$m=65536,t=3,p=2,x=1$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaA",
		"non-numeric cost":    "$argon2id$v=19$m=lots,t=3,p=2$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaA",
		"bad base64 salt":     "$argon2id$v=19$m=65536,t=3,p=2$!!!not-base64!!!$aGFzaGhhc2hoYXNoaGFzaA",
		"empty salt":          "$argon2id$v=19$m=65536,t=3,p=2$$aGFzaGhhc2hoYXNoaGFzaA",
		"missing version":     "$argon2id$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaA",
	}

	for name, hash := range cases {
		t.Run(name, func(t *testing.T) {
			match, needsRehash, err := VerifyPassword("any password", hash)
			if err == nil {
				t.Fatal("a malformed hash was accepted as a valid verification input")
			}
			if match {
				t.Error("match = true for a malformed hash")
			}
			if needsRehash {
				t.Error("needsRehash = true for a malformed hash")
			}
		})
	}
}

func TestHashPasswordRejectsBadInput(t *testing.T) {
	if _, err := HashPassword("", testParams()); err == nil {
		t.Error("HashPassword accepted an empty password")
	}

	weak := []Argon2Params{
		{Memory: 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32},
		{Memory: 65536, Iterations: 0, Parallelism: 2, SaltLength: 16, KeyLength: 32},
		{Memory: 65536, Iterations: 3, Parallelism: 0, SaltLength: 16, KeyLength: 32},
		{Memory: 65536, Iterations: 3, Parallelism: 2, SaltLength: 8, KeyLength: 32},
		{Memory: 65536, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 8},
	}
	for i, params := range weak {
		if _, err := HashPassword("password", params); err == nil {
			t.Errorf("case %d: HashPassword accepted parameters below the floor: %+v", i, params)
		}
	}
}

func TestDefaultArgon2ParamsMeetFloor(t *testing.T) {
	p := DefaultArgon2Params()
	if p.Memory < 19*1024 {
		t.Errorf("default memory %d KiB is below the 19 MiB OWASP floor for argon2id", p.Memory)
	}
	if p.Iterations < 2 {
		t.Errorf("default iterations = %d, want at least 2", p.Iterations)
	}
	if err := p.validate(); err != nil {
		t.Errorf("default parameters fail their own validation: %v", err)
	}
}

// --- tokens ---

func TestRandomIDShape(t *testing.T) {
	for _, length := range []int{1, 12, 22, 64} {
		id, err := RandomID(length)
		if err != nil {
			t.Fatalf("RandomID(%d): %v", length, err)
		}
		if len(id) != length {
			t.Errorf("len(RandomID(%d)) = %d", length, len(id))
		}
		for _, r := range id {
			if !strings.ContainsRune(idAlphabet, r) {
				t.Errorf("RandomID produced %q, which is outside the alphabet", r)
			}
		}
	}

	for _, length := range []int{0, -1} {
		if _, err := RandomID(length); err == nil {
			t.Errorf("RandomID(%d) did not fail", length)
		}
	}
}

// TestIDAlphabetHasNoLookalikes pins the property that makes these identifiers
// safe to read aloud or copy out of a screenshot.
func TestIDAlphabetHasNoLookalikes(t *testing.T) {
	if len(idAlphabet) != 32 {
		t.Fatalf("len(idAlphabet) = %d, want 32 so that byte sampling stays unbiased", len(idAlphabet))
	}
	for _, r := range "lo01" {
		if strings.ContainsRune(idAlphabet, r) {
			t.Errorf("alphabet contains look-alike character %q", r)
		}
	}
	seen := map[rune]struct{}{}
	for _, r := range idAlphabet {
		if _, dup := seen[r]; dup {
			t.Errorf("alphabet repeats %q, which skews the distribution", r)
		}
		seen[r] = struct{}{}
	}
}

func TestStatsKeyAndSubscriptionTokenDiffer(t *testing.T) {
	statsKey, err := NewStatsKey()
	if err != nil {
		t.Fatalf("NewStatsKey: %v", err)
	}
	if len(statsKey) != statsKeyLength {
		t.Errorf("len(NewStatsKey()) = %d, want %d", len(statsKey), statsKeyLength)
	}

	token, err := NewSubscriptionToken()
	if err != nil {
		t.Fatalf("NewSubscriptionToken: %v", err)
	}
	if len(token) != subscriptionTokenLength {
		t.Errorf("len(NewSubscriptionToken()) = %d, want %d", len(token), subscriptionTokenLength)
	}

	// The subscription token is a bearer secret and must carry materially more
	// entropy than the public stats key.
	if subscriptionTokenLength <= statsKeyLength {
		t.Error("the subscription token is not longer than the stats key")
	}
}

func TestRandomIDIsNotRepeating(t *testing.T) {
	const iterations = 500
	seen := make(map[string]struct{}, iterations)
	for i := 0; i < iterations; i++ {
		id, err := NewSubscriptionToken()
		if err != nil {
			t.Fatalf("NewSubscriptionToken: %v", err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate token after %d draws", i+1)
		}
		seen[id] = struct{}{}
	}
}

func TestRandomToken(t *testing.T) {
	token, err := RandomToken(32)
	if err != nil {
		t.Fatalf("RandomToken: %v", err)
	}
	// Unpadded base64url must be URL- and cookie-safe.
	for _, bad := range []string{"=", "+", "/", "\n"} {
		if strings.Contains(token, bad) {
			t.Errorf("token contains %q, which is not safe in a URL or cookie: %s", bad, token)
		}
	}
	if _, err := RandomToken(0); err == nil {
		t.Error("RandomToken(0) did not fail")
	}
}

func TestHashTokenAndEqualHash(t *testing.T) {
	a := HashToken("some-refresh-token")
	b := HashToken("some-refresh-token")
	c := HashToken("some-refresh-tokem")

	if len(a) != 32 {
		t.Errorf("len(HashToken(...)) = %d, want 32", len(a))
	}
	if !EqualHash(a, b) {
		t.Error("HashToken is not deterministic")
	}
	if EqualHash(a, c) {
		t.Error("EqualHash matched hashes of different tokens")
	}
	if EqualHash(a, a[:16]) {
		t.Error("EqualHash matched values of different length")
	}
}

func TestRandomBytes(t *testing.T) {
	b, err := RandomBytes(16)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	if len(b) != 16 {
		t.Errorf("len = %d, want 16", len(b))
	}
	if bytes.Equal(b, make([]byte, 16)) {
		t.Error("RandomBytes returned all zeroes")
	}
	for _, n := range []int{0, -1} {
		if _, err := RandomBytes(n); err == nil {
			t.Errorf("RandomBytes(%d) did not fail", n)
		}
	}
}
