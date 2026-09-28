package webhook

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

var (
	secret = []byte("a shared secret nobody else has")
	body   = []byte(`{"event":"user.limited","user":{"id":7}}`)
	sentAt = time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
)

func stamp(at time.Time) string { return strconv.FormatInt(at.Unix(), 10) }

func TestASignedDeliveryVerifies(t *testing.T) {
	signature := Sign(secret, body, sentAt)

	if err := Verify(secret, body, stamp(sentAt), signature, sentAt.Add(time.Second), DefaultTolerance); err != nil {
		t.Errorf("a correctly signed delivery failed to verify: %v", err)
	}
}

// The signature is only worth anything if changing any input breaks it.
func TestTamperingIsDetected(t *testing.T) {
	signature := Sign(secret, body, sentAt)
	now := sentAt.Add(time.Second)

	cases := map[string]error{
		"a different body":   Verify(secret, []byte(`{"event":"user.renewed","user":{"id":7}}`), stamp(sentAt), signature, now, DefaultTolerance),
		"a different secret": Verify([]byte("guessed"), body, stamp(sentAt), signature, now, DefaultTolerance),
		// The timestamp is signed: moving it forward to get an old body past the freshness
		// check must break the signature.
		"a moved timestamp": Verify(secret, body, stamp(sentAt.Add(time.Minute)), signature, now, DefaultTolerance),
	}

	for name, err := range cases {
		if !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: Verify returned %v, want ErrBadSignature", name, err)
		}
	}
}

// A captured delivery replayed later is refused even with a valid signature.
func TestStaleDeliveriesAreRefused(t *testing.T) {
	signature := Sign(secret, body, sentAt)

	err := Verify(secret, body, stamp(sentAt), signature, sentAt.Add(time.Hour), DefaultTolerance)
	if !errors.Is(err, ErrStale) {
		t.Errorf("an hour-old delivery returned %v, want ErrStale", err)
	}

	// And from the future, which is what a receiver with a slow clock sees.
	err = Verify(secret, body, stamp(sentAt), signature, sentAt.Add(-time.Hour), DefaultTolerance)
	if !errors.Is(err, ErrStale) {
		t.Errorf("a delivery an hour ahead returned %v, want ErrStale", err)
	}
}

func TestMalformedSignaturesAreRefused(t *testing.T) {
	now := sentAt.Add(time.Second)

	if err := Verify(secret, body, "", "", now, DefaultTolerance); !errors.Is(err, ErrMissingSignature) {
		t.Errorf("an unsigned delivery returned %v, want ErrMissingSignature", err)
	}

	for name, signature := range map[string]string{
		"another scheme": "sha1=abcdef",
		"not hex":        "sha256=not-hex-at-all",
		"empty digest":   "sha256=",
	} {
		if err := Verify(secret, body, stamp(sentAt), signature, now, DefaultTolerance); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: Verify returned %v, want ErrBadSignature", name, err)
		}
	}

	if err := Verify(secret, body, "yesterday", Sign(secret, body, sentAt), now, DefaultTolerance); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a non-numeric timestamp returned %v, want ErrBadSignature", err)
	}
}

// The scheme is fixed by documentation that receivers implement, so the exact bytes are
// pinned: a change here is a change every receiver has to make.
func TestTheSignatureFormatIsStable(t *testing.T) {
	got := Sign([]byte("secret"), []byte(`{}`), time.Unix(1_700_000_000, 0))

	// HMAC-SHA256("secret", "1700000000.{}"), computed with Python's hmac module rather than
	// Go's, so the test is not checking the implementation against itself:
	//
	//   python -c "import hmac,hashlib; print(hmac.new(b'secret', b'1700000000.{}',
	//              hashlib.sha256).hexdigest())"
	const want = "sha256=b8569b78799ff9e3cbff0fc2d63a33a2b57f3282abd07c37ae5e8e7d79a5f163"
	if got != want {
		t.Errorf("signature is %s, want %s — the scheme receivers implement has changed", got, want)
	}
}
