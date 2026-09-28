// Package webhook signs the panel's outgoing event deliveries and verifies them.
//
// Verification lives here too, next to signing, so that the one piece of this protocol a
// receiver has to reimplement has a reference to be checked against — and so the panel's
// own tests verify deliveries with exactly the code the documentation describes.
//
// The scheme:
//
//	X-Xraypanel-Timestamp: 1790000000
//	X-Xraypanel-Signature: sha256=hex(HMAC-SHA256(secret, timestamp + "." + body))
//
// The timestamp is inside the signed content so that a captured delivery cannot be replayed
// later: a receiver rejects anything whose timestamp is too far from its own clock, and
// cannot be tricked into accepting an old body under a fresh timestamp.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Header names. Prefixed with the product name so they cannot collide with a proxy's own
// headers on the way.
const (
	HeaderEvent     = "X-Xraypanel-Event"
	HeaderDelivery  = "X-Xraypanel-Delivery"
	HeaderTimestamp = "X-Xraypanel-Timestamp"
	HeaderSignature = "X-Xraypanel-Signature"

	signaturePrefix = "sha256="
)

// DefaultTolerance is how far a delivery's timestamp may be from the receiver's clock.
//
// Five minutes covers ordinary clock drift and a slow delivery, and is short enough that a
// captured request is useless by the time anybody could do something with it.
const DefaultTolerance = 5 * time.Minute

// Errors a receiver can tell apart.
var (
	ErrMissingSignature = errors.New("webhook: the delivery is not signed")
	ErrBadSignature     = errors.New("webhook: the signature does not match")
	ErrStale            = errors.New("webhook: the delivery's timestamp is outside the allowed window")
)

// Sign computes the signature header value for a body sent at a moment.
func Sign(secret, body []byte, at time.Time) string {
	return signaturePrefix + hex.EncodeToString(mac(secret, strconv.FormatInt(at.Unix(), 10), body))
}

// Verify checks a delivery the way a receiver should.
//
// Constant-time comparison: a byte-by-byte comparison that returns early leaks, through its
// timing, how much of a forged signature is right.
func Verify(secret, body []byte, timestamp, signature string, now time.Time, tolerance time.Duration) error {
	if signature == "" || timestamp == "" {
		return ErrMissingSignature
	}
	if !strings.HasPrefix(signature, signaturePrefix) {
		return fmt.Errorf("%w: unknown scheme", ErrBadSignature)
	}

	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: timestamp %q is not a number", ErrBadSignature, timestamp)
	}
	if tolerance > 0 {
		skew := now.Sub(time.Unix(seconds, 0))
		if skew < 0 {
			skew = -skew
		}
		if skew > tolerance {
			return ErrStale
		}
	}

	given, err := hex.DecodeString(strings.TrimPrefix(signature, signaturePrefix))
	if err != nil {
		return fmt.Errorf("%w: not hex", ErrBadSignature)
	}
	if !hmac.Equal(given, mac(secret, timestamp, body)) {
		return ErrBadSignature
	}
	return nil
}

func mac(secret []byte, timestamp string, body []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(timestamp))
	h.Write([]byte("."))
	h.Write(body)
	return h.Sum(nil)
}
