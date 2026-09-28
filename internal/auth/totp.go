package auth

import (
	"fmt"
	"net/url"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP parameters. These are the interoperable defaults: every authenticator app
// in common use supports 6 digits, a 30-second period and SHA-1. Choosing
// something stronger here would mean codes that Google Authenticator silently
// computes wrong, which surfaces as "2FA is broken" rather than as an error.
const (
	totpPeriod    = 30 * time.Second
	totpDigits    = otp.DigitsSix
	totpAlgorithm = otp.AlgorithmSHA1

	// totpSkew accepts one step either side of now, covering roughly a minute and
	// a half in total. It tolerates a phone whose clock drifts and a person who
	// starts typing just before a code rolls over.
	totpSkew = 1

	// totpSecretSize is the raw secret length in bytes. Twenty bytes matches the
	// HMAC-SHA1 block used by every authenticator and is what RFC 4226 recommends.
	totpSecretSize = 20
)

// TOTPEnrollment is what an administrator needs to add the panel to their
// authenticator app.
type TOTPEnrollment struct {
	// Secret is the base32 secret, for manual entry when a QR code cannot be
	// scanned.
	Secret string
	// URI is the otpauth:// URL a QR code should encode.
	URI string
}

// GenerateTOTPEnrollment creates a new secret for an administrator.
//
// The label includes the panel's own hostname so that an administrator managing
// several installations can tell the entries apart in their authenticator; two
// entries both called "xraypanel" are indistinguishable at the moment they are
// needed.
func GenerateTOTPEnrollment(issuer, accountName string) (*TOTPEnrollment, error) {
	if issuer == "" {
		issuer = tokenIssuer
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      uint(totpPeriod.Seconds()),
		SecretSize:  totpSecretSize,
		Digits:      totpDigits,
		Algorithm:   totpAlgorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: generate totp secret: %w", err)
	}

	return &TOTPEnrollment{Secret: key.Secret(), URI: key.URL()}, nil
}

// TOTPStep returns the time step a moment falls into.
//
// The step is what gets stored to prevent replay: it identifies the code rather
// than the code's value, so nothing secret has to be written down to remember that
// a code was used.
func TOTPStep(at time.Time) int64 {
	return at.Unix() / int64(totpPeriod.Seconds())
}

// VerifyTOTP checks a code against a secret and reports which step it matched.
//
// It walks the accepted steps one at a time with skew disabled, rather than
// letting the library apply skew internally, because the caller needs to know
// which step was used. Without that, replay protection could only remember "some
// code was accepted recently" and would either reject the legitimate next code or
// accept a replayed one.
func VerifyTOTP(secret, code string, now time.Time) (int64, error) {
	if secret == "" {
		return 0, ErrTOTPNotEnrolled
	}
	if code == "" {
		return 0, ErrTOTPInvalid
	}

	opts := totp.ValidateOpts{
		Period:    uint(totpPeriod.Seconds()),
		Skew:      0,
		Digits:    totpDigits,
		Algorithm: totpAlgorithm,
	}

	for offset := -totpSkew; offset <= totpSkew; offset++ {
		candidate := now.Add(time.Duration(offset) * totpPeriod)

		ok, err := totp.ValidateCustom(code, secret, candidate, opts)
		if err != nil {
			// A malformed secret or an unparsable code lands here. Either way the
			// code is not valid, and the reason is not the caller's business.
			continue
		}
		if ok {
			return TOTPStep(candidate), nil
		}
	}

	return 0, ErrTOTPInvalid
}

// TOTPQRCodeURL is a convenience for rendering the enrollment URI as a label in
// logs and documentation without exposing the secret.
func TOTPQRCodeURL(uri string) string {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "[UNPARSABLE OTPAUTH URI]"
	}
	query := parsed.Query()
	if query.Has("secret") {
		query.Set("secret", "[REDACTED]")
		parsed.RawQuery = query.Encode()
	}
	return parsed.String()
}
