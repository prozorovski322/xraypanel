package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestGenerateTOTPEnrollment(t *testing.T) {
	enrollment, err := GenerateTOTPEnrollment("panel.example.com", "root")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}

	if enrollment.Secret == "" {
		t.Error("secret is empty")
	}
	if !strings.HasPrefix(enrollment.URI, "otpauth://totp/") {
		t.Errorf("URI is not an otpauth URL: %s", enrollment.URI)
	}
	// The issuer has to appear in the label, otherwise two installations produce
	// indistinguishable entries in the authenticator app.
	if !strings.Contains(enrollment.URI, "panel.example.com") {
		t.Errorf("URI omits the issuer: %s", enrollment.URI)
	}
	if !strings.Contains(enrollment.URI, "root") {
		t.Errorf("URI omits the account name: %s", enrollment.URI)
	}

	// Two enrollments must never share a secret.
	other, err := GenerateTOTPEnrollment("panel.example.com", "root")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}
	if other.Secret == enrollment.Secret {
		t.Error("two enrollments produced the same secret")
	}
}

func TestGenerateTOTPEnrollmentDefaultsIssuer(t *testing.T) {
	enrollment, err := GenerateTOTPEnrollment("", "root")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}
	if !strings.Contains(enrollment.URI, tokenIssuer) {
		t.Errorf("empty issuer did not fall back to %q: %s", tokenIssuer, enrollment.URI)
	}
}

func TestVerifyTOTPAcceptsCurrentCode(t *testing.T) {
	enrollment, err := GenerateTOTPEnrollment("", "root")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}

	now := time.Date(2026, 3, 4, 10, 30, 15, 0, time.UTC)
	code, err := totp.GenerateCode(enrollment.Secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	step, err := VerifyTOTP(enrollment.Secret, code, now)
	if err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
	if step != TOTPStep(now) {
		t.Errorf("step = %d, want %d", step, TOTPStep(now))
	}
}

// TestVerifyTOTPToleratesSkew covers a phone with a drifting clock and someone who
// starts typing just before a code rolls over.
func TestVerifyTOTPToleratesSkew(t *testing.T) {
	enrollment, err := GenerateTOTPEnrollment("", "root")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}

	now := time.Date(2026, 3, 4, 10, 30, 15, 0, time.UTC)

	for _, offset := range []time.Duration{-totpPeriod, 0, totpPeriod} {
		generatedAt := now.Add(offset)
		code, err := totp.GenerateCode(enrollment.Secret, generatedAt)
		if err != nil {
			t.Fatalf("GenerateCode: %v", err)
		}

		step, err := VerifyTOTP(enrollment.Secret, code, now)
		if err != nil {
			t.Errorf("code from offset %s rejected: %v", offset, err)
			continue
		}
		// The reported step must be the one the code actually belongs to, not the
		// current one; replay protection depends on that distinction.
		if want := TOTPStep(generatedAt); step != want {
			t.Errorf("offset %s: step = %d, want %d", offset, step, want)
		}
	}
}

func TestVerifyTOTPRejectsOutsideSkew(t *testing.T) {
	enrollment, err := GenerateTOTPEnrollment("", "root")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}

	now := time.Date(2026, 3, 4, 10, 30, 15, 0, time.UTC)

	for _, offset := range []time.Duration{-3 * totpPeriod, 3 * totpPeriod, time.Hour} {
		code, err := totp.GenerateCode(enrollment.Secret, now.Add(offset))
		if err != nil {
			t.Fatalf("GenerateCode: %v", err)
		}
		if _, err := VerifyTOTP(enrollment.Secret, code, now); !errors.Is(err, ErrTOTPInvalid) {
			t.Errorf("code from offset %s accepted: err = %v", offset, err)
		}
	}
}

func TestVerifyTOTPRejectsBadInput(t *testing.T) {
	enrollment, err := GenerateTOTPEnrollment("", "root")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}
	now := time.Now()

	if _, err := VerifyTOTP("", "123456", now); !errors.Is(err, ErrTOTPNotEnrolled) {
		t.Errorf("empty secret: err = %v, want ErrTOTPNotEnrolled", err)
	}
	if _, err := VerifyTOTP(enrollment.Secret, "", now); !errors.Is(err, ErrTOTPInvalid) {
		t.Errorf("empty code: err = %v, want ErrTOTPInvalid", err)
	}

	for _, code := range []string{"000000", "12345", "1234567", "abcdef", "  1234  "} {
		if _, err := VerifyTOTP(enrollment.Secret, code, now); err == nil {
			t.Errorf("code %q was accepted", code)
		}
	}

	// A malformed secret must fail closed rather than panic.
	if _, err := VerifyTOTP("not-base32!!", "123456", now); err == nil {
		t.Error("a malformed secret produced no error")
	}
}

func TestTOTPStepAdvancesWithPeriod(t *testing.T) {
	base := time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)

	if TOTPStep(base) != TOTPStep(base.Add(totpPeriod-time.Second)) {
		t.Error("the step changed inside a single period")
	}
	if TOTPStep(base) == TOTPStep(base.Add(totpPeriod)) {
		t.Error("the step did not change after a full period")
	}
	if TOTPStep(base.Add(totpPeriod)) != TOTPStep(base)+1 {
		t.Error("the step did not advance by exactly one per period")
	}
}

// TestTOTPQRCodeURLHidesSecret matters because the enrollment URI is exactly the
// kind of string that ends up pasted into a bug report.
func TestTOTPQRCodeURLHidesSecret(t *testing.T) {
	enrollment, err := GenerateTOTPEnrollment("", "root")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}

	safe := TOTPQRCodeURL(enrollment.URI)
	if strings.Contains(safe, enrollment.Secret) {
		t.Errorf("the secret survived redaction: %s", safe)
	}
	if !strings.Contains(safe, "otpauth") {
		t.Errorf("redaction destroyed the URL: %s", safe)
	}

	if got := TOTPQRCodeURL("://not a url"); !strings.Contains(got, "UNPARSABLE") {
		t.Errorf("an unparsable URI was echoed: %s", got)
	}
}
