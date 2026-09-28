package auth

import "errors"

// Errors a caller is expected to branch on.
//
// The split between them is deliberately coarser at the HTTP boundary than it is
// here: a handler reports "invalid credentials" for several of these, because
// telling a caller whether a username exists, whether the password was right but
// the account is disabled, or whether 2FA is the missing piece hands an attacker a
// free oracle. The distinction exists so the audit log and the operator's log can
// record what actually happened.
var (
	// ErrInvalidCredentials means the username or password did not match.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")

	// ErrAccountDisabled means the credentials were right but the account is off.
	ErrAccountDisabled = errors.New("auth: account disabled")

	// ErrThrottled means the caller has failed too often and must wait.
	ErrThrottled = errors.New("auth: too many attempts")

	// ErrTOTPRequired means the password was accepted and a second factor is now
	// needed.
	ErrTOTPRequired = errors.New("auth: totp required")

	// ErrTOTPInvalid means the submitted code did not verify.
	ErrTOTPInvalid = errors.New("auth: invalid totp code")

	// ErrTOTPReplayed means the code was valid but already used. It is separate
	// from ErrTOTPInvalid because it is a signal worth alerting on: someone is
	// submitting a code they observed rather than one they generated.
	ErrTOTPReplayed = errors.New("auth: totp code already used")

	// ErrTOTPNotEnrolled means an operation needs a stored secret and there is
	// none.
	ErrTOTPNotEnrolled = errors.New("auth: totp not enrolled")

	// ErrTOTPAlreadyEnabled means enrollment was attempted while 2FA is already on.
	ErrTOTPAlreadyEnabled = errors.New("auth: totp already enabled")

	// ErrInvalidToken covers a malformed, expired, or wrongly signed token.
	ErrInvalidToken = errors.New("auth: invalid token")

	// ErrSessionReplayed means a refresh token that was already rotated or revoked
	// was presented again. The whole chain is revoked when this happens.
	ErrSessionReplayed = errors.New("auth: refresh token replayed")

	// ErrForbidden means the caller is authenticated but lacks the scope.
	ErrForbidden = errors.New("auth: forbidden")

	// ErrWeakPassword means the password is below the configured minimum.
	ErrWeakPassword = errors.New("auth: password too weak")

	// ErrUsernameTaken means an administrator with that username already exists.
	ErrUsernameTaken = errors.New("auth: username already taken")
)
