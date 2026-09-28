//go:build integration

package integration

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/xraypanel/panel/internal/auth"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

const (
	testPassword = "correct horse battery staple"
	testUsername = "root"
)

func testIP(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return addr
}

func (e *env) login(username, password, ip string) (*auth.LoginResult, error) {
	return e.svc.Login(context.Background(), auth.LoginInput{
		Username:  username,
		Password:  password,
		IP:        testIP(e.t, ip),
		UserAgent: "integration-test",
	})
}

// --- password login ---

func TestLoginSucceedsAndIssuesUsableTokens(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)

	result, err := e.login(testUsername, testPassword, "203.0.113.10")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.MFARequired {
		t.Fatal("MFA was required for an account without 2FA")
	}
	if result.Tokens.AccessToken == "" || result.Tokens.RefreshToken == "" {
		t.Fatal("login returned an empty token")
	}

	principal, err := e.svc.Authenticate(context.Background(), result.Tokens.AccessToken)
	if err != nil {
		t.Fatalf("the access token just issued did not authenticate: %v", err)
	}
	if principal.AdminID != adminID {
		t.Errorf("AdminID = %d, want %d", principal.AdminID, adminID)
	}
	if !principal.IsAdmin {
		t.Error("principal is not an admin")
	}
	if e.activeSessions(adminID) != 1 {
		t.Errorf("active sessions = %d, want 1", e.activeSessions(adminID))
	}
	if e.countAuditEntries("auth.login") != 1 {
		t.Error("the login was not recorded in the audit log")
	}
}

func TestLoginRejectsWrongPasswordAndUnknownUser(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(testUsername, testPassword)

	if _, err := e.login(testUsername, "wrong password entirely", "203.0.113.10"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("wrong password: err = %v, want ErrInvalidCredentials", err)
	}

	// A missing account must produce exactly the same error as a wrong password, or
	// the response becomes a username oracle.
	if _, err := e.login("nosuchuser", testPassword, "203.0.113.11"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("unknown user: err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginRejectsDisabledAccount(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)

	if err := e.q.SetAdminActive(context.Background(), dbgen.SetAdminActiveParams{
		ID:       adminID,
		IsActive: false,
	}); err != nil {
		t.Fatalf("SetAdminActive: %v", err)
	}

	if _, err := e.login(testUsername, testPassword, "203.0.113.10"); !errors.Is(err, auth.ErrAccountDisabled) {
		t.Errorf("err = %v, want ErrAccountDisabled", err)
	}
}

// --- throttling ---

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(testUsername, testPassword)

	const ip = "203.0.113.20"
	for i := 0; i < e.cfg.LoginMaxAttempts; i++ {
		if _, err := e.login(testUsername, "wrong", ip); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: err = %v, want ErrInvalidCredentials", i+1, err)
		}
	}

	// The correct password must now be refused too: otherwise the lockout only slows
	// an attacker who never guesses right.
	if _, err := e.login(testUsername, testPassword, ip); !errors.Is(err, auth.ErrThrottled) {
		t.Fatalf("after the threshold: err = %v, want ErrThrottled", err)
	}

	// Still locked just before the window elapses.
	e.clock.Advance(e.cfg.LoginLockout - time.Minute)
	if _, err := e.login(testUsername, testPassword, ip); !errors.Is(err, auth.ErrThrottled) {
		t.Errorf("inside the lockout: err = %v, want ErrThrottled", err)
	}

	// And allowed once it has.
	e.clock.Advance(2 * time.Minute)
	if _, err := e.login(testUsername, testPassword, ip); err != nil {
		t.Errorf("after the lockout elapsed: %v", err)
	}
}

// TestLockoutIsPerUsernameAcrossAddresses is the point of the username counter: a
// guessing run spread over many source addresses must still be stopped.
func TestLockoutIsPerUsernameAcrossAddresses(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(testUsername, testPassword)

	addresses := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
	for i, ip := range addresses {
		if _, err := e.login(testUsername, "wrong", ip); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: err = %v", i+1, err)
		}
	}

	if _, err := e.login(testUsername, testPassword, "198.51.100.99"); !errors.Is(err, auth.ErrThrottled) {
		t.Errorf("err = %v, want ErrThrottled from a fresh address", err)
	}
}

// TestSuccessfulLoginClearsFailures keeps an earlier typo from locking someone out
// on their next visit.
func TestSuccessfulLoginClearsFailures(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(testUsername, testPassword)

	const ip = "203.0.113.30"
	for i := 0; i < e.cfg.LoginMaxAttempts-1; i++ {
		if _, err := e.login(testUsername, "wrong", ip); err == nil {
			t.Fatal("a wrong password succeeded")
		}
	}
	if _, err := e.login(testUsername, testPassword, ip); err != nil {
		t.Fatalf("Login: %v", err)
	}

	// The counter is back to zero, so a fresh run of failures is needed to lock out.
	for i := 0; i < e.cfg.LoginMaxAttempts-1; i++ {
		if _, err := e.login(testUsername, "wrong", ip); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("after a success, attempt %d: err = %v", i+1, err)
		}
	}
	if _, err := e.login(testUsername, testPassword, ip); err != nil {
		t.Errorf("failures were not cleared by the successful login: %v", err)
	}
}

// --- refresh rotation and replay ---

func TestRefreshRotatesTokens(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)

	first, err := e.login(testUsername, testPassword, "203.0.113.40")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// The clock moves so the reissued access token differs from the first; without
	// it both would carry the same iat and be byte-identical.
	e.clock.Advance(time.Second)

	second, err := e.svc.Refresh(context.Background(), auth.RefreshInput{
		RefreshToken: first.Tokens.RefreshToken,
		IP:           testIP(t, "203.0.113.40"),
	})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if second.Tokens.RefreshToken == first.Tokens.RefreshToken {
		t.Error("the refresh token was not rotated")
	}
	if second.Tokens.AccessToken == first.Tokens.AccessToken {
		t.Error("the access token was not reissued")
	}
	if _, err := e.svc.Authenticate(context.Background(), second.Tokens.AccessToken); err != nil {
		t.Errorf("the rotated access token does not authenticate: %v", err)
	}
	// One active session, not two: rotation replaces rather than accumulates.
	if got := e.activeSessions(adminID); got != 1 {
		t.Errorf("active sessions = %d, want 1", got)
	}
}

// TestReplayedRefreshTokenRevokesWholeChain is the security property the whole
// rotation scheme exists for.
func TestReplayedRefreshTokenRevokesWholeChain(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)

	first, err := e.login(testUsername, testPassword, "203.0.113.50")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	e.clock.Advance(time.Second)
	second, err := e.svc.Refresh(context.Background(), auth.RefreshInput{
		RefreshToken: first.Tokens.RefreshToken,
	})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	e.clock.Advance(time.Second)
	// Presenting the already-rotated token is the signal that it was stolen.
	if _, err := e.svc.Refresh(context.Background(), auth.RefreshInput{
		RefreshToken: first.Tokens.RefreshToken,
	}); !errors.Is(err, auth.ErrSessionReplayed) {
		t.Fatalf("replaying a rotated token: err = %v, want ErrSessionReplayed", err)
	}

	// The legitimate holder loses their session too. That is intended: at this point
	// the panel cannot tell which of the two callers is the thief.
	if got := e.activeSessions(adminID); got != 0 {
		t.Errorf("active sessions = %d, want 0 after a chain revocation", got)
	}
	if _, err := e.svc.Refresh(context.Background(), auth.RefreshInput{
		RefreshToken: second.Tokens.RefreshToken,
	}); err == nil {
		t.Error("the descendant refresh token still worked after the chain was revoked")
	}

	// Access tokens are invalidated as well, otherwise the thief keeps API access
	// for the remainder of the token lifetime.
	if _, err := e.svc.Authenticate(context.Background(), second.Tokens.AccessToken); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("access token after chain revocation: err = %v, want ErrInvalidToken", err)
	}

	// At least one: presenting any already-revoked token from the chain is itself a
	// replay, so the descendant token checked above adds a second entry.
	if e.countAuditEntries("auth.refresh.replay_detected") < 1 {
		t.Error("the replay was not recorded in the audit log")
	}
}

func TestRefreshRejectsUnknownAndExpiredTokens(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(testUsername, testPassword)

	if _, err := e.svc.Refresh(context.Background(), auth.RefreshInput{
		RefreshToken: "not-a-real-token",
	}); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("unknown token: err = %v, want ErrInvalidToken", err)
	}

	result, err := e.login(testUsername, testPassword, "203.0.113.60")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	e.clock.Advance(e.cfg.RefreshTTL + time.Minute)
	if _, err := e.svc.Refresh(context.Background(), auth.RefreshInput{
		RefreshToken: result.Tokens.RefreshToken,
	}); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("expired token: err = %v, want ErrInvalidToken", err)
	}
}

func TestLogoutRevokesOneSessionAndLogoutAllRevokesEverything(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)

	first, err := e.login(testUsername, testPassword, "203.0.113.70")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	second, err := e.login(testUsername, testPassword, "203.0.113.71")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got := e.activeSessions(adminID); got != 2 {
		t.Fatalf("active sessions = %d, want 2", got)
	}

	if err := e.svc.Logout(context.Background(), first.Tokens.RefreshToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if got := e.activeSessions(adminID); got != 1 {
		t.Errorf("active sessions after one logout = %d, want 1", got)
	}
	// The other session must survive: signing out one browser is not signing out all.
	if _, err := e.svc.Authenticate(context.Background(), second.Tokens.AccessToken); err != nil {
		t.Errorf("the second session was affected by the first logging out: %v", err)
	}

	// An unknown token is not an error; the caller wanted to be logged out.
	if err := e.svc.Logout(context.Background(), "never-existed"); err != nil {
		t.Errorf("Logout with an unknown token: %v", err)
	}

	if err := e.svc.LogoutEverywhere(context.Background(), adminID); err != nil {
		t.Fatalf("LogoutEverywhere: %v", err)
	}
	if got := e.activeSessions(adminID); got != 0 {
		t.Errorf("active sessions after logout-all = %d, want 0", got)
	}
	if _, err := e.svc.Authenticate(context.Background(), second.Tokens.AccessToken); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("access token survived logout-all: err = %v", err)
	}
}

// --- password change ---

func TestChangePasswordInvalidatesEverything(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)

	session, err := e.login(testUsername, testPassword, "203.0.113.80")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	const newPassword = "a totally different passphrase"
	e.clock.Advance(time.Second)
	if err := e.svc.ChangePassword(context.Background(), adminID, testPassword, newPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// A password change is what someone does when they suspect compromise, so the
	// attacker's session must not survive it.
	if got := e.activeSessions(adminID); got != 0 {
		t.Errorf("active sessions = %d, want 0", got)
	}
	if _, err := e.svc.Authenticate(context.Background(), session.Tokens.AccessToken); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("the old access token still works: err = %v", err)
	}

	if _, err := e.login(testUsername, testPassword, "203.0.113.80"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Error("the old password still works")
	}
	if _, err := e.login(testUsername, newPassword, "203.0.113.80"); err != nil {
		t.Errorf("the new password does not work: %v", err)
	}
}

// TestTokenIssuedRightAfterInvalidationWorks is a regression test.
//
// The invalidation mark is rounded up to the next whole second while a token's iat is
// truncated down, so a login in the same second as a password change or a 2FA reset
// used to hand back a token that failed on first use: the login succeeded, the token
// looked older than the invalidation, and every request with it returned 401.
func TestTokenIssuedRightAfterInvalidationWorks(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)

	const newPassword = "an entirely different passphrase"
	if err := e.svc.ChangePassword(context.Background(), adminID, testPassword, newPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// No clock advance on purpose: this is the same-second case.
	result, err := e.login(testUsername, newPassword, "203.0.113.210")
	if err != nil {
		t.Fatalf("Login right after a password change: %v", err)
	}
	if _, err := e.svc.Authenticate(context.Background(), result.Tokens.AccessToken); err != nil {
		t.Fatalf("the token issued right after the password change does not authenticate: %v", err)
	}

	// The same must hold after a 2FA reset, which is the path an operator takes when
	// someone is locked out and is most likely to be scripted.
	e.enableTOTP(adminID)
	if err := e.svc.ResetTOTPByUsername(context.Background(), testUsername); err != nil {
		t.Fatalf("ResetTOTPByUsername: %v", err)
	}
	afterReset, err := e.login(testUsername, newPassword, "203.0.113.211")
	if err != nil {
		t.Fatalf("Login right after a 2FA reset: %v", err)
	}
	if _, err := e.svc.Authenticate(context.Background(), afterReset.Tokens.AccessToken); err != nil {
		t.Errorf("the token issued right after the 2FA reset does not authenticate: %v", err)
	}
}

// TestOldTokenStillDiesWhenIatIsFloored is the other half: raising iat to the
// invalidation mark must not resurrect tokens issued before it.
func TestOldTokenStillDiesWhenIatIsFloored(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)

	before, err := e.login(testUsername, testPassword, "203.0.113.212")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if err := e.svc.LogoutEverywhere(context.Background(), adminID); err != nil {
		t.Fatalf("LogoutEverywhere: %v", err)
	}

	if _, err := e.svc.Authenticate(context.Background(), before.Tokens.AccessToken); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("a token from before the invalidation survived: err = %v", err)
	}
}

func TestChangePasswordChecksCurrentAndPolicy(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)

	if err := e.svc.ChangePassword(context.Background(), adminID, "wrong current", "a valid new passphrase"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("wrong current password: err = %v, want ErrInvalidCredentials", err)
	}
	if err := e.svc.ChangePassword(context.Background(), adminID, testPassword, "short"); !errors.Is(err, auth.ErrWeakPassword) {
		t.Errorf("short new password: err = %v, want ErrWeakPassword", err)
	}
}

// --- TOTP ---

func TestTOTPEnrollmentAndLogin(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)

	enrollment, err := e.svc.BeginTOTPEnrollment(context.Background(), adminID)
	if err != nil {
		t.Fatalf("BeginTOTPEnrollment: %v", err)
	}

	// Enrollment alone must not turn 2FA on; an authenticator that failed to scan
	// would otherwise lock the account out.
	if _, err := e.login(testUsername, testPassword, "203.0.113.90"); err != nil {
		t.Fatalf("login during enrollment: %v", err)
	}

	code, err := totp.GenerateCode(enrollment.Secret, e.clock.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if err := e.svc.ConfirmTOTPEnrollment(context.Background(), adminID, code); err != nil {
		t.Fatalf("ConfirmTOTPEnrollment: %v", err)
	}

	// Password alone now yields only a ticket.
	e.clock.Advance(totpStep)
	first, err := e.login(testUsername, testPassword, "203.0.113.90")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !first.MFARequired {
		t.Fatal("2FA is enabled but the password alone produced a session")
	}
	if first.Tokens.AccessToken != "" || first.Tokens.RefreshToken != "" {
		t.Fatal("the password step issued session tokens before the second factor")
	}

	nextCode, err := totp.GenerateCode(enrollment.Secret, e.clock.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	final, err := e.svc.CompleteMFA(context.Background(), auth.CompleteMFAInput{
		MFAToken: first.MFAToken,
		Code:     nextCode,
	})
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}
	if final.Tokens.AccessToken == "" {
		t.Fatal("CompleteMFA returned no access token")
	}
	if _, err := e.svc.Authenticate(context.Background(), final.Tokens.AccessToken); err != nil {
		t.Errorf("the token from CompleteMFA does not authenticate: %v", err)
	}
}

// totpStep mirrors the period the auth package uses, so tests can move to a fresh
// code without depending on an unexported constant.
const totpStep = 30 * time.Second

// TestTOTPCodeCannotBeReplayed is why the accepted step is stored: a code observed
// over someone's shoulder stays valid for the rest of its window otherwise.
func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)
	secret := e.enableTOTP(adminID)

	e.clock.Advance(totpStep)
	code, err := totp.GenerateCode(secret, e.clock.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	first, err := e.login(testUsername, testPassword, "203.0.113.100")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := e.svc.CompleteMFA(context.Background(), auth.CompleteMFAInput{
		MFAToken: first.MFAToken,
		Code:     code,
	}); err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}

	// Same code, same time step, second use.
	second, err := e.login(testUsername, testPassword, "203.0.113.100")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := e.svc.CompleteMFA(context.Background(), auth.CompleteMFAInput{
		MFAToken: second.MFAToken,
		Code:     code,
	}); !errors.Is(err, auth.ErrTOTPReplayed) {
		t.Errorf("replayed code: err = %v, want ErrTOTPReplayed", err)
	}
}

func TestTOTPRejectsWrongCodeAndCountsTowardsLockout(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)
	e.enableTOTP(adminID)

	const ip = "203.0.113.110"
	e.clock.Advance(totpStep)

	for i := 0; i < e.cfg.LoginMaxAttempts; i++ {
		ticket, err := e.login(testUsername, testPassword, ip)
		if err != nil {
			t.Fatalf("attempt %d: Login: %v", i+1, err)
		}
		if _, err := e.svc.CompleteMFA(context.Background(), auth.CompleteMFAInput{
			MFAToken: ticket.MFAToken,
			Code:     "000000",
			IP:       testIP(t, ip),
		}); !errors.Is(err, auth.ErrTOTPInvalid) {
			t.Fatalf("attempt %d: err = %v, want ErrTOTPInvalid", i+1, err)
		}
	}

	// Guessing six digits must be rate limited, not merely wrong.
	if _, err := e.login(testUsername, testPassword, ip); !errors.Is(err, auth.ErrThrottled) {
		t.Errorf("after failed codes: err = %v, want ErrThrottled", err)
	}
}

func TestDisableTOTPRequiresPassword(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)
	e.enableTOTP(adminID)

	// A hijacked session must not be able to quietly remove the second factor.
	if err := e.svc.DisableTOTP(context.Background(), adminID, "wrong password"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("err = %v, want ErrInvalidCredentials", err)
	}

	if err := e.svc.DisableTOTP(context.Background(), adminID, testPassword); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}

	e.clock.Advance(time.Second)
	result, err := e.login(testUsername, testPassword, "203.0.113.120")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.MFARequired {
		t.Error("2FA is still required after being disabled")
	}
}

func TestReEnrollBlockedWhileEnabled(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)
	e.enableTOTP(adminID)

	// Replacing a working second factor with an unproven one would be a silent
	// downgrade.
	if _, err := e.svc.BeginTOTPEnrollment(context.Background(), adminID); !errors.Is(err, auth.ErrTOTPAlreadyEnabled) {
		t.Errorf("err = %v, want ErrTOTPAlreadyEnabled", err)
	}
}

func TestResetTOTPRecoversALostAuthenticator(t *testing.T) {
	e := newEnv(t)
	adminID := e.createAdmin(testUsername, testPassword)
	e.enableTOTP(adminID)

	if _, err := e.login(testUsername, testPassword, "203.0.113.130"); err != nil {
		t.Fatalf("Login: %v", err)
	}

	if err := e.svc.ResetTOTPByUsername(context.Background(), testUsername); err != nil {
		t.Fatalf("ResetTOTPByUsername: %v", err)
	}
	if got := e.activeSessions(adminID); got != 0 {
		t.Errorf("active sessions = %d, want 0 after a 2FA reset", got)
	}

	e.clock.Advance(time.Second)
	result, err := e.login(testUsername, testPassword, "203.0.113.130")
	if err != nil {
		t.Fatalf("Login after reset: %v", err)
	}
	if result.MFARequired {
		t.Error("2FA is still required after the reset")
	}

	if err := e.svc.ResetTOTPByUsername(context.Background(), "nosuchuser"); err == nil {
		t.Error("resetting a nonexistent administrator succeeded")
	}
}

// enableTOTP enrols and confirms 2FA, returning the secret.
func (e *env) enableTOTP(adminID int64) string {
	e.t.Helper()

	enrollment, err := e.svc.BeginTOTPEnrollment(context.Background(), adminID)
	if err != nil {
		e.t.Fatalf("BeginTOTPEnrollment: %v", err)
	}
	code, err := totp.GenerateCode(enrollment.Secret, e.clock.Now())
	if err != nil {
		e.t.Fatalf("GenerateCode: %v", err)
	}
	if err := e.svc.ConfirmTOTPEnrollment(context.Background(), adminID, code); err != nil {
		e.t.Fatalf("ConfirmTOTPEnrollment: %v", err)
	}
	return enrollment.Secret
}

// --- bootstrap ---

func TestBootstrapAdminIsCreatedOnceOnly(t *testing.T) {
	e := newEnv(t)

	created, err := e.svc.EnsureBootstrapAdmin(context.Background(), "bootstrap", testPassword)
	if err != nil {
		t.Fatalf("EnsureBootstrapAdmin: %v", err)
	}
	if !created {
		t.Fatal("the first administrator was not created")
	}

	// Running again must not touch the existing account: a password left in an env
	// file would otherwise be a standing backdoor that reasserts itself on restart.
	const changed = "an entirely different passphrase"
	admins, err := e.svc.ListAdmins(context.Background())
	if err != nil {
		t.Fatalf("ListAdmins: %v", err)
	}
	if err := e.svc.ChangePassword(context.Background(), admins[0].ID, testPassword, changed); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	created, err = e.svc.EnsureBootstrapAdmin(context.Background(), "bootstrap", testPassword)
	if err != nil {
		t.Fatalf("EnsureBootstrapAdmin (second run): %v", err)
	}
	if created {
		t.Error("a second administrator was created")
	}

	e.clock.Advance(time.Second)
	if _, err := e.login("bootstrap", changed, "203.0.113.140"); err != nil {
		t.Errorf("the changed password was reverted by the bootstrap path: %v", err)
	}
}

func TestCreateAdminRejectsDuplicateAndBadRole(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(testUsername, testPassword)

	if _, err := e.svc.CreateAdmin(context.Background(), auth.CreateAdminInput{
		Username: testUsername,
		Password: testPassword,
	}); !errors.Is(err, auth.ErrUsernameTaken) {
		t.Errorf("duplicate username: err = %v, want ErrUsernameTaken", err)
	}

	if _, err := e.svc.CreateAdmin(context.Background(), auth.CreateAdminInput{
		Username: "other",
		Password: testPassword,
		Role:     "root",
	}); err == nil {
		t.Error("an unknown role was accepted")
	}

	if _, err := e.svc.CreateAdmin(context.Background(), auth.CreateAdminInput{
		Username: "weak",
		Password: "short",
	}); !errors.Is(err, auth.ErrWeakPassword) {
		t.Error("a password below the minimum length was accepted")
	}
}
