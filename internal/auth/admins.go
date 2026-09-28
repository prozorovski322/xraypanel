package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/xraypanel/panel/internal/crypto"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// uniqueViolation is the PostgreSQL error code for a unique constraint breach.
const uniqueViolation = "23505"

// CreateAdminInput describes a new administrator.
type CreateAdminInput struct {
	Username string
	Password string
	Role     string
}

// CreateAdmin adds an administrator.
func (s *Service) CreateAdmin(ctx context.Context, in CreateAdminInput) (*dbgen.Admin, error) {
	username := strings.TrimSpace(in.Username)
	if username == "" {
		return nil, errors.New("auth: username must not be empty")
	}
	if in.Role == "" {
		in.Role = RoleAdmin
	}
	if in.Role != RoleSuperadmin && in.Role != RoleAdmin && in.Role != RoleViewer {
		return nil, fmt.Errorf("auth: unknown role %q", in.Role)
	}
	if err := s.CheckPasswordPolicy(username, in.Password); err != nil {
		return nil, err
	}

	hash, err := crypto.HashPassword(in.Password, s.cfg.Argon)
	if err != nil {
		return nil, fmt.Errorf("auth: hash password: %w", err)
	}

	admin, err := s.q.CreateAdmin(ctx, dbgen.CreateAdminParams{
		Username:     username,
		PasswordHash: hash,
		Role:         in.Role,
		// Stamped from the application clock, the same one that stamps a token's iat
		// claim, so a new account's first token is not rejected by clock skew.
		TokensValidFrom: s.now(),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return nil, ErrUsernameTaken
		}
		return nil, fmt.Errorf("auth: create admin: %w", err)
	}

	s.audit(ctx, auditEntry{
		actorType: "system", actorLabel: "auth",
		action: "admin.create", entityType: "admin", entityID: fmt.Sprint(admin.ID),
	})

	return &admin, nil
}

// CheckPasswordPolicy enforces the password rules.
//
// Length only, plus a check that the password is not the username. Composition
// rules ("one digit, one symbol") push people towards predictable substitutions and
// measurably weaken the result; length is what actually costs an attacker. Real
// strength here comes from the login lockout and argon2id cost, not from a regex.
func (s *Service) CheckPasswordPolicy(username, password string) error {
	if len(password) < s.cfg.MinPasswordLength {
		return fmt.Errorf("%w: must be at least %d characters",
			ErrWeakPassword, s.cfg.MinPasswordLength)
	}
	if strings.EqualFold(strings.TrimSpace(password), strings.TrimSpace(username)) {
		return fmt.Errorf("%w: must not equal the username", ErrWeakPassword)
	}
	return nil
}

// ChangePassword replaces an administrator's password after checking the current
// one.
//
// Every other session is signed out, and outstanding access tokens stop working:
// a password change is the action someone takes when they think they have been
// compromised, and it would be useless if the attacker's session survived it.
func (s *Service) ChangePassword(ctx context.Context, adminID int64, currentPassword, newPassword string) error {
	admin, err := s.q.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("auth: load admin: %w", err)
	}

	match, _, err := crypto.VerifyPassword(currentPassword, admin.PasswordHash)
	if err != nil {
		return fmt.Errorf("auth: stored password hash is unusable: %w", err)
	}
	if !match {
		return ErrInvalidCredentials
	}
	if err := s.CheckPasswordPolicy(admin.Username, newPassword); err != nil {
		return err
	}

	hash, err := crypto.HashPassword(newPassword, s.cfg.Argon)
	if err != nil {
		return fmt.Errorf("auth: hash password: %w", err)
	}

	// SetAdminPassword moves tokens_valid_from forward as part of the same
	// statement, so there is no window where the old access token still works.
	if err := s.q.SetAdminPassword(ctx, dbgen.SetAdminPasswordParams{
		ID:              adminID,
		PasswordHash:    hash,
		TokensValidFrom: s.invalidationMark(),
	}); err != nil {
		return fmt.Errorf("auth: store password: %w", err)
	}
	if _, err := s.q.RevokeAllAdminSessions(ctx, dbgen.RevokeAllAdminSessionsParams{
		AdminID:   adminID,
		RevokedAt: &[]time.Time{s.now()}[0],
	}); err != nil {
		return fmt.Errorf("auth: revoke sessions: %w", err)
	}

	s.audit(ctx, auditEntry{
		actorType: "admin", actorID: &adminID, actorLabel: admin.Username,
		action: "admin.password_change", entityType: "admin", entityID: fmt.Sprint(adminID),
	})
	return nil
}

// BeginTOTPEnrollment generates a secret and stores it without enabling 2FA.
//
// Two steps rather than one: enabling immediately would lock out anyone whose
// authenticator failed to add the entry, and recovering from that needs shell
// access to the server.
// TOTPEnabled reports whether an administrator has a second factor, for the account screen.
func (s *Service) TOTPEnabled(ctx context.Context, adminID int64) (bool, error) {
	admin, err := s.q.GetAdminByID(ctx, adminID)
	if err != nil {
		return false, fmt.Errorf("auth: read administrator: %w", err)
	}
	return admin.TotpEnabled, nil
}

func (s *Service) BeginTOTPEnrollment(ctx context.Context, adminID int64) (*TOTPEnrollment, error) {
	admin, err := s.q.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("auth: load admin: %w", err)
	}
	if admin.TotpEnabled {
		// Re-enrolling silently would replace a working second factor with an
		// unproven one.
		return nil, ErrTOTPAlreadyEnabled
	}

	enrollment, err := GenerateTOTPEnrollment(s.cfg.TOTPIssuer, admin.Username)
	if err != nil {
		return nil, err
	}

	encrypted, err := s.cipher.EncryptString(enrollment.Secret, totpSecretPurpose)
	if err != nil {
		return nil, fmt.Errorf("auth: encrypt totp secret: %w", err)
	}

	if err := s.q.StartTOTPEnrollment(ctx, dbgen.StartTOTPEnrollmentParams{
		ID:         adminID,
		TotpSecret: encrypted,
	}); err != nil {
		return nil, fmt.Errorf("auth: store totp secret: %w", err)
	}

	return enrollment, nil
}

// ConfirmTOTPEnrollment turns 2FA on once the administrator proves they can
// generate a code.
func (s *Service) ConfirmTOTPEnrollment(ctx context.Context, adminID int64, code string) error {
	admin, err := s.q.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("auth: load admin: %w", err)
	}
	if admin.TotpEnabled {
		return ErrTOTPAlreadyEnabled
	}
	if admin.TotpSecret == nil {
		return ErrTOTPNotEnrolled
	}

	secret, err := s.cipher.DecryptString(admin.TotpSecret, totpSecretPurpose)
	if err != nil {
		return fmt.Errorf("auth: decrypt totp secret: %w", err)
	}

	step, err := VerifyTOTP(secret, code, s.now())
	if err != nil {
		return err
	}

	// The confirming code is recorded as used, so it cannot immediately be replayed
	// as a login.
	if err := s.q.ConfirmTOTPEnrollment(ctx, dbgen.ConfirmTOTPEnrollmentParams{
		ID:              adminID,
		TotpLastStep:    &step,
		TokensValidFrom: s.invalidationMark(),
	}); err != nil {
		return fmt.Errorf("auth: enable totp: %w", err)
	}

	s.audit(ctx, auditEntry{
		actorType: "admin", actorID: &adminID, actorLabel: admin.Username,
		action: "admin.totp_enabled", entityType: "admin", entityID: fmt.Sprint(adminID),
	})
	return nil
}

// DisableTOTP turns 2FA off. The current password is required: otherwise a
// hijacked session could quietly remove the second factor and keep the account.
func (s *Service) DisableTOTP(ctx context.Context, adminID int64, password string) error {
	admin, err := s.q.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("auth: load admin: %w", err)
	}

	match, _, err := crypto.VerifyPassword(password, admin.PasswordHash)
	if err != nil {
		return fmt.Errorf("auth: stored password hash is unusable: %w", err)
	}
	if !match {
		return ErrInvalidCredentials
	}

	if err := s.q.DisableTOTP(ctx, dbgen.DisableTOTPParams{
		ID:              adminID,
		TokensValidFrom: s.invalidationMark(),
	}); err != nil {
		return fmt.Errorf("auth: disable totp: %w", err)
	}

	s.audit(ctx, auditEntry{
		actorType: "admin", actorID: &adminID, actorLabel: admin.Username,
		action: "admin.totp_disabled", entityType: "admin", entityID: fmt.Sprint(adminID),
	})
	return nil
}

// ResetTOTPByUsername clears 2FA without a password. It is the recovery path for a
// lost authenticator and is reachable only from the command line on the server, not
// over HTTP.
//
// This is why there are no printed recovery codes: whoever can run this already has
// shell access to the host, and a table of recovery codes would be one more secret
// to store and leak for no additional capability.
func (s *Service) ResetTOTPByUsername(ctx context.Context, username string) error {
	admin, err := s.q.GetAdminByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("auth: no administrator named %q", username)
		}
		return fmt.Errorf("auth: load admin: %w", err)
	}

	if err := s.q.DisableTOTP(ctx, dbgen.DisableTOTPParams{
		ID:              admin.ID,
		TokensValidFrom: s.invalidationMark(),
	}); err != nil {
		return fmt.Errorf("auth: disable totp: %w", err)
	}
	if _, err := s.q.RevokeAllAdminSessions(ctx, dbgen.RevokeAllAdminSessionsParams{
		AdminID:   admin.ID,
		RevokedAt: &[]time.Time{s.now()}[0],
	}); err != nil {
		return fmt.Errorf("auth: revoke sessions: %w", err)
	}

	s.audit(ctx, auditEntry{
		actorType: "system", actorLabel: "cli",
		action: "admin.totp_reset", entityType: "admin", entityID: fmt.Sprint(admin.ID),
	})
	return nil
}

// CreateAPIKeyInput describes a new API key.
type CreateAPIKeyInput struct {
	Name      string
	Scopes    []string
	CreatedBy *int64
	ExpiresAt *time.Time
}

// CreateAPIKey mints a key and stores its hash. The plaintext is returned once and
// cannot be recovered afterwards.
func (s *Service) CreateAPIKey(ctx context.Context, in CreateAPIKeyInput) (*GeneratedAPIKey, *dbgen.ApiKey, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, nil, errors.New("auth: api key name must not be empty")
	}
	if err := ValidateScopes(in.Scopes); err != nil {
		return nil, nil, err
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(s.now()) {
		return nil, nil, errors.New("auth: api key expiry must be in the future")
	}
	if in.Scopes == nil {
		// A key with no scopes can do nothing. That is the intended safe default,
		// but the column is NOT NULL, so normalise rather than relying on the driver.
		in.Scopes = []string{}
	}

	generated, err := GenerateAPIKey()
	if err != nil {
		return nil, nil, err
	}

	key, err := s.q.CreateAPIKey(ctx, dbgen.CreateAPIKeyParams{
		Name:      strings.TrimSpace(in.Name),
		KeyPrefix: generated.Prefix,
		KeyHash:   generated.Hash,
		Scopes:    in.Scopes,
		CreatedBy: in.CreatedBy,
		ExpiresAt: in.ExpiresAt,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("auth: create api key: %w", err)
	}

	s.audit(ctx, auditEntry{
		actorType: "admin", actorID: in.CreatedBy, actorLabel: "api-key:" + key.Name,
		action: "api_key.create", entityType: "api_key", entityID: fmt.Sprint(key.ID),
	})

	return generated, &key, nil
}

// RevokeAPIKey disables a key. Revoking an already revoked key is not an error.
func (s *Service) RevokeAPIKey(ctx context.Context, id int64) error {
	if _, err := s.q.RevokeAPIKey(ctx, dbgen.RevokeAPIKeyParams{
		ID:        id,
		RevokedAt: &[]time.Time{s.now()}[0],
	}); err != nil {
		return fmt.Errorf("auth: revoke api key: %w", err)
	}
	s.audit(ctx, auditEntry{
		actorType: "system", actorLabel: "auth",
		action: "api_key.revoke", entityType: "api_key", entityID: fmt.Sprint(id),
	})
	return nil
}

// ListAPIKeys returns every key, including revoked ones, so the UI can show
// history. Hashes are part of the row but are never rendered.
func (s *Service) ListAPIKeys(ctx context.Context) ([]dbgen.ApiKey, error) {
	keys, err := s.q.ListAPIKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: list api keys: %w", err)
	}
	return keys, nil
}

// ListAdmins returns every administrator.
func (s *Service) ListAdmins(ctx context.Context) ([]dbgen.Admin, error) {
	admins, err := s.q.ListAdmins(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: list admins: %w", err)
	}
	return admins, nil
}

// EnsureBootstrapAdmin creates the first administrator if there are none.
//
// It is a no-op once any administrator exists, so leaving the variables set in the
// environment is harmless. It does not update an existing account: an operator who
// changed their password should not have it silently reverted on the next restart,
// and BOOTSTRAP_ADMIN_PASSWORD living in an env file forever would make that a
// standing backdoor.
func (s *Service) EnsureBootstrapAdmin(ctx context.Context, username, password string) (bool, error) {
	count, err := s.q.CountAdmins(ctx)
	if err != nil {
		return false, fmt.Errorf("auth: count admins: %w", err)
	}
	if count > 0 {
		return false, nil
	}

	admin, err := s.CreateAdmin(ctx, CreateAdminInput{
		Username: username,
		Password: password,
		Role:     RoleSuperadmin,
	})
	if err != nil {
		return false, err
	}

	s.log.WarnContext(ctx, "created the first administrator from the environment; "+
		"remove BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD after signing in",
		slog.String("username", admin.Username))

	return true, nil
}
