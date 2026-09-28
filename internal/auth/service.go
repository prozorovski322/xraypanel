package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xraypanel/panel/internal/crypto"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// Encryption purposes for secrets this package stores.
const totpSecretPurpose = "admin.totp_secret" //nolint:gosec // a label, not a secret

// ipFailureMultiplier loosens the per-IP threshold relative to the per-username
// one. A single address can legitimately carry several administrators behind NAT,
// so the IP counter is a backstop against spraying rather than a primary limit.
const ipFailureMultiplier = 3

// Config holds the tunables the service needs.
type Config struct {
	RefreshTTL        time.Duration
	LoginMaxAttempts  int
	LoginWindow       time.Duration
	LoginLockout      time.Duration
	MinPasswordLength int
	TOTPIssuer        string
	Argon             crypto.Argon2Params

	// Clock is injectable so that lockout windows and expiry can be tested without
	// sleeping. Production leaves it nil and gets time.Now.
	Clock func() time.Time
}

// txBeginner is the part of a connection pool this service needs. Narrowing it
// keeps the dependency honest: the service starts transactions and nothing else.
type txBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Service implements administrator authentication.
//
// Unlike the rest of this package it is not unit-testable without a database, and
// deliberately so: every security property here is about what the database
// atomically agrees to, and a fake store would test the fake. The pure parts
// (tokens, scopes, TOTP, key format) are unit-tested separately, and this type is
// covered by integration tests against a real PostgreSQL.
type Service struct {
	pool   txBeginner
	q      *dbgen.Queries
	signer *TokenSigner
	cipher *crypto.Cipher
	log    *slog.Logger
	cfg    Config
	now    func() time.Time

	// decoyHash is verified when the username does not exist, so a missing account
	// costs the same time as a wrong password. Without it, response latency alone
	// enumerates valid usernames.
	decoyHash string
}

// NewService builds the authentication service.
func NewService(
	pool txBeginner,
	q *dbgen.Queries,
	signer *TokenSigner,
	cipher *crypto.Cipher,
	logger *slog.Logger,
	cfg Config,
) (*Service, error) {
	if cfg.RefreshTTL <= 0 {
		return nil, errors.New("auth: refresh ttl must be positive")
	}
	if cfg.LoginMaxAttempts <= 0 {
		return nil, errors.New("auth: login max attempts must be positive")
	}
	if cfg.MinPasswordLength <= 0 {
		cfg.MinPasswordLength = 12
	}

	// Computed once at startup rather than per failed login: the point is to match
	// the cost of a real verification, not to add a fresh hash to every attempt.
	decoySecret, err := crypto.RandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("auth: generate decoy secret: %w", err)
	}
	decoyHash, err := crypto.HashPassword(decoySecret, cfg.Argon)
	if err != nil {
		return nil, fmt.Errorf("auth: build decoy hash: %w", err)
	}

	now := cfg.Clock
	if now == nil {
		now = time.Now
	}

	return &Service{
		pool:      pool,
		q:         q,
		signer:    signer,
		cipher:    cipher,
		log:       logger,
		cfg:       cfg,
		now:       now,
		decoyHash: decoyHash,
	}, nil
}

// Principal is an authenticated caller: either a human administrator holding an
// access token, or a machine holding an API key.
type Principal struct {
	IsAdmin  bool
	AdminID  int64
	Username string
	Role     string

	IsAPIKey   bool
	APIKeyID   int64
	APIKeyName string
	Scopes     []string
}

// Can reports whether the principal may perform an action.
//
// An administrator is checked by role and an API key by its granted scopes. Both
// funnel through one method so a handler never has to remember which kind of
// caller it is looking at.
func (p *Principal) Can(scope string) bool {
	switch {
	case p == nil:
		return false
	case p.IsAdmin:
		return RoleAllows(p.Role, scope)
	case p.IsAPIKey:
		return HasScope(p.Scopes, scope)
	default:
		return false
	}
}

// Admin returns the administrator id and whether the principal is one.
//
// It is nil-safe so a handler reached without the authentication middleware denies
// the request instead of panicking: a wiring mistake should surface as a 403, not
// as a crash that takes down every other request in flight.
func (p *Principal) Admin() (int64, bool) {
	if p == nil || !p.IsAdmin {
		return 0, false
	}
	return p.AdminID, true
}

// Label identifies the principal in audit entries.
func (p *Principal) Label() string {
	switch {
	case p == nil:
		return "anonymous"
	case p.IsAdmin:
		return p.Username
	case p.IsAPIKey:
		return "api-key:" + p.APIKeyName
	default:
		return "unknown"
	}
}

// LoginInput is a password login attempt.
type LoginInput struct {
	Username  string
	Password  string
	IP        netip.Addr
	UserAgent string
}

// Tokens is a freshly issued token pair.
type Tokens struct {
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
}

// LoginResult reports the outcome of a login or refresh.
type LoginResult struct {
	// MFARequired means the password was correct and a TOTP code is now needed.
	// Tokens is empty in that case and MFAToken carries the ticket.
	MFARequired bool
	MFAToken    string
	MFAExpires  time.Time

	Tokens   Tokens
	AdminID  int64
	Username string
	Role     string
}

// Login verifies a username and password.
func (s *Service) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	ip := normalizeIP(in.IP)

	if err := s.checkThrottle(ctx, in.Username, ip); err != nil {
		return nil, err
	}

	admin, err := s.q.GetAdminByUsername(ctx, in.Username)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("auth: load admin: %w", err)
		}
		// Spend the same time as a real verification before failing, so latency
		// does not distinguish a missing account from a wrong password.
		_, _, _ = crypto.VerifyPassword(in.Password, s.decoyHash)
		s.recordAttempt(ctx, in.Username, ip, false)
		return nil, ErrInvalidCredentials
	}

	match, needsRehash, err := crypto.VerifyPassword(in.Password, admin.PasswordHash)
	if err != nil {
		// A corrupt stored hash is an operational fault, not a failed login, and
		// must not be reported to the caller as bad credentials.
		return nil, fmt.Errorf("auth: stored password hash for %q is unusable: %w", in.Username, err)
	}
	if !match {
		s.recordAttempt(ctx, in.Username, ip, false)
		return nil, ErrInvalidCredentials
	}

	if !admin.IsActive {
		// Counted as a failure so that a disabled account cannot be used as an
		// unlimited password oracle.
		s.recordAttempt(ctx, in.Username, ip, false)
		return nil, ErrAccountDisabled
	}

	if needsRehash {
		s.rehashPassword(ctx, admin.ID, in.Password)
	}

	// The failure counter is deliberately NOT cleared here.
	//
	// With 2FA on, a correct password is only half a login. Clearing the counter now
	// would let someone who already knows the password brute-force the six digit code
	// indefinitely: each wrong code costs one failure, and redoing the password step
	// would wipe it. It is cleared in completeLogin, once a session really exists.
	s.recordAttempt(ctx, in.Username, ip, true)

	if admin.TotpEnabled {
		token, expires, err := s.signer.IssueMFAToken(admin.ID)
		if err != nil {
			return nil, err
		}
		s.audit(ctx, auditEntry{
			actorType: "admin", actorID: &admin.ID, actorLabel: admin.Username,
			action: "auth.login.password_ok", entityType: "admin",
			entityID: fmt.Sprint(admin.ID), ip: &ip,
		})
		return &LoginResult{
			MFARequired: true,
			MFAToken:    token,
			MFAExpires:  expires,
			AdminID:     admin.ID,
			Username:    admin.Username,
			Role:        admin.Role,
		}, nil
	}

	return s.completeLogin(ctx, admin, in.UserAgent, ip, "auth.login")
}

// CompleteMFAInput finishes a login that needed a second factor.
type CompleteMFAInput struct {
	MFAToken  string
	Code      string
	IP        netip.Addr
	UserAgent string
}

// CompleteMFA verifies a TOTP code against an outstanding MFA ticket.
func (s *Service) CompleteMFA(ctx context.Context, in CompleteMFAInput) (*LoginResult, error) {
	ip := normalizeIP(in.IP)

	adminID, err := s.signer.ParseMFAToken(in.MFAToken)
	if err != nil {
		return nil, err
	}

	admin, err := s.q.GetAdminByID(ctx, adminID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("auth: load admin: %w", err)
	}
	if !admin.IsActive {
		return nil, ErrAccountDisabled
	}
	if !admin.TotpEnabled || admin.TotpSecret == nil {
		// 2FA was turned off between issuing the ticket and using it. Refusing is
		// safer than silently upgrading a half-authenticated ticket to a session.
		return nil, ErrTOTPNotEnrolled
	}

	// The code counts towards the lockout, so a stolen MFA ticket cannot be used
	// to brute-force six digits.
	if err := s.checkThrottle(ctx, admin.Username, ip); err != nil {
		return nil, err
	}

	secret, err := s.cipher.DecryptString(admin.TotpSecret, totpSecretPurpose)
	if err != nil {
		return nil, fmt.Errorf("auth: decrypt totp secret: %w", err)
	}

	step, err := VerifyTOTP(secret, in.Code, s.now())
	if err != nil {
		s.recordAttempt(ctx, admin.Username, ip, false)
		return nil, err
	}

	if err := s.consumeTOTPStep(ctx, admin.ID, step); err != nil {
		s.recordAttempt(ctx, admin.Username, ip, false)
		return nil, err
	}

	s.recordAttempt(ctx, admin.Username, ip, true)

	return s.completeLogin(ctx, admin, in.UserAgent, ip, "auth.login.mfa")
}

// RefreshInput rotates a refresh token.
type RefreshInput struct {
	RefreshToken string
	IP           netip.Addr
	UserAgent    string
}

// Refresh exchanges a refresh token for a new pair and invalidates the old one.
//
// Presenting a token that was already rotated or revoked is treated as evidence of
// theft: the entire chain descended from that login is revoked and the
// administrator's access tokens are invalidated. That is strict by design. The
// alternative, tolerating reuse, is exactly what makes rotation decorative, since
// a stolen token would then keep working alongside the legitimate one.
func (s *Service) Refresh(ctx context.Context, in RefreshInput) (*LoginResult, error) {
	ip := normalizeIP(in.IP)
	tokenHash := crypto.HashToken(in.RefreshToken)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	qtx := s.q.WithTx(tx)

	session, err := qtx.LockSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("auth: load session: %w", err)
	}

	if session.RevokedAt != nil {
		revoked, chainErr := qtx.RevokeSessionChain(ctx, dbgen.RevokeSessionChainParams{
			ChainID:   session.ChainID,
			RevokedAt: &[]time.Time{s.now()}[0],
		})
		if chainErr != nil {
			return nil, fmt.Errorf("auth: revoke chain: %w", chainErr)
		}
		if err := qtx.InvalidateAdminTokens(ctx, dbgen.InvalidateAdminTokensParams{
			ID:              session.AdminID,
			TokensValidFrom: s.invalidationMark(),
		}); err != nil {
			return nil, fmt.Errorf("auth: invalidate access tokens: %w", err)
		}
		s.auditTx(ctx, qtx, auditEntry{
			actorType: "system", actorLabel: "auth",
			action: "auth.refresh.replay_detected", entityType: "admin",
			entityID: fmt.Sprint(session.AdminID), ip: &ip,
		})
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("auth: commit chain revocation: %w", err)
		}

		s.log.WarnContext(ctx, "revoked refresh token replayed; chain revoked",
			slog.Int64("admin_id", session.AdminID),
			slog.Int64("sessions_revoked", revoked),
			slog.String("remote_addr", ip.String()))
		return nil, ErrSessionReplayed
	}

	if !s.now().Before(session.ExpiresAt) {
		return nil, ErrInvalidToken
	}

	admin, err := qtx.GetAdminByID(ctx, session.AdminID)
	if err != nil {
		return nil, fmt.Errorf("auth: load admin: %w", err)
	}
	if !admin.IsActive {
		return nil, ErrAccountDisabled
	}

	if _, err := qtx.RevokeSession(ctx, dbgen.RevokeSessionParams{
		ID:        session.ID,
		RevokedAt: &[]time.Time{s.now()}[0],
	}); err != nil {
		return nil, fmt.Errorf("auth: revoke rotated session: %w", err)
	}

	tokens, err := s.issueSession(ctx, qtx, admin, in.UserAgent, ip, &session)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("auth: commit rotation: %w", err)
	}

	return &LoginResult{
		Tokens:   *tokens,
		AdminID:  admin.ID,
		Username: admin.Username,
		Role:     admin.Role,
	}, nil
}

// Logout revokes a single refresh token. An unknown token is not an error: the
// caller wanted to be logged out and they are.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	session, err := s.q.GetSessionByTokenHash(ctx, crypto.HashToken(refreshToken))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("auth: load session: %w", err)
	}
	if _, err := s.q.RevokeSession(ctx, dbgen.RevokeSessionParams{
		ID:        session.ID,
		RevokedAt: &[]time.Time{s.now()}[0],
	}); err != nil {
		return fmt.Errorf("auth: revoke session: %w", err)
	}
	return nil
}

// LogoutEverywhere revokes every session and invalidates outstanding access
// tokens for an administrator.
func (s *Service) LogoutEverywhere(ctx context.Context, adminID int64) error {
	if _, err := s.q.RevokeAllAdminSessions(ctx, dbgen.RevokeAllAdminSessionsParams{
		AdminID:   adminID,
		RevokedAt: &[]time.Time{s.now()}[0],
	}); err != nil {
		return fmt.Errorf("auth: revoke sessions: %w", err)
	}
	if err := s.q.InvalidateAdminTokens(ctx, dbgen.InvalidateAdminTokensParams{
		ID:              adminID,
		TokensValidFrom: s.invalidationMark(),
	}); err != nil {
		return fmt.Errorf("auth: invalidate access tokens: %w", err)
	}
	return nil
}

// Authenticate resolves an access token to a principal.
func (s *Service) Authenticate(ctx context.Context, accessToken string) (*Principal, error) {
	claims, err := s.signer.ParseAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	adminID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		return nil, ErrInvalidToken
	}

	admin, err := s.q.GetAdminByID(ctx, adminID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("auth: load admin: %w", err)
	}
	if !admin.IsActive {
		return nil, ErrAccountDisabled
	}

	// A signature-valid token is still refused if it predates the account's
	// validity mark. This is what makes a password change, a 2FA change or a
	// "sign out everywhere" take effect now rather than when the token expires.
	if claims.IssuedAt.Time.Before(admin.TokensValidFrom) {
		return nil, ErrInvalidToken
	}

	return &Principal{
		IsAdmin:  true,
		AdminID:  admin.ID,
		Username: admin.Username,
		Role:     admin.Role,
	}, nil
}

// AuthenticateAPIKey resolves an API key to a principal.
func (s *Service) AuthenticateAPIKey(ctx context.Context, presented string) (*Principal, error) {
	_, hash, err := ParseAPIKey(presented)
	if err != nil {
		return nil, err
	}

	key, err := s.q.GetAPIKeyByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("auth: load api key: %w", err)
	}
	if key.RevokedAt != nil {
		return nil, ErrInvalidToken
	}
	if key.ExpiresAt != nil && !s.now().Before(*key.ExpiresAt) {
		return nil, ErrInvalidToken
	}

	// Best effort: a failed bookkeeping update must not fail the request.
	if err := s.q.TouchAPIKeyUsage(ctx, dbgen.TouchAPIKeyUsageParams{
		ID:         key.ID,
		LastUsedAt: &[]time.Time{s.now()}[0],
	}); err != nil {
		s.log.WarnContext(ctx, "could not record api key usage",
			slog.Int64("api_key_id", key.ID), slog.Any("error", err))
	}

	return &Principal{
		IsAPIKey:   true,
		APIKeyID:   key.ID,
		APIKeyName: key.Name,
		Scopes:     key.Scopes,
	}, nil
}

func (s *Service) completeLogin(
	ctx context.Context,
	admin dbgen.Admin,
	userAgent string,
	ip netip.Addr,
	action string,
) (*LoginResult, error) {
	tokens, err := s.issueSession(ctx, s.q, admin, userAgent, ip, nil)
	if err != nil {
		return nil, err
	}

	// Only a completed login clears the counter, so an earlier typo does not carry
	// over to the next visit while a half-finished login still counts.
	if _, err := s.q.ClearLoginFailures(ctx, admin.Username); err != nil {
		s.log.WarnContext(ctx, "could not clear login failures",
			slog.String("username", admin.Username), slog.Any("error", err))
	}

	if err := s.q.TouchAdminLogin(ctx, dbgen.TouchAdminLoginParams{
		ID:          admin.ID,
		LastLoginAt: &[]time.Time{s.now()}[0],
	}); err != nil {
		s.log.WarnContext(ctx, "could not record last login",
			slog.Int64("admin_id", admin.ID), slog.Any("error", err))
	}

	s.audit(ctx, auditEntry{
		actorType: "admin", actorID: &admin.ID, actorLabel: admin.Username,
		action: action, entityType: "admin", entityID: fmt.Sprint(admin.ID), ip: &ip,
	})

	return &LoginResult{
		Tokens:   *tokens,
		AdminID:  admin.ID,
		Username: admin.Username,
		Role:     admin.Role,
	}, nil
}

// issueSession mints a token pair. parent is non-nil when rotating, which keeps the
// new session in the same revocation chain.
func (s *Service) issueSession(
	ctx context.Context,
	q *dbgen.Queries,
	admin dbgen.Admin,
	userAgent string,
	ip netip.Addr,
	parent *dbgen.AdminSession,
) (*Tokens, error) {
	refreshToken, err := crypto.RandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("auth: generate refresh token: %w", err)
	}

	params := dbgen.CreateSessionParams{
		AdminID:   admin.ID,
		TokenHash: crypto.HashToken(refreshToken),
		UserAgent: truncate(userAgent, 512),
		Ip:        &ip,
		ExpiresAt: s.now().Add(s.cfg.RefreshTTL),
	}
	if parent != nil {
		params.ParentID = parent.ID
		params.ChainID = parent.ChainID
	}

	session, err := q.CreateSession(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("auth: create session: %w", err)
	}

	accessToken, accessExpires, err := s.signer.IssueAccessToken(admin.ID, admin.Role, admin.TokensValidFrom)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		AccessToken:      accessToken,
		AccessExpiresAt:  accessExpires,
		RefreshToken:     refreshToken,
		RefreshExpiresAt: session.ExpiresAt,
	}, nil
}

// checkThrottle denies the attempt if either counter is over its threshold and the
// most recent failure is still inside the lockout.
func (s *Service) checkThrottle(ctx context.Context, username string, ip netip.Addr) error {
	since := s.now().Add(-s.cfg.LoginWindow)

	byUser, err := s.q.LoginFailureStatsByUsername(ctx, dbgen.LoginFailureStatsByUsernameParams{
		Username: username,
		Since:    since,
	})
	if err != nil {
		return fmt.Errorf("auth: read login failures by username: %w", err)
	}
	if s.locked(byUser.Failures, byUser.LastFailureAt, s.cfg.LoginMaxAttempts) {
		return ErrThrottled
	}

	byIP, err := s.q.LoginFailureStatsByIP(ctx, dbgen.LoginFailureStatsByIPParams{
		Ip:    ip,
		Since: since,
	})
	if err != nil {
		return fmt.Errorf("auth: read login failures by ip: %w", err)
	}
	if s.locked(byIP.Failures, byIP.LastFailureAt, s.cfg.LoginMaxAttempts*ipFailureMultiplier) {
		return ErrThrottled
	}

	return nil
}

// invalidationMark returns the instant to store in tokens_valid_from.
//
// It rounds up to the next whole second, because an access token's iat is truncated
// down to a whole second. Storing the exact instant would leave a token issued
// earlier in that same second with iat equal to the mark, and the comparison in
// Authenticate treats equal as still valid. Rounding up closes that window, at the
// cost of also rejecting a token issued slightly after the invalidation, which is
// the safe direction to be wrong in.
func (s *Service) invalidationMark() time.Time {
	return s.now().Truncate(time.Second).Add(time.Second)
}

func (s *Service) locked(failures int64, lastFailureAt time.Time, threshold int) bool {
	if failures < int64(threshold) {
		return false
	}
	// lastFailureAt is only meaningful when there were failures; the query collapses
	// the empty case to the epoch, which can never be inside the lockout window.
	return s.now().Before(lastFailureAt.Add(s.cfg.LoginLockout))
}

func (s *Service) recordAttempt(ctx context.Context, username string, ip netip.Addr, success bool) {
	err := s.q.RecordLoginAttempt(ctx, dbgen.RecordLoginAttemptParams{
		Username: truncate(username, 256),
		Ip:       ip,
		Success:  success,
		At:       s.now(),
	})
	if err != nil {
		// Losing an attempt record weakens throttling, so it is worth a warning,
		// but failing the request over it would turn a logging fault into an outage.
		s.log.WarnContext(ctx, "could not record login attempt",
			slog.String("username", username), slog.Any("error", err))
	}
}

func (s *Service) consumeTOTPStep(ctx context.Context, adminID, step int64) error {
	rows, err := s.q.ConsumeTOTPStep(ctx, dbgen.ConsumeTOTPStepParams{ID: adminID, Step: &step})
	if err != nil {
		return fmt.Errorf("auth: consume totp step: %w", err)
	}
	if rows == 0 {
		return ErrTOTPReplayed
	}
	return nil
}

func (s *Service) rehashPassword(ctx context.Context, adminID int64, password string) {
	hash, err := crypto.HashPassword(password, s.cfg.Argon)
	if err != nil {
		s.log.WarnContext(ctx, "could not rehash password", slog.Any("error", err))
		return
	}
	// SetAdminPassword also moves tokens_valid_from, which would sign the admin out
	// of their other sessions during a routine login. Upgrade the hash only.
	if err := s.q.SetAdminPasswordHashOnly(ctx, dbgen.SetAdminPasswordHashOnlyParams{
		ID:           adminID,
		PasswordHash: hash,
	}); err != nil {
		s.log.WarnContext(ctx, "could not store rehashed password",
			slog.Int64("admin_id", adminID), slog.Any("error", err))
	}
}

func normalizeIP(ip netip.Addr) netip.Addr {
	if !ip.IsValid() {
		// login_attempts.ip is NOT NULL, and an unknown address is still worth
		// recording: the attempt happened.
		return netip.IPv4Unspecified()
	}
	return ip.Unmap()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// auditEntry is the internal shape of an audit record.
type auditEntry struct {
	actorType  string
	actorID    *int64
	actorLabel string
	action     string
	entityType string
	entityID   string
	ip         *netip.Addr
	diff       []byte
}

func (s *Service) audit(ctx context.Context, e auditEntry) {
	s.auditTx(ctx, s.q, e)
}

func (s *Service) auditTx(ctx context.Context, q *dbgen.Queries, e auditEntry) {
	var entityID *string
	if e.entityID != "" {
		entityID = &e.entityID
	}

	err := q.InsertAuditEntry(ctx, dbgen.InsertAuditEntryParams{
		At:         s.now(),
		ActorType:  e.actorType,
		ActorID:    e.actorID,
		ActorLabel: e.actorLabel,
		Action:     e.action,
		EntityType: e.entityType,
		EntityID:   entityID,
		Ip:         e.ip,
		Diff:       e.diff,
	})
	if err != nil {
		s.log.WarnContext(ctx, "could not write audit entry",
			slog.String("action", e.action), slog.Any("error", err))
	}
}
