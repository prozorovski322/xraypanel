// Package service holds the panel's business logic: the rules that sit between the
// HTTP surface and the database.
//
// It is one package rather than one per entity because these operations are not
// independent. Creating a user touches groups and bumps node config versions; changing
// an inbound's port has to be checked against every node carrying it. Splitting them
// would mean either circular imports or an interface per pair.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/crypto"
	"github.com/xraypanel/panel/internal/pki"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// PostgreSQL error codes the service translates into its own errors.
const (
	codeUniqueViolation     = "23505"
	codeForeignKeyViolation = "23503"
	codeCheckViolation      = "23514"
)

// Errors callers branch on. The HTTP layer maps them onto status codes.
var (
	// ErrNotFound means the addressed entity does not exist.
	ErrNotFound = errors.New("service: not found")

	// ErrConflict means a uniqueness rule was broken, such as a duplicate name.
	ErrConflict = errors.New("service: conflict")

	// ErrValidation means the request was understood and is not acceptable.
	ErrValidation = errors.New("service: validation failed")

	// ErrInUse means the entity is referenced by something else and cannot be removed.
	ErrInUse = errors.New("service: still in use")

	// ErrPortConflict is separate from ErrValidation because it is the one failure an
	// operator will hit repeatedly, and the message has to name the other inbound.
	ErrPortConflict = errors.New("service: port already used on that node")

	// ErrIdempotencyMismatch means a key was reused with a different request body.
	ErrIdempotencyMismatch = errors.New("service: idempotency key reused with a different request")

	// ErrIdempotencyInFlight means an identical request is still being processed.
	ErrIdempotencyInFlight = errors.New("service: an identical request is in flight")
)

// Encryption purposes for secrets this package stores.
const (
	purposeRealityPrivateKey = "reality.private_key"
	purposeSSServerKey       = "inbound.ss_server_key"
)

// Config holds the service's tunables.
type Config struct {
	// SubscriptionUpdateHours is advertised to clients as profile-update-interval.
	SubscriptionUpdateHours int

	// ProfileTitle names the subscription in clients that show one.
	ProfileTitle string

	// IdempotencyRetention is how long a completed key is remembered. It bounds how
	// late a retry can arrive and still be recognised.
	IdempotencyRetention time.Duration

	// EnrollmentTTL is how long a node enrollment token stays redeemable. Short by
	// default: it is a bearer secret worth a node's identity, and the window only has
	// to cover the minutes between an operator minting it and a node starting.
	EnrollmentTTL time.Duration

	// BillingLocation is the timezone billing periods are measured in. Stored times stay
	// UTC; this only decides when a day, a week or a month begins for a subscriber
	// (ADR-006). Nil means UTC.
	BillingLocation *time.Location
}

// Service implements the panel's business logic.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	cipher *crypto.Cipher
	audit  *audit.Recorder
	log    *slog.Logger
	now    func() time.Time
	cfg    Config

	// The certificate authority is read on every node connection and changes only
	// when it is first created, so it is loaded once and kept.
	caMu sync.Mutex
	ca   *pki.CA
}

// New builds the service. A nil clock means time.Now.
func New(
	pool *pgxpool.Pool,
	queries *dbgen.Queries,
	cipher *crypto.Cipher,
	logger *slog.Logger,
	now func() time.Time,
	cfg Config,
) *Service {
	if now == nil {
		now = time.Now
	}
	if cfg.SubscriptionUpdateHours <= 0 {
		cfg.SubscriptionUpdateHours = 12
	}
	if cfg.IdempotencyRetention <= 0 {
		cfg.IdempotencyRetention = 24 * time.Hour
	}
	if cfg.EnrollmentTTL <= 0 {
		cfg.EnrollmentTTL = time.Hour
	}

	return &Service{
		pool:   pool,
		q:      queries,
		cipher: cipher,
		audit:  audit.NewRecorder(queries, logger, now),
		log:    logger,
		now:    now,
		cfg:    cfg,
	}
}

// Queries exposes the generated query set, for callers that legitimately need a read
// the service does not wrap.
func (s *Service) Queries() *dbgen.Queries { return s.q }

// tx runs fn inside a transaction.
//
// The audit recorder handed to fn is bound to the same transaction, so a rolled back
// change cannot leave behind a trail entry claiming it happened.
func (s *Service) tx(ctx context.Context, fn func(*dbgen.Queries, *audit.Recorder) error) error {
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("service: begin transaction: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	queries := s.q.WithTx(transaction)

	if err := fn(queries, s.audit.WithQueries(queries)); err != nil {
		return err
	}

	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("service: commit: %w", err)
	}
	return nil
}

// translate maps a database error onto a service error.
//
// Done in one place so that every handler reports a duplicate name the same way,
// instead of some returning 500 because the translation was forgotten.
func translate(err error, what string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %s", ErrNotFound, what)
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case codeUniqueViolation:
			return fmt.Errorf("%w: %s already exists", ErrConflict, what)
		case codeForeignKeyViolation:
			// A missing parent and a still-referenced child are the same code; the
			// constraint name is what distinguishes them, and it is worth including
			// because the caller cannot otherwise tell which end was wrong.
			return fmt.Errorf("%w: %s references something that does not exist (%s)",
				ErrValidation, what, pgErr.ConstraintName)
		case codeCheckViolation:
			return fmt.Errorf("%w: %s violates %s", ErrValidation, what, pgErr.ConstraintName)
		}
	}

	return fmt.Errorf("service: %s: %w", what, err)
}

// WrapNotFound translates a raw database error for callers that read without going
// through a service method, so a missing row is reported the same way everywhere.
func WrapNotFound(err error, what string) error { return translate(err, what) }

// validationErrorf builds a validation error with a message meant for the caller.
func validationErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrValidation, fmt.Sprintf(format, args...))
}

// bumpNodesForUser marks every node serving this user as needing a new configuration.
//
// Called after anything that changes what a node should know about a user: credentials,
// group membership, or removal. The agent compares versions to decide whether to fetch,
// so a missed bump is a change that silently never reaches the node.
func (s *Service) bumpNodesForUser(ctx context.Context, queries *dbgen.Queries, userID int64) {
	if _, err := queries.BumpConfigVersionForUser(ctx, userID); err != nil {
		s.log.WarnContext(ctx, "could not bump node config versions for user",
			slog.Int64("user_id", userID), slog.Any("error", err))
	}
}

// bumpNodesForInbound marks every node carrying this inbound as needing a new
// configuration.
func (s *Service) bumpNodesForInbound(ctx context.Context, queries *dbgen.Queries, inboundID int64) {
	if _, err := queries.BumpConfigVersionForInbound(ctx, inboundID); err != nil {
		s.log.WarnContext(ctx, "could not bump node config versions for inbound",
			slog.Int64("inbound_id", inboundID), slog.Any("error", err))
	}
}
