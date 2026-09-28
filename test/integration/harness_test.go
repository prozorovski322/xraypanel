//go:build integration

// Package integration exercises the panel against a real PostgreSQL.
//
// The database comes from TEST_DATABASE_URL and the tests skip when it is unset, so
// `go test ./...` stays runnable with no infrastructure. The URL indirection is also
// what lets the same suite run against a natively installed PostgreSQL today and
// against a testcontainers-managed one later, without touching a line of test code.
//
// Every test truncates the tables it touches rather than relying on a fresh
// database. That keeps a run fast enough to be worth running often, which matters
// more for catching regressions than isolation-by-construction does.
package integration

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xraypanel/panel/internal/auth"
	"github.com/xraypanel/panel/internal/crypto"
	"github.com/xraypanel/panel/internal/postgres"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
	"github.com/xraypanel/panel/internal/service"
)

const testDatabaseEnv = "TEST_DATABASE_URL"

var migrateOnce sync.Once

// testMasterKey is fixed so that tokens issued in one test can be checked in
// another. It is not a secret; the database it protects is disposable.
var testMasterKey = []byte("0123456789abcdef0123456789abcdef")

// clock is a settable time source shared by the service and the token signer, so a
// test can step past a lockout window without sleeping.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

// newClock starts at the real present rather than a fixed date.
//
// The panel supplies every timestamp it later compares, but columns with a now()
// default (created_at) are still stamped by the database. Starting in a fictional
// past would put those rows in the future relative to the test clock.
func newClock() *clock {
	return &clock{now: time.Now().UTC().Truncate(time.Second)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type env struct {
	t     *testing.T
	pool  *pgxpool.Pool
	q     *dbgen.Queries
	svc   *auth.Service
	res   *service.Service
	sign  *auth.TokenSigner
	clock *clock
	cfg   auth.Config
}

// newEnv prepares a test environment: a migrated database, empty auth tables, and a
// wired service on a controllable clock.
func newEnv(t *testing.T) *env {
	t.Helper()

	dsn := os.Getenv(testDatabaseEnv)
	if dsn == "" {
		t.Skipf("%s is not set; skipping integration test", testDatabaseEnv)
	}

	ctx := context.Background()

	migrateOnce.Do(func() {
		if err := postgres.Migrate(ctx, dsn); err != nil {
			t.Fatalf("migrate test database: %v", err)
		}
	})

	pool, err := postgres.Connect(ctx, postgres.PoolConfig{
		DSN:             dsn,
		MaxConns:        8,
		MinConns:        1,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: 30 * time.Minute,
		ConnectTimeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)

	truncate(t, pool)

	clk := newClock()

	signer, err := auth.NewTokenSigner(testMasterKey, 15*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenSigner: %v", err)
	}
	signer.SetClock(clk.Now)

	cipher, err := crypto.NewCipher(testMasterKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	// Argon2 is deliberately cheap here. Production cost is asserted in the crypto
	// package; paying it on every login in this suite would make the tests something
	// nobody runs.
	argon := crypto.DefaultArgon2Params()
	argon.Memory = 8 * 1024
	argon.Iterations = 1

	cfg := auth.Config{
		RefreshTTL:        24 * time.Hour,
		LoginMaxAttempts:  3,
		LoginWindow:       15 * time.Minute,
		LoginLockout:      15 * time.Minute,
		MinPasswordLength: 12,
		TOTPIssuer:        "panel.test",
		Argon:             argon,
		Clock:             clk.Now,
	}

	queries := dbgen.New(pool)
	svc, err := auth.NewService(pool, queries, signer, cipher,
		slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn})), cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	resourceSvc := service.New(pool, queries, cipher,
		slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn})),
		clk.Now, service.Config{SubscriptionUpdateHours: 12, ProfileTitle: "test"})

	return &env{
		t: t, pool: pool, q: queries,
		svc: svc, res: resourceSvc,
		sign: signer, clock: clk, cfg: cfg,
	}
}

// newService builds a second service over the same database and clock.
//
// It is what a second panel process, or the same one after a restart, looks like: no
// in-memory state carried over, and everything that has to survive read back from the
// database.
func (e *env) newService() *service.Service {
	e.t.Helper()

	cipher, err := crypto.NewCipher(testMasterKey)
	if err != nil {
		e.t.Fatalf("NewCipher: %v", err)
	}

	return service.New(e.pool, e.q, cipher,
		slog.New(slog.NewTextHandler(testWriter{e.t}, &slog.HandlerOptions{Level: slog.LevelWarn})),
		e.clock.Now, service.Config{SubscriptionUpdateHours: 12, ProfileTitle: "test"})
}

// testWriter routes service logs into the test output, so a warning the service
// swallows still shows up when the test that it explains fails.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("service log: %s", p)
	return len(p), nil
}

// truncate empties the tables the auth suite touches. RESTART IDENTITY keeps
// generated ids small and predictable across tests.
func truncate(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	// Every table a test touches. Missing one lets a previous test's rows leak into the
	// next, which shows up as an assertion that fails only when tests run in a
	// particular order.
	const stmt = `TRUNCATE TABLE
		admin_sessions, login_attempts, api_keys, audit_log, admins,
		user_groups, inbound_group_members, inbound_groups,
		node_inbounds, hosts, inbounds, reality_keys,
		node_enrollment_tokens, nodes, pki,
		traffic_records, traffic_daily, traffic_batches,
		webhook_deliveries, webhook_endpoints,
		idempotency_keys, users
		RESTART IDENTITY CASCADE`

	if _, err := pool.Exec(context.Background(), stmt); err != nil {
		t.Fatalf("truncate auth tables: %v", err)
	}
}

// createAdmin adds an administrator and returns its id.
func (e *env) createAdmin(username, password string) int64 {
	e.t.Helper()

	admin, err := e.svc.CreateAdmin(context.Background(), auth.CreateAdminInput{
		Username: username,
		Password: password,
		Role:     auth.RoleSuperadmin,
	})
	if err != nil {
		e.t.Fatalf("CreateAdmin(%q): %v", username, err)
	}
	return admin.ID
}

// countAuditEntries reports how many audit rows carry an action.
func (e *env) countAuditEntries(action string) int {
	e.t.Helper()

	var count int
	err := e.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&count)
	if err != nil {
		e.t.Fatalf("count audit entries: %v", err)
	}
	return count
}

// activeSessions reports how many unrevoked sessions an administrator has.
func (e *env) activeSessions(adminID int64) int64 {
	e.t.Helper()

	count, err := e.q.CountActiveAdminSessions(context.Background(), dbgen.CountActiveAdminSessionsParams{
		AdminID: adminID,
		Now:     e.clock.Now(),
	})
	if err != nil {
		e.t.Fatalf("CountActiveAdminSessions: %v", err)
	}
	return count
}
