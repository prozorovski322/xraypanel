//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xraypanel/panel/internal/backup"
	"github.com/xraypanel/panel/internal/crypto"
	"github.com/xraypanel/panel/internal/httpapi"
	"github.com/xraypanel/panel/internal/postgres"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
	"github.com/xraypanel/panel/internal/service"
)

// The acceptance criterion for backups is not that a file appears. It is that a fresh dump
// restores into an empty database, the schema is current, and a panel started on it serves
// the same data. That is what this test does, with the real pg_dump and pg_restore.

// pgTool finds a PostgreSQL client binary, preferring PG_BIN when set.
func pgTool(t *testing.T, name string) string {
	t.Helper()
	if dir := os.Getenv("PG_BIN"); dir != "" {
		for _, candidate := range []string{filepath.Join(dir, name), filepath.Join(dir, name+".exe")} {
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
	}
	path, err := exec.LookPath(name)
	if err != nil {
		// In CI a skip here would report success for a test that never ran.
		if os.Getenv("CI") != "" {
			t.Fatalf("%s not found in CI (set PG_BIN)", name)
		}
		t.Skipf("%s not found (set PG_BIN or put it on PATH); skipping the backup test", name)
	}
	return path
}

func (e *env) backupRunner(t *testing.T, dir string, keep int) *backup.Runner {
	t.Helper()
	return backup.New(backup.Config{
		DSN:       os.Getenv(testDatabaseEnv),
		Dir:       dir,
		Keep:      keep,
		MaxAge:    30 * 24 * time.Hour,
		PGDump:    pgTool(t, "pg_dump"),
		PGRestore: pgTool(t, "pg_restore"),
		Timeout:   5 * time.Minute,
	}, slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn})), e.clock.Now)
}

// dropDatabase removes a database the test created, whatever state it is in.
func dropDatabase(t *testing.T, name string) {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), os.Getenv(testDatabaseEnv))
	if err != nil {
		t.Logf("drop %s: %v", name, err)
		return
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(),
		"DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
		t.Logf("drop %s: %v", name, err)
	}
}

func TestADumpRestoresIntoAPanelThatServesTheSameData(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	sub := e.subscriber(t)

	original := e.publicGet(e.newServer(), "/sub/"+sub.token, "v2rayNG/1.10.2")
	if original.Code != http.StatusOK || original.Body.Len() == 0 {
		t.Fatalf("the original panel does not serve the subscription: %d", original.Code)
	}

	runner := e.backupRunner(t, t.TempDir(), 5)
	dump, err := runner.Backup(ctx)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if !strings.HasSuffix(dump.Name(), ".dump") || dump.Size == 0 {
		t.Fatalf("dump is %+v", dump)
	}
	if _, err := os.Stat(dump.Path + ".sha256"); err != nil {
		t.Errorf("no checksum next to the dump: %v", err)
	}
	if err := runner.Verify(ctx, dump.Path); err != nil {
		t.Fatalf("Verify of a fresh dump: %v", err)
	}

	target := fmt.Sprintf("panel_restore_%d", time.Now().UnixNano()%1_000_000)
	t.Cleanup(func() { dropDatabase(t, target) })

	if err := runner.Restore(ctx, dump.Path, target); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if err := runner.Restore(ctx, dump.Path, target); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("a second restore over the same name was not refused: %v", err)
	}

	restoredDSN := databaseURL(t, target)

	// The schema is current: nothing for goose to do.
	pending, err := postgres.PendingMigrations(ctx, restoredDSN)
	if err != nil {
		t.Fatalf("PendingMigrations on the restored database: %v", err)
	}
	if pending != 0 {
		t.Errorf("the restored database has %d pending migrations, want 0", pending)
	}

	// A panel started on it serves the same thing, byte for byte.
	pool, err := postgres.Connect(ctx, postgres.PoolConfig{
		DSN: restoredDSN, MaxConns: 4, MinConns: 0,
		ConnMaxLifetime: time.Hour, ConnMaxIdleTime: time.Minute, ConnectTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("connect to the restored database: %v", err)
	}
	t.Cleanup(pool.Close)

	cipher, err := crypto.NewCipher(testMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	restored := service.New(pool, dbgen.New(pool), cipher,
		slog.New(slog.NewTextHandler(io.Discard, nil)), e.clock.Now,
		service.Config{SubscriptionUpdateHours: 12, ProfileTitle: "test"})
	server := httpapi.NewRouter(httpapi.Deps{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), DB: pool, Service: restored, Version: "test",
	})

	req := httptest.NewRequest(http.MethodGet, "/sub/"+sub.token, nil)
	req.Header.Set("User-Agent", "v2rayNG/1.10.2")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("the restored panel answered %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != original.Body.String() {
		t.Errorf("the restored panel serves a different profile:\n got %s\nwant %s", rec.Body.String(), original.Body.String())
	}
	if got, want := rec.Header().Get("Subscription-Userinfo"), original.Header().Get("Subscription-Userinfo"); got != want {
		t.Errorf("quota header differs after restore: %q vs %q", got, want)
	}
}

// A damaged dump must be caught by the tool, not by the operator during an outage.
func TestVerificationCatchesDamagedDumps(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.subscriber(t)

	runner := e.backupRunner(t, t.TempDir(), 5)
	dump, err := runner.Backup(ctx)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	content, err := os.ReadFile(dump.Path)
	if err != nil {
		t.Fatal(err)
	}

	// Changed after it was taken: the checksum notices.
	tampered := filepath.Join(t.TempDir(), dump.Name())
	flipped := append([]byte(nil), content...)
	flipped[len(flipped)/2] ^= 0xff
	writeWithChecksum(t, tampered, flipped, content)
	if err := runner.Verify(ctx, tampered); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("a modified dump passed: %v", err)
	}

	// Truncated before its checksum was taken, as a full disk would leave it, and only by the
	// last percent: the checksum matches, pg_restore --list reads the table of contents
	// without complaint, and only reading the data back notices.
	truncated := filepath.Join(t.TempDir(), dump.Name())
	cut := content[:len(content)-max(len(content)/100, 1)]
	writeWithChecksum(t, truncated, cut, cut)
	if err := runner.Verify(ctx, truncated); err == nil {
		t.Error("a truncated dump passed verification")
	}

	// And a restore refuses both.
	if err := runner.Restore(ctx, truncated, "panel_never_created"); err == nil {
		dropDatabase(t, "panel_never_created")
		t.Error("a truncated dump was restored")
	}
}

func TestRotationKeepsTheNewest(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.subscriber(t)

	dir := t.TempDir()
	runner := e.backupRunner(t, dir, 2)
	var names []string
	for range 3 {
		dump, err := runner.Backup(ctx)
		if err != nil {
			t.Fatalf("Backup: %v", err)
		}
		names = append(names, dump.Name())
		e.clock.Advance(time.Hour)
	}

	left, err := runner.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 2 || left[0].Name() != names[2] || left[1].Name() != names[1] {
		t.Fatalf("after three backups with keep=2, left %v, want %s and %s", left, names[2], names[1])
	}
	if _, err := os.Stat(filepath.Join(dir, names[0]+".sha256")); !os.IsNotExist(err) {
		t.Error("the rotated dump's checksum file was left behind")
	}
}

func writeWithChecksum(t *testing.T, path string, content, checksummed []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sumFile := filepath.Join(t.TempDir(), "sum")
	if err := os.WriteFile(sumFile, checksummed, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256Hex(t, sumFile)
	if err := os.WriteFile(path+".sha256", []byte(sum+"  "+filepath.Base(path)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// databaseURL is the test database's URL pointed at another database.
func databaseURL(t *testing.T, database string) string {
	t.Helper()
	parsed, err := url.Parse(os.Getenv(testDatabaseEnv))
	if err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + database
	return parsed.String()
}
