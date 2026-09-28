package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver for goose
	"github.com/pressly/goose/v3"
)

// migrationsFS embeds the schema so a released binary carries its own migrations.
// A container that has the binary but not the .sql files is a failure mode worth
// designing out.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

const migrationsDir = "migrations"

// MigrationsFS exposes the embedded migrations for tooling and tests.
func MigrationsFS() embed.FS { return migrationsFS }

// Migrate applies all pending migrations.
func Migrate(ctx context.Context, dsn string) error {
	db, err := openForMigration(dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := goose.UpContext(ctx, db, migrationsDir); err != nil {
		return fmt.Errorf("postgres: apply migrations: %w", err)
	}
	return nil
}

// MigrationStatus writes the applied/pending state of every migration to the
// goose logger.
func MigrationStatus(ctx context.Context, dsn string) error {
	db, err := openForMigration(dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := goose.StatusContext(ctx, db, migrationsDir); err != nil {
		return fmt.Errorf("postgres: migration status: %w", err)
	}
	return nil
}

// PendingMigrations returns how many migrations have not been applied yet.
//
// The panel refuses to serve on a schema older than the binary expects: running
// code against a schema it was not written for corrupts data in ways that are
// much harder to notice than a failed startup.
func PendingMigrations(ctx context.Context, dsn string) (int, error) {
	db, err := openForMigration(dsn)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	current, err := goose.GetDBVersionContext(ctx, db)
	if err != nil {
		return 0, fmt.Errorf("postgres: read schema version: %w", err)
	}

	migrations, err := goose.CollectMigrations(migrationsDir, 0, goose.MaxVersion)
	if err != nil {
		return 0, fmt.Errorf("postgres: collect migrations: %w", err)
	}

	pending := 0
	for _, m := range migrations {
		if m.Version > current {
			pending++
		}
	}
	return pending, nil
}

func openForMigration(dsn string) (*sql.DB, error) {
	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return nil, fmt.Errorf("postgres: set goose dialect: %w", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open migration connection: %w", err)
	}
	return db, nil
}
