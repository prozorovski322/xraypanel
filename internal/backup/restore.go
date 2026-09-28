package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/jackc/pgx/v5"
)

// databaseName is what Restore accepts as a target: plain identifiers only, so the name
// needs no quoting in the tools' connection strings and cannot be mistaken for anything else.
var databaseName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// Restore loads a verified dump into a new database on the same server.
//
// Into a new database, never over an existing one. The live database stays untouched until
// an operator swaps names, so a restore that turns out wrong costs nothing, and there is no
// code path in this tool that can drop the data it is supposed to protect. The swap is
// documented in docs/deployment.md.
func (r *Runner) Restore(ctx context.Context, path, target string) error {
	if !databaseName.MatchString(target) {
		return fmt.Errorf("backup: %q is not a plain database name (lowercase letters, digits, underscore)", target)
	}

	if err := r.Verify(ctx, path); err != nil {
		return fmt.Errorf("backup: refusing to restore an unverified dump: %w", err)
	}

	conn, err := pgx.Connect(ctx, r.cfg.DSN)
	if err != nil {
		return fmt.Errorf("backup: connect: %w", err)
	}
	defer conn.Close(ctx)

	var exists bool
	if err := conn.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, target).Scan(&exists); err != nil {
		return fmt.Errorf("backup: look up %s: %w", target, err)
	}
	if exists {
		return fmt.Errorf("backup: database %q already exists; restore goes into a new database only", target)
	}

	// Template0: the dump carries everything, including extensions, and anything added to
	// template1 on this server would otherwise collide with it.
	create := "CREATE DATABASE " + pgx.Identifier{target}.Sanitize() + " TEMPLATE template0"
	if _, err := conn.Exec(ctx, create); err != nil {
		return fmt.Errorf("backup: create %s: %w", target, err)
	}

	targetDSN, err := withDatabase(r.cfg.DSN, target)
	if err != nil {
		return err
	}
	dbArg, env, err := connection(targetDSN)
	if err != nil {
		return err
	}

	// One transaction and stop at the first error: a half-restored database that looks
	// complete is worse than none.
	if _, err := r.tool(ctx, env, r.cfg.PGRestore,
		"--no-password", "--no-owner", "--exit-on-error", "--single-transaction",
		"--dbname="+dbArg, path); err != nil {
		// The database is empty after a rolled back single transaction, and dropping it lets
		// the operator retry with the same name. It was created a moment ago by this call,
		// so this cannot drop anything that held data before.
		if _, dropErr := conn.Exec(ctx, "DROP DATABASE "+pgx.Identifier{target}.Sanitize()); dropErr != nil {
			err = errors.Join(err, fmt.Errorf("and removing the empty %s failed: %w", target, dropErr))
		}
		return fmt.Errorf("backup: pg_restore: %w", err)
	}

	r.log.InfoContext(ctx, "dump restored", slog.String("file", path), slog.String("database", target))
	return nil
}
