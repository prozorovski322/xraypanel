// Command backup takes, checks, rotates and restores dumps of the panel's database.
//
// It runs as its own service in the production compose file, next to the panel, with
// nothing but the database URL and a volume.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/xraypanel/panel/internal/backup"
	"github.com/xraypanel/panel/internal/config"
	"github.com/xraypanel/panel/internal/logging"
)

var (
	version = "dev"
	commit  = "none"
)

const usage = `backup - database backups for the panel

Usage:
  backup run                       Take a backup every BACKUP_INTERVAL (default)
  backup once                      Take one backup now and exit
  backup list                      List the dumps, newest first
  backup verify <file>             Check a dump's checksum and read it back in full
  backup restore <file> <database> Restore a dump into a NEW database on the same server
  backup health                    Exit non-zero if the newest dump is overdue
  backup version                   Print build information

<file> is a name in BACKUP_DIR or a path. Configuration is read from the environment:
DATABASE_URL, BACKUP_DIR, BACKUP_INTERVAL, BACKUP_KEEP, BACKUP_MAX_AGE, BACKUP_TIMEOUT.
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	args := os.Args[1:]
	command := "run"
	if len(args) > 0 {
		command, args = args[0], args[1:]
	}

	switch command {
	case "version":
		fmt.Printf("backup %s (commit %s)\n", version, commit)
		return nil
	case "help", "-h", "--help":
		_, _ = os.Stdout.WriteString(usage)
		return nil
	}

	cfg, err := config.LoadBackup()
	if err != nil {
		return err
	}

	logger := logging.New(os.Stderr, logging.Options{Level: cfg.Log.Level, Format: cfg.Log.Format})
	runner := backup.New(backup.Config{
		DSN:       cfg.DSN,
		Dir:       cfg.Dir,
		Keep:      cfg.Keep,
		MaxAge:    cfg.MaxAge,
		PGDump:    cfg.PGDump,
		PGRestore: cfg.PGRestore,
		Timeout:   cfg.Timeout,
	}, logger, nil)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch command {
	case "run":
		logger.InfoContext(ctx, "backup service starting",
			slog.String("version", version),
			slog.String("database", logging.RedactDSN(cfg.DSN)),
			slog.String("dir", cfg.Dir),
			slog.Duration("interval", cfg.Interval),
			slog.Int("keep", cfg.Keep),
			slog.Duration("max_age", cfg.MaxAge))
		runner.Run(ctx, cfg.Interval)
		return nil

	case "once":
		dump, err := runner.Backup(ctx)
		if err != nil {
			return err
		}
		fmt.Println(dump.Path)
		return nil

	case "list":
		dumps, err := runner.List()
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "FILE\tTAKEN (UTC)\tSIZE")
		for _, dump := range dumps {
			fmt.Fprintf(tw, "%s\t%s\t%d\n", dump.Name(), dump.TakenAt.Format(time.RFC3339), dump.Size)
		}
		return tw.Flush()

	case "verify":
		if len(args) != 1 {
			return errors.New("verify: expected a file")
		}
		path := resolve(cfg.Dir, args[0])
		if err := runner.Verify(ctx, path); err != nil {
			return err
		}
		fmt.Printf("%s: checksum matches, all data read back\n", path)
		return nil

	case "restore":
		if len(args) != 2 {
			return errors.New("restore: expected a file and the name of a new database")
		}
		path := resolve(cfg.Dir, args[0])
		if err := runner.Restore(ctx, path, args[1]); err != nil {
			return err
		}
		fmt.Printf("restored %s into database %q\n", path, args[1])
		fmt.Println("the live database is untouched; see docs/deployment.md for switching over")
		return nil

	case "health":
		latest, err := runner.Latest()
		if err != nil {
			return err
		}
		if !backup.Healthy(latest, cfg.Interval, time.Now()) {
			if latest == nil {
				return errors.New("no backup has been taken yet")
			}
			return fmt.Errorf("the newest backup, %s, is overdue", latest.Name())
		}
		return nil

	default:
		_, _ = os.Stdout.WriteString(usage)
		return fmt.Errorf("unknown command %q", command)
	}
}

// resolve accepts either a bare file name in the backup directory or a path.
func resolve(dir, name string) string {
	if _, err := os.Stat(name); err == nil {
		return name
	}
	return filepath.Join(dir, name)
}
