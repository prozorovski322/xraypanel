package config

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

// Backup is the configuration of the backup service. It shares the loader with the panel
// so that validation reads and reports the same way, and nothing else: the backup service
// needs the database and a directory, not the secret key.
type Backup struct {
	DSN string
	Dir string

	Interval time.Duration
	Keep     int
	MaxAge   time.Duration
	Timeout  time.Duration

	PGDump    string
	PGRestore string

	Log Log
}

// LoadBackup reads the backup service's configuration from the process environment.
func LoadBackup() (*Backup, error) { return LoadBackupFrom(os.LookupEnv) }

// LoadBackupFrom reads it from an arbitrary lookup.
func LoadBackupFrom(lookup LookupFunc) (*Backup, error) {
	l := newLoader(lookup)

	cfg := &Backup{
		DSN: l.required("DATABASE_URL"),
		Dir: l.str("BACKUP_DIR", "/backups"),

		Interval: l.duration("BACKUP_INTERVAL", 24*time.Hour, time.Minute, 30*24*time.Hour),
		Keep:     l.intVal("BACKUP_KEEP", 14, 1, 10_000),
		MaxAge:   l.duration("BACKUP_MAX_AGE", 30*24*time.Hour, time.Hour, 10*365*24*time.Hour),
		Timeout:  l.duration("BACKUP_TIMEOUT", time.Hour, time.Minute, 24*time.Hour),

		PGDump:    l.str("PG_DUMP_BINARY", "pg_dump"),
		PGRestore: l.str("PG_RESTORE_BINARY", "pg_restore"),

		Log: Log{
			Level:  l.enum("LOG_LEVEL", "info", "debug", "info", "warn", "error"),
			Format: l.enum("LOG_FORMAT", "json", "json", "text"),
		},
	}

	if cfg.DSN != "" && !isPostgresDSN(cfg.DSN) {
		l.errs = append(l.errs, errors.New("DATABASE_URL: must be a postgres:// or postgresql:// URL"))
	}
	// An age limit shorter than the interval keeps one dump at a time, which is a backup
	// with no history: the one bad night is the one copy there is.
	if cfg.MaxAge < cfg.Interval {
		l.errs = append(l.errs, fmt.Errorf(
			"BACKUP_MAX_AGE: must not be shorter than BACKUP_INTERVAL (%s < %s)", cfg.MaxAge, cfg.Interval))
	}

	if len(l.errs) > 0 {
		msgs := make([]string, 0, len(l.errs))
		for _, err := range l.errs {
			msgs = append(msgs, "  - "+err.Error())
		}
		slices.Sort(msgs)
		return nil, fmt.Errorf("invalid configuration (%d problem(s)):\n%s", len(msgs), strings.Join(msgs, "\n"))
	}
	return cfg, nil
}
