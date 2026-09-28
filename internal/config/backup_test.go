package config

import (
	"strings"
	"testing"
	"time"
)

func backupEnv(values map[string]string) LookupFunc {
	return func(key string) (string, bool) {
		v, ok := values[key]
		return v, ok
	}
}

func TestBackupDefaults(t *testing.T) {
	cfg, err := LoadBackupFrom(backupEnv(map[string]string{
		"DATABASE_URL": "postgres://panel:pw@postgres:5432/panel",
	}))
	if err != nil {
		t.Fatalf("LoadBackupFrom: %v", err)
	}
	if cfg.Dir != "/backups" || cfg.Interval != 24*time.Hour || cfg.Keep != 14 ||
		cfg.MaxAge != 30*24*time.Hour || cfg.PGDump != "pg_dump" || cfg.Log.Format != "json" {
		t.Errorf("defaults are %+v", cfg)
	}
}

func TestBackupReportsEveryProblem(t *testing.T) {
	_, err := LoadBackupFrom(backupEnv(map[string]string{
		"DATABASE_URL":    "mysql://nope",
		"BACKUP_INTERVAL": "7d",
		"BACKUP_KEEP":     "0",
	}))
	if err == nil {
		t.Fatal("a broken configuration loaded")
	}
	for _, key := range []string{"DATABASE_URL", "BACKUP_INTERVAL", "BACKUP_KEEP"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("the report does not mention %s:\n%v", key, err)
		}
	}
}

func TestBackupAgeMustCoverTheInterval(t *testing.T) {
	_, err := LoadBackupFrom(backupEnv(map[string]string{
		"DATABASE_URL":    "postgres://panel@postgres/panel",
		"BACKUP_INTERVAL": "48h",
		"BACKUP_MAX_AGE":  "24h",
	}))
	if err == nil || !strings.Contains(err.Error(), "BACKUP_MAX_AGE") {
		t.Errorf("an age limit below the interval was accepted: %v", err)
	}
}

func TestBackupDoesNotNeedTheSecretKey(t *testing.T) {
	if _, err := LoadBackupFrom(backupEnv(map[string]string{
		"DATABASE_URL": "postgres://panel@postgres/panel",
	})); err != nil {
		t.Errorf("the backup service asked for more than the database: %v", err)
	}
}
