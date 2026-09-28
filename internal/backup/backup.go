// Package backup takes, checks, rotates and restores dumps of the panel's database.
//
// A backup is part of the system rather than an operator's chore (ADR-012 defines a failed
// migration's rollback as a restore), so it runs as a service next to the panel, and it
// treats a dump nobody has read back as no dump at all: every one is verified before it is
// allowed to count, and rotation never deletes the newest verified dump.
//
// The work is done by pg_dump and pg_restore. This package is the part around them that
// is easy to get wrong in a shell script: naming, atomic publication, verification,
// rotation that cannot eat the last good copy, and keeping the password out of argv.
package backup

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// File naming. The timestamp is in the name, not only in the file's mtime, so that
// ordering survives a copy to another machine that does not preserve times.
const (
	filePrefix     = "panel-"
	fileSuffix     = ".dump"
	partialSuffix  = ".partial"
	checksumSuffix = ".sha256"
	timeLayout     = "20060102T150405Z"
)

// requiredEntries are table-of-contents lines a dump of this panel must contain. A dump of
// the wrong database, or one pg_dump wrote while seeing an empty schema, passes every
// format check and restores into nothing.
var requiredEntries = []string{
	"TABLE DATA public goose_db_version",
	"TABLE DATA public users",
	"TABLE DATA public nodes",
}

// Config is what a Runner needs.
type Config struct {
	// DSN is a postgres:// URL. Its password is passed to the tools through PGPASSWORD,
	// never on their command line, where every process on the host could read it.
	DSN string

	Dir string

	// Keep is how many dumps to keep at most, and MaxAge how old one may get. A dump is
	// deleted when it breaks either rule, except the newest, which is kept regardless:
	// if backups have been failing for longer than MaxAge, the last good one is exactly
	// the one that must not disappear.
	Keep   int
	MaxAge time.Duration

	PGDump    string
	PGRestore string

	// Timeout bounds one pg_dump or pg_restore run.
	Timeout time.Duration
}

// Runner performs backups.
type Runner struct {
	cfg Config
	log *slog.Logger
	now func() time.Time
}

// New builds a Runner. A nil clock means time.Now.
func New(cfg Config, logger *slog.Logger, now func() time.Time) *Runner {
	if now == nil {
		now = time.Now
	}
	if cfg.PGDump == "" {
		cfg.PGDump = "pg_dump"
	}
	if cfg.PGRestore == "" {
		cfg.PGRestore = "pg_restore"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = time.Hour
	}
	return &Runner{cfg: cfg, log: logger, now: now}
}

// Dump is one backup file.
type Dump struct {
	Path    string
	TakenAt time.Time
	Size    int64
}

// Name is the file name without the directory.
func (d Dump) Name() string { return filepath.Base(d.Path) }

// Backup takes a dump, verifies it, publishes it and rotates the old ones.
//
// The dump is written under a temporary name and renamed only once it has been read back
// successfully, so a file with the final name is always one that passed verification. A
// crash midway leaves a .partial file, which the next run removes.
func (r *Runner) Backup(ctx context.Context) (*Dump, error) {
	if err := os.MkdirAll(r.cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("backup: create %s: %w", r.cfg.Dir, err)
	}
	r.removeStalePartials()

	takenAt := r.now().UTC().Truncate(time.Second)
	name := filePrefix + takenAt.Format(timeLayout) + fileSuffix
	final := filepath.Join(r.cfg.Dir, name)
	partial := final + partialSuffix

	if _, err := os.Stat(final); err == nil {
		return nil, fmt.Errorf("backup: %s already exists; two backups in the same second", name)
	}

	started := time.Now()
	target, env, err := connection(r.cfg.DSN)
	if err != nil {
		return nil, err
	}
	// Custom format: compressed, restorable selectively, and readable by pg_restore --list,
	// which is what makes verifying it possible without a scratch database.
	if _, err := r.tool(ctx, env, r.cfg.PGDump,
		"--format=custom", "--no-password", "--file="+partial, "--dbname="+target); err != nil {
		_ = os.Remove(partial)
		return nil, fmt.Errorf("backup: pg_dump: %w", err)
	}

	if err := r.verifyArchive(ctx, partial); err != nil {
		// Kept rather than deleted: a dump that fails its own check is evidence of what is
		// wrong, and the next run cleans it up after a day.
		return nil, fmt.Errorf("backup: the new dump failed verification and was not published: %w", err)
	}

	sum, size, err := fileChecksum(partial)
	if err != nil {
		return nil, err
	}
	// sha256sum's own format, so the file can be checked off-host with `sha256sum -c`.
	checksumLine := fmt.Sprintf("%s  %s\n", sum, name)
	if err := writeFileSync(final+checksumSuffix, []byte(checksumLine)); err != nil {
		return nil, fmt.Errorf("backup: write checksum: %w", err)
	}
	if err := os.Rename(partial, final); err != nil {
		return nil, fmt.Errorf("backup: publish %s: %w", name, err)
	}

	dump := &Dump{Path: final, TakenAt: takenAt, Size: size}
	r.log.InfoContext(ctx, "backup taken and verified",
		slog.String("file", name),
		slog.Int64("bytes", size),
		slog.Duration("took", time.Since(started).Round(time.Millisecond)))

	if err := r.Rotate(ctx); err != nil {
		// The new dump exists and is good; failing to delete old ones is worth a warning,
		// not a failed backup.
		r.log.WarnContext(ctx, "rotation failed", slog.Any("error", err))
	}
	return dump, nil
}

// Verify checks a published dump: its checksum, then that pg_restore can read all of it.
func (r *Runner) Verify(ctx context.Context, path string) error {
	expected, err := os.ReadFile(path + checksumSuffix)
	if err != nil {
		return fmt.Errorf("backup: read checksum for %s: %w", filepath.Base(path), err)
	}
	fields := strings.Fields(string(expected))
	if len(fields) == 0 {
		return fmt.Errorf("backup: checksum file for %s is empty", filepath.Base(path))
	}

	actual, _, err := fileChecksum(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(fields[0], actual) {
		return fmt.Errorf("backup: %s does not match its checksum; the file changed after it was taken",
			filepath.Base(path))
	}
	return r.verifyArchive(ctx, path)
}

// verifyArchive reads an archive the way a restore would.
//
// Two passes. The table of contents proves the file is a dump of this panel. Then a full
// restore into /dev/null reads every data block, which catches what --list does not: a
// file cut short near its end passes --list and fails here (checked with pg_restore 16).
//
// What it cannot catch is a flipped bit inside table data: the archive format carries no
// data checksums, so such a dump reads back cleanly and restores wrong values. That is
// what the .sha256 written next to it is for, from the moment it is published on.
func (r *Runner) verifyArchive(ctx context.Context, path string) error {
	toc, err := r.tool(ctx, nil, r.cfg.PGRestore, "--list", path)
	if err != nil {
		return fmt.Errorf("read table of contents: %w", err)
	}
	if err := checkContents(toc); err != nil {
		return err
	}
	if _, err := r.tool(ctx, nil, r.cfg.PGRestore, "--file="+os.DevNull, path); err != nil {
		return fmt.Errorf("read the data back: %w", err)
	}
	return nil
}

// checkContents looks for the entries every dump of this panel has.
func checkContents(toc []byte) error {
	var missing []string
	for _, entry := range requiredEntries {
		if !bytes.Contains(toc, []byte(entry)) {
			missing = append(missing, entry)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the dump is missing %s; it is not a dump of this panel's database",
			strings.Join(missing, ", "))
	}
	return nil
}

// List returns the published dumps, newest first.
func (r *Runner) List() ([]Dump, error) {
	entries, err := os.ReadDir(r.cfg.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("backup: read %s: %w", r.cfg.Dir, err)
	}

	var dumps []Dump
	for _, entry := range entries {
		takenAt, ok := parseName(entry.Name())
		if !ok || entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		dumps = append(dumps, Dump{
			Path:    filepath.Join(r.cfg.Dir, entry.Name()),
			TakenAt: takenAt,
			Size:    info.Size(),
		})
	}
	sort.Slice(dumps, func(i, j int) bool { return dumps[i].TakenAt.After(dumps[j].TakenAt) })
	return dumps, nil
}

// Latest is the newest published dump, or nil.
func (r *Runner) Latest() (*Dump, error) {
	dumps, err := r.List()
	if err != nil || len(dumps) == 0 {
		return nil, err
	}
	return &dumps[0], nil
}

// Rotate deletes the dumps the retention rules no longer cover.
func (r *Runner) Rotate(ctx context.Context) error {
	dumps, err := r.List()
	if err != nil {
		return err
	}

	var errs []error
	for _, dump := range Expired(dumps, r.cfg.Keep, r.cfg.MaxAge, r.now()) {
		if err := os.Remove(dump.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
			continue
		}
		_ = os.Remove(dump.Path + checksumSuffix)
		r.log.InfoContext(ctx, "old backup removed", slog.String("file", dump.Name()))
	}
	return errors.Join(errs...)
}

// Expired picks the dumps to delete from a newest-first list.
//
// A dump goes when it is past the count or past the age, but the newest never goes: with
// backups failing for a month, deleting by age alone would leave nothing at all.
func Expired(newestFirst []Dump, keep int, maxAge time.Duration, now time.Time) []Dump {
	var out []Dump
	for i, dump := range newestFirst {
		if i == 0 {
			continue
		}
		if i >= keep || now.Sub(dump.TakenAt) > maxAge {
			out = append(out, dump)
		}
	}
	return out
}

// removeStalePartials deletes leftovers of runs that died midway. A day old at least, so a
// run still in progress in another process is not disturbed.
func (r *Runner) removeStalePartials() {
	entries, err := os.ReadDir(r.cfg.Dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), partialSuffix) {
			continue
		}
		info, err := entry.Info()
		if err != nil || r.now().Sub(info.ModTime()) < 24*time.Hour {
			continue
		}
		_ = os.Remove(filepath.Join(r.cfg.Dir, entry.Name()))
	}
}

// parseName reads the timestamp out of a published dump's file name.
func parseName(name string) (time.Time, bool) {
	stamp, ok := strings.CutPrefix(name, filePrefix)
	if !ok {
		return time.Time{}, false
	}
	stamp, ok = strings.CutSuffix(stamp, fileSuffix)
	if !ok {
		return time.Time{}, false
	}
	takenAt, err := time.Parse(timeLayout, stamp)
	if err != nil {
		return time.Time{}, false
	}
	return takenAt, true
}

// tool runs pg_dump or pg_restore and returns its standard output.
func (r *Runner) tool(ctx context.Context, env []string, binary string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", filepath.Base(binary), err, firstLines(stderr.String(), 5))
	}
	return stdout.Bytes(), nil
}

// connection splits a DSN into what goes on the command line and what goes in the
// environment.
func connection(dsn string) (string, []string, error) {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return "", nil, errors.New("backup: DATABASE_URL is not a valid URL")
	}
	var env []string
	if parsed.User != nil {
		if password, set := parsed.User.Password(); set {
			env = append(env, "PGPASSWORD="+password)
			parsed.User = url.User(parsed.User.Username())
		}
	}
	return parsed.String(), env, nil
}

// withDatabase points a DSN at another database on the same server.
func withDatabase(dsn, database string) (string, error) {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return "", errors.New("backup: DATABASE_URL is not a valid URL")
	}
	parsed.Path = "/" + database
	parsed.RawPath = ""
	return parsed.String(), nil
}

func fileChecksum(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("backup: open %s: %w", filepath.Base(path), err)
	}
	defer file.Close()

	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, fmt.Errorf("backup: read %s: %w", filepath.Base(path), err)
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func writeFileSync(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func firstLines(s string, n int) string {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() && len(lines) < n {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, " | ")
}
