// Package worker holds the panel's background housekeeping.
//
// Everything here is work that has to happen whether or not anybody is looking: rolling
// hourly traffic up into days, creating next month's partitions before traffic arrives for
// it, and dropping data that has aged out. None of it is on a request path, and all of it
// is written to be safe to run twice — a panel that restarts mid-pass must not need
// anybody to clean up after it.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// Config is how often the housekeeping runs and what it keeps.
type Config struct {
	Interval time.Duration

	// RecordRetention bounds how long hourly rows are kept; the daily rollup is what
	// survives.
	RecordRetention time.Duration

	// BatchRetention is how long a node's batch id is remembered so that a resend can be
	// recognised as a duplicate.
	BatchRetention time.Duration

	// PartitionsAhead is how many monthly partitions to keep created in advance.
	PartitionsAhead int
}

// Defaults for a caller that leaves a field empty.
const (
	defaultInterval        = time.Hour
	defaultRecordRetention = 90 * 24 * time.Hour
	defaultBatchRetention  = 48 * time.Hour
	defaultPartitionsAhead = 3
)

// Traffic keeps the accounting tables in shape.
type Traffic struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	log  *slog.Logger
	cfg  Config
}

// NewTraffic builds the housekeeping worker.
func NewTraffic(pool *pgxpool.Pool, logger *slog.Logger, cfg Config) (*Traffic, error) {
	if pool == nil {
		return nil, errors.New("worker: no database pool")
	}
	if logger == nil {
		return nil, errors.New("worker: no logger")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.RecordRetention <= 0 {
		cfg.RecordRetention = defaultRecordRetention
	}
	if cfg.BatchRetention <= 0 {
		cfg.BatchRetention = defaultBatchRetention
	}
	if cfg.PartitionsAhead <= 0 {
		cfg.PartitionsAhead = defaultPartitionsAhead
	}

	return &Traffic{pool: pool, q: dbgen.New(pool), log: logger, cfg: cfg}, nil
}

// Run does one pass immediately and then one every interval, until ctx is cancelled.
//
// Immediately, because the most likely reason a partition is missing or a rollup is behind
// is that the panel was down — so the first thing after a start is to catch up.
func (t *Traffic) Run(ctx context.Context) {
	t.Once(ctx)

	ticker := time.NewTicker(t.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.Once(ctx)
		}
	}
}

// Once performs one housekeeping pass.
//
// Each step is independent and a failure in one does not stop the others: a partition that
// could not be created is a different problem from a rollup that failed, and skipping the
// rest of the pass would turn one problem into four.
func (t *Traffic) Once(ctx context.Context) {
	now := time.Now().UTC()

	if err := t.EnsurePartitions(ctx, now); err != nil {
		t.log.ErrorContext(ctx, "could not create traffic partitions", slog.Any("error", err))
	}
	if err := t.RollUp(ctx, now); err != nil {
		t.log.ErrorContext(ctx, "could not roll traffic up into days", slog.Any("error", err))
	}
	if err := t.Prune(ctx, now); err != nil {
		t.log.ErrorContext(ctx, "could not prune old traffic", slog.Any("error", err))
	}
}

// EnsurePartitions creates the monthly partitions for this month and the next few.
//
// Traffic with no partition of its own lands in the default one, which is correct and
// slower to query, so this is about staying ahead rather than about correctness. Written in
// plain SQL because a partition name and its bounds cannot be parameters.
func (t *Traffic) EnsurePartitions(ctx context.Context, now time.Time) error {
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	for i := 0; i <= t.cfg.PartitionsAhead; i++ {
		start := month.AddDate(0, i, 0)
		end := start.AddDate(0, 1, 0)
		name := partitionName(start)

		// IF NOT EXISTS rather than a catalogue query first: two panels starting at once
		// would otherwise both decide to create it and one would fail.
		statement := fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s PARTITION OF traffic_records FOR VALUES FROM ('%s') TO ('%s')`,
			name,
			start.Format(time.RFC3339),
			end.Format(time.RFC3339),
		)
		if _, err := t.pool.Exec(ctx, statement); err != nil {
			return fmt.Errorf("worker: create partition %s: %w", name, err)
		}
	}
	return nil
}

// RollUp recomputes the daily totals for yesterday and today.
//
// Two days rather than one, because a day is only finished in UTC and a node that was
// offline can report an hour of it much later. Recomputed rather than accumulated, so
// running it again after such a late batch corrects the day instead of doubling it.
func (t *Traffic) RollUp(ctx context.Context, now time.Time) error {
	today := now.Truncate(24 * time.Hour)

	for _, day := range []time.Time{today.AddDate(0, 0, -1), today} {
		rows, err := t.q.RollUpTrafficDay(ctx, dbgen.RollUpTrafficDayParams{
			DayStart: day,
			DayEnd:   day.AddDate(0, 0, 1),
		})
		if err != nil {
			return fmt.Errorf("worker: roll up %s: %w", day.Format(time.DateOnly), err)
		}
		if rows > 0 {
			t.log.DebugContext(ctx, "rolled traffic up into a day",
				slog.String("day", day.Format(time.DateOnly)), slog.Int64("rows", rows))
		}
	}
	return nil
}

// Prune drops hourly rows and batch ids that have aged out.
//
// Whole partitions first, which is a catalogue operation rather than a scan of a billing
// table; the delete then only has to deal with rows in the default partition.
func (t *Traffic) Prune(ctx context.Context, now time.Time) error {
	cutoff := now.Add(-t.cfg.RecordRetention)

	if err := t.dropExpiredPartitions(ctx, cutoff); err != nil {
		return err
	}

	rows, err := t.q.DeleteTrafficRecordsBefore(ctx, cutoff)
	if err != nil {
		return fmt.Errorf("worker: delete old traffic records: %w", err)
	}
	if rows > 0 {
		t.log.InfoContext(ctx, "deleted traffic records past the retention window",
			slog.Int64("rows", rows), slog.Time("cutoff", cutoff))
	}

	batchCutoff := now.Add(-t.cfg.BatchRetention)
	batches, err := t.q.DeleteTrafficBatchesBefore(ctx, batchCutoff)
	if err != nil {
		return fmt.Errorf("worker: delete old traffic batches: %w", err)
	}
	if batches > 0 {
		t.log.DebugContext(ctx, "forgot traffic batch ids past the deduplication window",
			slog.Int64("rows", batches), slog.Time("cutoff", batchCutoff))
	}
	return nil
}

// dropExpiredPartitions removes monthly partitions whose whole range is older than cutoff.
func (t *Traffic) dropExpiredPartitions(ctx context.Context, cutoff time.Time) error {
	rows, err := t.pool.Query(ctx, `
		SELECT c.relname
		FROM pg_class c
		JOIN pg_inherits i ON i.inhrelid = c.oid
		JOIN pg_class p ON p.oid = i.inhparent
		WHERE p.relname = 'traffic_records'
		  AND c.relname <> 'traffic_records_default'
		ORDER BY c.relname`)
	if err != nil {
		return fmt.Errorf("worker: list traffic partitions: %w", err)
	}

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("worker: read a partition name: %w", err)
		}
		names = append(names, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("worker: list traffic partitions: %w", err)
	}

	for _, name := range names {
		start, ok := partitionMonth(name)
		if !ok {
			// A partition somebody else created, with a name this worker does not
			// recognise. Left alone: dropping a table because its name is unfamiliar is
			// not a decision a background job should make.
			continue
		}
		// The partition covers [start, start+1 month); it can only go once its last hour
		// is older than the cutoff.
		if !start.AddDate(0, 1, 0).Before(cutoff) {
			continue
		}

		if _, err := t.pool.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s`, name)); err != nil {
			return fmt.Errorf("worker: drop partition %s: %w", name, err)
		}
		t.log.InfoContext(ctx, "dropped a traffic partition past the retention window",
			slog.String("partition", name))
	}
	return nil
}

// partitionName is the convention migration 00001 established.
func partitionName(month time.Time) string {
	return fmt.Sprintf("traffic_records_%s", month.UTC().Format("2006_01"))
}

// partitionMonth reads the month back out of a partition name.
func partitionMonth(name string) (time.Time, bool) {
	const prefix = "traffic_records_"
	if len(name) != len(prefix)+len("2006_01") || name[:len(prefix)] != prefix {
		return time.Time{}, false
	}
	month, err := time.ParseInLocation("2006_01", name[len(prefix):], time.UTC)
	if err != nil {
		return time.Time{}, false
	}
	return month, true
}
