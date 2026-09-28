package backup

import (
	"context"
	"log/slog"
	"time"
)

// retryAfterFailure is how soon a failed backup is attempted again. Much shorter than a
// daily interval, because a failure is usually something transient, and a whole day
// without a backup is the cost of waiting for the next slot.
const retryAfterFailure = 10 * time.Minute

// Run takes a backup every interval until ctx ends.
//
// The schedule is anchored on the newest dump on disk rather than on process start. A
// container that restarts every few hours would otherwise either never reach its first
// backup or take one on every start.
func (r *Runner) Run(ctx context.Context, interval time.Duration) {
	next := r.firstDue(interval)

	for {
		wait := next.Sub(r.now())
		if wait > 0 {
			r.log.InfoContext(ctx, "next backup scheduled",
				slog.Time("at", next.UTC()), slog.Duration("in", wait.Round(time.Second)))
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}

		if _, err := r.Backup(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			r.log.ErrorContext(ctx, "backup failed", slog.Any("error", err),
				slog.Duration("retry_in", min(retryAfterFailure, interval)))
			next = r.now().Add(min(retryAfterFailure, interval))
			continue
		}
		next = r.now().Add(interval)
	}
}

// firstDue is when the first backup of this process should run.
func (r *Runner) firstDue(interval time.Duration) time.Time {
	latest, err := r.Latest()
	if err != nil || latest == nil {
		return r.now()
	}
	return NextDue(latest.TakenAt, interval, r.now())
}

// NextDue is when a backup is due, given the newest one.
func NextDue(latest time.Time, interval time.Duration, now time.Time) time.Time {
	due := latest.Add(interval)
	if due.Before(now) {
		return now
	}
	return due
}

// Healthy reports whether the newest dump is recent enough. Twice the interval, so that
// one failed run followed by a retry does not flap the health check.
func Healthy(latest *Dump, interval time.Duration, now time.Time) bool {
	return latest != nil && now.Sub(latest.TakenAt) <= 2*interval
}
