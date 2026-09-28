package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/xraypanel/panel/internal/service"
)

// Enforcer is the part of the service the enforcement worker drives.
type Enforcer interface {
	EnforceLimits(ctx context.Context) (service.Enforcement, error)
	ResetDueTraffic(ctx context.Context) (service.Enforcement, error)
}

// defaultEnforcementInterval matches the nodes' default traffic poll. Checking limits more
// often than traffic arrives buys nothing; checking less often lets a user run further past
// their limit than the poll interval already does.
const defaultEnforcementInterval = 30 * time.Second

// Enforcement switches users off when they run out of traffic or time, and resets counters
// when a new billing period starts.
type Enforcement struct {
	svc      Enforcer
	log      *slog.Logger
	interval time.Duration
}

// NewEnforcement builds the worker.
func NewEnforcement(svc Enforcer, logger *slog.Logger, interval time.Duration) (*Enforcement, error) {
	if svc == nil {
		return nil, errors.New("worker: no service")
	}
	if logger == nil {
		return nil, errors.New("worker: no logger")
	}
	if interval <= 0 {
		interval = defaultEnforcementInterval
	}
	return &Enforcement{svc: svc, log: logger, interval: interval}, nil
}

// Run does a pass immediately and then one every interval, until ctx is cancelled.
//
// Immediately, because the likeliest reason there is anything to do is that the panel was
// down — and every minute it waits is a minute an over-limit user keeps being served.
func (e *Enforcement) Run(ctx context.Context) {
	e.Once(ctx)

	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.Once(ctx)
		}
	}
}

// Once performs one pass.
//
// Resets run before limits. A user whose period ended while they were over their limit must
// come back, not be limited again: in the other order the same pass would limit them for the
// old period's traffic and then reset them, announcing a limit that no longer applies.
func (e *Enforcement) Once(ctx context.Context) {
	reset, err := e.svc.ResetDueTraffic(ctx)
	if err != nil {
		e.log.ErrorContext(ctx, "the traffic reset pass did not complete", slog.Any("error", err))
	}

	enforced, err := e.svc.EnforceLimits(ctx)
	if err != nil {
		e.log.ErrorContext(ctx, "the enforcement pass did not complete", slog.Any("error", err))
	}

	if !reset.Empty() || !enforced.Empty() {
		e.log.InfoContext(ctx, "enforcement pass",
			slog.Int("reset", reset.Reset),
			slog.Int("limited", enforced.Limited),
			slog.Int("expired", enforced.Expired))
	}
}
