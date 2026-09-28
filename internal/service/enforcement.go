package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xraypanel/panel/internal/audit"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// Enforcement is what one pass did.
type Enforcement struct {
	Limited int
	Expired int
	Reset   int
}

// Empty reports whether the pass changed nothing, which is the usual case.
func (e Enforcement) Empty() bool { return e.Limited == 0 && e.Expired == 0 && e.Reset == 0 }

// maxEnforcementBatch bounds one pass.
//
// A pass that tried to switch off every user at once — the first pass after an import, or
// after a limit was lowered for everybody — would hold one long transaction chain and bump
// every node's configuration in one go. Several smaller passes reach the same state, and the
// worker runs again in a few seconds.
const maxEnforcementBatch = 500

// EnforceLimits switches off users who have run out of traffic or time.
//
// This is what makes a limit mean anything. The status change bumps the configuration of
// every node that served the user, and the nodes then remove them from the running core
// without a restart (ADR-065) — so enforcement costs no other user their connection.
//
// Each user is handled in its own transaction. One user whose update fails must not stop the
// pass: the alternative is a single bad row keeping every other over-limit user online.
func (s *Service) EnforceLimits(ctx context.Context) (Enforcement, error) {
	now := s.now()
	var result Enforcement
	var problems []error

	overLimit, err := s.q.ListUsersOverLimit(ctx, maxEnforcementBatch)
	if err != nil {
		return result, translate(err, "users over limit")
	}

	for _, user := range overLimit {
		switched, err := s.switchOff(ctx, user.ID, dbgen.UserStatusLimited)
		switch {
		case errors.Is(err, errAlreadyHandled):
			continue
		case err != nil:
			problems = append(problems, fmt.Errorf("limit user %d: %w", user.ID, err))
			continue
		}

		result.Limited++
		s.log.InfoContext(ctx, "user reached their traffic limit and was switched off",
			slog.Int64("user_id", user.ID),
			slog.String("username", switched.Username),
			slog.Int64("traffic_used", switched.TrafficUsed),
			slog.Int64("traffic_limit", switched.TrafficLimit))
	}

	expired, err := s.q.ListUsersPastExpiry(ctx, dbgen.ListUsersPastExpiryParams{
		Now:     now,
		MaxRows: maxEnforcementBatch,
	})
	if err != nil {
		return result, translate(err, "expired users")
	}

	for _, user := range expired {
		switched, err := s.switchOff(ctx, user.ID, dbgen.UserStatusExpired)
		switch {
		case errors.Is(err, errAlreadyHandled):
			continue
		case err != nil:
			problems = append(problems, fmt.Errorf("expire user %d: %w", user.ID, err))
			continue
		}

		result.Expired++
		s.log.InfoContext(ctx, "user's subscription ended and was switched off",
			slog.Int64("user_id", user.ID),
			slog.String("username", switched.Username),
			slog.Any("expires_at", optionalTime(switched.ExpiresAt)))
	}

	return result, errors.Join(problems...)
}

// errAlreadyHandled means another pass — or another panel process — got there first.
var errAlreadyHandled = errors.New("service: this user was already switched off")

// switchedUser is what the two transitions have in common.
type switchedUser struct {
	Username     string
	XrayEmail    string
	TrafficUsed  int64
	TrafficLimit int64
	ExpiresAt    *time.Time
}

// switchOff performs one transition, bumps the nodes, audits it and queues the webhook.
func (s *Service) switchOff(ctx context.Context, userID int64, status dbgen.UserStatus) (switchedUser, error) {
	now := s.now()
	var switched switchedUser

	err := s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		var (
			username     string
			xrayEmail    string
			trafficUsed  int64
			trafficLimit int64
			expiresAt    *time.Time
			err          error
		)

		// The update re-checks that the user is still active, so two panel processes running
		// the same pass cannot both announce the transition. The one whose update matches no
		// row learns that from pgx.ErrNoRows.
		switch status {
		case dbgen.UserStatusLimited:
			row, updateErr := queries.LimitUser(ctx, userID)
			err = updateErr
			if updateErr == nil {
				username, xrayEmail = row.Username, row.XrayEmail
				trafficUsed, trafficLimit, expiresAt = row.TrafficUsed, row.TrafficLimit, row.ExpiresAt
			}
		case dbgen.UserStatusExpired:
			row, updateErr := queries.ExpireUser(ctx, userID)
			err = updateErr
			if updateErr == nil {
				username, xrayEmail = row.Username, row.XrayEmail
				trafficUsed, trafficLimit, expiresAt = row.TrafficUsed, row.TrafficLimit, row.ExpiresAt
			}
		default:
			return fmt.Errorf("service: %q is not an enforcement status", status)
		}

		if errors.Is(err, pgx.ErrNoRows) {
			return errAlreadyHandled
		}
		if err != nil {
			return translate(err, "user status")
		}

		// The nodes have to stop serving this user, and this is what tells them.
		s.bumpNodesForUser(ctx, queries, userID)

		action := "user.limited"
		event := EventUserLimited
		if status == dbgen.UserStatusExpired {
			action = "user.expired"
			event = EventUserExpired
		}

		recorder.Record(ctx, audit.SystemActor("enforcement"), audit.Entry{
			Action:     action,
			EntityType: "user",
			EntityID:   fmt.Sprint(userID),
			Before:     map[string]any{"status": string(dbgen.UserStatusActive)},
			After: map[string]any{
				"status":        string(status),
				"traffic_used":  trafficUsed,
				"traffic_limit": trafficLimit,
			},
		})

		// Queued in the same transaction as the change it describes: a notification that
		// escaped without the change, or a change nobody was told about, are both worse than
		// a user switched off one pass later.
		if err := s.enqueueWebhook(ctx, queries, event, userEventPayload(userEvent{
			ID:           userID,
			Username:     username,
			XrayEmail:    xrayEmail,
			Status:       string(status),
			TrafficUsed:  trafficUsed,
			TrafficLimit: trafficLimit,
			ExpiresAt:    expiresAt,
		}, event, now)); err != nil {
			return err
		}

		switched = switchedUser{
			Username:     username,
			XrayEmail:    xrayEmail,
			TrafficUsed:  trafficUsed,
			TrafficLimit: trafficLimit,
			ExpiresAt:    expiresAt,
		}
		return nil
	})
	if err != nil {
		return switchedUser{}, err
	}
	return switched, nil
}

// ResetDueTraffic clears the counters of users whose billing period has ended.
//
// The cutoffs are computed here rather than in SQL, because they depend on the billing
// timezone: a monthly reset has to happen at the start of the month where the subscriber
// lives, not wherever the database happens to think it is.
func (s *Service) ResetDueTraffic(ctx context.Context) (Enforcement, error) {
	now := s.now()
	var result Enforcement
	var problems []error

	daily := PeriodStart(dbgen.ResetStrategyDaily, now, s.cfg.BillingLocation)
	weekly := PeriodStart(dbgen.ResetStrategyWeekly, now, s.cfg.BillingLocation)
	monthly := PeriodStart(dbgen.ResetStrategyMonthly, now, s.cfg.BillingLocation)

	due, err := s.q.ListUsersDueForReset(ctx, dbgen.ListUsersDueForResetParams{
		DailyCutoff:   daily,
		WeeklyCutoff:  weekly,
		MonthlyCutoff: monthly,
		MaxRows:       maxEnforcementBatch,
	})
	if err != nil {
		return result, translate(err, "users due for reset")
	}

	for _, user := range due {
		cutoff := daily
		switch user.ResetStrategy {
		case dbgen.ResetStrategyWeekly:
			cutoff = weekly
		case dbgen.ResetStrategyMonthly:
			cutoff = monthly
		}

		wasLimited := user.Status == dbgen.UserStatusLimited

		if err := s.resetForPeriod(ctx, user.ID, cutoff, wasLimited); err != nil {
			if errors.Is(err, errAlreadyHandled) {
				continue
			}
			problems = append(problems, fmt.Errorf("reset user %d: %w", user.ID, err))
			continue
		}

		result.Reset++
		s.log.InfoContext(ctx, "reset a user's traffic for a new period",
			slog.Int64("user_id", user.ID),
			slog.String("username", user.Username),
			slog.String("strategy", string(user.ResetStrategy)),
			slog.Bool("reactivated", wasLimited))
	}

	return result, errors.Join(problems...)
}

// resetForPeriod clears one user's counter.
func (s *Service) resetForPeriod(ctx context.Context, userID int64, cutoff time.Time, wasLimited bool) error {
	now := s.now()

	return s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		row, err := queries.ResetUserTrafficForPeriod(ctx, dbgen.ResetUserTrafficForPeriodParams{
			ID:     userID,
			Now:    now,
			Cutoff: cutoff,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			// Another pass reset this user inside the same period. The guard on
			// last_reset_at is what makes running the worker twice harmless.
			return errAlreadyHandled
		}
		if err != nil {
			return translate(err, "user traffic")
		}

		// Only a user who was switched off for traffic needs the nodes to hear about this;
		// a reset for somebody already active changes nothing a node can see.
		if wasLimited {
			s.bumpNodesForUser(ctx, queries, userID)
		}

		recorder.Record(ctx, audit.SystemActor("reset"), audit.Entry{
			Action:     "user.traffic_reset",
			EntityType: "user",
			EntityID:   fmt.Sprint(userID),
			After: map[string]any{
				"status":        string(row.Status),
				"traffic_used":  row.TrafficUsed,
				"reactivated":   wasLimited,
				"last_reset_at": now.UTC(),
			},
		})
		return nil
	})
}
