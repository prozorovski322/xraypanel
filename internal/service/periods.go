package service

import (
	"time"

	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// PeriodStart is when the current billing period began for one reset strategy.
//
// Computed in the billing timezone and returned in UTC. That split is the whole point: a
// subscriber's month starts at midnight where they are told it does, while everything stored
// stays UTC (ADR-006). An installation whose operator and users are in Moscow would
// otherwise reset traffic at three in the morning, or at nine in the evening on the day
// before — both of which look like a bug to whoever is watching their allowance.
func PeriodStart(strategy dbgen.ResetStrategy, now time.Time, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	local := now.In(loc)

	switch strategy {
	case dbgen.ResetStrategyDaily:
		return startOfDay(local, loc).UTC()

	case dbgen.ResetStrategyWeekly:
		// ISO weeks: Monday. Go numbers Sunday as zero, which would otherwise make the
		// week start on the wrong day for most of the world.
		offset := (int(local.Weekday()) + 6) % 7
		return startOfDay(local, loc).AddDate(0, 0, -offset).UTC()

	case dbgen.ResetStrategyMonthly:
		return time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, loc).UTC()

	default:
		// Never, or a strategy this build does not know. A zero time means "no period has
		// started", so nothing is ever due — the safe direction for a value that arrived
		// from a newer schema.
		return time.Time{}
	}
}

// startOfDay is midnight local time.
//
// Built from the calendar date rather than by truncating, because truncation works in
// absolute time and a day is not always 24 hours long: on a daylight-saving boundary
// truncating lands an hour off, and the reset would fire twice or not at all.
func startOfDay(local time.Time, loc *time.Location) time.Time {
	year, month, day := local.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, loc)
}
