package service

import (
	"testing"
	"time"

	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

func mustLocation(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Skipf("timezone %s is not available on this machine: %v", name, err)
	}
	return loc
}

// Every boundary is checked as an absolute instant in UTC, because that is what the query
// compares against; a local wall-clock time that looks right can still be an hour off.
func TestPeriodStartInUTC(t *testing.T) {
	now := time.Date(2026, 5, 6, 15, 30, 0, 0, time.UTC) // a Wednesday

	cases := map[dbgen.ResetStrategy]time.Time{
		dbgen.ResetStrategyDaily:   time.Date(2026, 5, 6, 0, 0, 0, 0, time.UTC),
		dbgen.ResetStrategyWeekly:  time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC), // Monday
		dbgen.ResetStrategyMonthly: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	}
	for strategy, want := range cases {
		if got := PeriodStart(strategy, now, time.UTC); !got.Equal(want) {
			t.Errorf("%s: period starts %s, want %s", strategy, got, want)
		}
	}
}

// A subscriber in Moscow expects their month to start at midnight in Moscow, which is 21:00
// UTC on the last day of the previous month.
func TestPeriodStartFollowsTheBillingTimezone(t *testing.T) {
	moscow := mustLocation(t, "Europe/Moscow")

	// 22:30 UTC on 31 May is already 1 June in Moscow.
	now := time.Date(2026, 5, 31, 22, 30, 0, 0, time.UTC)

	got := PeriodStart(dbgen.ResetStrategyMonthly, now, moscow)
	want := time.Date(2026, 5, 31, 21, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("monthly period in Moscow starts %s, want %s (midnight 1 June local)", got, want)
	}

	got = PeriodStart(dbgen.ResetStrategyDaily, now, moscow)
	if !got.Equal(want) {
		t.Errorf("daily period in Moscow starts %s, want %s", got, want)
	}
}

// Weeks start on Monday. Go numbers Sunday as zero, which is the easy way to get this wrong:
// Sunday belongs to the week that began six days earlier, not to the one starting tomorrow.
func TestWeeksStartOnMonday(t *testing.T) {
	monday := time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC)

	for offset := 0; offset < 7; offset++ {
		now := monday.AddDate(0, 0, offset).Add(13 * time.Hour)
		if got := PeriodStart(dbgen.ResetStrategyWeekly, now, time.UTC); !got.Equal(monday) {
			t.Errorf("%s: week starts %s, want Monday %s", now.Weekday(), got, monday)
		}
	}
}

// Month boundaries, including a leap February and the turn of the year.
func TestMonthBoundaries(t *testing.T) {
	cases := []struct {
		now, want time.Time
	}{
		{time.Date(2028, 2, 29, 23, 59, 59, 0, time.UTC), time.Date(2028, 2, 1, 0, 0, 0, 0, time.UTC)},
		{time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC)},
		{time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC), time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)},
		{time.Date(2027, 1, 1, 0, 0, 1, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		if got := PeriodStart(dbgen.ResetStrategyMonthly, c.now, time.UTC); !got.Equal(c.want) {
			t.Errorf("at %s the month starts %s, want %s", c.now, got, c.want)
		}
	}
}

// On a daylight-saving boundary a day is 23 or 25 hours long. A period computed by
// truncating absolute time would land an hour off, and the reset would fire twice or not
// at all that day.
func TestDaylightSavingDaysStartAtLocalMidnight(t *testing.T) {
	berlin := mustLocation(t, "Europe/Berlin")

	// 29 March 2026: clocks go forward at 02:00, so the day is 23 hours long.
	now := time.Date(2026, 3, 29, 20, 0, 0, 0, berlin)

	got := PeriodStart(dbgen.ResetStrategyDaily, now, berlin)
	want := time.Date(2026, 3, 29, 0, 0, 0, 0, berlin).UTC() // 23:00 UTC the day before
	if !got.Equal(want) {
		t.Errorf("on the spring-forward day the period starts %s, want %s", got, want)
	}

	// 25 October 2026: clocks go back, so the day is 25 hours long.
	now = time.Date(2026, 10, 25, 20, 0, 0, 0, berlin)
	got = PeriodStart(dbgen.ResetStrategyDaily, now, berlin)
	want = time.Date(2026, 10, 25, 0, 0, 0, 0, berlin).UTC() // 22:00 UTC the day before
	if !got.Equal(want) {
		t.Errorf("on the fall-back day the period starts %s, want %s", got, want)
	}
}

// A strategy with no period — never, or one a newer schema added — must make nothing due,
// which is what a zero cutoff does in the query.
func TestNeverHasNoPeriod(t *testing.T) {
	now := time.Date(2026, 5, 6, 15, 30, 0, 0, time.UTC)

	if got := PeriodStart(dbgen.ResetStrategyNever, now, time.UTC); !got.IsZero() {
		t.Errorf("never has a period starting %s, want none", got)
	}
	if got := PeriodStart(dbgen.ResetStrategy("fortnightly"), now, time.UTC); !got.IsZero() {
		t.Errorf("an unknown strategy has a period starting %s, want none", got)
	}
}

// A nil location is UTC, not a panic.
func TestNilLocationIsUTC(t *testing.T) {
	now := time.Date(2026, 5, 6, 15, 30, 0, 0, time.UTC)
	if got := PeriodStart(dbgen.ResetStrategyDaily, now, nil); !got.Equal(time.Date(2026, 5, 6, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("with no location the day starts %s, want midnight UTC", got)
	}
}
