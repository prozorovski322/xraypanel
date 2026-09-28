package stats

import (
	"math"
	"sort"
	"testing"
	"time"
)

// Two core processes to attribute readings to. The agent starts the core, so it knows when
// the counters it is reading began.
var (
	coreStart   = time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	coreRestart = coreStart.Add(time.Hour)
)

// counters builds a reading the way the core reports one.
func counters(pairs ...any) map[string]int64 {
	reading := make(map[string]int64)
	for i := 0; i+2 < len(pairs)+1; i += 3 {
		email := pairs[i].(string)
		up := int64(pairs[i+1].(int))
		down := int64(pairs[i+2].(int))
		reading["user>>>"+email+">>>traffic>>>uplink"] = up
		reading["user>>>"+email+">>>traffic>>>downlink"] = down
	}
	return reading
}

// sorted makes deltas comparable: they come out of a map.
func sorted(deltas []Delta) []Delta {
	out := append([]Delta(nil), deltas...)
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out
}

func equal(t *testing.T, got, want []Delta) {
	t.Helper()

	got, want = sorted(got), sorted(want)
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// The counters of a core the agent started began at zero, so the first reading of one is
// billable in full. Treating it as a baseline would give every user whatever they moved in
// the first interval after a restart, which on a busy node is a lot.
func TestTheFirstReadingOfAFreshCoreIsBilled(t *testing.T) {
	tracker := NewTracker(ModeDelta, Snapshot{})

	equal(t, tracker.Observe(counters("aaaaaaaaaaaa", 5_000, 90_000), coreStart),
		[]Delta{{Email: "aaaaaaaaaaaa", Uplink: 5_000, Downlink: 90_000}})

	// And the next reading is the difference, not the whole counter again.
	equal(t, tracker.Observe(counters("aaaaaaaaaaaa", 5_100, 91_000), coreStart),
		[]Delta{{Email: "aaaaaaaaaaaa", Uplink: 100, Downlink: 1_000}})
}

// A core the agent cannot date may hold traffic somebody has already been billed for, so
// the first reading of one is a baseline and nothing else.
func TestAnUndatedCoreIsBaselined(t *testing.T) {
	tracker := NewTracker(ModeDelta, Snapshot{})

	if deltas := tracker.Observe(counters("aaaaaaaaaaaa", 5_000, 90_000), time.Time{}); len(deltas) != 0 {
		t.Errorf("the baseline reading produced %v, want nothing", deltas)
	}

	equal(t, tracker.Observe(counters("aaaaaaaaaaaa", 5_500, 90_500), time.Time{}),
		[]Delta{{Email: "aaaaaaaaaaaa", Uplink: 500, Downlink: 500}})
}

func TestUnchangedCountersProduceNothing(t *testing.T) {
	tracker := NewTracker(ModeDelta, Snapshot{})
	tracker.Observe(counters("aaaaaaaaaaaa", 5_000, 9_000), coreStart)

	if deltas := tracker.Observe(counters("aaaaaaaaaaaa", 5_000, 9_000), coreStart); len(deltas) != 0 {
		t.Errorf("an idle user produced %v, want nothing", deltas)
	}
}

// The core restarting resets its counters. What they hold afterwards is traffic since that
// restart; the difference would be negative.
func TestARestartedCoreIsBilledFromZero(t *testing.T) {
	tracker := NewTracker(ModeDelta, Snapshot{})
	tracker.Observe(counters("aaaaaaaaaaaa", 900_000, 900_000), coreStart)

	equal(t, tracker.Observe(counters("aaaaaaaaaaaa", 1_500, 2_500), coreRestart),
		[]Delta{{Email: "aaaaaaaaaaaa", Uplink: 1_500, Downlink: 2_500}})

	// And the next reading continues from there rather than from the old high value.
	equal(t, tracker.Observe(counters("aaaaaaaaaaaa", 2_000, 3_000), coreRestart),
		[]Delta{{Email: "aaaaaaaaaaaa", Uplink: 500, Downlink: 500}})
}

// Even without the restart being visible in the timestamps, a counter that went backwards
// can only mean the same thing.
func TestCounterGoingBackwardsIsBilledFromZero(t *testing.T) {
	tracker := NewTracker(ModeDelta, Snapshot{})
	tracker.Observe(counters("aaaaaaaaaaaa", 900_000, 900_000), coreStart)

	equal(t, tracker.Observe(counters("aaaaaaaaaaaa", 1_500, 2_500), coreStart),
		[]Delta{{Email: "aaaaaaaaaaaa", Uplink: 1_500, Downlink: 2_500}})
}

// A user added to a running core starts at zero, so the first value seen for them is all
// new traffic.
func TestACounterThatAppearsIsBilledInFull(t *testing.T) {
	tracker := NewTracker(ModeDelta, Snapshot{})
	tracker.Observe(counters("aaaaaaaaaaaa", 1_000, 1_000), coreStart)

	reading := counters("aaaaaaaaaaaa", 1_000, 1_000)
	for name, value := range counters("bbbbbbbbbbbb", 400, 700) {
		reading[name] = value
	}

	equal(t, tracker.Observe(reading, coreStart), []Delta{{Email: "bbbbbbbbbbbb", Uplink: 400, Downlink: 700}})
}

// A user removed from the core must be forgotten, or their reappearance looks like a
// restart and their traffic is billed from zero again.
func TestACounterThatDisappearsIsForgotten(t *testing.T) {
	tracker := NewTracker(ModeDelta, Snapshot{})
	tracker.Observe(counters("aaaaaaaaaaaa", 1_000, 1_000), coreStart)
	tracker.Observe(counters("aaaaaaaaaaaa", 4_000, 4_000), coreStart)

	// The user is taken off the inbound: their counters are gone from the reading.
	if deltas := tracker.Observe(map[string]int64{}, coreStart); len(deltas) != 0 {
		t.Errorf("a disappeared user produced %v, want nothing", deltas)
	}
	if _, remembered := tracker.Snapshot().Counters["user>>>aaaaaaaaaaaa>>>traffic>>>uplink"]; remembered {
		t.Error("the tracker still remembers a counter the core no longer reports")
	}

	// Added back, they start from zero and the whole value is new traffic.
	equal(t, tracker.Observe(counters("aaaaaaaaaaaa", 50, 60), coreStart),
		[]Delta{{Email: "aaaaaaaaaaaa", Uplink: 50, Downlink: 60}})
}

// The snapshot is what makes an agent restart cost nothing: the counters are still in the
// core that is still running, so the traffic since the last poll is still billable.
func TestASnapshotResumesAgainstTheSameCore(t *testing.T) {
	first := NewTracker(ModeDelta, Snapshot{})
	first.Observe(counters("aaaaaaaaaaaa", 1_000, 2_000), coreStart)
	snapshot := first.Snapshot()

	if !snapshot.CoreStartedAt.Equal(coreStart) {
		t.Errorf("the snapshot records the core as started at %s, want %s",
			snapshot.CoreStartedAt, coreStart)
	}

	resumed := NewTracker(ModeDelta, snapshot)
	equal(t, resumed.Observe(counters("aaaaaaaaaaaa", 1_250, 2_500), coreStart),
		[]Delta{{Email: "aaaaaaaaaaaa", Uplink: 250, Downlink: 500}})
}

// An agent that restarts and finds a different core must bill that core's counters in full:
// they are not a continuation of the ones in its snapshot.
func TestASnapshotFromAnotherCoreIsNotContinued(t *testing.T) {
	first := NewTracker(ModeDelta, Snapshot{})
	first.Observe(counters("aaaaaaaaaaaa", 900_000, 900_000), coreStart)

	resumed := NewTracker(ModeDelta, first.Snapshot())
	equal(t, resumed.Observe(counters("aaaaaaaaaaaa", 4_000, 5_000), coreRestart),
		[]Delta{{Email: "aaaaaaaaaaaa", Uplink: 4_000, Downlink: 5_000}})
}

// The snapshot must be a copy: a caller persisting it while the tracker keeps polling would
// otherwise write values that have moved on.
func TestSnapshotIsACopy(t *testing.T) {
	tracker := NewTracker(ModeDelta, Snapshot{})
	tracker.Observe(counters("aaaaaaaaaaaa", 1_000, 1_000), coreStart)

	snapshot := tracker.Snapshot()
	tracker.Observe(counters("aaaaaaaaaaaa", 9_000, 9_000), coreStart)

	if snapshot.Counters["user>>>aaaaaaaaaaaa>>>traffic>>>uplink"] != 1_000 {
		t.Error("the snapshot changed under the caller")
	}
}

func TestResetModeTreatsEachReadingAsADelta(t *testing.T) {
	tracker := NewTracker(ModeReset, Snapshot{})

	if !tracker.UsesReset() {
		t.Error("the reset strategy does not ask the core to reset")
	}
	equal(t, tracker.Observe(counters("aaaaaaaaaaaa", 300, 400), coreStart),
		[]Delta{{Email: "aaaaaaaaaaaa", Uplink: 300, Downlink: 400}})
	equal(t, tracker.Observe(counters("aaaaaaaaaaaa", 10, 20), coreStart),
		[]Delta{{Email: "aaaaaaaaaaaa", Uplink: 10, Downlink: 20}})

	if len(tracker.Snapshot().Counters) != 0 {
		t.Error("the reset strategy keeps a snapshot it cannot use")
	}
}

func TestUnknownAndMalformedCountersAreIgnored(t *testing.T) {
	tracker := NewTracker(ModeDelta, Snapshot{})

	reading := map[string]int64{
		// Inbound totals, which the panel accounts per node, not per user.
		"inbound>>>vless-tcp>>>traffic>>>uplink": 5_000,
		// Shapes that are not a user traffic counter at all.
		"user>>>aaaaaaaaaaaa>>>traffic":            100,
		"user>>>>>>traffic>>>uplink":               100,
		"user>>>aaaaaaaaaaaa>>>online>>>uplink":    100,
		"user>>>aaaaaaaaaaaa>>>traffic>>>sideways": 100,
		"": 100,
	}

	if deltas := tracker.Observe(reading, coreStart); len(deltas) != 0 {
		t.Errorf("counters that are not per-user traffic produced %v, want nothing", deltas)
	}
}

// A negative reading is not something the core should produce, and must not become a credit
// on somebody's balance.
func TestNegativeReadingsAreIgnored(t *testing.T) {
	tracker := NewTracker(ModeDelta, Snapshot{})
	tracker.Observe(counters("aaaaaaaaaaaa", 1_000, 1_000), coreStart)

	reading := map[string]int64{
		"user>>>aaaaaaaaaaaa>>>traffic>>>uplink":   -5_000,
		"user>>>aaaaaaaaaaaa>>>traffic>>>downlink": 1_500,
	}

	equal(t, tracker.Observe(reading, coreStart), []Delta{{Email: "aaaaaaaaaaaa", Downlink: 500}})
}

// Both directions of one user fold into one delta, and the total cannot wrap: a negative
// total reads downstream as a user who has used nothing.
func TestDeltasDoNotWrap(t *testing.T) {
	tracker := NewTracker(ModeReset, Snapshot{})

	reading := map[string]int64{
		"user>>>aaaaaaaaaaaa>>>traffic>>>uplink":   math.MaxInt64,
		"user>>>aaaaaaaaaaaa>>>traffic>>>downlink": math.MaxInt64,
	}
	deltas := tracker.Observe(reading, coreStart)
	if len(deltas) != 1 {
		t.Fatalf("got %v, want one delta", deltas)
	}
	if deltas[0].Uplink != math.MaxInt64 || deltas[0].Downlink != math.MaxInt64 {
		t.Errorf("got %v, want both directions saturated rather than wrapped", deltas[0])
	}

	if got := addSaturating(math.MaxInt64, 5); got != math.MaxInt64 {
		t.Errorf("addSaturating(MaxInt64, 5) = %d, want MaxInt64", got)
	}
	if got := addSaturating(math.MinInt64, -5); got != math.MinInt64 {
		t.Errorf("addSaturating(MinInt64, -5) = %d, want MinInt64", got)
	}
}

func TestModeValidation(t *testing.T) {
	if Mode("nonsense").Valid() {
		t.Error("an unknown mode validates")
	}
	// An unknown mode must not silently become the lossy one.
	if NewTracker(Mode("nonsense"), Snapshot{}).UsesReset() {
		t.Error("an unknown mode fell back to reset, which loses traffic on a crash")
	}
}
