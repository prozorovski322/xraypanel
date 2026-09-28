package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/xraypanel/panel/internal/agent/stats"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()

	state, err := Open(filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = state.Close() })
	return state
}

func hour(h int) time.Time {
	return time.Date(2026, 5, 4, h, 0, 0, 0, time.UTC)
}

// A node polling every thirty seconds produces a reading twice a minute. They have to fold
// into one row per hour and user, or a panel outage fills the volume with rows nobody will
// ever look at individually.
func TestDeltasFoldByHourAndUser(t *testing.T) {
	state := openTestStore(t)

	err := state.AddTrafficDeltas([]TrafficDelta{
		{Email: "aaaaaaaaaaaa", Uplink: 100, Downlink: 200, Hour: hour(10)},
		{Email: "aaaaaaaaaaaa", Uplink: 50, Downlink: 60, Hour: hour(10)},
		{Email: "aaaaaaaaaaaa", Uplink: 7, Downlink: 8, Hour: hour(11)},
		{Email: "bbbbbbbbbbbb", Uplink: 1, Downlink: 2, Hour: hour(10)},
	})
	if err != nil {
		t.Fatalf("AddTrafficDeltas: %v", err)
	}

	buffered, err := state.BufferedTrafficDeltas()
	if err != nil {
		t.Fatalf("BufferedTrafficDeltas: %v", err)
	}
	if len(buffered) != 3 {
		t.Fatalf("buffer holds %d rows, want 3 (two users, one of them in two hours): %+v", len(buffered), buffered)
	}

	for _, delta := range buffered {
		if delta.Email == "aaaaaaaaaaaa" && delta.Hour.Equal(hour(10)) {
			if delta.Uplink != 150 || delta.Downlink != 260 {
				t.Errorf("folded delta is %+v, want 150/260", delta)
			}
		}
	}
}

// The timestamp is truncated so that two readings in the same hour cannot land in
// different rows because of the minute they arrived in.
func TestHoursAreTruncated(t *testing.T) {
	state := openTestStore(t)

	mid := hour(10).Add(37 * time.Minute)
	if err := state.AddTrafficDeltas([]TrafficDelta{{Email: "aaaaaaaaaaaa", Uplink: 5, Hour: mid}}); err != nil {
		t.Fatalf("AddTrafficDeltas: %v", err)
	}

	buffered, err := state.BufferedTrafficDeltas()
	if err != nil {
		t.Fatalf("BufferedTrafficDeltas: %v", err)
	}
	if len(buffered) != 1 || !buffered[0].Hour.Equal(hour(10)) {
		t.Errorf("buffered %+v, want the hour truncated to %s", buffered, hour(10))
	}
}

func TestEmptyAndAnonymousDeltasAreDropped(t *testing.T) {
	state := openTestStore(t)

	err := state.AddTrafficDeltas([]TrafficDelta{
		{Email: "aaaaaaaaaaaa", Hour: hour(10)},            // nothing moved
		{Email: "", Uplink: 500, Hour: hour(10)},           // no stats key to bill
		{Email: "bbbbbbbbbbbb", Uplink: 1, Hour: hour(10)}, // kept
	})
	if err != nil {
		t.Fatalf("AddTrafficDeltas: %v", err)
	}

	buffered, _ := state.BufferedTrafficDeltas()
	if len(buffered) != 1 || buffered[0].Email != "bbbbbbbbbbbb" {
		t.Errorf("buffered %+v, want only the one delta that can be billed", buffered)
	}
}

// Taking a batch has to empty the buffer and hold the batch at the same time: deltas that
// leave the buffer without landing in a batch are bytes nobody will bill, and deltas in
// both would be billed twice.
func TestTakingABatchMovesEverythingOutOfTheBuffer(t *testing.T) {
	state := openTestStore(t)

	if err := state.AddTrafficDeltas([]TrafficDelta{
		{Email: "aaaaaaaaaaaa", Uplink: 10, Downlink: 20, Hour: hour(10)},
		{Email: "bbbbbbbbbbbb", Uplink: 30, Downlink: 40, Hour: hour(11)},
	}); err != nil {
		t.Fatalf("AddTrafficDeltas: %v", err)
	}

	batch, err := state.TakeTrafficBatch("batch-1", 100, time.Now())
	if err != nil {
		t.Fatalf("TakeTrafficBatch: %v", err)
	}
	if batch == nil || len(batch.Deltas) != 2 {
		t.Fatalf("batch is %+v, want two deltas", batch)
	}
	// Oldest hour first: it is the one closest to falling outside a retention window.
	if !batch.Deltas[0].Hour.Equal(hour(10)) {
		t.Errorf("batch starts at %s, want the oldest hour first", batch.Deltas[0].Hour)
	}

	buffered, _ := state.BufferedTrafficDeltas()
	if len(buffered) != 0 {
		t.Errorf("the buffer still holds %+v after the batch was taken", buffered)
	}

	pending, err := state.PendingTrafficBatches()
	if err != nil {
		t.Fatalf("PendingTrafficBatches: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "batch-1" {
		t.Errorf("pending batches are %+v, want the one that was taken", pending)
	}
}

func TestTakingAnEmptyBufferProducesNoBatch(t *testing.T) {
	state := openTestStore(t)

	batch, err := state.TakeTrafficBatch("batch-1", 100, time.Now())
	if err != nil {
		t.Fatalf("TakeTrafficBatch: %v", err)
	}
	if batch != nil {
		t.Errorf("an empty buffer produced batch %+v", batch)
	}
	if pending, _ := state.PendingTrafficBatches(); len(pending) != 0 {
		t.Errorf("an empty buffer left %d pending batches", len(pending))
	}
}

// An unacknowledged batch is kept and resent. This is the case that decides whether a
// panel restart costs anybody money.
func TestUnacknowledgedBatchesSurviveAndAreForgottenOnAck(t *testing.T) {
	state := openTestStore(t)

	if err := state.AddTrafficDeltas([]TrafficDelta{
		{Email: "aaaaaaaaaaaa", Uplink: 10, Hour: hour(10)},
	}); err != nil {
		t.Fatalf("AddTrafficDeltas: %v", err)
	}
	if _, err := state.TakeTrafficBatch("batch-1", 100, time.Now()); err != nil {
		t.Fatalf("TakeTrafficBatch: %v", err)
	}

	// New traffic arrives while the first batch is still in flight, and goes into a
	// second batch rather than joining the first.
	if err := state.AddTrafficDeltas([]TrafficDelta{
		{Email: "aaaaaaaaaaaa", Uplink: 5, Hour: hour(10)},
	}); err != nil {
		t.Fatalf("AddTrafficDeltas: %v", err)
	}
	if _, err := state.TakeTrafficBatch("batch-2", 100, time.Now().Add(time.Second)); err != nil {
		t.Fatalf("TakeTrafficBatch: %v", err)
	}

	pending, _ := state.PendingTrafficBatches()
	if len(pending) != 2 || pending[0].ID != "batch-1" || pending[1].ID != "batch-2" {
		t.Fatalf("pending batches are %+v, want batch-1 then batch-2", pending)
	}
	if pending[0].Deltas[0].Uplink != 10 || pending[1].Deltas[0].Uplink != 5 {
		t.Errorf("batches hold %+v and %+v, want the traffic split between them",
			pending[0].Deltas, pending[1].Deltas)
	}

	if err := state.AckTrafficBatch("batch-1"); err != nil {
		t.Fatalf("AckTrafficBatch: %v", err)
	}
	pending, _ = state.PendingTrafficBatches()
	if len(pending) != 1 || pending[0].ID != "batch-2" {
		t.Errorf("after the acknowledgement the pending batches are %+v, want only batch-2", pending)
	}

	// Acknowledging something twice, or something unknown, is not an error: the agent may
	// have been restarted between the panel storing a batch and saying so.
	if err := state.AckTrafficBatch("batch-1"); err != nil {
		t.Errorf("acknowledging a forgotten batch: %v", err)
	}
}

// Traffic buffered but not yet sent has to survive the agent being restarted. This is the
// case the whole buffer exists for.
func TestBufferedTrafficSurvivesAReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.db")

	state, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := state.AddTrafficDeltas([]TrafficDelta{
		{Email: "aaaaaaaaaaaa", Uplink: 1_234, Downlink: 5_678, Hour: hour(10)},
	}); err != nil {
		t.Fatalf("AddTrafficDeltas: %v", err)
	}
	if _, err := state.TakeTrafficBatch("in-flight", 100, time.Now()); err != nil {
		t.Fatalf("TakeTrafficBatch: %v", err)
	}
	coreStart := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	if err := state.SaveCounterSnapshot(stats.Snapshot{
		CoreStartedAt: coreStart,
		Counters:      map[string]int64{"user>>>aaaaaaaaaaaa>>>traffic>>>uplink": 1_234},
	}); err != nil {
		t.Fatalf("SaveCounterSnapshot: %v", err)
	}
	if err := state.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	pending, err := reopened.PendingTrafficBatches()
	if err != nil {
		t.Fatalf("PendingTrafficBatches: %v", err)
	}
	if len(pending) != 1 || pending[0].Deltas[0].Uplink != 1_234 {
		t.Errorf("after a restart the pending batches are %+v, want the traffic intact", pending)
	}

	snapshot, err := reopened.CounterSnapshot()
	if err != nil {
		t.Fatalf("CounterSnapshot: %v", err)
	}
	if snapshot.Counters["user>>>aaaaaaaaaaaa>>>traffic>>>uplink"] != 1_234 {
		t.Errorf("counter snapshot is %v, want it to survive a restart", snapshot.Counters)
	}
	// Without the process it came from, the snapshot cannot be told apart from one taken
	// before a restart, and the values would be continued against a counter that has since
	// started again from zero.
	if !snapshot.CoreStartedAt.Equal(coreStart) {
		t.Errorf("the snapshot came back with core start %s, want %s", snapshot.CoreStartedAt, coreStart)
	}
}

func TestNoCounterSnapshotYet(t *testing.T) {
	state := openTestStore(t)

	snapshot, err := state.CounterSnapshot()
	if err != nil {
		t.Fatalf("CounterSnapshot: %v", err)
	}
	if len(snapshot.Counters) != 0 || !snapshot.CoreStartedAt.IsZero() {
		t.Errorf("a fresh store returned %+v, want the zero snapshot", snapshot)
	}
}

// A node that cannot reach its panel for a week must not fill its volume. Billing data is
// worth keeping, but not at the price of the node itself.
func TestPendingBatchesAreBounded(t *testing.T) {
	state := openTestStore(t)

	start := time.Now().UTC()
	for i := 0; i < maxPendingBatches+20; i++ {
		if err := state.AddTrafficDeltas([]TrafficDelta{
			{Email: "aaaaaaaaaaaa", Uplink: int64(i + 1), Hour: hour(10)},
		}); err != nil {
			t.Fatalf("AddTrafficDeltas: %v", err)
		}
		id := "batch-" + time.Duration(i).String()
		if _, err := state.TakeTrafficBatch(id, 100, start.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("TakeTrafficBatch: %v", err)
		}
	}

	pending, err := state.PendingTrafficBatches()
	if err != nil {
		t.Fatalf("PendingTrafficBatches: %v", err)
	}
	if len(pending) != maxPendingBatches {
		t.Fatalf("keeping %d batches, want the cap of %d", len(pending), maxPendingBatches)
	}
	// The oldest are the ones dropped: the newest traffic is the most likely to still
	// matter to a bill.
	if pending[0].Deltas[0].Uplink != 21 {
		t.Errorf("the oldest kept batch holds %d, want the first 20 to have been dropped",
			pending[0].Deltas[0].Uplink)
	}
}

func TestBatchNeedsAnID(t *testing.T) {
	state := openTestStore(t)

	if _, err := state.TakeTrafficBatch("", 100, time.Now()); err == nil {
		t.Error("a batch with no id was accepted; the panel deduplicates on that id")
	}
	if _, err := state.TakeTrafficBatch("batch-1", 0, time.Now()); err == nil {
		t.Error("a batch with no limit was accepted; it would take nothing and lose nothing, silently")
	}
}

// A buffer bigger than one message has to come out in several batches, oldest first, with
// nothing dropped and nothing sent twice.
func TestABigBufferIsSplitAcrossBatches(t *testing.T) {
	state := openTestStore(t)

	for i := 0; i < 5; i++ {
		if err := state.AddTrafficDeltas([]TrafficDelta{
			{Email: "user-" + string(rune('a'+i)), Uplink: int64(i + 1), Hour: hour(10)},
		}); err != nil {
			t.Fatalf("AddTrafficDeltas: %v", err)
		}
	}

	first, err := state.TakeTrafficBatch("batch-1", 2, time.Now())
	if err != nil {
		t.Fatalf("TakeTrafficBatch: %v", err)
	}
	if first == nil || len(first.Deltas) != 2 {
		t.Fatalf("first batch is %+v, want two deltas", first)
	}

	second, err := state.TakeTrafficBatch("batch-2", 2, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("TakeTrafficBatch: %v", err)
	}
	if second == nil || len(second.Deltas) != 2 {
		t.Fatalf("second batch is %+v, want two deltas", second)
	}

	third, err := state.TakeTrafficBatch("batch-3", 2, time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("TakeTrafficBatch: %v", err)
	}
	if third == nil || len(third.Deltas) != 1 {
		t.Fatalf("third batch is %+v, want the last delta", third)
	}

	// Every delta exactly once: a split that loses one is unbilled traffic, and one that
	// repeats one is a user charged twice.
	seen := map[string]int{}
	for _, batch := range []*TrafficBatch{first, second, third} {
		for _, delta := range batch.Deltas {
			seen[delta.Email]++
		}
	}
	if len(seen) != 5 {
		t.Errorf("the batches together hold %d users, want 5: %v", len(seen), seen)
	}
	for email, times := range seen {
		if times != 1 {
			t.Errorf("%s appears %d times across the batches, want once", email, times)
		}
	}

	if buffered, _ := state.BufferedTrafficDeltas(); len(buffered) != 0 {
		t.Errorf("the buffer still holds %+v", buffered)
	}
}
