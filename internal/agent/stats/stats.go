// Package stats turns Xray's counters into billable deltas.
//
// This is the arithmetic users are charged by, so the failure modes are worth naming.
// Xray exposes a cumulative counter per user and direction, and offers to zero it as it is
// read. Reading with reset is simpler — whatever comes back is the delta — and it loses
// traffic for good the moment anything goes wrong between the read and the panel storing
// it: the core has already forgotten those bytes. Reading without reset keeps the core as
// the authority, so a crash costs nothing (ADR-008).
//
// What that costs instead is that this package has to know which process the counters
// belong to. A counter is cumulative over the life of one core process, so:
//
//   - the agent starts the core, which means its counters began at zero, which means the
//     first reading of a core the agent started is billable in full. Treating it as a
//     baseline instead would give every user the traffic they moved in the first poll
//     interval after every restart — and a node restarting under load moves a lot in
//     thirty seconds;
//   - a reading lower than the last one, or a core that has restarted since the snapshot
//     was taken, means the counters started again from zero, so the reading itself is the
//     delta rather than the difference;
//   - only a core the agent cannot account for — one already running that this agent did
//     not start, which it cannot date — needs a baseline reading, because its counters may
//     hold traffic somebody has already been billed for;
//   - a counter that disappears means the user is gone from that core, and remembering it
//     would make them look like they restarted the next time they appeared.
package stats

import (
	"math"
	"strings"
	"time"
)

// Mode is how counters are read.
type Mode string

// The two strategies. Delta is the default and the one the panel is built around; Reset
// exists as an escape hatch for an installation where the core's counters misbehave,
// and it trades correctness under failure for simplicity (ADR-008).
const (
	ModeDelta Mode = "delta"
	ModeReset Mode = "reset"
)

// Valid reports whether m is a mode this agent implements.
func (m Mode) Valid() bool { return m == ModeDelta || m == ModeReset }

// Counter name shape: user>>>{email}>>>traffic>>>uplink.
const (
	counterSeparator = ">>>"
	counterKindUser  = "user"
	counterTraffic   = "traffic"

	directionUp   = "uplink"
	directionDown = "downlink"
)

// Delta is traffic one user moved since the previous reading.
type Delta struct {
	// Email is the immutable stats key, which is what the panel bills on (ADR-007).
	Email    string
	Uplink   int64
	Downlink int64
}

// Empty reports whether this delta is worth reporting at all.
func (d Delta) Empty() bool { return d.Uplink == 0 && d.Downlink == 0 }

// Snapshot is what a tracker needs in order to resume rather than start over.
//
// It is persisted by the agent, so that a restart does not discard the traffic between the
// last poll and the restart: those bytes are still in the counters of the core that is
// still running.
type Snapshot struct {
	// CoreStartedAt identifies the process the counters belong to. A different value means
	// a different core, whose counters started again at zero.
	CoreStartedAt time.Time `json:"core_started_at"`

	// Counters is the last absolute value of each counter, by name.
	Counters map[string]int64 `json:"counters"`
}

// Tracker computes deltas from successive readings of the core's counters.
//
// Not safe for concurrent use: one poller owns one tracker.
type Tracker struct {
	mode Mode

	coreStartedAt time.Time
	last          map[string]int64

	// baselined is set once a reading has been taken from a core whose history is unknown.
	// Only such a core needs one.
	baselined bool
}

// NewTracker builds a tracker, resuming from a snapshot a previous run saved.
func NewTracker(mode Mode, snapshot Snapshot) *Tracker {
	if !mode.Valid() {
		mode = ModeDelta
	}

	tracker := &Tracker{
		mode:          mode,
		coreStartedAt: snapshot.CoreStartedAt,
		last:          make(map[string]int64, len(snapshot.Counters)),
	}
	for name, value := range snapshot.Counters {
		tracker.last[name] = value
	}
	return tracker
}

// UsesReset reports what to ask the core for.
func (t *Tracker) UsesReset() bool { return t.mode == ModeReset }

// Observe folds one reading into deltas per user.
//
// coreStartedAt is when the process being read was started, as the supervisor knows it. A
// zero value means the agent does not know — the core is not one it started — and only then
// is a reading treated as a baseline.
func (t *Tracker) Observe(counters map[string]int64, coreStartedAt time.Time) []Delta {
	byEmail := make(map[string]*Delta)

	// A core the agent started has counters that began at zero, so everything in them is
	// traffic nobody has billed yet. A core it cannot date might hold traffic that has
	// already been billed, and the first reading of one is a baseline.
	fresh := !coreStartedAt.IsZero() && !coreStartedAt.Equal(t.coreStartedAt)
	baseline := t.mode == ModeDelta && coreStartedAt.IsZero() && !t.baselined && len(t.last) == 0

	for name, value := range counters {
		email, direction, ok := parseUserCounter(name)
		if !ok {
			continue
		}
		if value < 0 {
			// Not something the core should ever report. Ignored rather than trusted: a
			// negative reading folded into a delta would take bytes off a user's balance,
			// which is a way to hand out free traffic.
			continue
		}

		amount := value
		if t.mode == ModeDelta {
			previous, seen := t.last[name]
			switch {
			case baseline:
				amount = 0
			case fresh, !seen, value < previous:
				// A new core process, a counter that appeared since the last reading, or a
				// counter that went backwards: in all three the counter started at zero and
				// its value is the traffic since then.
				amount = value
			default:
				amount = value - previous
			}
			t.last[name] = value
		}

		if amount == 0 {
			continue
		}

		delta := byEmail[email]
		if delta == nil {
			delta = &Delta{Email: email}
			byEmail[email] = delta
		}
		switch direction {
		case directionUp:
			delta.Uplink = addSaturating(delta.Uplink, amount)
		case directionDown:
			delta.Downlink = addSaturating(delta.Downlink, amount)
		}
	}

	if t.mode == ModeDelta {
		// Counters the core no longer reports belong to users who are no longer on it.
		// Keeping them would make the user look like they had restarted when they came
		// back, and would leak memory on an installation with churn.
		for name := range t.last {
			if _, present := counters[name]; !present {
				delete(t.last, name)
			}
		}
		if !coreStartedAt.IsZero() {
			t.coreStartedAt = coreStartedAt
		}
		if baseline {
			t.baselined = true
		}
	}

	deltas := make([]Delta, 0, len(byEmail))
	for _, delta := range byEmail {
		if delta.Empty() {
			continue
		}
		deltas = append(deltas, *delta)
	}
	return deltas
}

// Snapshot is the state to persist so that a restart resumes instead of starting over.
func (t *Tracker) Snapshot() Snapshot {
	counters := make(map[string]int64, len(t.last))
	for name, value := range t.last {
		counters[name] = value
	}
	return Snapshot{CoreStartedAt: t.coreStartedAt, Counters: counters}
}

// parseUserCounter reads a per-user traffic counter name.
func parseUserCounter(name string) (email, direction string, ok bool) {
	parts := strings.Split(name, counterSeparator)
	if len(parts) != 4 {
		return "", "", false
	}
	if parts[0] != counterKindUser || parts[2] != counterTraffic {
		return "", "", false
	}
	if parts[3] != directionUp && parts[3] != directionDown {
		return "", "", false
	}
	if parts[1] == "" {
		return "", "", false
	}
	return parts[1], parts[3], true
}

// addSaturating adds without wrapping.
//
// An int64 of bytes is 8 exabytes, which no user will move; but a counter the core
// reported wrongly, or a delta computed from a corrupted snapshot, could get close enough
// for the addition to wrap — and a wrapped total is a negative balance, which downstream
// reads as a user who has used no traffic at all.
func addSaturating(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	if b < 0 && a < math.MinInt64-b {
		return math.MinInt64
	}
	return a + b
}
