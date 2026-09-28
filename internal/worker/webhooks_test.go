package worker

import (
	"testing"
	"time"
)

// The retry schedule is what decides how long a receiver can be down before it misses an
// event for good, so it is pinned here rather than left implicit.
func TestBackoffDoublesAndIsCapped(t *testing.T) {
	cases := map[int]time.Duration{
		0:  30 * time.Second, // treated as the first attempt
		1:  30 * time.Second,
		2:  time.Minute,
		3:  2 * time.Minute,
		4:  4 * time.Minute,
		10: 4*time.Hour + 16*time.Minute,
		11: 6 * time.Hour,
		50: 6 * time.Hour,
	}
	for attempts, want := range cases {
		if got := backoff(attempts); got != want {
			t.Errorf("backoff(%d) = %s, want %s", attempts, got, want)
		}
	}
}

// How long a receiver can be down before an event is given up on. Worth pinning, because it
// is the number an operator will be asked for, and because it is easy to get wrong: after
// the last attempt nothing is scheduled, so N attempts have N-1 pauses between them.
//
// The default has to cover a receiver that is down overnight. Ten attempts give just over
// four hours, which does not; twelve give fourteen and a half.
func TestDefaultRetryWindow(t *testing.T) {
	var total time.Duration
	for attempt := 1; attempt < defaultWebhookMaxAttempts; attempt++ {
		total += backoff(attempt)
	}

	const want = 14*time.Hour + 31*time.Minute + 30*time.Second
	if total != want {
		t.Errorf("the default retry window is %s, want %s", total, want)
	}
}
