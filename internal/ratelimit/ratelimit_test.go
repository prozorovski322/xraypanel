package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)}
}

func TestBurstThenRefusal(t *testing.T) {
	clock := newClock()
	limiter := New(60, 3, WithClock(clock.Now))

	for i := range 3 {
		if ok, _ := limiter.Allow("a"); !ok {
			t.Fatalf("request %d within the burst was refused", i+1)
		}
	}

	ok, wait := limiter.Allow("a")
	if ok {
		t.Fatal("the request past the burst was allowed")
	}
	// 60 a minute is one a second, and the bucket is empty.
	if wait <= 0 || wait > time.Second {
		t.Fatalf("retry after %s, want (0, 1s]", wait)
	}
}

func TestRefillsAtTheConfiguredRate(t *testing.T) {
	clock := newClock()
	limiter := New(30, 1, WithClock(clock.Now)) // one token every two seconds

	if ok, _ := limiter.Allow("a"); !ok {
		t.Fatal("first request refused")
	}
	clock.advance(time.Second)
	if ok, _ := limiter.Allow("a"); ok {
		t.Fatal("allowed after half a refill interval")
	}
	clock.advance(time.Second)
	if ok, _ := limiter.Allow("a"); !ok {
		t.Fatal("refused after a full refill interval")
	}
}

func TestRefillIsCappedAtTheBurst(t *testing.T) {
	clock := newClock()
	limiter := New(60, 2, WithClock(clock.Now))

	limiter.Allow("a")
	clock.advance(time.Hour)

	allowed := 0
	for range 10 {
		if ok, _ := limiter.Allow("a"); ok {
			allowed++
		}
	}
	if allowed != 2 {
		t.Fatalf("an hour of idleness bought %d requests, want the burst of 2", allowed)
	}
}

func TestKeysAreIndependent(t *testing.T) {
	clock := newClock()
	limiter := New(60, 1, WithClock(clock.Now))

	limiter.Allow("a")
	if ok, _ := limiter.Allow("a"); ok {
		t.Fatal("a was not limited")
	}
	if ok, _ := limiter.Allow("b"); !ok {
		t.Fatal("b paid for a's requests")
	}
}

func TestIdleBucketsAreForgotten(t *testing.T) {
	clock := newClock()
	limiter := New(60, 5, WithClock(clock.Now))

	for i := range 50 {
		limiter.Allow(fmt.Sprintf("client-%d", i))
	}
	if limiter.Len() != 50 {
		t.Fatalf("tracking %d keys, want 50", limiter.Len())
	}

	// Long enough for every bucket to refill, and past the sweep interval.
	clock.advance(2 * time.Minute)
	limiter.Allow("fresh")

	if limiter.Len() != 1 {
		t.Fatalf("tracking %d keys after the sweep, want only the fresh one", limiter.Len())
	}
}

func TestAnEmptiedBucketSurvivesTheSweep(t *testing.T) {
	clock := newClock()
	limiter := New(1, 2, WithClock(clock.Now)) // one a minute

	limiter.Allow("a")
	limiter.Allow("a")

	// Past the sweep interval but not long enough to refill both tokens: forgetting the
	// bucket now would hand the client a fresh burst.
	clock.advance(61 * time.Second)
	limiter.Allow("other")

	ok, _ := limiter.Allow("a")
	if !ok {
		t.Fatal("the token refilled over the minute was not available")
	}
	if ok, _ := limiter.Allow("a"); ok {
		t.Fatal("the sweep reset a bucket that had not refilled")
	}
}

func TestPastTheKeyBoundNewClientsAreLetThrough(t *testing.T) {
	clock := newClock()
	limiter := New(60, 1, WithClock(clock.Now), WithMaxKeys(2))

	limiter.Allow("a")
	limiter.Allow("b")

	for range 3 {
		if ok, _ := limiter.Allow("c"); !ok {
			t.Fatal("a client beyond the bound was refused")
		}
	}
	if limiter.Len() != 2 {
		t.Fatalf("tracking %d keys, want the bound of 2", limiter.Len())
	}
	// Clients already tracked are still limited.
	if ok, _ := limiter.Allow("a"); ok {
		t.Fatal("a tracked client escaped its limit once the map was full")
	}
}
