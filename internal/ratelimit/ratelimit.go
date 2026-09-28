// Package ratelimit is an in-process token bucket keyed by an arbitrary string, used to
// bound how often one client can hit the public subscription endpoint.
//
// In process rather than in Postgres or Redis because the panel runs as one instance
// (ADR-002) and because the point is to keep load off the database: a limiter that
// needed a database write per request would cost what it protects against.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Limiter hands out tokens per key. The zero value is not usable; call New.
type Limiter struct {
	mu sync.Mutex

	// perSecond is the refill rate and burst the bucket size.
	perSecond float64
	burst     float64

	buckets map[string]*bucket
	maxKeys int

	now       func() time.Time
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Option adjusts a Limiter.
type Option func(*Limiter)

// WithClock replaces the time source, for tests.
func WithClock(now func() time.Time) Option {
	return func(l *Limiter) { l.now = now }
}

// WithMaxKeys bounds how many distinct keys are tracked at once.
func WithMaxKeys(n int) Option {
	return func(l *Limiter) { l.maxKeys = n }
}

// defaultMaxKeys bounds memory at a few megabytes whatever the traffic looks like.
const defaultMaxKeys = 100_000

// sweepEvery is how often idle buckets are dropped.
const sweepEvery = time.Minute

// New returns a limiter allowing perMinute requests per key on average, with bursts of
// up to burst.
func New(perMinute, burst int, opts ...Option) *Limiter {
	l := &Limiter{
		perSecond: float64(perMinute) / 60,
		burst:     float64(burst),
		buckets:   map[string]*bucket{},
		maxKeys:   defaultMaxKeys,
		now:       time.Now,
	}
	for _, opt := range opts {
		opt(l)
	}
	l.lastSweep = l.now()
	return l
}

// Allow takes a token for key. When none is left it reports how long until one is.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if now.Sub(l.lastSweep) >= sweepEvery {
		l.sweep(now)
	}

	b, ok := l.buckets[key]
	if !ok {
		// Past the bound the limiter lets new keys through untracked rather than refusing
		// them. It is a per-client limit, so a flood from that many distinct addresses is
		// not something it could stop anyway, and refusing would turn the flood into an
		// outage for every legitimate client that happened to arrive during it.
		if len(l.buckets) >= l.maxKeys {
			return true, 0
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}

	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.perSecond)
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}

	wait := time.Duration((1 - b.tokens) / l.perSecond * float64(time.Second))
	return false, wait
}

// sweep drops buckets that have refilled completely: forgetting them changes nothing,
// since a new bucket starts full.
func (l *Limiter) sweep(now time.Time) {
	for key, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.perSecond >= l.burst {
			delete(l.buckets, key)
		}
	}
	l.lastSweep = now
}

// Len reports how many keys are tracked, for tests and diagnostics.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
