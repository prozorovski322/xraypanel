package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/xraypanel/panel/internal/agent/stats"
)

// Buckets for traffic. Separate from meta because they have a different shape — many small
// rows with a lifecycle — and because clearing them must never risk the identity.
var (
	// bucketTraffic holds deltas that have not been handed to the panel yet, keyed by
	// hour and stats key.
	bucketTraffic = []byte("traffic")

	// bucketBatches holds batches that were sent and not yet acknowledged, keyed by batch
	// id. They stay until the panel confirms it stored them, and are resent on the next
	// connection — which is safe because the panel deduplicates by batch id.
	bucketBatches = []byte("batches")

	// keyCounters is the last absolute value of each of the core's counters, so that an
	// agent restart resumes instead of discarding the traffic since its last poll.
	keyCounters = []byte("counters")
)

// maxPendingBatches bounds how many unacknowledged batches are kept.
//
// A panel that has been unreachable for a week must not fill the node's volume, and a node
// that cannot report traffic is a billing problem rather than a service problem — so the
// oldest batches are dropped rather than the newest, and the drop is loud.
const maxPendingBatches = 500

// TrafficDelta is traffic one user moved in one hour on this node.
type TrafficDelta struct {
	// Email is users.xray_email: immutable, and the only user identifier a node holds.
	Email string `json:"email"`

	Uplink   int64 `json:"uplink"`
	Downlink int64 `json:"downlink"`

	// Hour is the UTC hour this traffic is attributed to. The agent stamps it, because
	// the agent is what observed the traffic; the panel's clock could be minutes away.
	Hour time.Time `json:"hour"`
}

// Empty reports whether there is nothing to report.
func (d TrafficDelta) Empty() bool { return d.Uplink == 0 && d.Downlink == 0 }

// TrafficBatch is one attempt to hand a set of deltas to the panel.
type TrafficBatch struct {
	// ID makes a resend after a lost acknowledgement safe to apply twice: the panel
	// records the id and ignores a batch it has already stored.
	ID string `json:"id"`

	Deltas []TrafficDelta `json:"deltas"`

	CreatedAt time.Time `json:"created_at"`
}

// AddTrafficDeltas folds deltas into the pending buffer.
//
// Folded rather than appended: a node polling every thirty seconds produces 120 readings
// an hour per user, and the panel is only ever told the total for an hour. Merging here
// keeps the buffer small enough that a long panel outage costs kilobytes.
func (s *Store) AddTrafficDeltas(deltas []TrafficDelta) error {
	if len(deltas) == 0 {
		return nil
	}

	if err := s.db.Update(func(tx *bolt.Tx) error { return addDeltasTx(tx, deltas) }); err != nil {
		return fmt.Errorf("store: buffer traffic: %w", err)
	}
	return nil
}

// RecordTrafficPoll stores the deltas from one poll and the counters they were computed
// from, in one transaction.
//
// One transaction because the two are only correct together. Written separately, a crash
// between them either loses the deltas — if the counters were saved first, the next poll
// computes no difference and the traffic is gone — or bills them twice, if the deltas were
// saved first and the next poll recomputes them from the older counters. Double billing is
// the worse of the two, and this avoids having to choose.
func (s *Store) RecordTrafficPoll(deltas []TrafficDelta, counters stats.Snapshot) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := addDeltasTx(tx, deltas); err != nil {
			return err
		}
		return saveCountersTx(tx, counters)
	})
	if err != nil {
		return fmt.Errorf("store: record a traffic poll: %w", err)
	}
	return nil
}

func addDeltasTx(tx *bolt.Tx, deltas []TrafficDelta) error {
	if len(deltas) == 0 {
		return nil
	}

	bucket, err := tx.CreateBucketIfNotExists(bucketTraffic)
	if err != nil {
		return err
	}

	for _, delta := range deltas {
		if delta.Email == "" || delta.Empty() {
			continue
		}
		delta.Hour = delta.Hour.UTC().Truncate(time.Hour)

		key := trafficKey(delta.Hour, delta.Email)
		if raw := bucket.Get(key); raw != nil {
			var existing TrafficDelta
			if err := json.Unmarshal(raw, &existing); err != nil {
				return fmt.Errorf("decode buffered delta: %w", err)
			}
			delta.Uplink = addSaturating(existing.Uplink, delta.Uplink)
			delta.Downlink = addSaturating(existing.Downlink, delta.Downlink)
		}

		encoded, err := json.Marshal(delta)
		if err != nil {
			return fmt.Errorf("encode delta: %w", err)
		}
		if err := bucket.Put(key, encoded); err != nil {
			return err
		}
	}
	return nil
}

// TakeTrafficBatch moves everything buffered into a batch under id and returns it.
//
// One transaction, because the two halves are the same event: deltas that left the buffer
// without landing in a batch are traffic nobody will ever bill, and deltas in a batch that
// are also still buffered would be billed twice if the batch is acknowledged.
//
// At most limit deltas are taken, oldest hour first; the rest stay buffered for the next
// batch. A single message with a day's worth of rows for a few thousand users is both
// unwieldy and all-or-nothing, where several batches make progress one acknowledgement at
// a time.
//
// Returns nil when there is nothing to send.
func (s *Store) TakeTrafficBatch(id string, limit int, now time.Time) (*TrafficBatch, error) {
	if id == "" {
		return nil, errors.New("store: a traffic batch needs an id")
	}
	if limit <= 0 {
		return nil, errors.New("store: a traffic batch needs a positive limit")
	}

	batch := &TrafficBatch{ID: id, CreatedAt: now.UTC()}

	err := s.db.Update(func(tx *bolt.Tx) error {
		pending, err := tx.CreateBucketIfNotExists(bucketTraffic)
		if err != nil {
			return err
		}
		batches, err := tx.CreateBucketIfNotExists(bucketBatches)
		if err != nil {
			return err
		}

		// Keys begin with the hour, so the cursor walks the buffer oldest first — which is
		// the order to report in: the oldest traffic is the closest to a retention window
		// or a month boundary.
		var taken [][]byte
		cursor := pending.Cursor()
		for key, raw := cursor.First(); key != nil && len(batch.Deltas) < limit; key, raw = cursor.Next() {
			var delta TrafficDelta
			if err := json.Unmarshal(raw, &delta); err != nil {
				return fmt.Errorf("decode buffered delta: %w", err)
			}
			batch.Deltas = append(batch.Deltas, delta)
			taken = append(taken, append([]byte(nil), key...))
		}
		if len(batch.Deltas) == 0 {
			return nil
		}

		encoded, err := json.Marshal(batch)
		if err != nil {
			return fmt.Errorf("encode batch: %w", err)
		}
		if err := batches.Put([]byte(id), encoded); err != nil {
			return err
		}

		for _, key := range taken {
			if err := pending.Delete(key); err != nil {
				return err
			}
		}

		return dropOldestBatches(batches)
	})
	if err != nil {
		return nil, fmt.Errorf("store: take a traffic batch: %w", err)
	}

	if len(batch.Deltas) == 0 {
		return nil, nil
	}
	return batch, nil
}

// PendingTrafficBatches returns batches the panel has not acknowledged, oldest first.
func (s *Store) PendingTrafficBatches() ([]*TrafficBatch, error) {
	var batches []*TrafficBatch

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketBatches)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(_, raw []byte) error {
			batch := &TrafficBatch{}
			if err := json.Unmarshal(raw, batch); err != nil {
				return fmt.Errorf("decode batch: %w", err)
			}
			batches = append(batches, batch)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("store: read pending batches: %w", err)
	}

	sort.Slice(batches, func(i, j int) bool { return batches[i].CreatedAt.Before(batches[j].CreatedAt) })
	return batches, nil
}

// AckTrafficBatch forgets a batch the panel has stored.
func (s *Store) AckTrafficBatch(id string) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketBatches)
		if bucket == nil {
			return nil
		}
		return bucket.Delete([]byte(id))
	})
	if err != nil {
		return fmt.Errorf("store: acknowledge batch %s: %w", id, err)
	}
	return nil
}

// SaveCounterSnapshot records the core's absolute counters and which process they came
// from.
//
// This is what makes an agent restart cost nothing: the counters are still in the running
// core, so the traffic since the last poll is still there to be read. The process identity
// matters as much as the values — counters from a core that has since restarted are not a
// continuation of these.
func (s *Store) SaveCounterSnapshot(counters stats.Snapshot) error {
	if err := s.db.Update(func(tx *bolt.Tx) error { return saveCountersTx(tx, counters) }); err != nil {
		return fmt.Errorf("store: write counters: %w", err)
	}
	return nil
}

func saveCountersTx(tx *bolt.Tx, counters stats.Snapshot) error {
	encoded, err := json.Marshal(counters)
	if err != nil {
		return fmt.Errorf("encode counters: %w", err)
	}
	return tx.Bucket(bucketMeta).Put(keyCounters, encoded)
}

// CounterSnapshot returns the saved counters. The zero value means there are none, which
// is what a node that has never polled looks like.
func (s *Store) CounterSnapshot() (stats.Snapshot, error) {
	var snapshot stats.Snapshot

	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketMeta).Get(keyCounters)
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &snapshot)
	})
	if err != nil {
		return stats.Snapshot{}, fmt.Errorf("store: read counters: %w", err)
	}
	return snapshot, nil
}

// BufferedTrafficDeltas returns what is waiting to be sent. For diagnostics and tests.
func (s *Store) BufferedTrafficDeltas() ([]TrafficDelta, error) {
	var deltas []TrafficDelta

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketTraffic)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(_, raw []byte) error {
			var delta TrafficDelta
			if err := json.Unmarshal(raw, &delta); err != nil {
				return err
			}
			deltas = append(deltas, delta)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("store: read buffered traffic: %w", err)
	}
	return deltas, nil
}

// trafficKey orders the buffer by hour, which is also the order the panel prefers to
// receive: the oldest hour is the one at risk of falling outside a retention window.
func trafficKey(hour time.Time, email string) []byte {
	return []byte(hour.UTC().Format(time.RFC3339) + "|" + email)
}

// dropOldestBatches enforces maxPendingBatches.
func dropOldestBatches(batches *bolt.Bucket) error {
	if batches.Stats().KeyN <= maxPendingBatches {
		return nil
	}

	type entry struct {
		key       []byte
		createdAt time.Time
	}
	var entries []entry

	err := batches.ForEach(func(key, raw []byte) error {
		var batch TrafficBatch
		if err := json.Unmarshal(raw, &batch); err != nil {
			return err
		}
		entries = append(entries, entry{key: append([]byte(nil), key...), createdAt: batch.CreatedAt})
		return nil
	})
	if err != nil {
		return err
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].createdAt.Before(entries[j].createdAt) })

	for i := 0; i < len(entries)-maxPendingBatches; i++ {
		if err := batches.Delete(entries[i].key); err != nil {
			return err
		}
	}
	return nil
}

// addSaturating adds without wrapping. A wrapped total is a negative number of bytes,
// which every reader downstream would take for "no traffic at all".
func addSaturating(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	if b < 0 && a < math.MinInt64-b {
		return math.MinInt64
	}
	return a + b
}
