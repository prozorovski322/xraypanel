package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xraypanel/panel/internal/audit"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// TrafficDelta is traffic one user moved on one node in one hour, as a node reported it.
type TrafficDelta struct {
	// XrayEmail is the immutable stats key. A node knows users by nothing else (ADR-007),
	// which is deliberate: a node holds no usernames and no personal data.
	XrayEmail string

	Uplink   int64
	Downlink int64

	// Hour is the UTC hour the node attributed the traffic to. Taken from the node
	// because the node is what observed it; the panel's clock may differ by minutes, and
	// an hour boundary is exactly where that would show up.
	Hour time.Time
}

// TrafficIngestResult is what became of one batch.
type TrafficIngestResult struct {
	// Duplicate means this batch had already been applied and was ignored. A node resends
	// whenever it did not hear an acknowledgement, so this is an ordinary outcome and not
	// an error.
	Duplicate bool

	// Applied is how many deltas were accounted, and Unknown how many named a stats key
	// that no longer resolves to a user.
	Applied int
	Unknown int

	Bytes int64
}

// maxTrafficBatchDeltas bounds what one batch may carry.
//
// A node is not a trusted input even with a valid certificate: a compromised or buggy one
// could otherwise hold a transaction open over an unbounded list.
const maxTrafficBatchDeltas = 5000

// maxTrafficHourSkew is how far into the future an hour may be.
//
// A node with a badly wrong clock would otherwise write traffic into a partition that does
// not exist yet, or into one so far ahead that no report would ever show it again.
const maxTrafficHourSkew = 2 * time.Hour

// IngestTrafficBatch accounts one batch of traffic from one node.
//
// Everything happens in one transaction, keyed by the batch id. Applying a batch twice
// would bill users for bytes they moved once, and applying half of one would move a user's
// counters without the hourly rows that explain them — with no way to tell afterwards
// which half landed.
func (s *Service) IngestTrafficBatch(
	ctx context.Context,
	nodeID int64,
	batchID string,
	deltas []TrafficDelta,
) (*TrafficIngestResult, error) {
	if batchID == "" {
		return nil, validationErrorf("a traffic batch must have an id")
	}
	if len(deltas) > maxTrafficBatchDeltas {
		return nil, validationErrorf("a traffic batch may carry at most %d deltas, got %d",
			maxTrafficBatchDeltas, len(deltas))
	}

	// The id is a uuid because that is what the deduplication table stores. Parsed rather
	// than trusted: a node sends this, and a value the column cannot hold would fail the
	// whole transaction with an error about types rather than about the node.
	parsed, err := uuid.Parse(batchID)
	if err != nil {
		return nil, validationErrorf("a traffic batch id must be a uuid: %v", err)
	}
	batchUUID := pgtype.UUID{Bytes: parsed, Valid: true}

	now := time.Now().UTC()
	result := &TrafficIngestResult{}

	err = s.tx(ctx, func(queries *dbgen.Queries, _ *audit.Recorder) error {
		// Claiming the id first makes the rest of this transaction conditional on the
		// batch being new: a concurrent duplicate blocks here and then finds nothing to
		// claim, rather than racing to apply the same bytes.
		if _, err := queries.RecordTrafficBatch(ctx, dbgen.RecordTrafficBatchParams{
			NodeID:     nodeID,
			BatchID:    batchUUID,
			ReceivedAt: now,
		}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				result.Duplicate = true
				return nil
			}
			return translate(err, "traffic batch")
		}

		// One lookup for the whole batch rather than one per delta: a node reports every
		// user that moved bytes in the interval, which on a busy node is most of them.
		emails := make([]string, 0, len(deltas))
		seen := make(map[string]struct{}, len(deltas))
		for _, delta := range deltas {
			if delta.XrayEmail == "" {
				continue
			}
			if _, dup := seen[delta.XrayEmail]; dup {
				continue
			}
			seen[delta.XrayEmail] = struct{}{}
			emails = append(emails, delta.XrayEmail)
		}

		userIDs := make(map[string]int64, len(emails))
		if len(emails) > 0 {
			rows, err := queries.FindUsersByXrayEmail(ctx, emails)
			if err != nil {
				return translate(err, "users")
			}
			for _, row := range rows {
				userIDs[row.XrayEmail] = row.ID
			}
		}

		// Accumulated per user across the batch, so a user reported in several hours costs
		// one update of their counters instead of one per hour.
		perUser := make(map[int64]int64, len(userIDs))
		var nodeBytes int64

		for _, delta := range deltas {
			if delta.Uplink < 0 || delta.Downlink < 0 {
				// Not something an honest node sends, and it would credit traffic back to
				// a user. Dropped rather than clamped, so the report says what happened.
				result.Unknown++
				continue
			}
			if delta.Uplink == 0 && delta.Downlink == 0 {
				continue
			}

			userID, known := userIDs[delta.XrayEmail]
			if !known {
				// The user was deleted between the node receiving its configuration and
				// reporting. Their traffic has nowhere to go.
				result.Unknown++
				continue
			}

			hour := delta.Hour.UTC().Truncate(time.Hour)
			if hour.IsZero() || hour.After(now.Add(maxTrafficHourSkew)) {
				result.Unknown++
				continue
			}

			if err := queries.AddTrafficRecord(ctx, dbgen.AddTrafficRecordParams{
				Hour:     hour,
				UserID:   userID,
				NodeID:   nodeID,
				Uplink:   delta.Uplink,
				Downlink: delta.Downlink,
			}); err != nil {
				return translate(err, "traffic record")
			}

			bytes := delta.Uplink + delta.Downlink
			perUser[userID] += bytes
			nodeBytes += bytes
			result.Applied++
			result.Bytes += bytes
		}

		for userID, bytes := range perUser {
			if err := queries.AddUserTraffic(ctx, dbgen.AddUserTrafficParams{
				ID:    userID,
				Bytes: bytes,
				// Traffic in this batch means the user was moving bytes recently; the
				// column only ever moves forward, so a late batch cannot make a user look
				// less active than they are.
				OnlineAt: now,
			}); err != nil {
				return translate(err, "user traffic")
			}
		}

		if nodeBytes > 0 {
			if err := queries.AddNodeTraffic(ctx, dbgen.AddNodeTrafficParams{
				ID:    nodeID,
				Bytes: nodeBytes,
			}); err != nil {
				return translate(err, "node traffic")
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	switch {
	case result.Duplicate:
		s.log.InfoContext(ctx, "ignored a traffic batch this panel has already stored",
			slog.Int64("node_id", nodeID), slog.String("batch_id", batchID))
	case result.Unknown > 0:
		s.log.WarnContext(ctx, "some traffic could not be attributed",
			slog.Int64("node_id", nodeID),
			slog.String("batch_id", batchID),
			slog.Int("applied", result.Applied),
			slog.Int("dropped", result.Unknown))
	}

	return result, nil
}

// UserTrafficByDay is one day of a user's traffic.
type UserTrafficByDay struct {
	Day      time.Time
	Uplink   int64
	Downlink int64
}

// UserTrafficHistory returns a user's daily traffic in a window, for the charts.
func (s *Service) UserTrafficHistory(
	ctx context.Context, userID int64, from, to time.Time,
) ([]UserTrafficByDay, error) {
	rows, err := s.q.ListUserTrafficByDay(ctx, dbgen.ListUserTrafficByDayParams{
		UserID:  userID,
		FromDay: dateOf(from),
		ToDay:   dateOf(to),
	})
	if err != nil {
		return nil, translate(err, "user traffic")
	}

	history := make([]UserTrafficByDay, 0, len(rows))
	for _, row := range rows {
		history = append(history, UserTrafficByDay{
			Day:      row.Day.Time.UTC(),
			Uplink:   row.Uplink,
			Downlink: row.Downlink,
		})
	}
	return history, nil
}

// dateOf takes the UTC calendar day out of an instant. The daily rollup is keyed by date,
// and billing days are UTC days (ADR-006).
func dateOf(at time.Time) pgtype.Date {
	year, month, day := at.UTC().Date()
	return pgtype.Date{Time: time.Date(year, month, day, 0, 0, 0, 0, time.UTC), Valid: true}
}

// NodeTrafficHistory is the same for a node.
func (s *Service) NodeTrafficHistory(
	ctx context.Context, nodeID int64, from, to time.Time,
) ([]UserTrafficByDay, error) {
	rows, err := s.q.ListNodeTrafficByDay(ctx, dbgen.ListNodeTrafficByDayParams{
		NodeID:  nodeID,
		FromDay: dateOf(from),
		ToDay:   dateOf(to),
	})
	if err != nil {
		return nil, translate(err, "node traffic")
	}

	history := make([]UserTrafficByDay, 0, len(rows))
	for _, row := range rows {
		history = append(history, UserTrafficByDay{
			Day:      row.Day.Time.UTC(),
			Uplink:   row.Uplink,
			Downlink: row.Downlink,
		})
	}
	return history, nil
}
