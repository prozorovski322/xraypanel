package link

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/xraypanel/panel/internal/agent/stats"
	"github.com/xraypanel/panel/internal/agent/store"
	"github.com/xraypanel/panel/internal/agent/xrayapi"
	nodectlv1 "github.com/xraypanel/panel/internal/nodectl/v1"
)

// maxDeltasPerBatch bounds one message on the control stream.
//
// A node that has been unable to report for a day holds one row per user per hour, which
// for a few thousand users is more than belongs in a single gRPC message. Splitting keeps
// each batch acknowledgeable on its own, so progress is never all-or-nothing.
const maxDeltasPerBatch = 2000

// pollTraffic reads the core's counters on a schedule and buffers what it finds.
//
// It runs for the life of the agent rather than for the life of a connection: traffic
// happens whether or not the panel is reachable, and a node that stopped counting during
// an outage would be a node whose users were not billed for that time.
func (a *Agent) pollTraffic(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// One last reading on the way out, so that a planned stop does not throw away
			// the traffic since the last tick.
			a.collectTraffic(context.WithoutCancel(ctx))
			return
		case <-ticker.C:
			a.collectTraffic(ctx)
		}
	}
}

// collectTraffic performs one poll.
//
// Failures are logged and dropped: the counters are cumulative and still in the core, so
// the next poll picks up everything this one missed. That is the property that makes this
// strategy worth its complexity (ADR-008).
func (a *Agent) collectTraffic(ctx context.Context) {
	if !a.sup.Running() {
		return
	}

	endpoint, ok := a.sup.Endpoint()
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, statsBudget)
	defer cancel()

	client, err := xrayapi.Dial(endpoint)
	if err != nil {
		a.log.WarnContext(ctx, "could not reach the core's api to read traffic", slog.Any("error", err))
		return
	}
	defer func() { _ = client.Close() }()

	counters, err := client.Counters(ctx, xrayapi.UserCounterPattern, a.tracker.UsesReset())
	if err != nil {
		a.log.WarnContext(ctx, "could not read traffic counters", slog.Any("error", err))
		return
	}

	// The counter names are the contract between the core and the billing pipeline, and a
	// user whose traffic is not being billed looks exactly like a user who moved none. At
	// debug level the names are printed, because that is the difference.
	if a.log.Enabled(ctx, slog.LevelDebug) {
		names := make([]string, 0, len(counters))
		for name, value := range counters {
			names = append(names, fmt.Sprintf("%s=%d", name, value))
		}
		a.log.DebugContext(ctx, "read traffic counters", slog.Any("counters", names))
	}

	// The core's start time is what tells the tracker whether these counters continue the
	// ones it saw last, or belong to a process that started again from zero.
	deltas := a.tracker.Observe(counters, a.sup.State().StartedAt)
	hour := time.Now().UTC().Truncate(time.Hour)

	buffered := make([]store.TrafficDelta, 0, len(deltas))
	for _, delta := range deltas {
		buffered = append(buffered, store.TrafficDelta{
			Email:    delta.Email,
			Uplink:   delta.Uplink,
			Downlink: delta.Downlink,
			Hour:     hour,
		})
	}

	// Both in one transaction: separately, a crash between them either loses the deltas
	// or bills them twice.
	if err := a.store.RecordTrafficPoll(buffered, a.tracker.Snapshot()); err != nil {
		// The deltas are lost, but the counters are not: they were not saved either, so
		// the next poll computes the difference from the same baseline and the traffic is
		// billed then.
		a.log.ErrorContext(ctx, "could not record a traffic poll", slog.Any("error", err))
		return
	}

	if len(buffered) > 0 {
		a.log.DebugContext(ctx, "buffered traffic", slog.Int("users", len(buffered)))
	}
}

// reportTraffic hands buffered traffic to the panel over an open stream.
//
// Unacknowledged batches go first and in order: they are the oldest traffic, and the
// oldest is what a retention window or a monthly boundary is closest to swallowing.
func (a *Agent) reportTraffic(ctx context.Context, stream nodectlv1.NodeControl_ControlClient) error {
	pending, err := a.store.PendingTrafficBatches()
	if err != nil {
		return err
	}

	for _, batch := range pending {
		if err := a.sendBatch(ctx, stream, batch); err != nil {
			return err
		}
	}

	for {
		id, err := batchID()
		if err != nil {
			return err
		}

		batch, err := a.store.TakeTrafficBatch(id, maxDeltasPerBatch, time.Now())
		if err != nil {
			return err
		}
		if batch == nil {
			return nil
		}

		if err := a.sendBatch(ctx, stream, batch); err != nil {
			return err
		}
		if len(batch.Deltas) < maxDeltasPerBatch {
			return nil
		}
	}
}

func (a *Agent) sendBatch(
	ctx context.Context,
	stream nodectlv1.NodeControl_ControlClient,
	batch *store.TrafficBatch,
) error {
	deltas := make([]*nodectlv1.TrafficDelta, 0, len(batch.Deltas))
	for _, delta := range batch.Deltas {
		deltas = append(deltas, &nodectlv1.TrafficDelta{
			XrayEmail: delta.Email,
			Uplink:    delta.Uplink,
			Downlink:  delta.Downlink,
			Hour:      delta.Hour.UTC().Format(time.RFC3339),
		})
	}

	a.log.DebugContext(ctx, "reporting traffic",
		slog.String("batch_id", batch.ID), slog.Int("deltas", len(deltas)))

	err := stream.Send(&nodectlv1.NodeMessage{
		Payload: &nodectlv1.NodeMessage_TrafficBatch{TrafficBatch: &nodectlv1.TrafficBatch{
			BatchId: batch.ID,
			Deltas:  deltas,
		}},
	})
	if err != nil {
		return fmt.Errorf("link: send a traffic batch: %w", err)
	}
	return nil
}

// handleTrafficAck forgets a batch the panel has stored.
func (a *Agent) handleTrafficAck(ctx context.Context, ack *nodectlv1.TrafficAck) error {
	if !ack.GetStored() {
		// Kept and resent on the next connection. The panel says why, and it is worth
		// seeing: a node that cannot report traffic is a node whose users are not billed.
		a.log.ErrorContext(ctx, "the panel could not store a traffic batch; it will be sent again",
			slog.String("batch_id", ack.GetBatchId()),
			slog.String("error", ack.GetError()))
		return nil
	}

	if err := a.store.AckTrafficBatch(ack.GetBatchId()); err != nil {
		return err
	}
	a.log.DebugContext(ctx, "the panel stored a traffic batch", slog.String("batch_id", ack.GetBatchId()))
	return nil
}

// newTracker builds the counter tracker, resuming from whatever the previous run saved.
func newTracker(state *store.Store, mode stats.Mode, logger *slog.Logger) *stats.Tracker {
	persisted, err := state.CounterSnapshot()
	if err != nil {
		// Starting without it is safe — the next reading of a core this agent started is
		// billed in full — but it is still worth reporting: a store that cannot be read is
		// a node that has lost more than its counters.
		logger.Error("could not read the saved traffic counters", slog.Any("error", err))
		persisted = stats.Snapshot{}
	}
	return stats.NewTracker(mode, persisted)
}

// batchID is a random identifier the panel deduplicates on.
//
// Random rather than a counter, because a counter would have to survive the volume being
// restored from a backup: two nodes, or one node twice, reusing batch 7 with different
// contents would have the panel discard real traffic as a duplicate.
func batchID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("link: generate a batch id: %w", err)
	}
	return id.String(), nil
}
