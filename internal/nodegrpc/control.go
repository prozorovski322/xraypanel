package nodegrpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodectlv1 "github.com/xraypanel/panel/internal/nodectl/v1"
	"github.com/xraypanel/panel/internal/service"
)

// helloTimeout is how long a node has to introduce itself after opening a stream. A
// connection that authenticates and then says nothing is a socket held open for free.
const helloTimeout = 15 * time.Second

// bookkeepingTimeout bounds the writes made as a stream ends. The stream's own context
// is already cancelled by then, so these need a budget of their own.
const bookkeepingTimeout = 10 * time.Second

// Control runs a node's long-lived stream.
//
// The shape is: authenticate (done by the interceptor), expect a Hello, register the
// connection, acknowledge, then serve until something ends it. What ends it is one of a
// heartbeat that never arrived, an identity that stopped being valid, the node going
// away, or the panel shutting down — and every one of those has to leave the node's
// recorded status matching reality, which is why the bookkeeping is in a defer.
func (s *Server) Control(stream nodectlv1.NodeControl_ControlServer) error {
	identity, err := nodeFromContext(stream.Context())
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	logger := s.log.With(
		slog.Int64("node_id", identity.node.ID),
		slog.String("node", identity.node.Name),
		slog.String("remote_addr", remoteAddr(ctx)))

	// Receiving happens in its own goroutine so that the loop below can wait on a
	// heartbeat deadline as well as on a message. A bare Recv would block until the
	// node sent something, which is precisely the case a timeout has to catch.
	incoming := make(chan *nodectlv1.NodeMessage)
	recvErr := make(chan error, 1)
	go func() {
		defer close(incoming)
		for {
			msg, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case incoming <- msg:
			case <-ctx.Done():
				return
			}
		}
	}()

	hello, err := waitForHello(ctx, incoming, recvErr)
	if err != nil {
		logger.WarnContext(ctx, "node stream ended before it introduced itself", slog.Any("error", err))
		return err
	}

	conn := &Connection{
		NodeID:      identity.node.ID,
		NodeName:    identity.node.Name,
		Fingerprint: identity.fingerprint,
		RemoteAddr:  remoteAddr(ctx),
		ConnectedAt: time.Now().UTC(),
		send:        make(chan *nodectlv1.PanelMessage, sendQueueDepth),
		disconnect:  cancel,
	}
	s.registry.recordHello(conn, hello, conn.ConnectedAt)

	if previous := s.registry.Add(conn); previous != nil {
		// Replaced rather than refused; see Registry.Add.
		logger.WarnContext(ctx, "a second control stream replaced an existing one",
			slog.String("previous_remote_addr", previous.RemoteAddr),
			slog.Time("previous_connected_at", previous.ConnectedAt))
		previous.disconnect()
	}

	if err := s.svc.MarkNodeConnected(ctx, identity.node.ID, service.NodeConnectionInfo{
		AgentVersion:   hello.GetAgentVersion(),
		XrayVersion:    hello.GetXrayVersion(),
		AppliedVersion: hello.GetAppliedVersion(),
	}); err != nil {
		logger.ErrorContext(ctx, "could not record a node as connected", slog.Any("error", err))
		s.registry.Remove(conn)
		return status.Error(codes.Internal, "the panel could not record this connection")
	}

	logger.InfoContext(ctx, "node connected",
		slog.String("agent_version", hello.GetAgentVersion()),
		slog.String("xray_version", hello.GetXrayVersion()),
		slog.Int64("applied_version", hello.GetAppliedVersion()),
		slog.Int64("desired_version", identity.node.ConfigVersion))

	// The status has to end up correct whichever way this function returns, including
	// a panic-free early return from a send failure.
	var endReason error
	defer func() {
		// Remove reports whether this connection was still the registered one. When it
		// was not, a newer stream has taken over the node and owns its recorded status,
		// so writing "disconnected" here would report a node that is connected as down.
		stillOurs := s.registry.Remove(conn)
		s.finishConnection(conn, endReason, stillOurs, logger)
	}()

	// Sending is owned by one goroutine: the stream's Send is not safe to call from
	// two places, and from M7 the panel pushes configuration from outside this loop.
	sendFailed := make(chan error, 1)
	go func() {
		for {
			select {
			case msg := <-conn.send:
				if err := stream.Send(msg); err != nil {
					sendFailed <- err
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	if err := s.registry.Send(conn.NodeID, &nodectlv1.PanelMessage{
		Payload: &nodectlv1.PanelMessage_HelloAck{HelloAck: &nodectlv1.HelloAck{
			NodeId:           identity.node.ID,
			NodeName:         identity.node.Name,
			DesiredVersion:   identity.node.ConfigVersion,
			HeartbeatSeconds: int32(s.cfg.HeartbeatInterval.Seconds()),
			PanelTime:        time.Now().UTC().Format(time.RFC3339),
		}},
	}); err != nil {
		endReason = fmt.Errorf("could not acknowledge the node: %w", err)
		return status.Error(codes.Internal, "the panel could not answer this connection")
	}

	// The node is brought up to date as soon as it is registered, not on its first
	// heartbeat: a node that has just reconnected after a panel restart may be running
	// a configuration from before it, and waiting an interval to notice would leave
	// removed users connected for that long.
	s.syncConfig(ctx, conn, identity.node.ID, identity.node.ConfigVersion, hello.GetAppliedVersion(), logger)

	endReason = s.serve(ctx, conn, identity, incoming, recvErr, sendFailed, logger)
	return endReason
}

// syncConfig pushes the desired configuration when the node is not already running it.
//
// Comparing versions rather than pushing unconditionally keeps a reconnect cheap, and
// keeps the whole mechanism driven by one number that only the panel increments
// (ADR-044). A failure here is logged and not returned: a node with a stale
// configuration is still a connected node, and dropping its stream would cost it the
// chance to be corrected on the next attempt.
func (s *Server) syncConfig(
	ctx context.Context,
	conn *Connection,
	nodeID int64,
	desiredVersion int64,
	nodeAppliedVersion int64,
	logger *slog.Logger,
) {
	if desiredVersion == nodeAppliedVersion {
		return
	}

	sent, failed := s.registry.pushState(conn)
	if sent == desiredVersion {
		// Already on its way down this stream; the node will report on it.
		return
	}
	if failed == desiredVersion {
		// It has already been tried on this connection and the node refused it.
		// Resending every heartbeat would fill both logs with the same failure; a new
		// version, or a reconnection, is what retries.
		return
	}

	desired, err := s.svc.DesiredNodeConfig(ctx, nodeID)
	if err != nil {
		logger.ErrorContext(ctx, "could not build the configuration for a node",
			slog.Int64("desired_version", desiredVersion), slog.Any("error", err))
		return
	}

	message := &nodectlv1.PanelMessage{
		Payload: &nodectlv1.PanelMessage_ApplyConfig{ApplyConfig: &nodectlv1.ApplyConfig{
			ConfigVersion:  desired.Version,
			ConfigJson:     desired.JSON,
			StructuralHash: desired.StructuralHash,
			InboundHashes:  desired.InboundHashes,
		}},
	}

	if err := s.registry.Send(nodeID, message); err != nil {
		logger.WarnContext(ctx, "could not send a configuration to a node",
			slog.Int64("config_version", desired.Version), slog.Any("error", err))
		return
	}

	s.registry.recordSent(conn, desired.Version)
	logger.InfoContext(ctx, "sent a configuration to a node",
		slog.Int64("config_version", desired.Version),
		slog.Int("inbounds", len(desired.InboundHashes)),
		slog.Bool("empty", desired.Empty()),
		slog.Int("bytes", len(desired.JSON)))
}

// serve is the steady state: messages in, heartbeat deadline enforced.
func (s *Server) serve(
	ctx context.Context,
	conn *Connection,
	identity authenticatedNode,
	incoming <-chan *nodectlv1.NodeMessage,
	recvErr <-chan error,
	sendFailed <-chan error,
	logger *slog.Logger,
) error {
	deadline := time.NewTimer(s.cfg.HeartbeatTimeout)
	defer deadline.Stop()

	for {
		select {
		case <-ctx.Done():
			// Either the node hung up, or the panel is shutting down, or this stream
			// was replaced by a newer one.
			return ctx.Err()

		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				// The node closed its side deliberately.
				return nil
			}
			return err

		case err := <-sendFailed:
			return fmt.Errorf("sending to the node failed: %w", err)

		case <-deadline.C:
			// Nothing at all for three intervals. The TCP connection may well still
			// look open from here; only the missing heartbeat says otherwise.
			return fmt.Errorf("no heartbeat for %s", s.cfg.HeartbeatTimeout)

		case msg, ok := <-incoming:
			if !ok {
				return nil
			}
			if !deadline.Stop() {
				// Drain a deadline that fired while this message was being handled, so
				// the reset below is not immediately satisfied by a stale tick.
				select {
				case <-deadline.C:
				default:
				}
			}
			deadline.Reset(s.cfg.HeartbeatTimeout)

			if err := s.handle(ctx, conn, identity, msg, logger); err != nil {
				return err
			}
		}
	}
}

// handle dispatches one message from a node.
func (s *Server) handle(
	ctx context.Context,
	conn *Connection,
	identity authenticatedNode,
	msg *nodectlv1.NodeMessage,
	logger *slog.Logger,
) error {
	switch payload := msg.GetPayload().(type) {
	case *nodectlv1.NodeMessage_Heartbeat:
		return s.handleHeartbeat(ctx, conn, identity, payload.Heartbeat, logger)

	case *nodectlv1.NodeMessage_Hello:
		// A second Hello is not an error worth dropping a node for, but it is not
		// something a correct agent does either.
		logger.WarnContext(ctx, "ignored a second hello on an established stream")
		return nil

	case *nodectlv1.NodeMessage_ApplyResult:
		return s.handleApplyResult(ctx, conn, identity, payload.ApplyResult, logger)

	case *nodectlv1.NodeMessage_TrafficBatch:
		return s.handleTrafficBatch(ctx, conn, identity, payload.TrafficBatch, logger)

	default:
		// An unknown payload is a newer agent talking to an older panel. Ignoring it is
		// the whole point of a oneof.
		logger.WarnContext(ctx, "ignored an unrecognised message from a node")
		return nil
	}
}

// handleTrafficBatch accounts a batch of traffic and tells the node whether it may forget
// it.
//
// The acknowledgement is the whole protocol here. A node that dropped a batch as soon as it
// was sent would lose billable bytes whenever the panel failed to store one; a node that
// kept every batch for ever would fill its volume. So it keeps each batch until this says
// it is stored, and resends otherwise — which is safe because the panel deduplicates by
// batch id.
func (s *Server) handleTrafficBatch(
	ctx context.Context,
	conn *Connection,
	identity authenticatedNode,
	batch *nodectlv1.TrafficBatch,
	logger *slog.Logger,
) error {
	deltas := make([]service.TrafficDelta, 0, len(batch.GetDeltas()))
	for _, delta := range batch.GetDeltas() {
		hour, err := time.Parse(time.RFC3339, delta.GetHour())
		if err != nil {
			// One unreadable hour must not cost the whole batch: the rest of it is real
			// traffic, and the node would resend this batch for ever.
			logger.WarnContext(ctx, "dropped a traffic delta with an unreadable hour",
				slog.String("batch_id", batch.GetBatchId()),
				slog.String("hour", delta.GetHour()))
			continue
		}
		deltas = append(deltas, service.TrafficDelta{
			XrayEmail: delta.GetXrayEmail(),
			Uplink:    delta.GetUplink(),
			Downlink:  delta.GetDownlink(),
			Hour:      hour,
		})
	}

	result, err := s.svc.IngestTrafficBatch(ctx, identity.node.ID, batch.GetBatchId(), deltas)
	if err != nil {
		logger.ErrorContext(ctx, "could not store a traffic batch",
			slog.String("batch_id", batch.GetBatchId()),
			slog.Int("deltas", len(deltas)),
			slog.Any("error", err))

		// Reported as not stored, so the node keeps it. The reason is sent as well: a node
		// whose batches are being refused is a node whose users are not being billed, and
		// that has to be visible from the node's log too.
		return s.sendTrafficAck(conn, batch.GetBatchId(), false, err.Error())
	}

	switch {
	case result.Duplicate:
		logger.InfoContext(ctx, "a node resent a traffic batch this panel already had",
			slog.String("batch_id", batch.GetBatchId()))
	case result.Applied > 0 || result.Unknown > 0:
		logger.InfoContext(ctx, "stored a traffic batch",
			slog.String("batch_id", batch.GetBatchId()),
			slog.Int("applied", result.Applied),
			slog.Int("dropped", result.Unknown),
			slog.Int64("bytes", result.Bytes))
	}

	return s.sendTrafficAck(conn, batch.GetBatchId(), true, "")
}

// sendTrafficAck answers a batch on the same stream it arrived on.
func (s *Server) sendTrafficAck(conn *Connection, batchID string, stored bool, reason string) error {
	if len(reason) > 300 {
		reason = reason[:300]
	}

	// Non-blocking, like every other write to a node: a node that is not reading its
	// stream must not be able to hold up the panel. A lost acknowledgement costs one
	// resend, which is exactly what the batch id is for.
	_ = sendTo(conn, &nodectlv1.PanelMessage{
		Payload: &nodectlv1.PanelMessage_TrafficAck{TrafficAck: &nodectlv1.TrafficAck{
			BatchId: batchID,
			Stored:  stored,
			Error:   reason,
		}},
	})
	return nil
}

// handleApplyResult records what a node made of a configuration it was sent.
func (s *Server) handleApplyResult(
	ctx context.Context,
	conn *Connection,
	identity authenticatedNode,
	result *nodectlv1.ApplyResult,
	logger *slog.Logger,
) error {
	version := result.GetConfigVersion()

	if result.GetOk() {
		s.registry.recordApplied(conn, version)
		logger.InfoContext(ctx, "node applied a configuration",
			slog.Int64("config_version", version),
			slog.Bool("restarted", result.GetRestarted()))
	} else {
		s.registry.recordApplyFailure(conn, version)
		logger.ErrorContext(ctx, "node refused a configuration",
			slog.Int64("config_version", version),
			slog.String("error", result.GetError()))
	}

	err := s.svc.RecordNodeApplyResult(ctx, identity.node.ID, version, result.GetError(), result.GetRestarted())
	if err != nil {
		// Losing the record is not worth ending a working stream over; the node's
		// heartbeats keep reporting what it is running.
		logger.ErrorContext(ctx, "could not record an apply result", slog.Any("error", err))
	}
	return nil
}

// handleHeartbeat records a heartbeat and re-checks that the node is still who it was.
func (s *Server) handleHeartbeat(
	ctx context.Context,
	conn *Connection,
	identity authenticatedNode,
	beat *nodectlv1.Heartbeat,
	logger *slog.Logger,
) error {
	s.registry.recordHeartbeat(conn, beat, time.Now().UTC())

	node, err := s.svc.RecordNodeHeartbeat(ctx, identity.node.ID, identity.fingerprint, service.NodeHeartbeat{
		// The version the node reported when it introduced itself; a heartbeat does not
		// repeat it.
		XrayVersion:    s.registry.snapshot(conn).XrayVersion,
		AppliedVersion: beat.GetAppliedVersion(),
	})
	switch {
	case err == nil:
		// The heartbeat is also how the panel notices a node is behind. Driving the push
		// from it means there is one mechanism rather than two, and it recovers by
		// itself: a push that was lost, or failed, is retried the moment the version
		// moves, without any bookkeeping that could go stale.
		s.syncConfig(ctx, conn, node.ID, node.ConfigVersion, beat.GetAppliedVersion(), logger)
		return nil

	case errors.Is(err, service.ErrNodeNotAuthenticated), errors.Is(err, service.ErrNodeDisabled):
		// The node was authenticated when the stream opened and is not any more: it was
		// re-enrolled, disabled or deleted while connected. Ending the stream here is
		// what makes those take effect without waiting for the node to reconnect.
		logger.WarnContext(ctx, "ending the stream: this node is no longer authorised",
			slog.Any("error", err))
		return status.Error(codes.Unauthenticated, "this node is no longer authorised")

	default:
		// A database hiccup is not the node's fault, and dropping every node's stream
		// because of one is worse than missing a heartbeat write.
		logger.ErrorContext(ctx, "could not record a heartbeat", slog.Any("error", err))
		return nil
	}
}

// waitForHello reads the first message, which has to be a Hello.
func waitForHello(
	ctx context.Context,
	incoming <-chan *nodectlv1.NodeMessage,
	recvErr <-chan error,
) (*nodectlv1.Hello, error) {
	timer := time.NewTimer(helloTimeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()

	case err := <-recvErr:
		return nil, err

	case <-timer.C:
		return nil, status.Error(codes.DeadlineExceeded, "no hello within the allowed time")

	case msg, ok := <-incoming:
		if !ok {
			return nil, status.Error(codes.Unavailable, "the stream ended before a hello arrived")
		}
		hello := msg.GetHello()
		if hello == nil {
			return nil, status.Error(codes.InvalidArgument, "the first message on a stream must be a hello")
		}
		return hello, nil
	}
}

// finishConnection records that a stream has ended.
//
// It runs with its own context because the stream's is already gone, and it is what
// keeps nodes.status honest: a node whose stream died has to stop reading as connected
// even though nothing asked the panel to change it.
func (s *Server) finishConnection(conn *Connection, endReason error, stillOurs bool, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), bookkeepingTimeout)
	defer cancel()

	if !stillOurs {
		// Another stream holds this node now. Its registration is the current truth.
		logger.InfoContext(ctx, "replaced stream ended",
			slog.Duration("connected_for", time.Since(conn.ConnectedAt)))
		return
	}

	reason := ""
	switch {
	case endReason == nil:
	case errors.Is(endReason, context.Canceled):
		// The panel ended the stream: a shutdown, or this connection being replaced.
		// Not the node's error, so nothing is recorded against it.
	default:
		reason = endReason.Error()
	}

	if err := s.svc.MarkNodeDisconnected(ctx, conn.NodeID, reason); err != nil {
		logger.ErrorContext(ctx, "could not record a node as disconnected", slog.Any("error", err))
	}

	logger.InfoContext(ctx, "node disconnected",
		slog.Duration("connected_for", time.Since(conn.ConnectedAt)),
		slog.String("reason", reason))
}
