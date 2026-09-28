//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/nodegrpc"
	"github.com/xraypanel/panel/internal/service"
	"github.com/xraypanel/panel/internal/worker"
)

// The arithmetic of billing is unit-tested; what these tests answer is whether the bytes a
// user actually moves end up on that user's account. Between the two there is a real
// xray-core counting, an agent polling it, a protocol carrying batches, a panel storing
// them, and a dozen places where bytes could be dropped or counted twice — and none of that
// shows up in a unit test.

// payloadSize is what a client pushes through the node. Big enough that protocol overhead
// is a small fraction of it, small enough to move in a second on a loopback.
const payloadSize = 512 * 1024

// pushBytes sends total bytes through conn and reads the same number back.
//
// Reading and writing at once: the echo server sends every byte back, so a test that wrote
// everything before reading would deadlock on the first full buffer.
func pushBytes(conn net.Conn, total int) error {
	if err := conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return err
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	chunk := make([]byte, 16*1024)
	for i := range chunk {
		chunk[i] = byte(i)
	}

	writeErr := make(chan error, 1)
	go func() {
		written := 0
		for written < total {
			size := len(chunk)
			if remaining := total - written; remaining < size {
				size = remaining
			}
			n, err := conn.Write(chunk[:size])
			written += n
			if err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()

	buffer := make([]byte, 32*1024)
	read := 0
	for read < total {
		n, err := conn.Read(buffer)
		read += n
		if err != nil {
			return fmt.Errorf("read back %d of %d bytes: %w", read, total, err)
		}
	}

	if err := <-writeErr; err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// TestTrafficIsAccountedEndToEnd pushes a known amount of traffic through a real node and
// checks what the panel bills for it.
func TestTrafficIsAccountedEndToEnd(t *testing.T) {
	binary := xrayBinaryOrSkip(t)

	e := newEnv(t)
	panel := e.startPanel(nodegrpc.Config{HeartbeatInterval: time.Second, HeartbeatTimeout: 5 * time.Second})

	echo := startEchoServer(t)
	fixture := e.buildPlainNode(t)
	userID, uuidAlice := e.createUser(t, "alice")

	enrollment := e.enrollmentFor(fixture.nodeID)
	startAgent(t, panel.addr, enrollment.CAPin, enrollment.Token, binary, "")

	waitFor(t, "the node to apply its configuration", func() bool {
		row := e.nodeRow(fixture.nodeID)
		return row.appliedVersion > 0 && row.appliedVersion == e.configVersion(fixture.nodeID)
	})
	waitFor(t, "xray to serve the inbound port", func() bool { return listening(fixture.listenPort) })

	alice := startXrayClient(t, binary, fixture.listenPort, uuidAlice, "")

	var conn net.Conn
	waitFor(t, "alice's traffic to reach the echo server", func() bool {
		opened, err := alice.dial(echo.addr)
		if err != nil {
			return false
		}
		if err := roundTrip(opened, "hello"); err != nil {
			_ = opened.Close()
			return false
		}
		conn = opened
		return true
	})

	if err := pushBytes(conn, payloadSize); err != nil {
		t.Fatalf("pushing %d bytes through the node: %v", payloadSize, err)
	}
	_ = conn.Close()

	// Both directions are counted, so the floor is twice the payload minus a little for the
	// possibility that the last writes are still in flight when the poll happens.
	const wantAtLeast = 2 * payloadSize * 9 / 10

	waitFor(t, "the traffic to be accounted", func() bool {
		return e.userTraffic(t, userID).used >= wantAtLeast
	})

	traffic := e.userTraffic(t, userID)

	// And an upper bound, because a plausible bug here is counting the same bytes twice —
	// a batch applied on both a send and a resend, or a delta folded in twice. Protocol
	// overhead is a few percent on a payload this size, so anything approaching double is
	// a defect rather than accounting.
	const wantAtMost = 2 * payloadSize * 3 / 2

	if traffic.used > wantAtMost {
		t.Errorf("the panel accounted %d bytes for %d bytes of payload in each direction; "+
			"more than %d means bytes are being counted more than once",
			traffic.used, payloadSize, wantAtMost)
	}
	if traffic.lifetime != traffic.used {
		t.Errorf("traffic_used is %d and traffic_lifetime is %d; with no reset yet they must agree",
			traffic.used, traffic.lifetime)
	}
	if got := e.nodeTraffic(t, fixture.nodeID); got != traffic.used {
		t.Errorf("the node accounts %d bytes and the user %d; the same traffic must land on both",
			got, traffic.used)
	}
	if traffic.onlineAt == nil {
		t.Error("a user who just moved half a megabyte is not marked as having been online")
	}

	// The hourly rows are what the history is built from, so the same traffic has to be
	// there too rather than only in the user's counters.
	var hourly int64
	rows := e.trafficRows(t, userID)
	for _, row := range rows {
		hourly += row.Uplink + row.Downlink
	}
	if hourly != traffic.used {
		t.Errorf("the hourly rows hold %d bytes and the user's counter %d; they are written in "+
			"the same transaction and cannot disagree", hourly, traffic.used)
	}
}

// TestAUserOverTheLimitLosesAccessOnARealNode is M10's acceptance test: the whole loop from
// bytes moved to access withdrawn, through a real core, with nothing driven by hand.
//
// The path is long — xray counts, the agent polls and reports, the panel accounts, the
// enforcement worker switches the user off, the node's configuration version moves, the
// agent reconciles the running core — and every link in it has its own tests. This one is
// here because the property users are sold, "the limit is the limit", only holds if all of
// them hold at once.
func TestAUserOverTheLimitLosesAccessOnARealNode(t *testing.T) {
	binary := xrayBinaryOrSkip(t)

	e := newEnv(t)
	panel := e.startPanel(nodegrpc.Config{HeartbeatInterval: time.Second, HeartbeatTimeout: 5 * time.Second})

	echo := startEchoServer(t)
	fixture := e.buildPlainNode(t)

	// Alice's allowance is less than what she is about to move; Bob has none.
	aliceUser, err := e.res.CreateUser(context.Background(), audit.SystemActor("test"),
		service.CreateUserInput{Username: "alice", TrafficLimit: payloadSize / 2})
	if err != nil {
		t.Fatalf("CreateUser alice: %v", err)
	}
	uuidAlice := e.uuidOf(t, aliceUser.ID)
	_, uuidBob := e.createUser(t, "bob")

	enrollment := e.enrollmentFor(fixture.nodeID)
	startAgent(t, panel.addr, enrollment.CAPin, enrollment.Token, binary, "")

	waitFor(t, "the node to apply its configuration", func() bool {
		row := e.nodeRow(fixture.nodeID)
		return row.appliedVersion > 0 && row.appliedVersion == e.configVersion(fixture.nodeID)
	})
	waitFor(t, "xray to serve the inbound port", func() bool { return listening(fixture.listenPort) })

	// The enforcement worker runs as it does in production, only faster.
	enforcer, err := worker.NewEnforcement(e.res, testLogger(t), time.Second)
	if err != nil {
		t.Fatalf("worker.NewEnforcement: %v", err)
	}
	ctx, stop := context.WithCancel(context.Background())
	enforcing := make(chan struct{})
	go func() { defer close(enforcing); enforcer.Run(ctx) }()
	t.Cleanup(func() { stop(); <-enforcing })

	alice := startXrayClient(t, binary, fixture.listenPort, uuidAlice, "")
	bob := startXrayClient(t, binary, fixture.listenPort, uuidBob, "")

	// Bob holds a connection for the whole test: enforcing Alice's limit must cost him
	// nothing.
	var bobHeld net.Conn
	waitFor(t, "bob's traffic to reach the echo server", func() bool {
		conn, err := bob.dial(echo.addr)
		if err != nil {
			return false
		}
		if err := roundTrip(conn, "bob is here"); err != nil {
			_ = conn.Close()
			return false
		}
		bobHeld = conn
		return true
	})
	defer bobHeld.Close()

	restartsBefore := e.coreRestarts(fixture.nodeID)

	// Alice goes over.
	var conn net.Conn
	waitFor(t, "alice's traffic to reach the echo server", func() bool {
		opened, err := alice.dial(echo.addr)
		if err != nil {
			return false
		}
		conn = opened
		return true
	})
	if err := pushBytes(conn, payloadSize); err != nil {
		t.Fatalf("alice pushing her traffic: %v", err)
	}
	_ = conn.Close()
	exceededAt := time.Now()

	waitFor(t, "alice to be switched off", func() bool {
		return e.userStatus(t, aliceUser.ID) == "limited"
	})
	waitFor(t, "alice's removal to reach the node", func() bool {
		return e.nodeRow(fixture.nodeID).appliedVersion == e.configVersion(fixture.nodeID)
	})

	// The proof: Alice cannot get on any more.
	waitFor(t, "alice to be refused by the node", func() bool {
		return alice.works(echo.addr) != nil
	})
	t.Logf("alice lost access %s after going over her limit (polls and passes every second)",
		time.Since(exceededAt).Round(100*time.Millisecond))

	// Bob is untouched, on the connection he opened before any of this.
	if err := roundTrip(bobHeld, "bob is still here"); err != nil {
		t.Fatalf("enforcing alice's limit broke bob's connection: %v", err)
	}
	if err := bob.works(echo.addr); err != nil {
		t.Errorf("bob cannot make a new connection after alice was limited: %v", err)
	}
	if after := e.coreRestarts(fixture.nodeID); after != restartsBefore {
		t.Errorf("enforcing a limit restarted the core (%d restarts, was %d)", after, restartsBefore)
	}
}

// A panel outage must not cost anybody's traffic, and neither must an agent restart during
// one. This is the case the local buffer and the batch ids exist for.
func TestTrafficSurvivesAPanelOutageAndAnAgentRestart(t *testing.T) {
	binary := xrayBinaryOrSkip(t)

	e := newEnv(t)
	panel := e.startPanel(nodegrpc.Config{HeartbeatInterval: time.Second, HeartbeatTimeout: 5 * time.Second})

	echo := startEchoServer(t)
	fixture := e.buildPlainNode(t)
	userID, uuidAlice := e.createUser(t, "alice")

	enrollment := e.enrollmentFor(fixture.nodeID)
	agent := startAgent(t, panel.addr, enrollment.CAPin, enrollment.Token, binary, "")

	waitFor(t, "the node to apply its configuration", func() bool {
		row := e.nodeRow(fixture.nodeID)
		return row.appliedVersion > 0 && row.appliedVersion == e.configVersion(fixture.nodeID)
	})
	waitFor(t, "xray to serve the inbound port", func() bool { return listening(fixture.listenPort) })

	alice := startXrayClient(t, binary, fixture.listenPort, uuidAlice, "")

	// A first exchange, so the counters exist and the agent has taken its baseline reading.
	waitFor(t, "alice's traffic to reach the echo server", func() bool {
		return alice.works(echo.addr) == nil
	})
	waitFor(t, "the first traffic to be accounted", func() bool {
		return e.userTraffic(t, userID).used > 0
	})
	accountedBefore := e.userTraffic(t, userID).used

	// The panel goes away. The node keeps serving and keeps counting.
	panel.stop()

	conn, err := alice.dial(echo.addr)
	if err != nil {
		t.Fatalf("alice cannot connect while the panel is down: %v", err)
	}
	if err := pushBytes(conn, payloadSize); err != nil {
		t.Fatalf("pushing bytes while the panel is down: %v", err)
	}
	_ = conn.Close()

	// Long enough for several polls, so the traffic is in the node's own buffer.
	time.Sleep(3 * time.Second)

	buffered, err := agent.store.BufferedTrafficDeltas()
	if err != nil {
		t.Fatalf("BufferedTrafficDeltas: %v", err)
	}
	pending, err := agent.store.PendingTrafficBatches()
	if err != nil {
		t.Fatalf("PendingTrafficBatches: %v", err)
	}
	var held int64
	for _, delta := range buffered {
		held += delta.Uplink + delta.Downlink
	}
	for _, batch := range pending {
		for _, delta := range batch.Deltas {
			held += delta.Uplink + delta.Downlink
		}
	}
	if held == 0 {
		t.Fatal("the node buffered no traffic while the panel was down, so the bytes are already lost")
	}

	// Now the agent restarts too: a container replacement during the outage. The buffer is
	// on the volume, so the traffic has to still be there afterwards.
	dir := agent.stopKeepingState()
	restarted := startAgent(t, panel.addr, enrollment.CAPin, "", binary, dir)

	afterRestart, err := restarted.store.PendingTrafficBatches()
	if err != nil {
		t.Fatalf("PendingTrafficBatches after the restart: %v", err)
	}
	var survived int64
	for _, batch := range afterRestart {
		for _, delta := range batch.Deltas {
			survived += delta.Uplink + delta.Downlink
		}
	}
	buffered, err = restarted.store.BufferedTrafficDeltas()
	if err != nil {
		t.Fatalf("BufferedTrafficDeltas after the restart: %v", err)
	}
	for _, delta := range buffered {
		survived += delta.Uplink + delta.Downlink
	}
	if survived == 0 {
		t.Fatal("the restarted agent has no buffered traffic; the bytes moved during the outage are gone")
	}

	// The panel comes back and the traffic arrives.
	panel.start()

	waitFor(t, "the node to reconnect", func() bool {
		return panel.server.Registry().IsConnected(fixture.nodeID)
	})
	waitFor(t, "the buffered traffic to be accounted", func() bool {
		return e.userTraffic(t, userID).used >= accountedBefore+2*payloadSize*9/10
	})

	accountedAfter := e.userTraffic(t, userID).used

	// Once, not twice: every batch the node sent before the outage ended may be resent,
	// and the batch ids are what stop that from being billed again.
	upperBound := accountedBefore + 2*payloadSize*3/2
	if accountedAfter > upperBound {
		t.Errorf("after the outage the user is billed %d bytes, want at most %d; "+
			"resent batches are being applied more than once", accountedAfter, upperBound)
	}

	// And nothing is left waiting: every batch was acknowledged and forgotten.
	waitFor(t, "the node to have nothing left to report", func() bool {
		pending, err := restarted.store.PendingTrafficBatches()
		if err != nil {
			return false
		}
		return len(pending) == 0
	})
}
