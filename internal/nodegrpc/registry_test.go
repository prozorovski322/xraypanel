package nodegrpc

import (
	"errors"
	"testing"
	"time"

	nodectlv1 "github.com/xraypanel/panel/internal/nodectl/v1"
)

func newConnection(nodeID int64, name string) *Connection {
	return &Connection{
		NodeID:      nodeID,
		NodeName:    name,
		Fingerprint: []byte{0xde, 0xad},
		ConnectedAt: time.Now().UTC(),
		send:        make(chan *nodectlv1.PanelMessage, sendQueueDepth),
		disconnect:  func() {},
	}
}

func TestRegistryTracksConnections(t *testing.T) {
	registry := NewRegistry()

	if registry.IsConnected(1) {
		t.Error("an empty registry reports a node as connected")
	}

	first := newConnection(1, "berlin")
	if previous := registry.Add(first); previous != nil {
		t.Error("adding to an empty registry replaced something")
	}
	if !registry.IsConnected(1) || registry.Count() != 1 {
		t.Error("the connection was not registered")
	}

	if !registry.Remove(first) {
		t.Error("Remove did not report removing the registered connection")
	}
	if registry.IsConnected(1) || registry.Count() != 0 {
		t.Error("the connection was not removed")
	}
}

// The subtle one. A replaced stream's handler returns at an arbitrary later moment, and
// removing by node id would then delete the connection that replaced it — leaving the
// panel reporting a live node as offline until it happened to reconnect.
func TestRemovingAReplacedConnectionLeavesItsSuccessor(t *testing.T) {
	registry := NewRegistry()

	first := newConnection(1, "berlin")
	second := newConnection(1, "berlin")

	registry.Add(first)
	if previous := registry.Add(second); previous != first {
		t.Fatal("Add did not return the connection it replaced")
	}

	if registry.Remove(first) {
		t.Error("Remove claimed to remove a connection that had already been replaced")
	}
	if !registry.IsConnected(1) {
		t.Fatal("removing the replaced connection deregistered the node")
	}

	live, ok := registry.Status(1)
	if !ok || live.NodeName != "berlin" {
		t.Fatalf("the surviving connection is not reported: %+v", live)
	}

	if !registry.Remove(second) {
		t.Error("the surviving connection could not be removed")
	}
}

func TestSendRequiresAConnectedNode(t *testing.T) {
	registry := NewRegistry()

	err := registry.Send(1, &nodectlv1.PanelMessage{})
	if !errors.Is(err, ErrNotConnected) {
		t.Errorf("Send to an unknown node returned %v, want ErrNotConnected", err)
	}

	conn := newConnection(1, "berlin")
	registry.Add(conn)

	for i := range sendQueueDepth {
		if err := registry.Send(1, &nodectlv1.PanelMessage{}); err != nil {
			t.Fatalf("Send %d of %d failed: %v", i+1, sendQueueDepth, err)
		}
	}

	// A node that is not draining its stream must not be able to make the panel block:
	// the configuration it is behind on is superseded anyway.
	if err := registry.Send(1, &nodectlv1.PanelMessage{}); !errors.Is(err, ErrSendQueueFull) {
		t.Errorf("Send past the queue depth returned %v, want ErrSendQueueFull", err)
	}
}

func TestSnapshotIsOrderedAndReportsWhatNodesSaid(t *testing.T) {
	registry := NewRegistry()

	for _, id := range []int64{3, 1, 2} {
		conn := newConnection(id, "node")
		registry.Add(conn)
		registry.recordHello(conn, &nodectlv1.Hello{
			AgentVersion:   "v1",
			XrayVersion:    "v26",
			AppliedVersion: id,
		}, time.Now().UTC())
	}

	snapshot := registry.Snapshot()
	if len(snapshot) != 3 {
		t.Fatalf("snapshot holds %d nodes, want 3", len(snapshot))
	}
	for i, want := range []int64{1, 2, 3} {
		if snapshot[i].NodeID != want {
			t.Errorf("snapshot[%d] is node %d, want %d", i, snapshot[i].NodeID, want)
		}
		if snapshot[i].AppliedVersion != want || snapshot[i].AgentVersion != "v1" {
			t.Errorf("node %d reported state not recorded: %+v", want, snapshot[i])
		}
	}
}

func TestHeartbeatUpdatesLiveState(t *testing.T) {
	registry := NewRegistry()
	conn := newConnection(1, "berlin")
	registry.Add(conn)

	at := time.Now().UTC()
	registry.recordHeartbeat(conn, &nodectlv1.Heartbeat{
		AppliedVersion: 7,
		XrayRunning:    true,
	}, at)

	live, ok := registry.Status(1)
	if !ok {
		t.Fatal("the node is not connected")
	}
	if live.AppliedVersion != 7 || !live.XrayRunning || !live.LastHeartbeat.Equal(at) {
		t.Errorf("heartbeat not reflected: %+v", live)
	}
	if live.Fingerprint != "dead" {
		t.Errorf("fingerprint rendered as %q, want hex", live.Fingerprint)
	}
}

func TestDisconnectAllEndsEveryStream(t *testing.T) {
	registry := NewRegistry()

	ended := 0
	for id := int64(1); id <= 3; id++ {
		conn := newConnection(id, "node")
		conn.disconnect = func() { ended++ }
		registry.Add(conn)
	}

	registry.DisconnectAll()

	if ended != 3 {
		t.Errorf("%d streams were asked to end, want 3", ended)
	}
}
