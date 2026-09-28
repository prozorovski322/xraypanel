package nodegrpc

import (
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"time"

	nodectlv1 "github.com/xraypanel/panel/internal/nodectl/v1"
)

// ErrNotConnected means the node has no open control stream on this panel process.
var ErrNotConnected = errors.New("nodegrpc: node is not connected")

// ErrSendQueueFull means a node is not draining its stream fast enough.
var ErrSendQueueFull = errors.New("nodegrpc: the node's send queue is full")

// sendQueueDepth is how many messages may be waiting for one node.
//
// Small on purpose. The panel's messages are desired state, not events: if a node is
// so far behind that a handful are queued, the right answer is to fail the send and
// let the reconciler try again with the current state, not to accumulate a backlog of
// configurations that were already superseded.
const sendQueueDepth = 8

// Connection is one node's live control stream.
//
// The mutable fields are guarded by the registry's lock rather than by the connection,
// so that a snapshot of every node is consistent with itself.
type Connection struct {
	NodeID      int64
	NodeName    string
	Fingerprint []byte
	RemoteAddr  string
	ConnectedAt time.Time

	// send carries messages to the goroutine that owns the stream's Send side.
	send chan *nodectlv1.PanelMessage

	// disconnect ends this stream. Used to evict a connection that has been replaced.
	disconnect func()

	agentVersion   string
	xrayVersion    string
	appliedVersion int64
	xrayRunning    bool
	lastHeartbeat  time.Time

	// sentVersion is the configuration version last pushed down this stream, and
	// failedVersion the last one the node reported it could not apply.
	//
	// Both are per-connection rather than stored, because they are about this
	// conversation: a reconnection is a fresh attempt, and should push again even for a
	// version that failed before. Without failedVersion the panel would resend a
	// permanently broken configuration on every heartbeat for ever.
	sentVersion   int64
	failedVersion int64
}

// NodeStatus is a point-in-time view of a connected node, for the API and the logs.
type NodeStatus struct {
	NodeID         int64
	NodeName       string
	Fingerprint    string
	RemoteAddr     string
	ConnectedAt    time.Time
	LastHeartbeat  time.Time
	AgentVersion   string
	XrayVersion    string
	AppliedVersion int64
	XrayRunning    bool
}

// Registry holds the control streams this panel process has open.
//
// It is deliberately in-process and not persisted: it answers "is a stream open here
// right now", which no other process can answer for it. The durable half of the same
// question lives in nodes.status, written when a stream opens and closes.
type Registry struct {
	mu    sync.Mutex
	conns map[int64]*Connection
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry {
	return &Registry{conns: make(map[int64]*Connection)}
}

// Add registers a connection, returning any it replaced.
//
// A second stream for a node that already has one replaces it rather than being
// refused. The panel cannot tell a duplicate agent from a node reconnecting after a
// network partition it has not noticed yet, and refusing the new stream in the second
// case would leave the node unreachable until the dead stream's keepalive expired —
// locking out the node that is actually there in favour of one that is not.
//
// The caller disconnects the returned connection after Add returns.
func (r *Registry) Add(conn *Connection) *Connection {
	r.mu.Lock()
	defer r.mu.Unlock()

	previous := r.conns[conn.NodeID]
	r.conns[conn.NodeID] = conn
	return previous
}

// Remove deregisters a connection, but only if it is still the registered one.
//
// The identity check is the point. A replaced stream's handler returns at some
// arbitrary later moment, and a plain delete by node id would then remove the
// connection that replaced it, leaving the panel believing a live node is offline.
func (r *Registry) Remove(conn *Connection) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if current, ok := r.conns[conn.NodeID]; ok && current == conn {
		delete(r.conns, conn.NodeID)
		return true
	}
	return false
}

// IsConnected reports whether a node has an open stream here.
func (r *Registry) IsConnected(nodeID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, ok := r.conns[nodeID]
	return ok
}

// Count reports how many nodes are connected.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.conns)
}

// Status returns one node's live state.
func (r *Registry) Status(nodeID int64) (NodeStatus, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	conn, ok := r.conns[nodeID]
	if !ok {
		return NodeStatus{}, false
	}
	return conn.status(), true
}

// Snapshot returns every connected node, ordered by id so that output is stable.
func (r *Registry) Snapshot() []NodeStatus {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]NodeStatus, 0, len(r.conns))
	for _, conn := range r.conns {
		out = append(out, conn.status())
	}
	slices.SortFunc(out, func(a, b NodeStatus) int {
		return int(a.NodeID - b.NodeID)
	})
	return out
}

// Send queues a message for a node.
//
// It never blocks: a node that is not reading is a node whose stream will be torn down
// by the heartbeat timeout, and blocking here would hold up whatever the panel was
// doing when it decided to push.
func (r *Registry) Send(nodeID int64, msg *nodectlv1.PanelMessage) error {
	r.mu.Lock()
	conn, ok := r.conns[nodeID]
	r.mu.Unlock()

	if !ok {
		return ErrNotConnected
	}

	select {
	case conn.send <- msg:
		return nil
	default:
		return ErrSendQueueFull
	}
}

// sendTo writes to one particular connection rather than to whichever connection a node
// currently has.
//
// The distinction matters for an answer to something that arrived on a stream: if the node
// has meanwhile reconnected, the reply belongs to the stream that asked, and sending it to
// the new one would answer a question nobody there asked.
func sendTo(conn *Connection, msg *nodectlv1.PanelMessage) error {
	select {
	case conn.send <- msg:
		return nil
	default:
		return ErrSendQueueFull
	}
}

// DisconnectAll ends every stream. Called when the panel is shutting down.
func (r *Registry) DisconnectAll() {
	r.mu.Lock()
	conns := make([]*Connection, 0, len(r.conns))
	for _, conn := range r.conns {
		conns = append(conns, conn)
	}
	r.mu.Unlock()

	for _, conn := range conns {
		conn.disconnect()
	}
}

// recordHello stores what a node reported when its stream opened.
func (r *Registry) recordHello(conn *Connection, hello *nodectlv1.Hello, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	conn.agentVersion = hello.GetAgentVersion()
	conn.xrayVersion = hello.GetXrayVersion()
	conn.appliedVersion = hello.GetAppliedVersion()
	conn.lastHeartbeat = at
}

// recordHeartbeat stores what a node reported in a heartbeat.
func (r *Registry) recordHeartbeat(conn *Connection, beat *nodectlv1.Heartbeat, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	conn.appliedVersion = beat.GetAppliedVersion()
	conn.xrayRunning = beat.GetXrayRunning()
	conn.lastHeartbeat = at
}

// pushState reports what has been pushed down a connection and what failed.
func (r *Registry) pushState(conn *Connection) (sent, failed int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return conn.sentVersion, conn.failedVersion
}

// recordSent notes that a configuration version was queued for a node.
func (r *Registry) recordSent(conn *Connection, version int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	conn.sentVersion = version
}

// recordApplyFailure notes that a node could not apply a version.
func (r *Registry) recordApplyFailure(conn *Connection, version int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	conn.failedVersion = version
}

// recordApplied notes that a node applied a version, clearing any failure for it.
func (r *Registry) recordApplied(conn *Connection, version int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	conn.appliedVersion = version
	if conn.failedVersion == version {
		conn.failedVersion = 0
	}
}

// snapshot renders one connection, whether or not it is still the registered one. Used
// by a stream's own handler, which holds the connection it is serving.
func (r *Registry) snapshot(conn *Connection) NodeStatus {
	r.mu.Lock()
	defer r.mu.Unlock()

	return conn.status()
}

// status renders a connection. The caller holds the registry lock.
func (c *Connection) status() NodeStatus {
	return NodeStatus{
		NodeID:         c.NodeID,
		NodeName:       c.NodeName,
		Fingerprint:    hex.EncodeToString(c.Fingerprint),
		RemoteAddr:     c.RemoteAddr,
		ConnectedAt:    c.ConnectedAt,
		LastHeartbeat:  c.lastHeartbeat,
		AgentVersion:   c.agentVersion,
		XrayVersion:    c.xrayVersion,
		AppliedVersion: c.appliedVersion,
		XrayRunning:    c.xrayRunning,
	}
}
