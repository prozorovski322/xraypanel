//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xraypanel/panel/internal/agent/link"
	"github.com/xraypanel/panel/internal/agent/store"
	"github.com/xraypanel/panel/internal/agent/supervisor"
	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/nodegrpc"
	"github.com/xraypanel/panel/internal/service"
)

// These are the tests that justify the whole milestone: a real agent, a real panel over a
// real socket, and a real xray-core process. Every layer already has its own tests and
// they can all pass while the thing as a whole does not work — the first symptom of which
// would be a node that never comes up, on a server an operator cannot easily watch.

// panelServer is a node control server a test can stop and start again on the same
// address, which is how a panel outage is simulated.
type panelServer struct {
	t    *testing.T
	env  *env
	cfg  nodegrpc.Config
	addr string

	server   *nodegrpc.Server
	listener net.Listener
	served   chan error
}

// startPanel brings up a control server on a free address and keeps that address for the
// rest of the test, so a restart is indistinguishable from the node's point of view.
func (e *env) startPanel(cfg nodegrpc.Config) *panelServer {
	e.t.Helper()

	// Reserved and released, so the same port can be bound again after a stop. A test
	// binding it twice in a row is fine; nothing else on the machine is listening there.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatalf("reserve a port: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	panel := &panelServer{t: e.t, env: e, cfg: cfg, addr: addr}
	panel.start()
	e.t.Cleanup(panel.stop)
	return panel
}

func (p *panelServer) start() {
	p.t.Helper()

	logger := slog.New(slog.NewTextHandler(testWriter{p.t}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	server, err := nodegrpc.New(context.Background(), p.env.res, logger, p.cfg)
	if err != nil {
		p.t.Fatalf("nodegrpc.New: %v", err)
	}

	listener, err := net.Listen("tcp", p.addr)
	if err != nil {
		p.t.Fatalf("listen on %s: %v", p.addr, err)
	}

	p.server = server
	p.listener = listener
	p.served = make(chan error, 1)
	go func() { p.served <- server.Serve(listener) }()
}

func (p *panelServer) stop() {
	if p.server == nil {
		return
	}
	p.server.Stop()
	if err := <-p.served; err != nil {
		p.t.Errorf("Serve returned %v", err)
	}
	p.server = nil
}

// agentProcess is an agent running in this test process, with its own data directory.
type agentProcess struct {
	t     *testing.T
	store *store.Store
	sup   *supervisor.Supervisor
	dir   string

	cancel context.CancelFunc
	done   chan error
}

// startAgent runs an agent against a panel, reusing dir when one is given so that an
// agent restart finds the state the previous one left.
func startAgent(t *testing.T, panelAddr, pin, token, xrayBinary, dir string) *agentProcess {
	t.Helper()

	if dir == "" {
		dir = t.TempDir()
	}

	state, err := store.Open(filepath.Join(dir, "agent.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelInfo}))

	sup, err := supervisor.New(supervisor.Config{
		Binary:       xrayBinary,
		ConfigPath:   filepath.Join(dir, "config.json"),
		Logger:       logger,
		ReadyTimeout: 20 * time.Second,
		StopTimeout:  5 * time.Second,
		RestartMin:   200 * time.Millisecond,
		RestartMax:   time.Second,
	})
	if err != nil {
		t.Fatalf("supervisor.New: %v", err)
	}

	node, err := link.New(link.Config{
		PanelAddr:       panelAddr,
		CAPin:           pin,
		EnrollmentToken: token,
		AgentVersion:    "test-agent",
		Hostname:        "node.test",
		Logger:          logger,
		ReconnectMin:    200 * time.Millisecond,
		ReconnectMax:    time.Second,
		Heartbeat:       time.Second,
		// A second rather than the production thirty: these tests wait for traffic to be
		// accounted, and the interval is what that wait is made of.
		StatsInterval: time.Second,
	}, state, sup)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	process := &agentProcess{t: t, store: state, sup: sup, dir: dir, cancel: cancel, done: make(chan error, 1)}
	go func() { process.done <- node.Run(ctx) }()

	t.Cleanup(process.stop)
	return process
}

// stop shuts the agent down the way a SIGTERM would, core included.
func (a *agentProcess) stop() {
	if a.cancel == nil {
		return
	}
	a.cancel()
	a.cancel = nil

	select {
	case <-a.done:
	case <-time.After(30 * time.Second):
		a.t.Error("the agent did not stop")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := a.sup.Close(ctx); err != nil {
		a.t.Errorf("stopping xray: %v", err)
	}
	if err := a.store.Close(); err != nil {
		a.t.Errorf("closing the store: %v", err)
	}
}

// stopKeepingState stops the agent but leaves its data directory, so that another agent
// can be started on it. This is what a container replacement looks like.
func (a *agentProcess) stopKeepingState() string {
	a.stop()
	return a.dir
}

// xrayBinary returns the real Xray binary, skipping the test when there is none.
func xrayBinaryOrSkip(t *testing.T) string {
	t.Helper()

	binary := os.Getenv(xrayBinaryEnv)
	if binary == "" {
		t.Skipf("%s is not set; skipping the end-to-end agent test", xrayBinaryEnv)
	}
	return binary
}

// simpleNode is one Reality inbound on a high port with one user, which is the smallest
// installation a real Xray will actually serve.
type simpleNode struct {
	nodeID     int64
	inboundID  int64
	listenPort int
	userID     int64
}

func (e *env) buildSimpleNode(t *testing.T) simpleNode {
	t.Helper()

	ctx := context.Background()
	actor := audit.SystemActor("test")

	key, err := e.res.CreateRealityKey(ctx, actor, service.CreateRealityKeyInput{
		Name:        "primary",
		Dest:        "www.cloudflare.com:443",
		ServerNames: []string{"www.cloudflare.com"},
	})
	if err != nil {
		t.Fatalf("CreateRealityKey: %v", err)
	}

	// A high port, because the test process is not root and 443 is not bindable in CI.
	// Reality needs no certificate files, which is why it is the protocol used here.
	port := freeTCPPort(t)

	inbound, err := e.res.CreateInbound(ctx, actor, service.CreateInboundInput{
		Tag:          "vless-reality",
		Protocol:     "vless",
		Transport:    "tcp",
		Security:     "reality",
		ListenPort:   int32(port),
		Flow:         "xtls-rprx-vision",
		RealityKeyID: &key.ID,
		Sniffing:     json.RawMessage(`{"enabled":true,"destOverride":["http","tls"]}`),
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("CreateInbound: %v", err)
	}

	if _, err := e.res.CreateGroup(ctx, actor, service.CreateGroupInput{
		Name:       "everything",
		IsDefault:  true,
		InboundIDs: []int64{inbound.ID},
	}); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	node, err := e.res.CreateNode(ctx, actor, service.CreateNodeInput{
		Name: "de-1", Address: "de1.example.com", CountryCode: "DE", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if err := e.res.AttachInbound(ctx, actor, node.ID, inbound.ID); err != nil {
		t.Fatalf("AttachInbound: %v", err)
	}

	user, err := e.res.CreateUser(ctx, actor, service.CreateUserInput{Username: "alice"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	return simpleNode{nodeID: node.ID, inboundID: inbound.ID, listenPort: port, userID: user.ID}
}

// freeTCPPort asks the operating system for a port nobody is using.
func freeTCPPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// listening reports whether anything accepts connections on a local port. This is the
// only assertion that proves a node is actually serving: the panel's view of a node is
// hearsay until something answers on the port a client would dial.
func listening(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// TestAgentEnrollsAppliesAndServes is the milestone's acceptance test.
func TestAgentEnrollsAppliesAndServes(t *testing.T) {
	binary := xrayBinaryOrSkip(t)

	e := newEnv(t)
	panel := e.startPanel(nodegrpc.Config{HeartbeatInterval: time.Second, HeartbeatTimeout: 5 * time.Second})

	fixture := e.buildSimpleNode(t)
	enrollment := e.enrollmentFor(fixture.nodeID)

	startAgent(t, panel.addr, enrollment.CAPin, enrollment.Token, binary, "")

	// The agent enrols by itself, with nothing but an address, a pin and a token.
	waitFor(t, "the node to connect", func() bool {
		return panel.server.Registry().IsConnected(fixture.nodeID)
	})
	waitFor(t, "the certificate to be recorded", func() bool {
		return e.nodeRow(fixture.nodeID).hasCert
	})

	// The panel pushes the configuration without being asked, because the node reported
	// an applied version behind the desired one.
	waitFor(t, "the node to report the configuration as applied", func() bool {
		row := e.nodeRow(fixture.nodeID)
		return row.appliedVersion > 0 && row.appliedVersion == e.configVersion(fixture.nodeID)
	})

	// And the proof: the real Xray is listening on the port a client would dial.
	waitFor(t, "xray to serve the inbound port", func() bool {
		return listening(fixture.listenPort)
	})

	if row := e.nodeRow(fixture.nodeID); row.lastError != "" {
		t.Errorf("the node recorded an error: %q", row.lastError)
	}
	if row := e.nodeRow(fixture.nodeID); row.xrayVersion == "" {
		t.Error("the node did not report which xray it is running")
	}

	// A change in the panel reaches the node without anybody restarting anything. The
	// push is driven by the heartbeat, so this also proves the comparison works.
	versionBefore := e.configVersion(fixture.nodeID)
	if _, err := e.res.CreateUser(context.Background(), audit.SystemActor("test"),
		service.CreateUserInput{Username: "bob"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if after := e.configVersion(fixture.nodeID); after <= versionBefore {
		t.Fatalf("adding a user did not bump the node's config version (%d then %d)",
			versionBefore, after)
	}

	waitFor(t, "the new user to reach the node", func() bool {
		row := e.nodeRow(fixture.nodeID)
		return row.appliedVersion == e.configVersion(fixture.nodeID)
	})
	if !listening(fixture.listenPort) {
		t.Error("xray stopped serving after a configuration change")
	}
}

// A panel outage must not be a service outage. This is the property that decides whether
// the control plane can be restarted during the day.
func TestNodeKeepsServingWhileThePanelIsDown(t *testing.T) {
	binary := xrayBinaryOrSkip(t)

	e := newEnv(t)
	panel := e.startPanel(nodegrpc.Config{HeartbeatInterval: time.Second, HeartbeatTimeout: 5 * time.Second})

	fixture := e.buildSimpleNode(t)
	enrollment := e.enrollmentFor(fixture.nodeID)
	agent := startAgent(t, panel.addr, enrollment.CAPin, enrollment.Token, binary, "")

	waitFor(t, "xray to serve the inbound port", func() bool { return listening(fixture.listenPort) })

	panel.stop()

	// Long enough for several heartbeats to fail.
	time.Sleep(3 * time.Second)

	if !listening(fixture.listenPort) {
		t.Fatal("xray stopped when the panel went away")
	}
	if !agent.sup.Running() {
		t.Fatal("the supervisor gave up on the core because the panel was unreachable")
	}

	// And when the panel comes back the node reconnects on its own.
	panel.start()

	waitFor(t, "the node to reconnect", func() bool {
		return panel.server.Registry().IsConnected(fixture.nodeID)
	})
	waitFor(t, "the node's status to be connected again", func() bool {
		return e.nodeRow(fixture.nodeID).status == "connected"
	})
	if !listening(fixture.listenPort) {
		t.Error("xray is not serving after the panel returned")
	}
}

// The other half of the same property: an agent that restarts while the panel is down has
// to bring the core back from its own cache, without asking anybody.
func TestAgentStartsFromCacheWithNoPanel(t *testing.T) {
	binary := xrayBinaryOrSkip(t)

	e := newEnv(t)
	panel := e.startPanel(nodegrpc.Config{HeartbeatInterval: time.Second, HeartbeatTimeout: 5 * time.Second})

	fixture := e.buildSimpleNode(t)
	enrollment := e.enrollmentFor(fixture.nodeID)
	agent := startAgent(t, panel.addr, enrollment.CAPin, enrollment.Token, binary, "")

	// Waiting for the port alone is not enough: the inbound binds a moment before the
	// apply is confirmed, and stopping the agent in that window is a different test —
	// an interrupted apply — which the store's own tests cover.
	waitFor(t, "the configuration to be confirmed", func() bool {
		row := e.nodeRow(fixture.nodeID)
		return row.appliedVersion > 0 && row.appliedVersion == e.configVersion(fixture.nodeID)
	})
	waitFor(t, "xray to serve the inbound port", func() bool { return listening(fixture.listenPort) })

	// Take both down: the node is rebooting during a panel outage.
	dir := agent.stopKeepingState()
	panel.stop()

	waitFor(t, "the port to be released", func() bool { return !listening(fixture.listenPort) })

	// A fresh agent on the same volume, with no token this time — it is already enrolled,
	// and an operator would not have issued another one.
	restarted := startAgent(t, panel.addr, enrollment.CAPin, "", binary, dir)

	waitFor(t, "xray to come back from the cache", func() bool { return listening(fixture.listenPort) })

	if !restarted.sup.Running() {
		t.Fatal("the supervisor is not running the cached configuration")
	}

	// It is serving, and it has not spoken to the panel at all yet.
	if panel.server != nil {
		t.Fatal("the panel is up; this test is not testing what it says it is")
	}

	panel.start()
	waitFor(t, "the node to reconnect once the panel is back", func() bool {
		return panel.server.Registry().IsConnected(fixture.nodeID)
	})
}

// A node with nothing to serve should be idle rather than left running a configuration
// the panel has moved on from. Otherwise detaching an inbound leaves its users connected
// until somebody restarts something.
func TestNodeWithNothingToServeStopsTheCore(t *testing.T) {
	binary := xrayBinaryOrSkip(t)

	e := newEnv(t)
	panel := e.startPanel(nodegrpc.Config{HeartbeatInterval: time.Second, HeartbeatTimeout: 5 * time.Second})

	fixture := e.buildSimpleNode(t)
	enrollment := e.enrollmentFor(fixture.nodeID)
	agent := startAgent(t, panel.addr, enrollment.CAPin, enrollment.Token, binary, "")

	waitFor(t, "xray to serve the inbound port", func() bool { return listening(fixture.listenPort) })

	// Take the inbound off the node. There is now nothing for it to run.
	if err := e.res.DetachInbound(context.Background(), audit.SystemActor("test"),
		fixture.nodeID, fixture.inboundID); err != nil {
		t.Fatalf("DetachInbound: %v", err)
	}

	waitFor(t, "the node to stop serving", func() bool { return !listening(fixture.listenPort) })
	waitFor(t, "the node to report the empty configuration as applied", func() bool {
		row := e.nodeRow(fixture.nodeID)
		return row.appliedVersion == e.configVersion(fixture.nodeID)
	})

	if agent.sup.Running() {
		t.Error("the core is still running with nothing to serve")
	}
	if row := e.nodeRow(fixture.nodeID); row.status != "connected" {
		t.Errorf("the node's status is %q; an idle node is still a connected node", row.status)
	}
}

// An agent with no identity and no token cannot do anything, and has to say so rather
// than retry in silence for ever.
func TestAgentWithoutEnrollmentStopsWithAClearError(t *testing.T) {
	e := newEnv(t)
	panel := e.startPanel(nodegrpc.Config{HeartbeatInterval: time.Second})

	state, err := store.Open(filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer state.Close()

	logger := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelError}))

	sup, err := supervisor.New(supervisor.Config{
		Binary:     "xray-that-does-not-exist",
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("supervisor.New: %v", err)
	}

	node, err := link.New(link.Config{
		PanelAddr: panel.addr,
		CAPin:     e.caPin(),
		Logger:    logger,
		Heartbeat: time.Second,
	}, state, sup)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = node.Run(ctx)
	if err == nil {
		t.Fatal("the agent kept running with no way to enrol")
	}
	if !errors.Is(err, link.ErrNoEnrollment) {
		t.Errorf("Run returned %v, want ErrNoEnrollment", err)
	}
}

// A pin that cannot be a pin is a node that can never connect, so it is refused at
// startup rather than at the first handshake.
func TestAgentRefusesAnImpossiblePin(t *testing.T) {
	state, err := store.Open(filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer state.Close()

	logger := slog.New(slog.NewTextHandler(testWriter{t}, nil))
	sup, err := supervisor.New(supervisor.Config{
		Binary: "xray", ConfigPath: filepath.Join(t.TempDir(), "c.json"), Logger: logger,
	})
	if err != nil {
		t.Fatalf("supervisor.New: %v", err)
	}

	if _, err := link.New(link.Config{
		PanelAddr: "127.0.0.1:1", CAPin: "not-a-pin", Logger: logger,
	}, state, sup); err == nil {
		t.Error("the agent accepted a pin that cannot be one")
	}
}

// configVersion reads what the panel currently wants a node to be running.
func (e *env) configVersion(nodeID int64) int64 {
	e.t.Helper()

	var version int64
	err := e.pool.QueryRow(context.Background(),
		`SELECT config_version FROM nodes WHERE id = $1`, nodeID).Scan(&version)
	if err != nil {
		e.t.Fatalf("read config version: %v", err)
	}
	return version
}
