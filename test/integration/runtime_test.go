//go:build integration

package integration

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/nodegrpc"
	"github.com/xraypanel/panel/internal/service"
)

// These are the tests the milestone exists for. Everything else about runtime
// reconciliation can be true — the plan correct, the API calls accepted — while the one
// thing that matters is false: that a user who is watching something does not notice when
// another user is added, removed or re-keyed.
//
// So the assertions here are made through a real client over a real connection carrying
// real bytes, because that is the only vantage point from which a dropped connection is
// visible at all. A test that checked the panel's view would pass just as happily with
// the core restarted on every change.

// echoServer is a target for traffic sent through the node: whatever it receives, it
// sends back. It stands in for the internet.
type echoServer struct {
	addr string
}

func startEchoServer(t *testing.T) echoServer {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buffer := make([]byte, 4096)
				for {
					n, err := conn.Read(buffer)
					if n > 0 {
						if _, err := conn.Write(buffer[:n]); err != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()

	return echoServer{addr: listener.Addr().String()}
}

// xrayClient is a real Xray running as a client: a SOCKS listener in front of a VLESS
// outbound aimed at the node under test. One per user, because a client carries one
// credential.
type xrayClient struct {
	t         *testing.T
	socksAddr string
	cmd       *exec.Cmd
}

// startXrayClient writes a client configuration and runs it.
func startXrayClient(t *testing.T, binary string, serverPort int, uuid, flow string) *xrayClient {
	t.Helper()

	socksPort := freeTCPPort(t)

	outboundStream := map[string]any{"network": "tcp", "security": "none"}
	vnextUser := map[string]any{"id": uuid, "encryption": "none"}
	if flow != "" {
		vnextUser["flow"] = flow
	}

	document := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag":      "socks",
			"listen":   "127.0.0.1",
			"port":     socksPort,
			"protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": false},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": "127.0.0.1",
				"port":    serverPort,
				"users":   []any{vnextUser},
			}}},
			"streamSettings": outboundStream,
		}},
	}

	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("encode the client configuration: %v", err)
	}

	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write the client configuration: %v", err)
	}

	// The client's own log goes to the process's stdout rather than through t.Log: it
	// outlives the test function by however long it takes to die, and logging from there
	// panics the test binary.
	cmd := exec.Command(binary, "run", "-config", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the xray client: %v", err)
	}

	client := &xrayClient{t: t, socksAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)), cmd: cmd}
	t.Cleanup(client.stop)

	waitFor(t, "the client's socks port to accept connections", func() bool {
		return listening(socksPort)
	})
	return client
}

func (c *xrayClient) stop() {
	if c.cmd == nil || c.cmd.Process == nil {
		return
	}
	_ = c.cmd.Process.Kill()
	_, _ = c.cmd.Process.Wait()
	c.cmd = nil
}

// dial opens a connection through the client to target, and returns it so the caller can
// keep it open across a configuration change.
func (c *xrayClient) dial(target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", c.socksAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial the socks port: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// SOCKS5, no authentication.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks greeting: %w", err)
	}
	greeting := make([]byte, 2)
	if _, err := readFull(conn, greeting); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks greeting reply: %w", err)
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks greeting refused: %v", greeting)
	}

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("target %q is not an IPv4 address", target)
	}

	request := []byte{0x05, 0x01, 0x00, 0x01}
	request = append(request, ip...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks connect: %w", err)
	}

	reply := make([]byte, 10)
	if _, err := readFull(conn, reply); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks connect reply: %w", err)
	}
	if reply[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks connect refused with code %d", reply[1])
	}

	// The deadline above was for the handshake; the caller decides its own.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// roundTrip sends a message and expects it back, which is what proves the whole path is
// carrying traffic rather than merely being connected.
func roundTrip(conn net.Conn, message string) error {
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	if _, err := conn.Write([]byte(message)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	buffer := make([]byte, len(message))
	if _, err := readFull(conn, buffer); err != nil {
		return fmt.Errorf("read back: %w", err)
	}
	if string(buffer) != message {
		return fmt.Errorf("echoed %q, want %q", buffer, message)
	}
	return nil
}

// works reports whether a fresh connection through this client carries traffic. Used for
// the users who are supposed to be able to connect, and for the ones who are not.
func (c *xrayClient) works(target string) error {
	conn, err := c.dial(target)
	if err != nil {
		return err
	}
	defer conn.Close()
	return roundTrip(conn, "hello through the node")
}

func readFull(conn net.Conn, buffer []byte) (int, error) {
	read := 0
	for read < len(buffer) {
		n, err := conn.Read(buffer[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

// plainNode is a node with one VLESS inbound over raw TCP and no transport security, so
// that a client configuration is three lines and needs no certificates. What is being
// tested is reconciliation, not TLS.
type plainNode struct {
	nodeID     int64
	inboundID  int64
	groupID    int64
	listenPort int
}

func (e *env) buildPlainNode(t *testing.T) plainNode {
	t.Helper()

	ctx := context.Background()
	actor := audit.SystemActor("test")

	port := freeTCPPort(t)

	inbound, err := e.res.CreateInbound(ctx, actor, service.CreateInboundInput{
		Tag:        "vless-plain",
		Protocol:   "vless",
		Transport:  "tcp",
		Security:   "none",
		ListenPort: int32(port),
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("CreateInbound: %v", err)
	}

	group, err := e.res.CreateGroup(ctx, actor, service.CreateGroupInput{
		Name:       "everything",
		IsDefault:  true,
		InboundIDs: []int64{inbound.ID},
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	node, err := e.res.CreateNode(ctx, actor, service.CreateNodeInput{
		Name: "rt-1", Address: "rt1.example.com", CountryCode: "DE", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if err := e.res.AttachInbound(ctx, actor, node.ID, inbound.ID); err != nil {
		t.Fatalf("AttachInbound: %v", err)
	}

	return plainNode{nodeID: node.ID, inboundID: inbound.ID, groupID: group.ID, listenPort: port}
}

// createUser makes a user and returns the UUID a client needs.
func (e *env) createUser(t *testing.T, username string) (int64, string) {
	t.Helper()

	user, err := e.res.CreateUser(context.Background(), audit.SystemActor("test"),
		service.CreateUserInput{Username: username})
	if err != nil {
		t.Fatalf("CreateUser %q: %v", username, err)
	}
	return user.ID, e.uuidOf(t, user.ID)
}

// uuidOf reads the credential a VLESS client connects with.
func (e *env) uuidOf(t *testing.T, userID int64) string {
	t.Helper()

	var uuid string
	err := e.pool.QueryRow(context.Background(),
		`SELECT vless_uuid::text FROM users WHERE id = $1`, userID).Scan(&uuid)
	if err != nil {
		t.Fatalf("read the uuid of user %d: %v", userID, err)
	}
	return uuid
}

// restartsOf counts how many times the node reported having restarted its core, which is
// recorded in the audit log by the panel.
func (e *env) coreRestarts(nodeID int64) int {
	e.t.Helper()

	var count int
	err := e.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log
		  WHERE action = 'node.core_restarted' AND entity_type = 'node' AND entity_id = $1`,
		strconv.FormatInt(nodeID, 10)).Scan(&count)
	if err != nil {
		e.t.Fatalf("count core restarts: %v", err)
	}
	return count
}

// TestUserChangesDoNotInterruptOtherUsers is the milestone's acceptance test.
func TestUserChangesDoNotInterruptOtherUsers(t *testing.T) {
	binary := xrayBinaryOrSkip(t)

	e := newEnv(t)
	panel := e.startPanel(nodegrpc.Config{HeartbeatInterval: time.Second, HeartbeatTimeout: 5 * time.Second})

	echo := startEchoServer(t)
	fixture := e.buildPlainNode(t)

	_, uuidAlice := e.createUser(t, "alice")

	enrollment := e.enrollmentFor(fixture.nodeID)
	startAgent(t, panel.addr, enrollment.CAPin, enrollment.Token, binary, "")

	waitFor(t, "the node to apply its configuration", func() bool {
		row := e.nodeRow(fixture.nodeID)
		return row.appliedVersion > 0 && row.appliedVersion == e.configVersion(fixture.nodeID)
	})
	waitFor(t, "xray to serve the inbound port", func() bool { return listening(fixture.listenPort) })

	// Alice connects and keeps the connection open for the rest of the test.
	alice := startXrayClient(t, binary, fixture.listenPort, uuidAlice, "")

	var held net.Conn
	waitFor(t, "alice's traffic to reach the echo server", func() bool {
		conn, err := alice.dial(echo.addr)
		if err != nil {
			return false
		}
		if err := roundTrip(conn, "first"); err != nil {
			_ = conn.Close()
			return false
		}
		held = conn
		return true
	})
	defer held.Close()

	restartsBefore := e.coreRestarts(fixture.nodeID)

	// --- a user is added -------------------------------------------------------
	_, uuidBob := e.createUser(t, "bob")

	waitFor(t, "bob to reach the node", func() bool {
		return e.nodeRow(fixture.nodeID).appliedVersion == e.configVersion(fixture.nodeID)
	})

	// The whole point: Alice's existing connection still carries bytes.
	if err := roundTrip(held, "after bob was added"); err != nil {
		t.Fatalf("alice's connection broke when bob was added: %v", err)
	}

	bob := startXrayClient(t, binary, fixture.listenPort, uuidBob, "")
	waitFor(t, "bob's traffic to reach the echo server", func() bool {
		return bob.works(echo.addr) == nil
	})

	// Bob holds a connection open too, so that removing him answers a question M10 needs:
	// whether taking a user off an inbound also tears down what they already have open.
	bobHeld, err := bob.dial(echo.addr)
	if err != nil {
		t.Fatalf("bob cannot open a connection to hold: %v", err)
	}
	defer bobHeld.Close()
	if err := roundTrip(bobHeld, "bob is connected"); err != nil {
		t.Fatalf("bob's held connection does not carry traffic: %v", err)
	}

	if after := e.coreRestarts(fixture.nodeID); after != restartsBefore {
		t.Errorf("adding a user restarted the core (%d restarts, was %d)", after, restartsBefore)
	}

	// --- a user is removed ----------------------------------------------------
	if err := e.res.DeleteUser(context.Background(), audit.SystemActor("test"), bobID(t, e)); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	waitFor(t, "bob's removal to reach the node", func() bool {
		return e.nodeRow(fixture.nodeID).appliedVersion == e.configVersion(fixture.nodeID)
	})

	// Bob can no longer get on. A fresh connection is what a removed user's client would
	// make; whether Xray also tears down the connections he already had is its own
	// behaviour, and the one that matters for access control is this one.
	waitFor(t, "bob to be refused", func() bool { return bob.works(echo.addr) != nil })

	// Recorded rather than asserted, because it is upstream behaviour this milestone does
	// not control — and because M10 has to know it: if a removed user keeps the session
	// they already had, then hitting a traffic limit does not end the download in
	// progress, and enforcement needs to say so or do something about it.
	if err := roundTrip(bobHeld, "after bob was removed"); err != nil {
		t.Logf("removing a user also ended the connection they already had: %v", err)
	} else {
		t.Log("removing a user does NOT end the connection they already had; " +
			"enforcement in M10 has to account for this")
	}

	// And Alice is still untouched, on the same connection she opened at the start.
	if err := roundTrip(held, "after bob was removed"); err != nil {
		t.Fatalf("alice's connection broke when bob was removed: %v", err)
	}
	if err := alice.works(echo.addr); err != nil {
		t.Fatalf("alice cannot make a new connection after bob was removed: %v", err)
	}

	if after := e.coreRestarts(fixture.nodeID); after != restartsBefore {
		t.Errorf("removing a user restarted the core (%d restarts, was %d)", after, restartsBefore)
	}
}

// bobID looks up the user the test just created, so the test does not have to thread the
// id through the waits above.
func bobID(t *testing.T, e *env) int64 {
	t.Helper()

	var id int64
	err := e.pool.QueryRow(context.Background(), `SELECT id FROM users WHERE username = 'bob'`).Scan(&id)
	if err != nil {
		t.Fatalf("find bob: %v", err)
	}
	return id
}

// Detaching an inbound must not cost the users of the inbound that stays their
// connections: the core's API can close one listener on its own.
func TestDetachingAnInboundLeavesTheOtherAlone(t *testing.T) {
	binary := xrayBinaryOrSkip(t)

	e := newEnv(t)
	panel := e.startPanel(nodegrpc.Config{HeartbeatInterval: time.Second, HeartbeatTimeout: 5 * time.Second})

	echo := startEchoServer(t)
	fixture := e.buildPlainNode(t)
	ctx := context.Background()
	actor := audit.SystemActor("test")

	// A second inbound, attached before the agent starts so that both are in the
	// configuration the node first applies.
	secondPort := freeTCPPort(t)
	second, err := e.res.CreateInbound(ctx, actor, service.CreateInboundInput{
		Tag: "vless-second", Protocol: "vless", Transport: "tcp", Security: "none",
		ListenPort: int32(secondPort), Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateInbound: %v", err)
	}
	if err := e.res.AttachInbound(ctx, actor, fixture.nodeID, second.ID); err != nil {
		t.Fatalf("AttachInbound: %v", err)
	}
	if _, err := e.res.UpdateGroup(ctx, actor, fixture.groupID, service.UpdateGroupInput{
		SetInbounds: true,
		InboundIDs:  []int64{fixture.inboundID, second.ID},
	}); err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}

	_, uuidAlice := e.createUser(t, "alice")

	enrollment := e.enrollmentFor(fixture.nodeID)
	startAgent(t, panel.addr, enrollment.CAPin, enrollment.Token, binary, "")

	waitFor(t, "the node to apply its configuration", func() bool {
		row := e.nodeRow(fixture.nodeID)
		return row.appliedVersion > 0 && row.appliedVersion == e.configVersion(fixture.nodeID)
	})
	waitFor(t, "both inbounds to serve", func() bool {
		return listening(fixture.listenPort) && listening(secondPort)
	})

	alice := startXrayClient(t, binary, fixture.listenPort, uuidAlice, "")

	var held net.Conn
	waitFor(t, "alice's traffic to reach the echo server", func() bool {
		conn, err := alice.dial(echo.addr)
		if err != nil {
			return false
		}
		if err := roundTrip(conn, "first"); err != nil {
			_ = conn.Close()
			return false
		}
		held = conn
		return true
	})
	defer held.Close()

	restartsBefore := e.coreRestarts(fixture.nodeID)

	// Take the second inbound off the node.
	if err := e.res.DetachInbound(ctx, actor, fixture.nodeID, second.ID); err != nil {
		t.Fatalf("DetachInbound: %v", err)
	}

	waitFor(t, "the second inbound to stop serving", func() bool { return !listening(secondPort) })

	if err := roundTrip(held, "after the other inbound was detached"); err != nil {
		t.Fatalf("alice's connection broke when another inbound was detached: %v", err)
	}
	if after := e.coreRestarts(fixture.nodeID); after != restartsBefore {
		t.Errorf("detaching an inbound restarted the core (%d restarts, was %d)", after, restartsBefore)
	}
	if !listening(fixture.listenPort) {
		t.Error("the inbound that was kept stopped serving")
	}
}

// The other side of the same coin, and the documented limit of this milestone: a change
// the core's API cannot make is a restart, it is reported as one, and the node converges.
func TestStructuralChangeRestartsTheCoreAndIsReported(t *testing.T) {
	binary := xrayBinaryOrSkip(t)

	e := newEnv(t)
	panel := e.startPanel(nodegrpc.Config{HeartbeatInterval: time.Second, HeartbeatTimeout: 5 * time.Second})

	fixture := e.buildPlainNode(t)
	e.createUser(t, "alice")

	enrollment := e.enrollmentFor(fixture.nodeID)
	startAgent(t, panel.addr, enrollment.CAPin, enrollment.Token, binary, "")

	waitFor(t, "the node to apply its configuration", func() bool {
		row := e.nodeRow(fixture.nodeID)
		return row.appliedVersion > 0 && row.appliedVersion == e.configVersion(fixture.nodeID)
	})
	waitFor(t, "xray to serve the inbound port", func() bool { return listening(fixture.listenPort) })

	restartsBefore := e.coreRestarts(fixture.nodeID)

	// Moving the inbound's port needs a new listener, which the API cannot do.
	newPort := freeTCPPort(t)
	port32 := int32(newPort)
	if _, err := e.res.UpdateInbound(context.Background(), audit.SystemActor("test"), fixture.inboundID,
		service.UpdateInboundInput{ListenPort: &port32}); err != nil {
		t.Fatalf("UpdateInbound: %v", err)
	}

	waitFor(t, "the node to serve the new port", func() bool { return listening(newPort) })
	waitFor(t, "the node to report the change as applied", func() bool {
		row := e.nodeRow(fixture.nodeID)
		return row.appliedVersion == e.configVersion(fixture.nodeID) && row.lastError == ""
	})
	waitFor(t, "the restart to be recorded", func() bool {
		return e.coreRestarts(fixture.nodeID) > restartsBefore
	})

	if listening(fixture.listenPort) {
		t.Error("the old port is still being served after the inbound moved")
	}
}
