//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	nodectlv1 "github.com/xraypanel/panel/internal/nodectl/v1"
	"github.com/xraypanel/panel/internal/nodegrpc"
	"github.com/xraypanel/panel/internal/pki"
	"github.com/xraypanel/panel/internal/service"
)

// The node protocol is the one part of the panel where a mistake is not a wrong answer
// but an unauthorised one: whoever holds a certificate the panel accepts is handed
// every user's credentials in the configuration that follows. So the tests here are
// mostly about refusal, and they run against the real gRPC stack over a real TCP
// socket with real TLS — a faked transport would prove nothing about the part that
// actually decides.

// nodeServer starts a control server for one test and returns its address.
func (e *env) nodeServer(cfg nodegrpc.Config) (*nodegrpc.Server, string) {
	e.t.Helper()

	logger := slog.New(slog.NewTextHandler(testWriter{e.t}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	server, err := nodegrpc.New(context.Background(), e.res, logger, cfg)
	if err != nil {
		e.t.Fatalf("nodegrpc.New: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatalf("listen: %v", err)
	}

	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()

	e.t.Cleanup(func() {
		server.Stop()
		if err := <-served; err != nil {
			e.t.Errorf("Serve returned %v", err)
		}
	})

	return server, listener.Addr().String()
}

// caPin reads the pin an operator would hand to a node.
func (e *env) caPin() string {
	e.t.Helper()

	info, err := e.res.CAInfo(context.Background())
	if err != nil {
		e.t.Fatalf("CAInfo: %v", err)
	}
	return info.Pin
}

// newNode creates a node row and returns its id.
func (e *env) newNode(name string) int64 {
	e.t.Helper()

	node, err := e.res.CreateNode(context.Background(), testActor(), service.CreateNodeInput{
		Name: name, Address: name + ".example.com", Enabled: true,
	})
	if err != nil {
		e.t.Fatalf("CreateNode(%q): %v", name, err)
	}
	return node.ID
}

// enrollmentFor mints a token for a node.
func (e *env) enrollmentFor(nodeID int64) *service.NodeEnrollment {
	e.t.Helper()

	enrollment, err := e.res.CreateEnrollmentToken(context.Background(), testActor(), nodeID, 0)
	if err != nil {
		e.t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	return enrollment
}

// dial opens a client connection with the given TLS configuration.
func dial(t *testing.T, addr string, tlsConfig *tls.Config) nodectlv1.NodeControlClient {
	t.Helper()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return nodectlv1.NewNodeControlClient(conn)
}

// enrollingClient is the configuration a node uses before it has a certificate: no
// client certificate of its own, and the panel verified by the pinned authority.
func enrollingClient(t *testing.T, pin string) *tls.Config {
	t.Helper()

	cfg, err := pki.EnrollTLSConfig(pin)
	if err != nil {
		t.Fatalf("EnrollTLSConfig: %v", err)
	}
	return cfg
}

// nodeClient is the configuration a node uses once it holds a certificate.
func nodeClient(t *testing.T, caPEM, certPEM, keyPEM []byte) *tls.Config {
	t.Helper()

	cfg, err := pki.NodeTLSConfig(caPEM, certPEM, keyPEM)
	if err != nil {
		t.Fatalf("NodeTLSConfig: %v", err)
	}
	return cfg
}

// enrolledNode is a node that has been through enrollment and can now connect.
type enrolledNode struct {
	nodeID  int64
	certPEM []byte
	keyPEM  []byte
	caPEM   []byte
}

// enroll runs a real enrollment: generate a key pair, send the request, keep the
// certificate. This is exactly what the agent will do in M7.
func enroll(t *testing.T, addr, pin, token string) *enrolledNode {
	t.Helper()

	csrPEM, keyPEM, err := pki.CreateNodeCSR("whatever-the-node-calls-itself")
	if err != nil {
		t.Fatalf("CreateNodeCSR: %v", err)
	}

	client := dial(t, addr, enrollingClient(t, pin))
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	response, err := client.Enroll(ctx, &nodectlv1.EnrollRequest{
		Token:        token,
		CsrPem:       string(csrPEM),
		AgentVersion: "test-agent",
		Hostname:     "node.test",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	if response.GetServerName() != pki.PanelServerName {
		t.Errorf("server name is %q, want %q", response.GetServerName(), pki.PanelServerName)
	}
	if response.GetCaPem() == "" || response.GetCertificatePem() == "" {
		t.Fatal("enrollment returned no certificate material")
	}

	return &enrolledNode{
		nodeID:  response.GetNodeId(),
		certPEM: []byte(response.GetCertificatePem()),
		keyPEM:  keyPEM,
		caPEM:   []byte(response.GetCaPem()),
	}
}

// openStream starts a control stream and sends the opening hello.
func (n *enrolledNode) openStream(t *testing.T, addr string, applied int64) (
	nodectlv1.NodeControl_ControlClient, context.CancelFunc,
) {
	t.Helper()

	client := dial(t, addr, nodeClient(t, n.caPEM, n.certPEM, n.keyPEM))

	ctx, cancel := context.WithCancel(t.Context())
	stream, err := client.Control(ctx)
	if err != nil {
		cancel()
		t.Fatalf("Control: %v", err)
	}

	if err := stream.Send(&nodectlv1.NodeMessage{
		Payload: &nodectlv1.NodeMessage_Hello{Hello: &nodectlv1.Hello{
			AgentVersion:   "test-agent",
			XrayVersion:    "v26.3.27",
			AppliedVersion: applied,
			StartedAt:      time.Now().UTC().Format(time.RFC3339),
		}},
	}); err != nil {
		cancel()
		t.Fatalf("send hello: %v", err)
	}

	return stream, cancel
}

// nodeRow reads a node straight from the database.
func (e *env) nodeRow(id int64) nodeSnapshot {
	e.t.Helper()

	var row nodeSnapshot
	err := e.pool.QueryRow(context.Background(), `
		SELECT status::text, coalesce(agent_version,''), coalesce(xray_version,''),
		       coalesce(applied_version,0), last_error,
		       cert_fingerprint IS NOT NULL, coalesce(cert_serial,''),
		       last_heartbeat_at IS NOT NULL
		FROM nodes WHERE id = $1`, id).Scan(
		&row.status, &row.agentVersion, &row.xrayVersion, &row.appliedVersion,
		&row.lastError, &row.hasCert, &row.certSerial, &row.hasHeartbeat)
	if err != nil {
		e.t.Fatalf("read node %d: %v", id, err)
	}
	return row
}

type nodeSnapshot struct {
	status         string
	agentVersion   string
	xrayVersion    string
	appliedVersion int64
	lastError      string
	hasCert        bool
	certSerial     string
	hasHeartbeat   bool
}

// waitFor polls until the condition holds, which is how a test observes something the
// server does on its own schedule without sleeping for a fixed guess.
func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ------------------------------------------------------------------ happy path

func TestNodeEnrollsAndConnects(t *testing.T) {
	e := newEnv(t)
	server, addr := e.nodeServer(nodegrpc.Config{HeartbeatInterval: 5 * time.Second})

	nodeID := e.newNode("berlin")
	enrollment := e.enrollmentFor(nodeID)

	node := enroll(t, addr, enrollment.CAPin, enrollment.Token)
	if node.nodeID != nodeID {
		t.Fatalf("enrolled as node %d, want %d", node.nodeID, nodeID)
	}

	// The certificate has to be recorded, or the panel could not recognise the node on
	// its next connection.
	row := e.nodeRow(nodeID)
	if !row.hasCert || row.certSerial == "" {
		t.Fatalf("no certificate recorded for the node: %+v", row)
	}

	stream, cancel := node.openStream(t, addr, 41)

	// The panel answers a hello with an acknowledgement carrying the version it wants.
	first, err := stream.Recv()
	if err != nil {
		t.Fatalf("receive hello ack: %v", err)
	}
	ack := first.GetHelloAck()
	if ack == nil {
		t.Fatalf("first message from the panel is %T, want a hello ack", first.GetPayload())
	}
	if ack.GetNodeId() != nodeID || ack.GetNodeName() != "berlin" {
		t.Errorf("acknowledgement identifies node %d/%q", ack.GetNodeId(), ack.GetNodeName())
	}
	if ack.GetHeartbeatSeconds() != 5 {
		t.Errorf("heartbeat interval advertised as %ds, want 5", ack.GetHeartbeatSeconds())
	}

	waitFor(t, "the node to be registered as connected", func() bool {
		return server.Registry().IsConnected(nodeID)
	})

	waitFor(t, "the node's stored status to become connected", func() bool {
		return e.nodeRow(nodeID).status == "connected"
	})

	row = e.nodeRow(nodeID)
	if row.agentVersion != "test-agent" || row.xrayVersion != "v26.3.27" {
		t.Errorf("versions not recorded from the hello: %+v", row)
	}
	if row.appliedVersion != 41 {
		t.Errorf("applied version is %d, want 41", row.appliedVersion)
	}

	// A heartbeat has to be accepted and reflected in both the live view and the row.
	if err := stream.Send(&nodectlv1.NodeMessage{
		Payload: &nodectlv1.NodeMessage_Heartbeat{Heartbeat: &nodectlv1.Heartbeat{
			SentAt:         time.Now().UTC().Format(time.RFC3339),
			XrayRunning:    true,
			AppliedVersion: 42,
			ActiveUsers:    3,
		}},
	}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}

	waitFor(t, "the heartbeat to be recorded", func() bool {
		live, ok := server.Registry().Status(nodeID)
		return ok && live.AppliedVersion == 42 && live.XrayRunning
	})
	waitFor(t, "the heartbeat to reach the database", func() bool {
		row := e.nodeRow(nodeID)
		return row.appliedVersion == 42 && row.hasHeartbeat
	})

	// And the status must follow the stream down. This is the half that a design where
	// status is written by the node itself gets wrong: nobody reports their own death.
	cancel()

	waitFor(t, "the node to be deregistered", func() bool {
		return !server.Registry().IsConnected(nodeID)
	})
	waitFor(t, "the node's stored status to become disconnected", func() bool {
		return e.nodeRow(nodeID).status == "disconnected"
	})

	if row := e.nodeRow(nodeID); row.lastError != "" {
		t.Errorf("a node that hung up cleanly recorded an error: %q", row.lastError)
	}

	if e.countAuditEntries("node.enroll") != 1 {
		t.Error("the enrollment was not audited")
	}
}

// ------------------------------------------------------------------- refusals

func TestEnrollmentTokenIsSingleUse(t *testing.T) {
	e := newEnv(t)
	_, addr := e.nodeServer(nodegrpc.Config{})

	nodeID := e.newNode("berlin")
	enrollment := e.enrollmentFor(nodeID)

	first := enroll(t, addr, enrollment.CAPin, enrollment.Token)

	// The same token again, from a second applicant with its own key pair: this is
	// what replaying a token somebody found looks like.
	csrPEM, _, err := pki.CreateNodeCSR("node")
	if err != nil {
		t.Fatalf("CreateNodeCSR: %v", err)
	}
	client := dial(t, addr, enrollingClient(t, enrollment.CAPin))
	_, err = client.Enroll(t.Context(), &nodectlv1.EnrollRequest{
		Token: enrollment.Token, CsrPem: string(csrPEM),
	})
	assertStatus(t, err, codes.PermissionDenied)

	// The first node's certificate must still be the one on the row: a rejected replay
	// must not have replaced it.
	row := e.nodeRow(nodeID)
	if !row.hasCert {
		t.Fatal("the node lost its certificate")
	}
	if first.nodeID != nodeID {
		t.Fatalf("enrolled as the wrong node")
	}
}

func TestExpiredEnrollmentTokenIsRejected(t *testing.T) {
	e := newEnv(t)
	_, addr := e.nodeServer(nodegrpc.Config{})

	nodeID := e.newNode("berlin")
	enrollment := e.enrollmentFor(nodeID)

	// Past the default lifetime. The panel compares against its own clock, which is
	// the test's, so no waiting is involved.
	e.clock.Advance(2 * time.Hour)

	csrPEM, _, err := pki.CreateNodeCSR("node")
	if err != nil {
		t.Fatalf("CreateNodeCSR: %v", err)
	}
	client := dial(t, addr, enrollingClient(t, enrollment.CAPin))
	_, err = client.Enroll(t.Context(), &nodectlv1.EnrollRequest{
		Token: enrollment.Token, CsrPem: string(csrPEM),
	})
	assertStatus(t, err, codes.PermissionDenied)

	if e.nodeRow(nodeID).hasCert {
		t.Error("an expired token was still issued a certificate")
	}
}

func TestUnknownEnrollmentTokenIsRejected(t *testing.T) {
	e := newEnv(t)
	_, addr := e.nodeServer(nodegrpc.Config{})
	e.newNode("berlin")

	csrPEM, _, err := pki.CreateNodeCSR("node")
	if err != nil {
		t.Fatalf("CreateNodeCSR: %v", err)
	}

	client := dial(t, addr, enrollingClient(t, e.caPin()))
	_, err = client.Enroll(t.Context(), &nodectlv1.EnrollRequest{
		Token: "not-a-token-anybody-issued", CsrPem: string(csrPEM),
	})
	assertStatus(t, err, codes.PermissionDenied)

	// The refusal must not say which of the reasons applied. An unauthenticated caller
	// that can tell "no such token" from "already used" has an oracle.
	if message := status.Convert(err).Message(); message != "enrollment was rejected" {
		t.Errorf("refusal message %q leaks why it failed", message)
	}
}

func TestEnrollmentRejectsAnUnusableCertificateRequest(t *testing.T) {
	e := newEnv(t)
	_, addr := e.nodeServer(nodegrpc.Config{})

	nodeID := e.newNode("berlin")
	enrollment := e.enrollmentFor(nodeID)

	client := dial(t, addr, enrollingClient(t, enrollment.CAPin))
	_, err := client.Enroll(t.Context(), &nodectlv1.EnrollRequest{
		Token: enrollment.Token, CsrPem: "-----BEGIN CERTIFICATE REQUEST-----\nnonsense\n-----END CERTIFICATE REQUEST-----",
	})
	assertStatus(t, err, codes.PermissionDenied)

	// The token must survive: a malformed request from a broken agent should not cost
	// the operator a token and a trip to the panel.
	tokens, err := e.res.ListEnrollmentTokens(context.Background(), nodeID)
	if err != nil {
		t.Fatalf("ListEnrollmentTokens: %v", err)
	}
	if len(tokens) != 1 || tokens[0].UsedAt != nil {
		t.Errorf("the token was consumed by a request that was never signed: %+v", tokens)
	}
}

func TestDisabledNodeCannotEnrollOrConnect(t *testing.T) {
	e := newEnv(t)
	_, addr := e.nodeServer(nodegrpc.Config{})

	nodeID := e.newNode("berlin")
	enrollment := e.enrollmentFor(nodeID)
	node := enroll(t, addr, enrollment.CAPin, enrollment.Token)

	disabled := false
	if _, err := e.res.UpdateNode(context.Background(), testActor(), nodeID,
		service.UpdateNodeInput{Enabled: &disabled}); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}

	// A valid certificate is not enough once the node is switched off.
	client := dial(t, addr, nodeClient(t, node.caPEM, node.certPEM, node.keyPEM))
	stream, err := client.Control(t.Context())
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	_, err = stream.Recv()
	assertStatus(t, err, codes.PermissionDenied)

	// And a fresh token for a disabled node is refused too, so that "disabled" cannot
	// be worked around by re-enrolling.
	second := e.enrollmentFor(nodeID)
	csrPEM, _, err := pki.CreateNodeCSR("node")
	if err != nil {
		t.Fatalf("CreateNodeCSR: %v", err)
	}
	enrollClient := dial(t, addr, enrollingClient(t, second.CAPin))
	_, err = enrollClient.Enroll(t.Context(), &nodectlv1.EnrollRequest{
		Token: second.Token, CsrPem: string(csrPEM),
	})
	assertStatus(t, err, codes.PermissionDenied)
}

// A certificate signed by a different authority is the plainest attack on this
// interface, and the one a TLS misconfiguration would let through.
func TestForeignCertificateIsRejected(t *testing.T) {
	e := newEnv(t)
	_, addr := e.nodeServer(nodegrpc.Config{})

	nodeID := e.newNode("berlin")
	enrollment := e.enrollmentFor(nodeID)
	real := enroll(t, addr, enrollment.CAPin, enrollment.Token)

	// Somebody else's authority, issuing itself a certificate for the same node.
	foreign, _, err := pki.CreateCA(time.Now())
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	csrPEM, keyPEM, err := pki.CreateNodeCSR("node")
	if err != nil {
		t.Fatalf("CreateNodeCSR: %v", err)
	}
	issued, err := foreign.IssueNodeCertificate(csrPEM, nodeID, "berlin", time.Now())
	if err != nil {
		t.Fatalf("IssueNodeCertificate: %v", err)
	}

	// The panel is still verified against the real authority, so only the client
	// certificate is under test.
	client := dial(t, addr, nodeClient(t, real.caPEM, issued.CertPEM, keyPEM))
	stream, err := client.Control(t.Context())
	if err == nil {
		_, err = stream.Recv()
	}
	if err == nil {
		t.Fatal("a certificate from a foreign authority was accepted")
	}
}

func TestConnectingWithNoCertificateIsRejected(t *testing.T) {
	e := newEnv(t)
	_, addr := e.nodeServer(nodegrpc.Config{})
	e.newNode("berlin")

	// The same configuration enrollment uses, which presents no client certificate.
	client := dial(t, addr, enrollingClient(t, e.caPin()))
	stream, err := client.Control(t.Context())
	if err == nil {
		_, err = stream.Recv()
	}
	assertStatus(t, err, codes.Unauthenticated)
}

// The other half of mutual authentication: a node must refuse a panel it cannot verify,
// because the alternative is handing an enrollment token to whoever answers.
func TestNodeRefusesAPanelItCannotVerify(t *testing.T) {
	e := newEnv(t)
	_, addr := e.nodeServer(nodegrpc.Config{})

	nodeID := e.newNode("berlin")
	enrollment := e.enrollmentFor(nodeID)

	other, _, err := pki.CreateCA(time.Now())
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	csrPEM, _, err := pki.CreateNodeCSR("node")
	if err != nil {
		t.Fatalf("CreateNodeCSR: %v", err)
	}

	// Correct token, wrong pin: the node believes the panel is somebody else's.
	client := dial(t, addr, enrollingClient(t, other.Pin()))
	_, err = client.Enroll(t.Context(), &nodectlv1.EnrollRequest{
		Token: enrollment.Token, CsrPem: string(csrPEM),
	})
	if err == nil {
		t.Fatal("the node sent its token to a panel it could not verify")
	}
	if !strings.Contains(err.Error(), "pinned key") {
		t.Errorf("connection failed for an unexpected reason: %v", err)
	}

	// And the token is still unredeemed, since the exchange never happened.
	if e.nodeRow(nodeID).hasCert {
		t.Error("a certificate was issued over a connection the node rejected")
	}
}

// ------------------------------------------------- revocation and replacement

// Re-enrolling is how a node's certificate is replaced, and it has to take effect on a
// stream that is already open — otherwise a compromised certificate keeps its access
// until the attacker chooses to reconnect.
func TestReEnrollmentEndsTheOldStream(t *testing.T) {
	e := newEnv(t)
	server, addr := e.nodeServer(nodegrpc.Config{HeartbeatInterval: 5 * time.Second})

	nodeID := e.newNode("berlin")
	first := enroll(t, addr, e.caPin(), e.enrollmentFor(nodeID).Token)

	stream, cancel := first.openStream(t, addr, 1)
	defer cancel()
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("receive hello ack: %v", err)
	}
	waitFor(t, "the first stream to register", func() bool {
		return server.Registry().IsConnected(nodeID)
	})

	// The node is re-enrolled, which writes a new fingerprint over the old one.
	second := enroll(t, addr, e.caPin(), e.enrollmentFor(nodeID).Token)
	if string(second.certPEM) == string(first.certPEM) {
		t.Fatal("re-enrollment returned the same certificate")
	}

	// The old stream is authenticated until it says something. Its next heartbeat is
	// where the panel notices the certificate is no longer anybody's.
	if err := stream.Send(&nodectlv1.NodeMessage{
		Payload: &nodectlv1.NodeMessage_Heartbeat{Heartbeat: &nodectlv1.Heartbeat{
			SentAt: time.Now().UTC().Format(time.RFC3339),
		}},
	}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}

	_, err := stream.Recv()
	assertStatus(t, err, codes.Unauthenticated)

	// The replacement certificate works.
	newStream, newCancel := second.openStream(t, addr, 2)
	defer newCancel()
	if _, err := newStream.Recv(); err != nil {
		t.Fatalf("the replacement certificate could not connect: %v", err)
	}
}

// A node reconnecting after a partition the panel has not noticed must not be locked
// out by the stale stream it left behind.
func TestSecondStreamReplacesTheFirst(t *testing.T) {
	e := newEnv(t)
	server, addr := e.nodeServer(nodegrpc.Config{HeartbeatInterval: 5 * time.Second})

	nodeID := e.newNode("berlin")
	node := enroll(t, addr, e.caPin(), e.enrollmentFor(nodeID).Token)

	first, cancelFirst := node.openStream(t, addr, 1)
	defer cancelFirst()
	if _, err := first.Recv(); err != nil {
		t.Fatalf("receive hello ack: %v", err)
	}
	waitFor(t, "the first stream to register", func() bool {
		return server.Registry().IsConnected(nodeID)
	})

	second, cancelSecond := node.openStream(t, addr, 2)
	defer cancelSecond()
	if _, err := second.Recv(); err != nil {
		t.Fatalf("the second stream was refused: %v", err)
	}

	// The first stream is ended by the panel.
	if _, err := first.Recv(); err == nil {
		t.Fatal("the replaced stream is still open")
	}

	// And the node is still registered, by the connection that replaced it. Getting
	// this wrong — removing the entry when the old handler returns — would report a
	// live node as offline.
	waitFor(t, "the surviving stream to be the registered one", func() bool {
		live, ok := server.Registry().Status(nodeID)
		return ok && live.AppliedVersion == 2
	})

	if e.nodeRow(nodeID).status != "connected" {
		t.Errorf("the node's stored status is %q after a reconnection, want connected",
			e.nodeRow(nodeID).status)
	}
}

// ---------------------------------------------------------------- liveness

// A half-open TCP connection looks open from the panel's side indefinitely. The
// heartbeat deadline is the only thing that notices, so it is worth a test of its own
// even though it has to spend real time.
func TestSilentNodeIsDisconnected(t *testing.T) {
	e := newEnv(t)
	server, addr := e.nodeServer(nodegrpc.Config{
		HeartbeatInterval: 5 * time.Second,
		HeartbeatTimeout:  time.Second,
	})

	nodeID := e.newNode("berlin")
	node := enroll(t, addr, e.caPin(), e.enrollmentFor(nodeID).Token)

	stream, cancel := node.openStream(t, addr, 1)
	defer cancel()
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("receive hello ack: %v", err)
	}
	waitFor(t, "the stream to register", func() bool {
		return server.Registry().IsConnected(nodeID)
	})

	// Say nothing at all.
	if _, err := stream.Recv(); err == nil {
		t.Fatal("a silent node kept its stream")
	}

	waitFor(t, "the node to be marked as failed", func() bool {
		row := e.nodeRow(nodeID)
		return row.status == "error" && strings.Contains(row.lastError, "heartbeat")
	})
}

// A stream that authenticates and then says nothing is a socket held open for free.
func TestStreamWithoutAHelloIsClosed(t *testing.T) {
	e := newEnv(t)
	_, addr := e.nodeServer(nodegrpc.Config{HeartbeatInterval: 5 * time.Second})

	nodeID := e.newNode("berlin")
	node := enroll(t, addr, e.caPin(), e.enrollmentFor(nodeID).Token)

	client := dial(t, addr, nodeClient(t, node.caPEM, node.certPEM, node.keyPEM))
	stream, err := client.Control(t.Context())
	if err != nil {
		t.Fatalf("Control: %v", err)
	}

	// A heartbeat before a hello: the panel must not accept it as an introduction.
	if err := stream.Send(&nodectlv1.NodeMessage{
		Payload: &nodectlv1.NodeMessage_Heartbeat{Heartbeat: &nodectlv1.Heartbeat{
			SentAt: time.Now().UTC().Format(time.RFC3339),
		}},
	}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}

	_, err = stream.Recv()
	assertStatus(t, err, codes.InvalidArgument)

	if e.nodeRow(nodeID).status == "connected" {
		t.Error("a stream that never introduced itself counted as a connection")
	}
}

// ------------------------------------------------------------ startup hygiene

// Node status means "a stream is open to this process". A row left at connected by a
// crash is a lie the next process has to clear, or a dead node reads as healthy until
// it happens to come back.
func TestStartupClearsStaleConnectionState(t *testing.T) {
	e := newEnv(t)
	nodeID := e.newNode("berlin")

	if err := e.res.MarkNodeConnected(context.Background(), nodeID,
		service.NodeConnectionInfo{AgentVersion: "before-the-crash"}); err != nil {
		t.Fatalf("MarkNodeConnected: %v", err)
	}
	if e.nodeRow(nodeID).status != "connected" {
		t.Fatal("the node was not marked as connected")
	}

	cleared, err := e.res.ResetNodeConnectionState(context.Background())
	if err != nil {
		t.Fatalf("ResetNodeConnectionState: %v", err)
	}
	if cleared != 1 {
		t.Errorf("cleared %d nodes, want 1", cleared)
	}
	if status := e.nodeRow(nodeID).status; status != "disconnected" {
		t.Errorf("status is %q after a restart, want disconnected", status)
	}

	// A node an administrator switched off must stay off: the stream ending is the
	// expected consequence of disabling it, not new information.
	disabled := false
	if _, err := e.res.UpdateNode(context.Background(), testActor(), nodeID,
		service.UpdateNodeInput{Enabled: &disabled}); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE nodes SET status = 'disabled' WHERE id = $1`, nodeID); err != nil {
		t.Fatalf("set disabled: %v", err)
	}
	if _, err := e.res.ResetNodeConnectionState(context.Background()); err != nil {
		t.Fatalf("ResetNodeConnectionState: %v", err)
	}
	if status := e.nodeRow(nodeID).status; status != "disabled" {
		t.Errorf("a disabled node became %q at startup", status)
	}
}

// ------------------------------------------------------- authority management

// The authority is created once and kept. Regenerating it would invalidate every node
// certificate in one step, which is the worst possible outcome of a restart.
func TestCertificateAuthorityIsStable(t *testing.T) {
	e := newEnv(t)

	first, err := e.res.CAInfo(context.Background())
	if err != nil {
		t.Fatalf("CAInfo: %v", err)
	}

	// A second service over the same database is what a second process, or a restart,
	// looks like.
	other := e.newService()
	second, err := other.CAInfo(context.Background())
	if err != nil {
		t.Fatalf("CAInfo on a fresh service: %v", err)
	}

	if first.Pin != second.Pin {
		t.Errorf("two processes disagree about the authority: %s and %s", first.Pin, second.Pin)
	}
	if first.CertificatePEM != second.CertificatePEM {
		t.Error("the stored authority certificate was replaced")
	}

	// Exactly one row, whatever the order of those calls was.
	var rows int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM pki`).Scan(&rows); err != nil {
		t.Fatalf("count pki rows: %v", err)
	}
	if rows != 1 {
		t.Errorf("the pki table holds %d rows, want 1", rows)
	}
}

// A revoked token must be unredeemable, and a redeemed one must not be deletable: its
// record is how an operator knows which certificate came from where.
func TestEnrollmentTokenRevocation(t *testing.T) {
	e := newEnv(t)
	_, addr := e.nodeServer(nodegrpc.Config{})

	nodeID := e.newNode("berlin")
	enrollment := e.enrollmentFor(nodeID)

	if err := e.res.RevokeEnrollmentToken(context.Background(), testActor(), nodeID, enrollment.TokenID); err != nil {
		t.Fatalf("RevokeEnrollmentToken: %v", err)
	}

	csrPEM, _, err := pki.CreateNodeCSR("node")
	if err != nil {
		t.Fatalf("CreateNodeCSR: %v", err)
	}
	client := dial(t, addr, enrollingClient(t, enrollment.CAPin))
	_, err = client.Enroll(t.Context(), &nodectlv1.EnrollRequest{
		Token: enrollment.Token, CsrPem: string(csrPEM),
	})
	assertStatus(t, err, codes.PermissionDenied)

	// A used token cannot be revoked away.
	used := e.enrollmentFor(nodeID)
	enroll(t, addr, used.CAPin, used.Token)
	err = e.res.RevokeEnrollmentToken(context.Background(), testActor(), nodeID, used.TokenID)
	if !errors.Is(err, service.ErrNotFound) {
		t.Errorf("revoking a redeemed token returned %v, want ErrNotFound", err)
	}

	// Nor can a token be revoked through another node's id.
	third := e.enrollmentFor(nodeID)
	otherNode := e.newNode("paris")
	err = e.res.RevokeEnrollmentToken(context.Background(), testActor(), otherNode, third.TokenID)
	if !errors.Is(err, service.ErrNotFound) {
		t.Errorf("revoking through the wrong node returned %v, want ErrNotFound", err)
	}
}

// assertStatus checks a gRPC error's code, and says what it actually was when it does
// not match — a bare "want error" here would hide an unauthorised call succeeding for
// the wrong reason.
func assertStatus(t *testing.T, err error, want codes.Code) {
	t.Helper()

	if err == nil {
		t.Fatalf("the call succeeded; expected %s", want)
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("the stream ended without a status; expected %s", want)
	}
	if got := status.Code(err); got != want {
		t.Fatalf("status is %s (%v), want %s", got, err, want)
	}
}
