package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func mustCA(t *testing.T) (*CA, []byte) {
	t.Helper()
	ca, keyPEM, err := CreateCA(time.Now())
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	return ca, keyPEM
}

func TestCreateCAProducesAUsableAuthority(t *testing.T) {
	now := time.Now().UTC()
	ca, keyPEM := mustCA(t)

	cert := ca.Certificate()
	if !cert.IsCA {
		t.Error("the authority certificate is not marked as a CA")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("the authority cannot sign certificates")
	}
	if !cert.MaxPathLenZero {
		t.Error("the authority does not forbid intermediates")
	}
	if !cert.NotBefore.Before(now) {
		t.Errorf("NotBefore %s is not backdated; a node with a fast clock would reject it", cert.NotBefore)
	}

	// Reloading has to produce the same authority, since that is what every restart does.
	reloaded, err := LoadCA(ca.CertPEM(), keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if reloaded.Pin() != ca.Pin() {
		t.Errorf("pin changed across a reload: %s then %s", ca.Pin(), reloaded.Pin())
	}
}

// A certificate and a key travel through the database separately, one encrypted and
// one not. Pairing the wrong two has to fail here rather than at a handshake weeks later.
func TestLoadCARejectsAMismatchedKey(t *testing.T) {
	first, _ := mustCA(t)
	_, otherKeyPEM := mustCA(t)

	_, err := LoadCA(first.CertPEM(), otherKeyPEM)
	if !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("LoadCA with a foreign key: got %v, want ErrKeyMismatch", err)
	}
}

func TestLoadCARejectsALeafCertificate(t *testing.T) {
	ca, _ := mustCA(t)
	serverPEM, serverKeyPEM, err := ca.IssueServerCertificate(time.Now(), nil)
	if err != nil {
		t.Fatalf("IssueServerCertificate: %v", err)
	}

	if _, err := LoadCA(serverPEM, serverKeyPEM); !errors.Is(err, ErrNotCA) {
		t.Fatalf("LoadCA with a leaf: got %v, want ErrNotCA", err)
	}
}

func TestIssueNodeCertificateIgnoresTheRequestedSubject(t *testing.T) {
	ca, _ := mustCA(t)

	// An applicant claiming to be another node. The panel must not take its word.
	csrPEM, _, err := CreateNodeCSR("node-9999")
	if err != nil {
		t.Fatalf("CreateNodeCSR: %v", err)
	}

	issued, err := ca.IssueNodeCertificate(csrPEM, 7, "berlin", time.Now())
	if err != nil {
		t.Fatalf("IssueNodeCertificate: %v", err)
	}

	cert, err := ParseCertificate(issued.CertPEM)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.Subject.CommonName != "node-7" {
		t.Errorf("common name is %q, want node-7: the requested subject was honoured", cert.Subject.CommonName)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("extended key usage is %v, want client authentication only", cert.ExtKeyUsage)
	}
	if cert.IsCA {
		t.Error("a node certificate is marked as a certificate authority")
	}

	// The fingerprint is the node's identity, so it has to be the hash of what was issued.
	if got := FingerprintOf(cert); string(got) != string(issued.Fingerprint) {
		t.Error("the recorded fingerprint is not the fingerprint of the issued certificate")
	}
	if issued.Serial == "" {
		t.Error("no serial recorded for the audit trail")
	}
}

// Two enrollments must never produce the same identity, or one node would
// authenticate as another.
func TestIssuedCertificatesAreDistinct(t *testing.T) {
	ca, _ := mustCA(t)

	seen := make(map[string]bool)
	for i := range 5 {
		csrPEM, _, err := CreateNodeCSR("node")
		if err != nil {
			t.Fatalf("CreateNodeCSR: %v", err)
		}
		issued, err := ca.IssueNodeCertificate(csrPEM, int64(i), "node", time.Now())
		if err != nil {
			t.Fatalf("IssueNodeCertificate: %v", err)
		}
		if seen[string(issued.Fingerprint)] {
			t.Fatal("two issued certificates share a fingerprint")
		}
		seen[string(issued.Fingerprint)] = true
	}
}

// A leaf outliving its authority produces a chain Go rejects, which looks like a
// broken node rather than an expiring CA.
func TestIssuedCertificatesNeverOutliveTheAuthority(t *testing.T) {
	ca, _ := mustCA(t)
	// Ask for certificates as the authority is about to expire.
	late := ca.NotAfter().Add(-time.Hour)

	csrPEM, _, err := CreateNodeCSR("node")
	if err != nil {
		t.Fatalf("CreateNodeCSR: %v", err)
	}
	issued, err := ca.IssueNodeCertificate(csrPEM, 1, "node", late)
	if err != nil {
		t.Fatalf("IssueNodeCertificate: %v", err)
	}
	if issued.NotAfter.After(ca.NotAfter()) {
		t.Errorf("node certificate expires %s, after the authority's %s", issued.NotAfter, ca.NotAfter())
	}

	serverPEM, _, err := ca.IssueServerCertificate(late, nil)
	if err != nil {
		t.Fatalf("IssueServerCertificate: %v", err)
	}
	server, err := ParseCertificate(serverPEM)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if server.NotAfter.After(ca.NotAfter()) {
		t.Errorf("server certificate expires %s, after the authority's %s", server.NotAfter, ca.NotAfter())
	}
}

func TestParseCSRRejectsWhatThePanelWillNotSign(t *testing.T) {
	validCSR, _, err := CreateNodeCSR("node")
	if err != nil {
		t.Fatalf("CreateNodeCSR: %v", err)
	}

	tests := []struct {
		name string
		csr  []byte
	}{
		{"empty", nil},
		{"not PEM", []byte("hello")},
		{"a certificate rather than a request", func() []byte {
			ca, _ := mustCA(t)
			return ca.CertPEM()
		}()},
		{"truncated DER inside a correct block", func() []byte {
			block, _ := pem.Decode(validCSR)
			return pem.EncodeToMemory(&pem.Block{Type: blockCSR, Bytes: block.Bytes[:len(block.Bytes)/2]})
		}()},
		{"signature from another key", tamperedCSR(t)},
		{"an RSA key", rsaCSR(t)},
		{"the wrong curve", p384CSR(t)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseCSR(tt.csr); err == nil {
				t.Fatal("ParseCSR accepted a request it should have refused")
			}
		})
	}

	if _, err := ParseCSR(validCSR); err != nil {
		t.Fatalf("ParseCSR rejected a request this package produced: %v", err)
	}
}

// tamperedCSR builds a request whose self-signature does not verify, which is what an
// applicant asking for a certificate over somebody else's public key looks like.
func tamperedCSR(t *testing.T) []byte {
	t.Helper()

	csrPEM, _, err := CreateNodeCSR("node")
	if err != nil {
		t.Fatalf("CreateNodeCSR: %v", err)
	}
	block, _ := pem.Decode(csrPEM)

	// Flip a bit inside the signature at the end of the structure.
	der := make([]byte, len(block.Bytes))
	copy(der, block.Bytes)
	der[len(der)-1] ^= 0x01

	return pem.EncodeToMemory(&pem.Block{Type: blockCSR, Bytes: der})
}

func rsaCSR(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "node"}}, key)
	if err != nil {
		t.Fatalf("create rsa csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockCSR, Bytes: der})
}

func p384CSR(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p384 key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "node"}}, key)
	if err != nil {
		t.Fatalf("create p384 csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockCSR, Bytes: der})
}

func TestNormalizePin(t *testing.T) {
	ca, _ := mustCA(t)

	upper := strings.ToUpper(ca.Pin())
	got, err := NormalizePin("  " + upper + "  ")
	if err != nil {
		t.Fatalf("NormalizePin: %v", err)
	}
	if got != ca.Pin() {
		t.Errorf("NormalizePin returned %q, want %q", got, ca.Pin())
	}

	for _, bad := range []string{"", "abc", strings.Repeat("z", 64)} {
		if _, err := NormalizePin(bad); err == nil {
			t.Errorf("NormalizePin(%q) accepted an invalid pin", bad)
		}
	}
}

// ------------------------------------------------------------------ handshakes

// handshake runs one real TLS handshake between the panel's server configuration and
// a client configuration, and reports what each side made of it.
//
// A real handshake rather than calling the verification function directly: what is
// being checked is that these configurations reject each other, and that is a
// property of the whole TLS stack, not of one callback.
func handshake(t *testing.T, server, client *tls.Config) (clientErr, serverErr error) {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		// Accept does not handshake; the handshake happens on first use.
		done <- conn.(*tls.Conn).HandshakeContext(t.Context())
	}()

	conn, err := tls.Dial("tcp", listener.Addr().String(), client)
	if err == nil {
		err = conn.HandshakeContext(t.Context())
		// Write something so that the server side sees the handshake through even
		// when the client is the one that will be rejected.
		_, _ = conn.Write([]byte("ping"))
		conn.Close()
	}

	// A TCP-level accept error means the test itself broke, not the configuration.
	serverErr = <-done
	if serverErr != nil && errors.Is(serverErr, net.ErrClosed) {
		t.Fatalf("listener closed unexpectedly: %v", serverErr)
	}
	return err, serverErr
}

func serverConfig(t *testing.T, ca *CA) *tls.Config {
	t.Helper()

	certPEM, keyPEM, err := ca.IssueServerCertificate(time.Now(), nil)
	if err != nil {
		t.Fatalf("IssueServerCertificate: %v", err)
	}
	cfg, err := ca.ServerTLSConfig(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	return cfg
}

func nodeConfig(t *testing.T, ca *CA, nodeID int64) *tls.Config {
	t.Helper()

	csrPEM, keyPEM, err := CreateNodeCSR("node")
	if err != nil {
		t.Fatalf("CreateNodeCSR: %v", err)
	}
	issued, err := ca.IssueNodeCertificate(csrPEM, nodeID, "node", time.Now())
	if err != nil {
		t.Fatalf("IssueNodeCertificate: %v", err)
	}
	cfg, err := NodeTLSConfig(ca.CertPEM(), issued.CertPEM, keyPEM)
	if err != nil {
		t.Fatalf("NodeTLSConfig: %v", err)
	}
	return cfg
}

func TestEnrollingClientAcceptsThePinnedPanel(t *testing.T) {
	ca, _ := mustCA(t)

	client, err := EnrollTLSConfig(ca.Pin())
	if err != nil {
		t.Fatalf("EnrollTLSConfig: %v", err)
	}

	clientErr, serverErr := handshake(t, serverConfig(t, ca), client)
	if clientErr != nil {
		t.Errorf("client rejected the panel it pinned: %v", clientErr)
	}
	if serverErr != nil {
		t.Errorf("panel rejected a client with no certificate, which is how enrollment starts: %v", serverErr)
	}
}

// The point of the pin: an attacker who answers on the panel's address, with a
// perfectly valid certificate of their own, must not be handed an enrollment token.
func TestEnrollingClientRejectsAnImpostor(t *testing.T) {
	real, _ := mustCA(t)
	impostor, _ := mustCA(t)

	client, err := EnrollTLSConfig(real.Pin())
	if err != nil {
		t.Fatalf("EnrollTLSConfig: %v", err)
	}

	clientErr, _ := handshake(t, serverConfig(t, impostor), client)
	if clientErr == nil {
		t.Fatal("the client accepted a panel signed by an authority it never pinned")
	}
	if !strings.Contains(clientErr.Error(), "does not match the pinned key") {
		t.Errorf("unexpected rejection reason: %v", clientErr)
	}
}

func TestNodeWithAValidCertificateConnects(t *testing.T) {
	ca, _ := mustCA(t)

	clientErr, serverErr := handshake(t, serverConfig(t, ca), nodeConfig(t, ca, 1))
	if clientErr != nil {
		t.Errorf("node rejected the panel: %v", clientErr)
	}
	if serverErr != nil {
		t.Errorf("panel rejected its own node's certificate: %v", serverErr)
	}
}

// A certificate signed by somebody else's authority is the plainest form of the
// attack this design has to stop.
func TestPanelRejectsACertificateFromAnotherAuthority(t *testing.T) {
	ca, _ := mustCA(t)
	foreign, _ := mustCA(t)

	client := nodeConfig(t, foreign, 1)
	// Trust the real panel, so that only the client certificate is under test.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	client.RootCAs = pool

	_, serverErr := handshake(t, serverConfig(t, ca), client)
	if serverErr == nil {
		t.Fatal("the panel accepted a client certificate signed by a foreign authority")
	}
}

func TestPanelRejectsASelfSignedClientCertificate(t *testing.T) {
	ca, _ := mustCA(t)

	// A self-signed certificate is what an attacker produces with no CA at all.
	selfCA, selfKeyPEM := mustCA(t)
	client, err := NodeTLSConfig(ca.CertPEM(), selfCA.CertPEM(), selfKeyPEM)
	if err != nil {
		t.Fatalf("NodeTLSConfig: %v", err)
	}

	_, serverErr := handshake(t, serverConfig(t, ca), client)
	if serverErr == nil {
		t.Fatal("the panel accepted a self-signed client certificate")
	}
}

// The panel presents a fixed internal name, so a node that verifies against the
// address it dialled instead of that name would reject every connection.
func TestNodeRequiresThePanelsFixedName(t *testing.T) {
	ca, _ := mustCA(t)

	client := nodeConfig(t, ca, 1)
	client.ServerName = "panel.example.com"

	clientErr, _ := handshake(t, serverConfig(t, ca), client)
	if clientErr == nil {
		t.Fatal("the panel's certificate was accepted for a name it does not carry")
	}
}
