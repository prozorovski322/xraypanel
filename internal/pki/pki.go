// Package pki holds the panel's certificate authority: the one that signs node
// client certificates and the panel's own gRPC server certificate.
//
// Why a private CA rather than a public one: the panel is not a website. Its gRPC
// port is reached by a known, small set of nodes, and what has to be authenticated
// is mutual — the node proving it is a node the panel enrolled, and the panel
// proving it is the panel. A public CA can only do the second half, and only for a
// name that resolves publicly.
//
// Nothing here touches the database. The CA material is handed in already decrypted,
// which keeps this package testable without a schema and keeps the decision about
// where secrets live in one place (see service.EnsureCA).
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// PanelServerName is the name a node requires in the panel's server certificate.
//
// It is a fixed internal name rather than the address the node dials. The panel's
// address is an operational detail that changes when it moves hosts or sits behind a
// different DNS name; its identity is cryptographic and should not. A node therefore
// verifies "signed by my CA, for this name", which is exactly the property that
// matters, and moving the panel needs no certificate work at all.
const PanelServerName = "panel.xraypanel.internal"

// Validity periods.
const (
	// CAValidity outlives the certificates it signs by a wide margin, because
	// replacing the CA means re-enrolling every node.
	CAValidity = 10 * 365 * 24 * time.Hour

	// NodeCertValidity is deliberately finite. There is no automatic renewal yet;
	// the documented path is for an administrator to issue a new enrollment token,
	// and the panel warns while a certificate is still usable. See
	// docs/node-protocol.md.
	NodeCertValidity = 365 * 24 * time.Hour

	// ServerCertValidity is short because the certificate is generated in memory on
	// every start and never stored: a panel that has been running for a year without
	// a restart gets a fresh one on the next one.
	ServerCertValidity = 90 * 24 * time.Hour

	// clockSkew backdates NotBefore. Without it a node whose clock is a minute ahead
	// rejects a certificate that was just issued to it.
	clockSkew = 5 * time.Minute
)

// PEM block types.
const (
	blockCertificate = "CERTIFICATE"
	blockECKey       = "EC PRIVATE KEY"
	blockCSR         = "CERTIFICATE REQUEST"
)

// Errors callers distinguish.
var (
	// ErrMalformedPEM means the input was not the PEM block type expected.
	ErrMalformedPEM = errors.New("pki: malformed PEM input")

	// ErrKeyMismatch means a certificate and a private key do not belong together.
	ErrKeyMismatch = errors.New("pki: certificate and private key do not match")

	// ErrNotCA means a certificate presented as an authority is not one.
	ErrNotCA = errors.New("pki: certificate is not a certificate authority")

	// ErrBadCSR means a certificate request was unusable: not PEM, not a CSR, a
	// broken self-signature, or a key the panel will not sign.
	ErrBadCSR = errors.New("pki: certificate request is not acceptable")
)

// CA is a loaded certificate authority.
//
// Safe for concurrent use: issuing reads the key and never mutates it.
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
}

// CreateCA generates a fresh authority and returns it along with its private key in
// PEM form, for the caller to encrypt and store.
//
// P-256 ECDSA rather than RSA: the only consumers are Go's own TLS stack on both
// ends, signatures are smaller and faster, and there is no legacy client to placate.
func CreateCA(now time.Time) (*CA, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate ca key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "xraypanel node CA",
			Organization: []string{"xraypanel"},
		},
		NotBefore:             now.Add(-clockSkew).UTC(),
		NotAfter:              now.Add(CAValidity).UTC(),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,

		// The CA signs leaves and nothing else. A path length of zero means a
		// stolen node certificate cannot be used to sign further certificates
		// even if the key usage were somehow wrong.
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: create ca certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: parse own ca certificate: %w", err)
	}

	keyPEM, err := encodeECKey(key)
	if err != nil {
		return nil, nil, err
	}

	return &CA{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: blockCertificate, Bytes: der}),
		key:     key,
	}, keyPEM, nil
}

// LoadCA parses a stored authority and checks that the two halves match.
//
// The match check is not ceremony: the certificate and the key travel separately
// through the database, one in plain text and one encrypted, and a mix-up between
// them would otherwise surface as nodes failing to verify the panel long after the
// mistake.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, ErrNotCA
	}

	key, err := parseECKey(keyPEM)
	if err != nil {
		return nil, err
	}

	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: ca certificate does not carry an ECDSA key", ErrKeyMismatch)
	}
	if !public.Equal(&key.PublicKey) {
		return nil, ErrKeyMismatch
	}

	return &CA{cert: cert, certPEM: certPEM, key: key}, nil
}

// CertPEM returns the authority certificate, which is public.
func (c *CA) CertPEM() []byte { return c.certPEM }

// Certificate returns the parsed authority certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// NotAfter is when the authority itself expires.
func (c *CA) NotAfter() time.Time { return c.cert.NotAfter }

// Pin returns the value a node pins the panel's authority by: the SHA-256 of the
// authority's SubjectPublicKeyInfo, lowercase hex.
//
// The public key rather than the whole certificate, because a certificate can be
// legitimately re-encoded or reissued over the same key, and a pin that breaks on
// that would push operators towards turning verification off.
func (c *CA) Pin() string { return PinFor(c.cert) }

// PinFor computes the pin of any certificate. See [CA.Pin].
func PinFor(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// IssuedCertificate is what the panel records about a certificate it signed.
type IssuedCertificate struct {
	CertPEM []byte

	// Fingerprint is the SHA-256 of the certificate DER. This is a node's identity:
	// the panel looks a connection up by it.
	Fingerprint []byte

	// Serial is the hex serial number, for the audit trail.
	Serial string

	NotAfter time.Time
}

// IssueNodeCertificate signs a node's certificate request.
//
// The subject is the panel's choice, not the applicant's: the request contributes a
// public key and a proof that the applicant holds the matching private key, and
// nothing else. Taking a name from a request would let whoever holds an enrollment
// token pick which node they claim to be.
func (c *CA) IssueNodeCertificate(csrPEM []byte, nodeID int64, nodeName string, now time.Time) (*IssuedCertificate, error) {
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		return nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	notAfter := now.Add(NodeCertValidity).UTC()
	// A leaf must never outlive the authority that signed it; Go's verifier would
	// reject the chain, which is a confusing way to learn the CA is nearly expired.
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   nodeCommonName(nodeID),
			Organization: []string{"xraypanel nodes"},

			// The name is informational, for a human reading `openssl x509`. The
			// panel never resolves a node by it.
			OrganizationalUnit: []string{sanitizeForSubject(nodeName)},
		},
		NotBefore:             now.Add(-clockSkew).UTC(),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("pki: sign node certificate: %w", err)
	}

	fingerprint := sha256.Sum256(der)
	return &IssuedCertificate{
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: blockCertificate, Bytes: der}),
		Fingerprint: fingerprint[:],
		Serial:      strings.ToLower(serial.Text(16)),
		NotAfter:    notAfter,
	}, nil
}

// IssueServerCertificate signs a certificate for the panel's own gRPC listener,
// returning the certificate and its freshly generated key.
//
// Generated at startup and never stored: nodes pin the authority, not this
// certificate, so there is nothing for anyone to remember about it. That removes a
// stored secret, a rotation schedule, and an expiry that could take the control
// plane down, in exchange for a key that lives only as long as the process.
func (c *CA) IssueServerCertificate(now time.Time, extraNames []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate server key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	notAfter := now.Add(ServerCertValidity).UTC()
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}

	names := append([]string{PanelServerName}, extraNames...)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: PanelServerName, Organization: []string{"xraypanel"}},
		DNSNames:              names,
		NotBefore:             now.Add(-clockSkew).UTC(),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: sign server certificate: %w", err)
	}

	keyPEM, err = encodeECKey(key)
	if err != nil {
		return nil, nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: blockCertificate, Bytes: der}), keyPEM, nil
}

// CreateNodeCSR generates a key pair and a certificate request for it.
//
// It lives on the panel side of the repository only because both the node agent and
// the tests need exactly the same thing. The private key is returned to the caller
// and never leaves the machine that called this.
func CreateNodeCSR(commonName string) (csrPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate node key: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: create certificate request: %w", err)
	}

	keyPEM, err = encodeECKey(key)
	if err != nil {
		return nil, nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: blockCSR, Bytes: der}), keyPEM, nil
}

// FingerprintOf returns the SHA-256 of a certificate's DER, which is how the panel
// identifies a node.
func FingerprintOf(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.Raw)
	return sum[:]
}

// ParseCertificate decodes a single PEM-encoded certificate.
func ParseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != blockCertificate {
		return nil, fmt.Errorf("%w: expected a %s block", ErrMalformedPEM, blockCertificate)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse certificate: %w", err)
	}
	return cert, nil
}

// ParseCSR decodes a certificate request and checks everything about it that the
// panel is willing to check before signing.
func ParseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != blockCSR {
		return nil, fmt.Errorf("%w: expected a %s block", ErrBadCSR, blockCSR)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadCSR, err.Error())
	}

	// The self-signature proves the applicant holds the private key for the public
	// key it is asking to have certified. Without this check anyone could have a
	// certificate issued over somebody else's public key.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: signature does not verify", ErrBadCSR)
	}

	// Only P-256 ECDSA, which is what CreateNodeCSR produces. Accepting whatever an
	// applicant sends means accepting a 512-bit RSA key from a broken agent and
	// certifying it.
	public, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: only ECDSA keys are accepted", ErrBadCSR)
	}
	if public.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: only the P-256 curve is accepted", ErrBadCSR)
	}

	return csr, nil
}

// nodeCommonName is the subject the panel puts in a node certificate. It carries the
// node id so that a human looking at a certificate can tell whose it is; the panel
// itself resolves identity by fingerprint.
func nodeCommonName(nodeID int64) string {
	return fmt.Sprintf("node-%d", nodeID)
}

// sanitizeForSubject keeps a node's name printable inside a certificate subject.
func sanitizeForSubject(name string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	if len(cleaned) > 64 {
		cleaned = cleaned[:64]
	}
	if cleaned == "" {
		return "unnamed"
	}
	return cleaned
}

// randomSerial draws a 128-bit serial number.
//
// Random rather than sequential: a counter would need a transaction of its own, and
// the only requirement on a serial is that the CA never reuse one.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("pki: draw serial number: %w", err)
	}
	// Zero is a legal integer and a confusing serial; one is not special.
	return serial.Add(serial, big.NewInt(1)), nil
}

func encodeECKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockECKey, Bytes: der}), nil
}

func parseECKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != blockECKey {
		return nil, fmt.Errorf("%w: expected a %s block", ErrMalformedPEM, blockECKey)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse private key: %w", err)
	}
	return key, nil
}
