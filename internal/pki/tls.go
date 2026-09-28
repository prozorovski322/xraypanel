package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// pinLength is the hex length of a SHA-256 pin.
const pinLength = 64

// ErrPinMismatch means the authority presented by the panel is not the one the node
// was told to expect. It is kept separate because it is the one failure that means
// "someone is between you and the panel" rather than "something is misconfigured".
var ErrPinMismatch = errors.New("pki: the panel's certificate authority does not match the pinned key")

// ServerTLSConfig builds the TLS configuration for the panel's gRPC listener.
//
// ClientAuth is VerifyClientCertIfGiven rather than RequireAndVerifyClientCert
// because enrollment happens on this same listener: a node that has no certificate
// yet must be able to reach exactly one method to obtain one. Requiring a
// certificate at the TLS layer would need a second port, and a second port is a
// second firewall rule for every operator. The authorisation decision is therefore
// made per method, deny by default, in the interceptor (ADR-050).
func (c *CA) ServerTLSConfig(certPEM, keyPEM []byte) (*tls.Config, error) {
	// The authority is appended to the chain the panel presents, so that a node
	// enrolling for the first time — which has the pin but not yet the authority
	// certificate — has something to check the pin against.
	chain := make([]byte, 0, len(certPEM)+len(c.certPEM))
	chain = append(chain, certPEM...)
	chain = append(chain, c.certPEM...)

	pair, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: load server key pair: %w", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(c.cert)

	return &tls.Config{
		Certificates: []tls.Certificate{pair},

		// Both ends of this connection are Go programs the same project ships, so
		// there is no old client to stay compatible with and no reason to offer
		// anything below 1.3.
		MinVersion: tls.VersionTLS13,

		ClientCAs:  pool,
		ClientAuth: tls.VerifyClientCertIfGiven,
	}, nil
}

// NodeTLSConfig builds the configuration a node uses once it holds a certificate.
//
// It verifies the panel the ordinary way, against the authority the node was given
// at enrollment, requiring [PanelServerName] regardless of the address dialled.
func NodeTLSConfig(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	ca, err := ParseCertificate(caPEM)
	if err != nil {
		return nil, err
	}
	if !ca.IsCA {
		return nil, ErrNotCA
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: load node key pair: %w", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		RootCAs:      pool,
		ServerName:   PanelServerName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// EnrollTLSConfig builds the configuration used for the one call a node makes before
// it has any certificate of its own.
//
// The node has no authority certificate yet, so it cannot verify the panel the
// ordinary way. It does have the authority's public-key pin, handed to the operator
// together with the enrollment token, and that is enough: the panel's chain has to
// terminate in an authority whose public key hashes to the pin, and the leaf has to
// be valid for [PanelServerName].
//
// The alternative — skipping verification for this one call — would hand the
// enrollment token, and with it a node's identity and every user credential the
// panel later sends that node, to anyone able to answer on the panel's address.
func EnrollTLSConfig(pin string) (*tls.Config, error) {
	normalized, err := NormalizePin(pin)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: PanelServerName,

		// Go's own verification cannot express "trust whichever authority matches
		// this pin", so it is turned off and replaced below. InsecureSkipVerify here
		// does not mean unverified: VerifyPeerCertificate is called for every
		// handshake and rejects anything that does not chain to the pinned key.
		InsecureSkipVerify:    true, //nolint:gosec // replaced by the pinned check below
		VerifyPeerCertificate: verifyPinnedChain(normalized, time.Now),
		// A resumed session skips VerifyPeerCertificate. There is no session cache here
		// anyway; this states it, so the pinned check can never be bypassed.
		SessionTicketsDisabled: true,
	}, nil
}

// verifyPinnedChain checks a presented chain against a pinned authority public key.
func verifyPinnedChain(pin string, now func() time.Time) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("pki: the panel presented no certificate")
		}

		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("pki: parse presented certificate: %w", err)
			}
			certs = append(certs, cert)
		}

		roots := x509.NewCertPool()
		intermediates := x509.NewCertPool()
		var pinned bool
		for _, cert := range certs[1:] {
			if PinFor(cert) == pin && cert.IsCA {
				roots.AddCert(cert)
				pinned = true
				continue
			}
			intermediates.AddCert(cert)
		}
		if !pinned {
			return ErrPinMismatch
		}

		// Trust comes only from the pool built above, so a chain the panel presents
		// that happens to be signed by a public authority is still rejected.
		_, err := certs[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			DNSName:       PanelServerName,
			CurrentTime:   now(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			return fmt.Errorf("pki: the panel's certificate does not verify: %w", err)
		}
		return nil
	}
}

// NormalizePin validates a pin and returns it in the canonical lowercase hex form.
func NormalizePin(pin string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(pin))
	if len(normalized) != pinLength {
		return "", fmt.Errorf("pki: a pin is %d hex characters, got %d", pinLength, len(normalized))
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", errors.New("pki: a pin must be hexadecimal")
	}
	return normalized, nil
}
