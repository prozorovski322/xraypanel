package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/pki"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// pkiEntryCA is the primary key of the authority row. There is exactly one.
const pkiEntryCA = "ca"

// purposeCAKey is the encryption purpose for the authority's private key.
const purposeCAKey = "pki.ca_key"

// caExpiryWarning is how long before the authority expires the panel starts
// complaining. Replacing it means re-enrolling every node, so the warning has to
// arrive with enough time to schedule that.
const caExpiryWarning = 90 * 24 * time.Hour

// EnsureCA returns the panel's certificate authority, creating it on first use.
//
// Created lazily rather than in a migration: the private key has to be encrypted with
// PANEL_SECRET_KEY, and a migration has no access to it. Created once and never
// rotated automatically, because a new authority invalidates every node certificate
// at once, and doing that to a running installation on a timer would be an outage
// nobody asked for.
func (s *Service) EnsureCA(ctx context.Context) (*pki.CA, error) {
	s.caMu.Lock()
	defer s.caMu.Unlock()

	if s.ca != nil {
		return s.ca, nil
	}

	ca, err := s.loadCA(ctx)
	switch {
	case err == nil:
	case errors.Is(err, pgx.ErrNoRows):
		ca, err = s.createCA(ctx)
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	if remaining := ca.NotAfter().Sub(s.now()); remaining < caExpiryWarning {
		// Not an error: an expired authority still lets the panel start, and a panel
		// that refuses to start is a worse outage than one that complains loudly.
		s.log.WarnContext(ctx, "the node certificate authority is close to expiry; "+
			"replacing it requires re-enrolling every node",
			slog.Time("not_after", ca.NotAfter()),
			slog.Duration("remaining", remaining))
	}

	s.ca = ca
	return ca, nil
}

// loadCA reads and decrypts the stored authority.
func (s *Service) loadCA(ctx context.Context) (*pki.CA, error) {
	row, err := s.q.GetPKIEntry(ctx, pkiEntryCA)
	if err != nil {
		return nil, err
	}

	keyPEM, err := s.cipher.Decrypt(row.KeyEnc, purposeCAKey)
	if err != nil {
		// Almost always a changed PANEL_SECRET_KEY. Saying so is worth more than the
		// nothing the cipher is willing to say about why.
		return nil, fmt.Errorf("service: the stored certificate authority cannot be decrypted, "+
			"which happens when PANEL_SECRET_KEY is not the key it was stored with: %w", err)
	}

	ca, err := pki.LoadCA([]byte(row.CertPem), keyPEM)
	if err != nil {
		return nil, fmt.Errorf("service: load certificate authority: %w", err)
	}
	return ca, nil
}

// createCA generates the authority and stores it, tolerating a concurrent creator.
func (s *Service) createCA(ctx context.Context) (*pki.CA, error) {
	ca, keyPEM, err := pki.CreateCA(s.now())
	if err != nil {
		return nil, fmt.Errorf("service: create certificate authority: %w", err)
	}

	encrypted, err := s.cipher.Encrypt(keyPEM, purposeCAKey)
	if err != nil {
		return nil, fmt.Errorf("service: encrypt certificate authority key: %w", err)
	}

	rows, err := s.q.InsertPKIEntryIfAbsent(ctx, dbgen.InsertPKIEntryIfAbsentParams{
		ID:      pkiEntryCA,
		CertPem: string(ca.CertPEM()),
		KeyEnc:  encrypted,
	})
	if err != nil {
		return nil, translate(err, "certificate authority")
	}
	if rows == 0 {
		// Another process created it first. Its authority is the real one, and the one
		// generated here has to be thrown away rather than used for a single request.
		return s.loadCA(ctx)
	}

	s.audit.Record(ctx, audit.SystemActor("panel"), audit.Entry{
		Action:     "pki.ca.create",
		EntityType: "pki",
		EntityID:   pkiEntryCA,
		After: map[string]any{
			"pin":       ca.Pin(),
			"not_after": ca.NotAfter().UTC().Format(time.RFC3339),
		},
	})

	s.log.InfoContext(ctx, "created the node certificate authority",
		slog.String("pin", ca.Pin()),
		slog.Time("not_after", ca.NotAfter()))

	return ca, nil
}

// CAInfo is what an operator needs in order to provision a node by hand.
//
// All of it is public: the certificate and its public-key pin are what a node checks
// the panel against, not what it authenticates with.
type CAInfo struct {
	Pin            string
	ServerName     string
	CertificatePEM string
	NotAfter       time.Time
}

// CAInfo returns the authority's public half.
func (s *Service) CAInfo(ctx context.Context) (*CAInfo, error) {
	ca, err := s.EnsureCA(ctx)
	if err != nil {
		return nil, err
	}
	return &CAInfo{
		Pin:            ca.Pin(),
		ServerName:     pki.PanelServerName,
		CertificatePEM: string(ca.CertPEM()),
		NotAfter:       ca.NotAfter(),
	}, nil
}

// IssueServerCertificate builds the key pair the gRPC listener presents to nodes.
//
// Generated per process and never stored; see pki.CA.IssueServerCertificate.
func (s *Service) IssueServerCertificate(ctx context.Context, extraNames []string) (certPEM, keyPEM []byte, err error) {
	ca, err := s.EnsureCA(ctx)
	if err != nil {
		return nil, nil, err
	}
	return ca.IssueServerCertificate(s.now(), extraNames)
}
