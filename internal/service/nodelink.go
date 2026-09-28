package service

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/crypto"
	"github.com/xraypanel/panel/internal/pki"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// Errors the node-facing surface returns.
var (
	// ErrEnrollmentRejected covers every reason an enrollment can fail: an unknown
	// token, a used one, an expired one, a token for a disabled node, an unusable
	// certificate request.
	//
	// Deliberately one error. The applicant is unauthenticated by definition, and
	// telling it which of those it got right turns a stolen token into an oracle. The
	// distinction is written to the panel's log, where the operator is.
	ErrEnrollmentRejected = errors.New("service: enrollment rejected")

	// ErrNodeNotAuthenticated means the certificate presented is not the current
	// certificate of any node.
	ErrNodeNotAuthenticated = errors.New("service: no node holds that certificate")

	// ErrNodeDisabled means the node is known and administratively switched off.
	ErrNodeDisabled = errors.New("service: node is disabled")
)

// enrollmentTokenBytes is the entropy in an enrollment token. It is a bearer secret
// that is worth a node's identity for as long as it is unused, so it is sized like
// one rather than for legibility.
const enrollmentTokenBytes = 32

// NodeEnrollment is everything an operator has to give a node so it can join.
//
// All three fields together, because a token alone is not enough to join safely: a
// node that cannot verify the panel before sending its token hands that token to
// whoever answers on the address. See docs/node-protocol.md.
type NodeEnrollment struct {
	TokenID int64
	NodeID  int64

	// Token is returned exactly once. Only its hash is stored.
	Token string

	// CAPin is the SHA-256 of the authority's public key, which the node pins.
	CAPin string

	// ServerName is the name the node must require in the panel's certificate.
	ServerName string

	ExpiresAt time.Time
}

// CreateEnrollmentToken mints a single-use token for one node.
func (s *Service) CreateEnrollmentToken(
	ctx context.Context, actor audit.Actor, nodeID int64, ttl time.Duration,
) (*NodeEnrollment, error) {
	if ttl <= 0 {
		ttl = s.cfg.EnrollmentTTL
	}

	ca, err := s.EnsureCA(ctx)
	if err != nil {
		return nil, err
	}

	token, err := crypto.RandomToken(enrollmentTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("service: generate enrollment token: %w", err)
	}

	expiresAt := s.now().UTC().Add(ttl)

	var created dbgen.NodeEnrollmentToken
	err = s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		node, err := queries.GetNode(ctx, nodeID)
		if err != nil {
			return translate(err, "node")
		}

		row, err := queries.CreateNodeEnrollmentToken(ctx, dbgen.CreateNodeEnrollmentTokenParams{
			TokenHash: crypto.HashToken(token),
			NodeID:    &nodeID,
			CreatedBy: actor.ID,
			ExpiresAt: expiresAt,
		})
		if err != nil {
			return translate(err, "enrollment token")
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "node.enrollment_token.create",
			EntityType: "node",
			EntityID:   fmt.Sprint(nodeID),
			After: map[string]any{
				"token_id":   row.ID,
				"node":       node.Name,
				"expires_at": expiresAt.Format(time.RFC3339),
			},
		})

		created = row
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &NodeEnrollment{
		TokenID:    created.ID,
		NodeID:     nodeID,
		Token:      token,
		CAPin:      ca.Pin(),
		ServerName: pki.PanelServerName,
		ExpiresAt:  expiresAt,
	}, nil
}

// EnrollmentTokenSummary is a token as the API reports it, without the secret.
type EnrollmentTokenSummary struct {
	ID        int64
	NodeID    int64
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// ListEnrollmentTokens lists a node's tokens, newest first.
func (s *Service) ListEnrollmentTokens(ctx context.Context, nodeID int64) ([]EnrollmentTokenSummary, error) {
	if _, err := s.q.GetNode(ctx, nodeID); err != nil {
		return nil, translate(err, "node")
	}

	rows, err := s.q.ListNodeEnrollmentTokens(ctx, &nodeID)
	if err != nil {
		return nil, translate(err, "enrollment tokens")
	}

	out := make([]EnrollmentTokenSummary, 0, len(rows))
	for _, row := range rows {
		out = append(out, EnrollmentTokenSummary{
			ID:        row.ID,
			NodeID:    nodeID,
			ExpiresAt: row.ExpiresAt,
			UsedAt:    row.UsedAt,
			CreatedAt: row.CreatedAt,
		})
	}
	return out, nil
}

// RevokeEnrollmentToken deletes a token that has not been redeemed.
func (s *Service) RevokeEnrollmentToken(ctx context.Context, actor audit.Actor, nodeID, tokenID int64) error {
	return s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		rows, err := queries.DeleteUnusedNodeEnrollmentToken(ctx, dbgen.DeleteUnusedNodeEnrollmentTokenParams{
			ID:     tokenID,
			NodeID: &nodeID,
		})
		if err != nil {
			return translate(err, "enrollment token")
		}
		if rows == 0 {
			// Either it never existed, or it belongs to another node, or it has been
			// redeemed — and a redeemed token is kept on purpose as the record of where
			// a certificate came from.
			return fmt.Errorf("%w: no unused enrollment token with that id on this node", ErrNotFound)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "node.enrollment_token.revoke",
			EntityType: "node_enrollment_token",
			EntityID:   fmt.Sprint(tokenID),
			Before:     map[string]any{"node_id": nodeID},
		})
		return nil
	})
}

// EnrollNodeInput is an applicant's request for a certificate.
type EnrollNodeInput struct {
	Token  string
	CSRPEM []byte

	// Advisory fields, recorded and never trusted.
	AgentVersion string
	Hostname     string

	// RemoteAddr is used only for the log, so that a rejected enrollment can be
	// traced back to where it came from.
	RemoteAddr string
}

// EnrollNodeResult is what an accepted applicant receives.
type EnrollNodeResult struct {
	Node       dbgen.Node
	CertPEM    []byte
	CAPEM      []byte
	ServerName string
	NotAfter   time.Time
}

// EnrollNode exchanges a single-use token for a node certificate.
//
// The token is consumed in the same statement that checks it, so two agents replaying
// the same token cannot both be issued a certificate. Issuing overwrites the node's
// stored fingerprint, which is what retires the previous certificate: identity is the
// fingerprint on the row, not the signature of the authority.
func (s *Service) EnrollNode(ctx context.Context, in EnrollNodeInput) (*EnrollNodeResult, error) {
	ca, err := s.EnsureCA(ctx)
	if err != nil {
		return nil, err
	}

	// Parsed before the token is consumed: a malformed request should not burn a
	// token the operator then has to reissue.
	if _, err := pki.ParseCSR(in.CSRPEM); err != nil {
		s.rejectEnrollment(ctx, in, "certificate request is not acceptable", slog.Any("error", err))
		return nil, ErrEnrollmentRejected
	}

	now := s.now().UTC()

	var result EnrollNodeResult
	err = s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		claimed, err := queries.ClaimNodeEnrollmentToken(ctx, dbgen.ClaimNodeEnrollmentTokenParams{
			Now:       now,
			TokenHash: crypto.HashToken(in.Token),
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				reason, attrs := s.classifyToken(ctx, in.Token, now)
				s.rejectEnrollment(ctx, in, reason, attrs...)
				return ErrEnrollmentRejected
			}
			return translate(err, "enrollment token")
		}

		node, err := queries.GetNode(ctx, *claimed.NodeID)
		if err != nil {
			return translate(err, "node")
		}
		if !node.IsEnabled {
			s.rejectEnrollment(ctx, in, "the node is disabled",
				slog.Int64("node_id", node.ID))
			return ErrEnrollmentRejected
		}

		issued, err := ca.IssueNodeCertificate(in.CSRPEM, node.ID, node.Name, now)
		if err != nil {
			return fmt.Errorf("service: issue node certificate: %w", err)
		}

		serial := issued.Serial
		notAfter := issued.NotAfter
		updated, err := queries.SetNodeCertificate(ctx, dbgen.SetNodeCertificateParams{
			ID:              node.ID,
			CertFingerprint: issued.Fingerprint,
			CertSerial:      &serial,
			CertExpiresAt:   &notAfter,
		})
		if err != nil {
			return translate(err, "node certificate")
		}

		// The actor is the node: an enrollment is not something an administrator did,
		// it is something a machine did with a credential an administrator issued.
		recorder.Record(ctx, audit.Actor{
			Type:  audit.ActorNode,
			ID:    &node.ID,
			Label: node.Name,
		}, audit.Entry{
			Action:     "node.enroll",
			EntityType: "node",
			EntityID:   fmt.Sprint(node.ID),
			Before: map[string]any{
				"cert_fingerprint": fingerprintHex(node.CertFingerprint),
			},
			After: map[string]any{
				"cert_fingerprint": fingerprintHex(issued.Fingerprint),
				"cert_serial":      serial,
				"cert_expires_at":  notAfter.Format(time.RFC3339),
				"token_id":         claimed.ID,
				"agent_version":    in.AgentVersion,
				"hostname":         in.Hostname,
				"remote_addr":      in.RemoteAddr,
			},
		})

		result = EnrollNodeResult{
			Node:       updated,
			CertPEM:    issued.CertPEM,
			CAPEM:      ca.CertPEM(),
			ServerName: pki.PanelServerName,
			NotAfter:   notAfter,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.log.InfoContext(ctx, "issued a node certificate",
		slog.Int64("node_id", result.Node.ID),
		slog.String("node", result.Node.Name),
		slog.String("fingerprint", fingerprintHex(result.Node.CertFingerprint)),
		slog.Time("not_after", result.NotAfter))

	return &result, nil
}

// classifyToken says why a token was not claimable, for the log.
func (s *Service) classifyToken(ctx context.Context, token string, now time.Time) (string, []slog.Attr) {
	row, err := s.q.GetNodeEnrollmentTokenByHash(ctx, crypto.HashToken(token))
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "no such enrollment token", nil
	case err != nil:
		return "enrollment token could not be read", []slog.Attr{slog.Any("error", err)}
	case row.UsedAt != nil:
		// The interesting case: a token that worked once and is being presented again
		// is either a retrying agent or somebody who found it.
		return "enrollment token has already been used", []slog.Attr{
			slog.Time("used_at", *row.UsedAt),
			slog.Any("used_by_node", row.UsedByNode),
		}
	case !row.ExpiresAt.After(now):
		return "enrollment token has expired", []slog.Attr{slog.Time("expired_at", row.ExpiresAt)}
	case row.NodeID == nil:
		return "enrollment token is not bound to a node", nil
	default:
		return "enrollment token was not claimable", nil
	}
}

// rejectEnrollment logs a refusal. The caller returns ErrEnrollmentRejected, which
// says none of this to the applicant.
func (s *Service) rejectEnrollment(ctx context.Context, in EnrollNodeInput, reason string, attrs ...slog.Attr) {
	args := []any{
		slog.String("reason", reason),
		slog.String("remote_addr", in.RemoteAddr),
		slog.String("hostname", in.Hostname),
		slog.String("agent_version", in.AgentVersion),
	}
	for _, attr := range attrs {
		args = append(args, attr)
	}
	s.log.WarnContext(ctx, "rejected a node enrollment", args...)
}

// AuthenticateNode resolves a client certificate fingerprint to a node.
//
// This is the whole of node authentication: a certificate the authority signed is not
// enough, it has to be the certificate currently recorded for some node. That makes
// re-enrolling a node the act that retires its previous certificate, with no
// revocation list to distribute (ADR-052).
func (s *Service) AuthenticateNode(ctx context.Context, fingerprint []byte) (*dbgen.Node, error) {
	node, err := s.q.GetNodeByCertFingerprint(ctx, fingerprint)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNodeNotAuthenticated
		}
		return nil, translate(err, "node")
	}
	if !node.IsEnabled {
		return nil, ErrNodeDisabled
	}
	return &node, nil
}

// NodeConnectionInfo is what a node reports about itself when a stream opens.
type NodeConnectionInfo struct {
	AgentVersion   string
	XrayVersion    string
	AppliedVersion int64
}

// MarkNodeConnected records that a node's control stream is open.
func (s *Service) MarkNodeConnected(ctx context.Context, nodeID int64, info NodeConnectionInfo) error {
	err := s.q.MarkNodeConnected(ctx, dbgen.MarkNodeConnectedParams{
		ID:             nodeID,
		AgentVersion:   optionalString(info.AgentVersion),
		XrayVersion:    optionalString(info.XrayVersion),
		AppliedVersion: optionalVersion(info.AppliedVersion),
		Now:            s.now().UTC(),
	})
	if err != nil {
		return translate(err, "node connection state")
	}
	return nil
}

// MarkNodeDisconnected records that a node's control stream has ended.
//
// reason is empty for an ordinary shutdown and carries the failure otherwise; the
// distinction is what separates the 'disconnected' and 'error' statuses.
func (s *Service) MarkNodeDisconnected(ctx context.Context, nodeID int64, reason string) error {
	if len(reason) > 500 {
		reason = reason[:500]
	}
	err := s.q.MarkNodeDisconnected(ctx, dbgen.MarkNodeDisconnectedParams{
		ID:        nodeID,
		HadError:  reason != "",
		LastError: reason,
	})
	if err != nil {
		return translate(err, "node connection state")
	}
	return nil
}

// ResetNodeConnectionState marks every node disconnected. Called once at startup,
// because a status of 'connected' means "a stream is open to this process".
func (s *Service) ResetNodeConnectionState(ctx context.Context) (int64, error) {
	rows, err := s.q.MarkAllNodesDisconnected(ctx)
	if err != nil {
		return 0, translate(err, "node connection state")
	}
	return rows, nil
}

// NodeHeartbeat is what a node reports periodically.
type NodeHeartbeat struct {
	XrayVersion    string
	AppliedVersion int64
}

// RecordNodeHeartbeat stores a heartbeat and re-checks the node's identity.
//
// The identity check is on every heartbeat rather than only at connection time,
// because a certificate can be retired while a stream is open: an administrator
// re-enrolling or disabling a node has to take effect on the connection that is
// already up, not on the next one. The fingerprint is the one from the live TLS
// session, so a node whose certificate has been replaced fails here.
// It returns the node's current row, so the caller can compare the version the node
// reports with the version the panel wants without a second read.
func (s *Service) RecordNodeHeartbeat(
	ctx context.Context, nodeID int64, fingerprint []byte, beat NodeHeartbeat,
) (*dbgen.Node, error) {
	node, err := s.AuthenticateNode(ctx, fingerprint)
	if err != nil {
		return nil, err
	}
	if node.ID != nodeID {
		// The certificate now belongs to a different node, which means this stream's
		// identity is no longer what it was authenticated as.
		return nil, ErrNodeNotAuthenticated
	}

	err = s.q.TouchNodeHeartbeat(ctx, dbgen.TouchNodeHeartbeatParams{
		ID:             nodeID,
		Now:            s.now().UTC(),
		AppliedVersion: optionalVersion(beat.AppliedVersion),
		XrayVersion:    optionalString(beat.XrayVersion),
	})
	if err != nil {
		return nil, translate(err, "node heartbeat")
	}
	return node, nil
}

// fingerprintHex renders a fingerprint for logs and the audit trail. A node's
// fingerprint is public: it identifies the node, it does not authorise anything.
func fingerprintHex(fingerprint []byte) string {
	if len(fingerprint) == 0 {
		return ""
	}
	return hex.EncodeToString(fingerprint)
}

// optionalString turns an empty string into a NULL, so that "the node did not say"
// and "the node said nothing is running" are the same absent value.
func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// optionalVersion turns a zero version into a NULL: a node that has applied nothing
// has no applied version, rather than version zero.
func optionalVersion(version int64) *int64 {
	if version <= 0 {
		return nil
	}
	return &version
}
