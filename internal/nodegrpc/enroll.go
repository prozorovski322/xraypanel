package nodegrpc

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodectlv1 "github.com/xraypanel/panel/internal/nodectl/v1"
	"github.com/xraypanel/panel/internal/service"
)

// maxEnrollFieldLength bounds the advisory strings an unauthenticated caller can send.
// They are stored in the audit trail, and an unauthenticated caller must not be able to
// decide how much of the database one request fills.
const maxEnrollFieldLength = 200

// Enroll exchanges a single-use token for a client certificate.
//
// This is the only method reachable without a client certificate, and everything about
// it is written on the assumption that the caller is unknown: the token is consumed by
// the same statement that validates it, the request's subject is ignored, and every
// failure returns the same message. The reason is in the panel's log, where the
// operator can read it and an attacker cannot.
func (s *Server) Enroll(ctx context.Context, req *nodectlv1.EnrollRequest) (*nodectlv1.EnrollResponse, error) {
	if strings.TrimSpace(req.GetToken()) == "" || strings.TrimSpace(req.GetCsrPem()) == "" {
		return nil, status.Error(codes.InvalidArgument, "a token and a certificate request are required")
	}

	result, err := s.svc.EnrollNode(ctx, service.EnrollNodeInput{
		Token:        req.GetToken(),
		CSRPEM:       []byte(req.GetCsrPem()),
		AgentVersion: truncate(req.GetAgentVersion(), maxEnrollFieldLength),
		Hostname:     truncate(req.GetHostname(), maxEnrollFieldLength),
		RemoteAddr:   remoteAddr(ctx),
	})
	switch {
	case err == nil:
	case errors.Is(err, service.ErrEnrollmentRejected):
		// One message for every reason. See the log for which one it was.
		return nil, status.Error(codes.PermissionDenied, "enrollment was rejected")
	default:
		s.log.ErrorContext(ctx, "enrollment failed",
			slog.String("remote_addr", remoteAddr(ctx)), slog.Any("error", err))
		return nil, status.Error(codes.Internal, "enrollment could not be completed")
	}

	return &nodectlv1.EnrollResponse{
		CertificatePem: string(result.CertPEM),
		CaPem:          string(result.CAPEM),
		NodeId:         result.Node.ID,
		NodeName:       result.Node.Name,
		ServerName:     result.ServerName,
		NotAfter:       result.NotAfter.UTC().Format(time.RFC3339),
	}, nil
}

// truncate bounds a string the caller controls.
func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
