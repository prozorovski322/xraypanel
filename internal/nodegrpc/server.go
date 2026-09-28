// Package nodegrpc is the panel's side of the node control protocol.
//
// The panel is the gRPC server and nodes dial in. That is the opposite of how a
// control plane is often drawn, and it is what makes the design work in practice:
// nodes sit behind NAT with no inbound management port, "connected" is simply whether
// a node's stream is open, and mutual TLS falls out naturally — the node proves it is
// a node the panel enrolled, and the panel proves it is the panel (ADR-001).
package nodegrpc

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	nodectlv1 "github.com/xraypanel/panel/internal/nodectl/v1"
	"github.com/xraypanel/panel/internal/pki"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
	"github.com/xraypanel/panel/internal/service"
)

// Config holds the server's tunables.
type Config struct {
	// HeartbeatInterval is how often a node is told to report in.
	HeartbeatInterval time.Duration

	// HeartbeatTimeout is how long the panel waits for anything at all from a node
	// before tearing the stream down. It has to be a multiple of the interval: a
	// single lost packet must not cost a node its connection, while a half-open TCP
	// connection has to be noticed at all, which nothing below the application layer
	// reliably does.
	HeartbeatTimeout time.Duration

	// ExtraServerNames are additional names to put in the panel's server
	// certificate, for an operator who would rather have nodes verify a real DNS
	// name. Nodes require pki.PanelServerName regardless, so this is never needed
	// for the panel's own agent.
	ExtraServerNames []string
}

// Server is the node-facing gRPC server.
type Server struct {
	nodectlv1.UnimplementedNodeControlServer

	svc      *service.Service
	log      *slog.Logger
	cfg      Config
	registry *Registry
	grpc     *grpc.Server
}

// New builds the server, issuing the certificate it will present to nodes.
//
// The certificate is generated here rather than read from disk: it is signed by the
// panel's own authority, nodes verify the authority and not the leaf, and a key that
// exists only in this process's memory is one fewer secret to manage.
func New(ctx context.Context, svc *service.Service, logger *slog.Logger, cfg Config) (*Server, error) {
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.HeartbeatTimeout <= cfg.HeartbeatInterval {
		cfg.HeartbeatTimeout = 3 * cfg.HeartbeatInterval
	}

	ca, err := svc.EnsureCA(ctx)
	if err != nil {
		return nil, err
	}

	certPEM, keyPEM, err := svc.IssueServerCertificate(ctx, cfg.ExtraServerNames)
	if err != nil {
		return nil, fmt.Errorf("nodegrpc: issue server certificate: %w", err)
	}

	tlsConfig, err := ca.ServerTLSConfig(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	server := &Server{
		svc:      svc,
		log:      logger,
		cfg:      cfg,
		registry: NewRegistry(),
	}

	server.grpc = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.UnaryInterceptor(server.unaryInterceptor),
		grpc.StreamInterceptor(server.streamInterceptor),

		// The panel probes an idle connection itself rather than waiting for the
		// operating system to give up on it, which can take hours.
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    cfg.HeartbeatInterval,
			Timeout: cfg.HeartbeatInterval,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			// A node that pings more often than this is misbehaving; half the
			// interval leaves room for jitter without inviting a ping flood.
			MinTime: cfg.HeartbeatInterval / 2,

			// No pings on a connection with no stream. A node with nothing open has
			// nothing to keep alive.
			PermitWithoutStream: false,
		}),
	)

	nodectlv1.RegisterNodeControlServer(server.grpc, server)

	logger.InfoContext(ctx, "node control server ready",
		slog.String("ca_pin", ca.Pin()),
		slog.String("server_name", pki.PanelServerName),
		slog.Duration("heartbeat_interval", cfg.HeartbeatInterval),
		slog.Duration("heartbeat_timeout", cfg.HeartbeatTimeout))

	return server, nil
}

// Registry exposes the live connections, for the HTTP layer and for the reconciler.
func (s *Server) Registry() *Registry { return s.registry }

// Serve handles connections until the server is stopped.
func (s *Server) Serve(listener net.Listener) error {
	if err := s.grpc.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("nodegrpc: serve: %w", err)
	}
	return nil
}

// GracefulStop stops accepting connections and waits for the open streams to end.
//
// The streams are asked to end first. Without that, GracefulStop would wait for
// long-lived streams that by design never finish on their own.
func (s *Server) GracefulStop() {
	s.registry.DisconnectAll()
	s.grpc.GracefulStop()
}

// Stop ends everything immediately.
func (s *Server) Stop() { s.grpc.Stop() }

// ---------------------------------------------------------------- authentication

// methodsWithoutCertificate is the allowlist of methods reachable without a client
// certificate. Everything else is denied, so a method added later is closed until
// somebody decides otherwise, rather than open until somebody notices.
var methodsWithoutCertificate = map[string]bool{
	nodectlv1.NodeControl_Enroll_FullMethodName: true,
}

// nodeContextKey carries the authenticated node down to the handler.
type nodeContextKey struct{}

// authenticatedNode is the identity a handler may rely on.
type authenticatedNode struct {
	node        *dbgen.Node
	fingerprint []byte
}

func (s *Server) unaryInterceptor(
	ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	ctx, err := s.authenticate(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (s *Server) streamInterceptor(
	srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	ctx, err := s.authenticate(stream.Context(), info.FullMethod)
	if err != nil {
		return err
	}
	return handler(srv, &contextStream{ServerStream: stream, ctx: ctx})
}

// contextStream replaces a stream's context, which is the only way to pass the
// authenticated identity from an interceptor into a streaming handler.
type contextStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *contextStream) Context() context.Context { return s.ctx }

// authenticate resolves the caller's certificate to a node, or refuses.
func (s *Server) authenticate(ctx context.Context, fullMethod string) (context.Context, error) {
	if methodsWithoutCertificate[fullMethod] {
		return ctx, nil
	}

	cert, err := peerCertificate(ctx)
	if err != nil {
		s.log.WarnContext(ctx, "refused a node call with no verified certificate",
			slog.String("method", fullMethod),
			slog.String("remote_addr", remoteAddr(ctx)),
			slog.Any("error", err))
		return nil, status.Error(codes.Unauthenticated, "a client certificate is required")
	}

	fingerprint := pki.FingerprintOf(cert)
	node, err := s.svc.AuthenticateNode(ctx, fingerprint)
	switch {
	case err == nil:
	case errors.Is(err, service.ErrNodeNotAuthenticated):
		// The certificate verified against the panel's own authority and still is not
		// anybody's: it was retired by a re-enrollment, or it belongs to a node that
		// has since been deleted.
		s.log.WarnContext(ctx, "refused a node call with a retired or unknown certificate",
			slog.String("method", fullMethod),
			slog.String("remote_addr", remoteAddr(ctx)),
			slog.String("fingerprint", fmt.Sprintf("%x", fingerprint)),
			slog.String("subject", cert.Subject.CommonName))
		return nil, status.Error(codes.Unauthenticated, "this certificate is not registered")
	case errors.Is(err, service.ErrNodeDisabled):
		s.log.InfoContext(ctx, "refused a call from a disabled node",
			slog.String("method", fullMethod),
			slog.String("remote_addr", remoteAddr(ctx)))
		return nil, status.Error(codes.PermissionDenied, "this node is disabled")
	default:
		s.log.ErrorContext(ctx, "could not authenticate a node",
			slog.String("method", fullMethod), slog.Any("error", err))
		return nil, status.Error(codes.Internal, "authentication failed")
	}

	return context.WithValue(ctx, nodeContextKey{}, authenticatedNode{
		node: node, fingerprint: fingerprint,
	}), nil
}

// nodeFromContext returns the identity the interceptor established.
//
// A missing value is a programming error, not a request the caller got wrong: it means
// a handler is reachable without having gone through authentication.
func nodeFromContext(ctx context.Context) (authenticatedNode, error) {
	identity, ok := ctx.Value(nodeContextKey{}).(authenticatedNode)
	if !ok {
		return authenticatedNode{}, status.Error(codes.Internal, "the request was not authenticated")
	}
	return identity, nil
}

// peerCertificate returns the client certificate the TLS stack verified.
//
// VerifiedChains rather than PeerCertificates: the latter is whatever the client sent,
// verified or not, and reading identity out of it would accept any self-signed
// certificate that happened to be presented.
func peerCertificate(ctx context.Context) (*x509.Certificate, error) {
	info, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("nodegrpc: no peer information on the connection")
	}

	tlsInfo, ok := info.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, errors.New("nodegrpc: the connection is not TLS")
	}

	chains := tlsInfo.State.VerifiedChains
	if len(chains) == 0 || len(chains[0]) == 0 {
		return nil, errors.New("nodegrpc: the peer presented no verified certificate")
	}
	return chains[0][0], nil
}

// remoteAddr renders the peer address for logs.
func remoteAddr(ctx context.Context) string {
	if info, ok := peer.FromContext(ctx); ok && info.Addr != nil {
		return info.Addr.String()
	}
	return "unknown"
}
