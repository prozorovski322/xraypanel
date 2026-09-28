// Package link is the node agent's side of the control protocol: enrolling once,
// staying connected, and applying what the panel sends.
//
// The order of operations in Run is the whole design. The core is brought up from the
// local cache before the panel is contacted at all, so that a node restarting during a
// panel outage serves its users anyway; only then does the agent start trying to
// connect, for ever, with backoff. A control plane that is down should cost nobody their
// connection.
package link

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/xraypanel/panel/internal/agent/reconcile"
	"github.com/xraypanel/panel/internal/agent/stats"
	"github.com/xraypanel/panel/internal/agent/store"
	"github.com/xraypanel/panel/internal/agent/supervisor"
	"github.com/xraypanel/panel/internal/agent/xrayapi"
	nodectlv1 "github.com/xraypanel/panel/internal/nodectl/v1"
	"github.com/xraypanel/panel/internal/pki"
)

// Defaults and bounds.
const (
	defaultReconnectMin = time.Second
	defaultReconnectMax = time.Minute
	defaultHeartbeat    = 30 * time.Second

	// minHeartbeat and maxHeartbeat bound what the panel is allowed to ask for. The
	// panel owns the interval, but a value of zero or of a day would break the agent
	// either way, and the agent is the one that has to survive a misconfigured panel.
	//
	// The floor is only a floor. What keeps operators from choosing something silly is
	// the panel's own configuration validation; this is here so that a panel bug cannot
	// turn every node into a busy loop.
	minHeartbeat = time.Second
	maxHeartbeat = 10 * time.Minute

	// applyBudget bounds one configuration apply, which includes validating it and
	// restarting the core.
	applyBudget = 2 * time.Minute

	// statsBudget bounds one traffic poll. The core answers from memory, so anything
	// slower means it is wedged and the next tick should try again rather than pile up.
	statsBudget = 20 * time.Second

	// defaultStatsInterval is used when a caller does not set one.
	defaultStatsInterval = 30 * time.Second

	// enrollBudget bounds the one call a node makes before it has an identity.
	enrollBudget = 30 * time.Second

	// certExpiryWarning is when the agent starts saying its certificate is running out.
	// There is no automatic renewal yet, so the warning is the mechanism.
	certExpiryWarning = 30 * 24 * time.Hour
)

// ErrNoEnrollment means the node has no identity and no way to obtain one.
var ErrNoEnrollment = errors.New("link: this node is not enrolled and no enrollment token is configured")

// Config is how the agent reaches its panel.
type Config struct {
	// PanelAddr is host:port of the panel's node port.
	PanelAddr string

	// CAPin is the panel authority's public-key fingerprint, handed out with the
	// enrollment token. It is what makes the first connection safe.
	CAPin string

	// EnrollmentToken is used once, and only when the node has no identity yet.
	EnrollmentToken string

	AgentVersion string
	Hostname     string

	Logger *slog.Logger

	ReconnectMin time.Duration
	ReconnectMax time.Duration

	// Heartbeat is used until the panel says otherwise.
	Heartbeat time.Duration

	// StatsInterval is how often the core's traffic counters are read.
	StatsInterval time.Duration

	// StatsStrategy is how deltas are derived; see the stats package.
	StatsStrategy stats.Mode
}

// Agent keeps one node in the state the panel wants it in.
type Agent struct {
	cfg   Config
	store *store.Store
	sup   *supervisor.Supervisor
	log   *slog.Logger

	// tracker turns the core's cumulative counters into billable deltas. Owned by the
	// polling goroutine, which is the only thing that touches it.
	tracker *stats.Tracker
}

// New builds the agent.
func New(cfg Config, state *store.Store, sup *supervisor.Supervisor) (*Agent, error) {
	if strings.TrimSpace(cfg.PanelAddr) == "" {
		return nil, errors.New("link: no panel address configured")
	}
	if cfg.Logger == nil {
		return nil, errors.New("link: no logger")
	}
	if state == nil || sup == nil {
		return nil, errors.New("link: the agent needs a store and a supervisor")
	}
	if cfg.ReconnectMin <= 0 {
		cfg.ReconnectMin = defaultReconnectMin
	}
	if cfg.ReconnectMax < cfg.ReconnectMin {
		cfg.ReconnectMax = defaultReconnectMax
	}
	if cfg.Heartbeat <= 0 {
		cfg.Heartbeat = defaultHeartbeat
	}
	if cfg.StatsInterval <= 0 {
		cfg.StatsInterval = defaultStatsInterval
	}
	if !cfg.StatsStrategy.Valid() {
		cfg.StatsStrategy = stats.ModeDelta
	}

	// Validated here rather than at the first handshake: a malformed pin means this
	// agent can never connect, and that should be said at startup.
	if _, err := pki.NormalizePin(cfg.CAPin); err != nil {
		return nil, fmt.Errorf("link: %w", err)
	}

	return &Agent{
		cfg:     cfg,
		store:   state,
		sup:     sup,
		log:     cfg.Logger,
		tracker: newTracker(state, cfg.StatsStrategy, cfg.Logger),
	}, nil
}

// Run starts the core from cache and then stays connected until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.startFromCache(ctx)

	// Counting runs whether or not the panel is reachable: traffic happens during an
	// outage too, and a node that stopped counting through one would be a node whose
	// users were not billed for that time.
	polling := make(chan struct{})
	go func() {
		defer close(polling)
		a.pollTraffic(ctx)
	}()
	defer func() {
		select {
		case <-polling:
		case <-time.After(statsBudget + time.Second):
			a.log.Warn("the traffic poller did not stop in time")
		}
	}()

	attempt := 0
	for {
		if ctx.Err() != nil {
			return nil
		}

		err := a.session(ctx)
		switch {
		case err == nil, errors.Is(err, context.Canceled):
			if ctx.Err() != nil {
				return nil
			}
		case errors.Is(err, ErrNoEnrollment):
			// Nothing the agent can do about this, and retrying would hide it. The
			// operator has to issue a token.
			return err
		default:
			a.log.ErrorContext(ctx, "lost the connection to the panel", slog.Any("error", err))
		}

		attempt++
		delay := a.backoff(attempt)
		a.log.InfoContext(ctx, "reconnecting to the panel",
			slog.Duration("in", delay), slog.Int("attempt", attempt))

		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil
		}
	}
}

// startFromCache brings the core up on the last configuration the panel gave, before
// the panel has been contacted.
//
// This is what makes a panel outage survivable: a node that reboots while the control
// plane is down comes back serving the same users. A failure here is logged and not
// fatal вЂ” the panel may be about to send something better.
func (a *Agent) startFromCache(ctx context.Context) {
	cached, confirmed, err := a.store.DesiredConfig()
	if err != nil {
		a.log.ErrorContext(ctx, "could not read the cached configuration", slog.Any("error", err))
		return
	}
	if cached == nil {
		a.log.InfoContext(ctx, "no cached configuration; waiting for the panel")
		return
	}
	if cached.Empty() {
		a.log.InfoContext(ctx, "the cached configuration runs nothing; waiting for the panel",
			slog.Int64("config_version", cached.Version))
		return
	}
	if !confirmed {
		// The agent stopped in the middle of applying this. Starting it is still the best
		// available guess at what the panel wants, and the version is reported as
		// unconfirmed so the panel sends it again.
		a.log.WarnContext(ctx, "the cached configuration was never confirmed; starting it anyway",
			slog.Int64("config_version", cached.Version))
	}

	applyCtx, cancel := context.WithTimeout(ctx, applyBudget)
	defer cancel()

	if err := a.sup.Apply(applyCtx, cached.JSON); err != nil {
		a.log.ErrorContext(ctx, "could not start xray from the cached configuration",
			slog.Int64("config_version", cached.Version), slog.Any("error", err))
		return
	}

	a.log.InfoContext(ctx, "started xray from the cached configuration",
		slog.Int64("config_version", cached.Version))
}

// session runs one connection to the panel from beginning to end.
func (a *Agent) session(ctx context.Context) error {
	identity, err := a.identity(ctx)
	if err != nil {
		return err
	}

	if remaining := time.Until(identity.NotAfter); !identity.NotAfter.IsZero() && remaining < certExpiryWarning {
		a.log.WarnContext(ctx, "this node's certificate is running out; ask an operator for a "+
			"new enrollment token before it expires",
			slog.Time("not_after", identity.NotAfter),
			slog.Duration("remaining", remaining))
	}

	tlsConfig, err := pki.NodeTLSConfig(identity.CAPEM, identity.CertPEM, identity.KeyPEM)
	if err != nil {
		return err
	}

	conn, err := grpc.NewClient(a.cfg.PanelAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return fmt.Errorf("link: dial %s: %w", a.cfg.PanelAddr, err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := nodectlv1.NewNodeControlClient(conn).Control(ctx)
	if err != nil {
		return fmt.Errorf("link: open the control stream: %w", err)
	}

	appliedVersion, err := a.store.AppliedVersion()
	if err != nil {
		return err
	}

	if err := stream.Send(&nodectlv1.NodeMessage{
		Payload: &nodectlv1.NodeMessage_Hello{Hello: &nodectlv1.Hello{
			AgentVersion:   a.cfg.AgentVersion,
			XrayVersion:    a.sup.Version(ctx),
			AppliedVersion: appliedVersion,
			StartedAt:      time.Now().UTC().Format(time.RFC3339),
		}},
	}); err != nil {
		return fmt.Errorf("link: send hello: %w", err)
	}

	return a.serve(ctx, stream, identity)
}

// serve handles the stream: messages in, heartbeats out.
func (a *Agent) serve(
	ctx context.Context,
	stream nodectlv1.NodeControl_ControlClient,
	identity *store.Identity,
) error {
	interval := a.cfg.Heartbeat

	// The first message is the panel's acknowledgement, which carries the interval it
	// wants. Reading it before starting the ticker means the agent never heartbeats at
	// the wrong rate even once.
	first, err := stream.Recv()
	if err != nil {
		return a.classify(err)
	}
	ack := first.GetHelloAck()
	if ack == nil {
		return errors.New("link: the panel's first message was not an acknowledgement")
	}
	if advertised := time.Duration(ack.GetHeartbeatSeconds()) * time.Second; advertised >= minHeartbeat && advertised <= maxHeartbeat {
		interval = advertised
	}

	a.log.InfoContext(ctx, "connected to the panel",
		slog.Int64("node_id", ack.GetNodeId()),
		slog.String("node", ack.GetNodeName()),
		slog.Int64("desired_version", ack.GetDesiredVersion()),
		slog.Duration("heartbeat", interval))

	incoming := make(chan *nodectlv1.PanelMessage)
	recvErr := make(chan error, 1)
	go func() {
		defer close(incoming)
		for {
			message, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case incoming <- message:
			case <-ctx.Done():
				return
			}
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case err := <-recvErr:
			return a.classify(err)

		case <-ticker.C:
			if err := a.heartbeat(ctx, stream); err != nil {
				return err
			}
			// Reported on the same tick rather than on a schedule of its own: the traffic
			// is already buffered and durable, so what matters is that it leaves
			// regularly, not promptly, and one timer is easier to reason about than two.
			if err := a.reportTraffic(ctx, stream); err != nil {
				return err
			}

		case message, ok := <-incoming:
			if !ok {
				return errors.New("link: the panel closed the stream")
			}
			if err := a.handle(ctx, stream, message, identity); err != nil {
				return err
			}
		}
	}
}

// heartbeat reports what the node is doing.
func (a *Agent) heartbeat(ctx context.Context, stream nodectlv1.NodeControl_ControlClient) error {
	version, err := a.store.AppliedVersion()
	if err != nil {
		return err
	}

	err = stream.Send(&nodectlv1.NodeMessage{
		Payload: &nodectlv1.NodeMessage_Heartbeat{Heartbeat: &nodectlv1.Heartbeat{
			SentAt:         time.Now().UTC().Format(time.RFC3339),
			XrayRunning:    a.sup.Running(),
			AppliedVersion: version,
		}},
	})
	if err != nil {
		return fmt.Errorf("link: send heartbeat: %w", err)
	}
	return nil
}

// handle dispatches one message from the panel.
func (a *Agent) handle(
	ctx context.Context,
	stream nodectlv1.NodeControl_ControlClient,
	message *nodectlv1.PanelMessage,
	identity *store.Identity,
) error {
	switch payload := message.GetPayload().(type) {
	case *nodectlv1.PanelMessage_ApplyConfig:
		return a.applyConfig(ctx, stream, payload.ApplyConfig)

	case *nodectlv1.PanelMessage_TrafficAck:
		return a.handleTrafficAck(ctx, payload.TrafficAck)

	case *nodectlv1.PanelMessage_HelloAck:
		a.log.WarnContext(ctx, "ignored a second acknowledgement from the panel")
		return nil

	default:
		// A newer panel talking to an older agent. Ignoring it is what the oneof is for.
		a.log.WarnContext(ctx, "ignored an unrecognised message from the panel")
		return nil
	}
}

// applyConfig puts the node into the state the panel asked for, and reports the outcome.
//
// Applied synchronously, so there is never more than one apply in flight: two overlapping
// restarts of the same core is a way to end up with neither configuration running. It
// costs at most one skipped heartbeat, and the panel tolerates several.
func (a *Agent) applyConfig(
	ctx context.Context,
	stream nodectlv1.NodeControl_ControlClient,
	config *nodectlv1.ApplyConfig,
) error {
	version := config.GetConfigVersion()
	payload := config.GetConfigJson()

	a.log.InfoContext(ctx, "applying a configuration from the panel",
		slog.Int64("config_version", version),
		slog.Int("bytes", len(payload)),
		slog.Bool("empty", len(payload) == 0))

	applyCtx, cancel := context.WithTimeout(ctx, applyBudget)
	defer cancel()

	// Read before anything is written: the configuration the core is running is the one
	// the store calls desired, which may be an unconfirmed record the agent started from
	// cache. Recording the new configuration as pending first would make the node look
	// as though it were already running what it is about to apply, and the reconciler
	// would compute the difference between the new configuration and itself вЂ” which is
	// no difference at all, leaving the core untouched.
	running, _, runningErr := a.store.DesiredConfig()
	if runningErr != nil {
		a.log.ErrorContext(ctx, "could not read what this node is running",
			slog.Any("error", runningErr))
	}

	record := &store.AppliedConfig{
		Version:        version,
		JSON:           payload,
		StructuralHash: config.GetStructuralHash(),
		InboundHashes:  config.GetInboundHashes(),
		AppliedAt:      time.Now().UTC(),
	}

	// Recorded as pending before anything is touched. An agent killed from here until the
	// confirmation below comes back knowing what it was in the middle of, instead of
	// waiting for a panel that may be the reason it was restarted.
	if len(payload) > 0 {
		if err := a.store.SavePendingConfig(record); err != nil {
			a.log.ErrorContext(ctx, "could not record the configuration as pending",
				slog.Int64("config_version", version), slog.Any("error", err))
		}
	}

	var applyErr error
	var restarted bool

	if len(payload) == 0 {
		// The panel wants nothing running. A node with no inbounds, or none with active
		// users, is better idle than left serving a configuration the panel has
		// forgotten about.
		restarted = a.sup.Running()
		applyErr = a.sup.Stop(applyCtx)
	} else {
		restarted, applyErr = a.applyDesired(applyCtx, running, record)
	}

	if applyErr == nil {
		saveErr := a.store.SaveAppliedConfig(record)
		if saveErr != nil {
			// The core is running the new configuration and the cache does not know it.
			// Reported as a failure: the alternative is a node that comes back from a
			// reboot running the previous configuration while the panel believes
			// otherwise.
			applyErr = fmt.Errorf("applied but could not be cached: %w", saveErr)
		}
	}

	message := &nodectlv1.ApplyResult{ConfigVersion: version, Ok: applyErr == nil, Restarted: restarted}
	if applyErr != nil {
		message.Error = applyErr.Error()
		a.log.ErrorContext(ctx, "could not apply the configuration",
			slog.Int64("config_version", version), slog.Any("error", applyErr))
	} else {
		a.log.InfoContext(ctx, "applied the configuration",
			slog.Int64("config_version", version), slog.Bool("restarted", restarted))
	}

	if err := stream.Send(&nodectlv1.NodeMessage{
		Payload: &nodectlv1.NodeMessage_ApplyResult{ApplyResult: message},
	}); err != nil {
		return fmt.Errorf("link: send apply result: %w", err)
	}
	return nil
}

// applyDesired puts a non-empty configuration in place, restarting the core only when the
// change cannot be made on the running one.
//
// A restart is the fallback for everything: no previous configuration to compare with, a
// change the core's API cannot make, or a reconciliation that failed halfway. It always
// converges, because the configuration is on disk before any of the runtime calls are
// made.
func (a *Agent) applyDesired(
	ctx context.Context,
	running *store.AppliedConfig,
	record *store.AppliedConfig,
) (restarted bool, err error) {
	plan, reason := a.planFor(ctx, running, record)

	if plan.Restart {
		a.log.InfoContext(ctx, "restarting the core",
			slog.Int64("config_version", record.Version),
			slog.String("reason", reason))
		return true, a.sup.Apply(ctx, record.JSON)
	}

	if err := a.reconcile(ctx, record, plan); err != nil {
		// The core is left running whatever it had; the new configuration is on disk, so
		// a restart lands on it. Loud, because a reconciliation that keeps failing means
		// the runtime path is broken and every change is costing connections.
		a.log.WarnContext(ctx, "could not reconcile the running core; restarting it to converge",
			slog.Int64("config_version", record.Version), slog.Any("error", err))
		return true, a.sup.Apply(ctx, record.JSON)
	}

	a.log.InfoContext(ctx, "reconciled the running core without a restart",
		slog.Int64("config_version", record.Version),
		slog.Int("operations", plan.Operations()),
		slog.Any("inbounds", plan.Tags()))
	return false, nil
}

// planFor decides between the runtime path and a restart.
func (a *Agent) planFor(
	ctx context.Context,
	running *store.AppliedConfig,
	record *store.AppliedConfig,
) (reconcile.Plan, string) {
	if !a.sup.Running() {
		return reconcile.Plan{Restart: true}, "the core is not running"
	}
	if running.Empty() {
		return reconcile.Plan{Restart: true}, "this node has no configuration to compare with"
	}

	plan, err := reconcile.Compute(snapshotOf(running), snapshotOf(record))
	if err != nil {
		return reconcile.Plan{Restart: true}, fmt.Sprintf("the change could not be planned: %v", err)
	}
	return plan, plan.Reason
}

// reconcile writes the configuration and makes the changes on the running core.
func (a *Agent) reconcile(ctx context.Context, record *store.AppliedConfig, plan reconcile.Plan) error {
	// On disk first. A core that dies mid-reconciliation is restarted by the supervisor
	// from this file, which is the desired state rather than the one being replaced.
	if err := a.sup.SwapConfig(ctx, record.JSON); err != nil {
		return err
	}
	if plan.Empty() {
		return nil
	}

	endpoint, ok := a.sup.Endpoint()
	if !ok {
		return errors.New("link: the configuration has no api inbound to reconcile through")
	}

	client, err := xrayapi.Dial(endpoint)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	if err := reconcile.Execute(ctx, client, plan); err != nil {
		return err
	}

	desired, err := reconcile.Parse(record.JSON)
	if err != nil {
		return err
	}
	return reconcile.Verify(ctx, client, desired, plan.Tags())
}

// snapshotOf is the reconciler's view of a stored configuration.
func snapshotOf(config *store.AppliedConfig) reconcile.Snapshot {
	if config == nil {
		return reconcile.Snapshot{}
	}
	return reconcile.Snapshot{
		JSON:           config.JSON,
		StructuralHash: config.StructuralHash,
		InboundHashes:  config.InboundHashes,
	}
}

// identity returns the node's identity, enrolling if it has none.
func (a *Agent) identity(ctx context.Context) (*store.Identity, error) {
	identity, err := a.store.Identity()
	switch {
	case err == nil:
		return identity, nil
	case !errors.Is(err, store.ErrNotEnrolled):
		return nil, err
	}

	if strings.TrimSpace(a.cfg.EnrollmentToken) == "" {
		return nil, ErrNoEnrollment
	}
	return a.enroll(ctx)
}

// enroll exchanges the token for a certificate, once.
//
// The key pair is generated here and the private half never leaves this process: the
// panel receives a certificate request and nothing else (ADR-049).
func (a *Agent) enroll(ctx context.Context) (*store.Identity, error) {
	a.log.InfoContext(ctx, "enrolling with the panel", slog.String("panel", a.cfg.PanelAddr))

	csrPEM, keyPEM, err := pki.CreateNodeCSR(a.cfg.Hostname)
	if err != nil {
		return nil, err
	}

	// The panel cannot be verified the usual way yet вЂ” the authority arrives in the
	// answer to this very call вЂ” so it is verified against the pinned public key that
	// came with the token.
	tlsConfig, err := pki.EnrollTLSConfig(a.cfg.CAPin)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(a.cfg.PanelAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("link: dial %s: %w", a.cfg.PanelAddr, err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(ctx, enrollBudget)
	defer cancel()

	response, err := nodectlv1.NewNodeControlClient(conn).Enroll(ctx, &nodectlv1.EnrollRequest{
		Token:        a.cfg.EnrollmentToken,
		CsrPem:       string(csrPEM),
		AgentVersion: a.cfg.AgentVersion,
		Hostname:     a.cfg.Hostname,
	})
	if err != nil {
		if status.Code(err) == codes.PermissionDenied {
			// One message covers every reason on purpose (ADR-056); the panel's log has
			// the detail, so the agent's log says where to look.
			return nil, fmt.Errorf("link: the panel rejected this enrollment; "+
				"the reason is in the panel's log: %w", err)
		}
		return nil, fmt.Errorf("link: enroll: %w", err)
	}

	notAfter, parseErr := time.Parse(time.RFC3339, response.GetNotAfter())
	if parseErr != nil {
		// Not fatal: the certificate is usable and the date is only used for a warning.
		a.log.WarnContext(ctx, "the panel sent an expiry this agent cannot read",
			slog.String("not_after", response.GetNotAfter()))
	}

	identity := &store.Identity{
		NodeID:     response.GetNodeId(),
		NodeName:   response.GetNodeName(),
		CertPEM:    []byte(response.GetCertificatePem()),
		KeyPEM:     keyPEM,
		CAPEM:      []byte(response.GetCaPem()),
		ServerName: response.GetServerName(),
		NotAfter:   notAfter,
		EnrolledAt: time.Now().UTC(),
	}
	if err := a.store.SaveIdentity(identity); err != nil {
		// The certificate exists and the token that bought it is spent. Losing it here
		// means an operator has to issue another token, so it is reported plainly.
		return nil, fmt.Errorf("link: a certificate was issued but could not be stored, "+
			"so a new enrollment token will be needed: %w", err)
	}

	a.log.InfoContext(ctx, "enrolled",
		slog.Int64("node_id", identity.NodeID),
		slog.String("node", identity.NodeName),
		slog.Time("not_after", identity.NotAfter))

	return identity, nil
}

// classify turns a stream error into something worth logging, and says what an operator
// has to do about the one case they cannot ignore.
func (a *Agent) classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}

	switch status.Code(err) {
	case codes.Unauthenticated:
		// The panel no longer recognises this certificate: the node was re-enrolled or
		// deleted. Retrying cannot fix it, and the agent deliberately does not throw its
		// identity away on the panel's word вЂ” a transient fault must not cost a node its
		// certificate. So it keeps trying, loudly.
		a.log.Error("the panel does not recognise this node's certificate; " +
			"it has been re-enrolled or removed. Ask an operator for a new enrollment token")
	case codes.PermissionDenied:
		a.log.Error("the panel is refusing this node; it is most likely disabled")
	}

	return fmt.Errorf("link: %w", err)
}

// backoff grows the delay between attempts and jitters it.
//
// The jitter is not decoration: every node on an installation reconnects when the panel
// comes back, and without it they all arrive at the same instant, repeatedly.
func (a *Agent) backoff(attempt int) time.Duration {
	delay := a.cfg.ReconnectMin
	for i := 1; i < attempt && delay < a.cfg.ReconnectMax; i++ {
		delay *= 2
	}
	if delay > a.cfg.ReconnectMax {
		delay = a.cfg.ReconnectMax
	}

	// Up to a quarter either way.
	spread := delay / 4
	if spread <= 0 {
		return delay
	}
	return delay - spread + time.Duration(rand.Int64N(int64(2*spread)))
}
