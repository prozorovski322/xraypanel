// Package config turns the process environment into a validated configuration
// struct. Every problem is reported at once and startup fails before anything
// opens a socket or a database connection.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"
)

// Environment names. Production tightens several validation rules.
const (
	EnvDev  = "dev"
	EnvProd = "prod"
)

// Config is the fully validated configuration of the panel process.
type Config struct {
	Env          string
	Log          Log
	HTTP         HTTP
	GRPC         GRPC
	DB           DB
	Auth         Auth
	Bootstrap    Bootstrap
	Subscription Subscription
	Traffic      Traffic
	Enforcement  Enforcement
	Webhooks     Webhooks

	// SecretKey encrypts secrets at rest in the database: the CA private key,
	// Reality private keys, TOTP secrets and webhook secrets. It also derives
	// the JWT signing key, so that an operator manages exactly one secret.
	SecretKey []byte

	// BillingLocation is the timezone traffic-reset schedules are evaluated in.
	// Everything stored in the database stays UTC regardless.
	BillingLocation *time.Location

	// TOTPIssuer labels entries in an administrator's authenticator app. Setting it
	// to this installation's hostname is what lets someone who runs several panels
	// tell the entries apart at the moment they need to.
	TOTPIssuer string
}

// IsProd reports whether the panel runs with production validation rules.
func (c *Config) IsProd() bool { return c.Env == EnvProd }

type Log struct {
	Level  string // debug|info|warn|error
	Format string // json|text
}

type HTTP struct {
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration

	// TrustedProxies lists networks whose X-Forwarded-For header is believed.
	// Empty means the header is ignored entirely and the socket peer address is
	// used, which is the safe default: an attacker-controlled header must never
	// be able to spoof the client IP that rate limiting and audit logs record.
	TrustedProxies []net.IPNet
}

type GRPC struct {
	// Addr is where nodes dial in. Nodes always initiate the connection, so the
	// panel is the gRPC server and authenticates nodes by client certificate.
	Addr            string
	ShutdownTimeout time.Duration

	// HeartbeatInterval is how often a connected node is told to report in. The panel
	// owns the interval so it can be changed without redeploying nodes.
	HeartbeatInterval time.Duration

	// HeartbeatTimeout is how long silence from a node is tolerated before its stream
	// is torn down. Validation keeps it above the interval, since a value below it
	// would disconnect every node on schedule.
	HeartbeatTimeout time.Duration

	// ExtraServerNames adds names to the panel's gRPC certificate. Nodes require
	// pki.PanelServerName regardless of the address they dial, so this is only for an
	// operator who wants a real DNS name in there as well.
	ExtraServerNames []string

	// EnrollmentTTL is how long a node enrollment token stays redeemable. It is a
	// bearer secret worth a node's identity, so the window only has to cover the
	// minutes between minting it and the node starting.
	EnrollmentTTL time.Duration
}

type DB struct {
	DSN             string
	MaxConns        int
	MinConns        int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	ConnectTimeout  time.Duration
}

type Auth struct {
	AccessTTL  time.Duration
	RefreshTTL time.Duration

	// Login throttling, enforced per (username, IP) pair.
	LoginMaxAttempts int
	LoginWindow      time.Duration
	LoginLockout     time.Duration

	// SecureCookies controls the Secure attribute on the refresh cookie. It is
	// forced on in production: a refresh token sent over plain HTTP is a
	// refresh token handed to anyone on the path.
	SecureCookies bool
}

// Subscription configures what clients are told about their own subscription.
type Subscription struct {
	// UpdateHours is advertised as profile-update-interval. Too low wastes the panel's
	// bandwidth on clients that refetch constantly; too high delays a revocation from
	// reaching a client that only refreshes on schedule.
	UpdateHours int

	// ProfileTitle names the profile in clients that display one.
	ProfileTitle string

	// RatePerMinute and RateBurst bound how often one client address may hit the public
	// endpoint. A client refreshes a few times a day, so the defaults leave room for a
	// household or a carrier NAT behind one address while stopping a loop or a scan.
	RatePerMinute int
	RateBurst     int
}

// Traffic is how the accounting data is kept in shape.
type Traffic struct {
	// MaintenanceInterval is how often the housekeeping runs: rolling hourly rows up into
	// daily ones, creating the next months' partitions, and dropping what has aged out.
	MaintenanceInterval time.Duration

	// RecordRetention is how long the hourly rows are kept. The daily rollup is what
	// charts are drawn from and is not deleted, so this bounds the biggest table in the
	// database without losing the history an operator looks at.
	RecordRetention time.Duration

	// BatchRetention is how long a node's batch id is remembered for deduplication. It
	// has to outlive the longest outage during which a node might still be holding an
	// unacknowledged batch, because forgetting an id turns a resend into double billing.
	BatchRetention time.Duration

	// PartitionsAhead is how many monthly partitions to keep created in advance. Traffic
	// arriving with no partition lands in the default one, which works and is slower to
	// query — so this is about staying ahead, not about correctness.
	PartitionsAhead int
}

// Enforcement is how often limits and billing periods are checked.
type Enforcement struct {
	// Interval is how often over-limit and expired users are switched off and finished
	// periods are reset. It pairs with the nodes' traffic poll: together they bound how far
	// past their limit a user can get.
	Interval time.Duration
}

// Webhooks is how outgoing event deliveries are attempted.
type Webhooks struct {
	// Interval is how often the delivery queue is checked.
	Interval time.Duration

	// Timeout bounds one delivery; a slower receiver is treated as down.
	Timeout time.Duration

	// MaxAttempts is when the panel gives up on a delivery.
	MaxAttempts int

	// Retention is how long delivered rows are kept.
	Retention time.Duration
}

// Bootstrap optionally seeds the first administrator on startup. It is a no-op
// once any administrator exists, so leaving it set is harmless but pointless.
type Bootstrap struct {
	AdminUsername string
	AdminPassword string
}

// Enabled reports whether a first administrator should be seeded.
func (b Bootstrap) Enabled() bool {
	return b.AdminUsername != "" && b.AdminPassword != ""
}

// MinPasswordLength applies to every administrator password, including the
// bootstrap one. It is deliberately above the usual eight characters: these accounts
// own the whole installation, and length is what actually costs an attacker.
// Composition rules are not used; see auth.Service.CheckPasswordPolicy.
const MinPasswordLength = 12

// Load reads the configuration from the process environment.
func Load() (*Config, error) { return LoadFrom(os.LookupEnv) }

// LoadFrom reads the configuration from an arbitrary lookup function. All
// validation problems are collected and returned as a single joined error.
func LoadFrom(lookup LookupFunc) (*Config, error) {
	l := newLoader(lookup)

	env := l.enum("APP_ENV", EnvDev, EnvDev, EnvProd)
	isProd := env == EnvProd

	defaultLogFormat := "text"
	if isProd {
		defaultLogFormat = "json"
	}

	cfg := &Config{
		Env: env,
		Log: Log{
			Level:  l.enum("LOG_LEVEL", "info", "debug", "info", "warn", "error"),
			Format: l.enum("LOG_FORMAT", defaultLogFormat, "json", "text"),
		},
		HTTP: HTTP{
			Addr:            l.listenAddr("HTTP_ADDR", ":8080"),
			ReadTimeout:     l.duration("HTTP_READ_TIMEOUT", 15*time.Second, time.Second, 5*time.Minute),
			WriteTimeout:    l.duration("HTTP_WRITE_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
			IdleTimeout:     l.duration("HTTP_IDLE_TIMEOUT", 60*time.Second, time.Second, 30*time.Minute),
			ShutdownTimeout: l.duration("HTTP_SHUTDOWN_TIMEOUT", 15*time.Second, time.Second, 5*time.Minute),
			TrustedProxies:  l.cidrList("HTTP_TRUSTED_PROXIES", ""),
		},
		GRPC: GRPC{
			Addr:              l.listenAddr("GRPC_ADDR", ":8443"),
			ShutdownTimeout:   l.duration("GRPC_SHUTDOWN_TIMEOUT", 15*time.Second, time.Second, 5*time.Minute),
			HeartbeatInterval: l.duration("NODE_HEARTBEAT_INTERVAL", 30*time.Second, 5*time.Second, 10*time.Minute),
			HeartbeatTimeout:  l.duration("NODE_HEARTBEAT_TIMEOUT", 90*time.Second, 10*time.Second, 30*time.Minute),
			ExtraServerNames:  l.dnsNameList("GRPC_EXTRA_SERVER_NAMES", ""),
			EnrollmentTTL:     l.duration("NODE_ENROLLMENT_TTL", time.Hour, time.Minute, 30*24*time.Hour),
		},
		DB: DB{
			DSN:             l.required("DATABASE_URL"),
			MaxConns:        l.intVal("DB_MAX_CONNS", 10, 1, 1000),
			MinConns:        l.intVal("DB_MIN_CONNS", 2, 0, 1000),
			ConnMaxLifetime: l.duration("DB_CONN_MAX_LIFETIME", time.Hour, time.Minute, 24*time.Hour),
			ConnMaxIdleTime: l.duration("DB_CONN_MAX_IDLE_TIME", 30*time.Minute, time.Minute, 24*time.Hour),
			ConnectTimeout:  l.duration("DB_CONNECT_TIMEOUT", 10*time.Second, time.Second, 2*time.Minute),
		},
		Auth: Auth{
			AccessTTL:        l.duration("AUTH_ACCESS_TTL", 15*time.Minute, time.Minute, 24*time.Hour),
			RefreshTTL:       l.duration("AUTH_REFRESH_TTL", 30*24*time.Hour, time.Hour, 365*24*time.Hour),
			LoginMaxAttempts: l.intVal("AUTH_LOGIN_MAX_ATTEMPTS", 5, 1, 1000),
			LoginWindow:      l.duration("AUTH_LOGIN_WINDOW", 15*time.Minute, time.Minute, 24*time.Hour),
			LoginLockout:     l.duration("AUTH_LOGIN_LOCKOUT", 15*time.Minute, time.Minute, 24*time.Hour),
			SecureCookies:    l.boolVal("AUTH_SECURE_COOKIES", isProd),
		},
		Bootstrap: Bootstrap{
			AdminUsername: l.str("BOOTSTRAP_ADMIN_USERNAME", ""),
			AdminPassword: l.str("BOOTSTRAP_ADMIN_PASSWORD", ""),
		},
		Subscription: Subscription{
			UpdateHours:   l.intVal("SUBSCRIPTION_UPDATE_HOURS", 12, 1, 24*30),
			ProfileTitle:  l.str("SUBSCRIPTION_PROFILE_TITLE", "xraypanel"),
			RatePerMinute: l.intVal("SUBSCRIPTION_RATE_LIMIT", 30, 1, 100_000),
			RateBurst:     l.intVal("SUBSCRIPTION_RATE_BURST", 20, 1, 100_000),
		},
		Traffic: Traffic{
			MaintenanceInterval: l.duration("TRAFFIC_MAINTENANCE_INTERVAL", time.Hour, time.Minute, 24*time.Hour),
			RecordRetention:     l.duration("TRAFFIC_RECORD_RETENTION", 90*24*time.Hour, 24*time.Hour, 3650*24*time.Hour),
			// Two days rather than hours: a node that was unreachable overnight still
			// holds unacknowledged batches, and forgetting their ids would let the same
			// bytes be billed twice.
			BatchRetention:  l.duration("TRAFFIC_BATCH_RETENTION", 48*time.Hour, time.Hour, 30*24*time.Hour),
			PartitionsAhead: l.intVal("TRAFFIC_PARTITIONS_AHEAD", 3, 1, 24),
		},
		Enforcement: Enforcement{
			Interval: l.duration("ENFORCEMENT_INTERVAL", 30*time.Second, time.Second, time.Hour),
		},
		Webhooks: Webhooks{
			Interval:    l.duration("WEBHOOK_INTERVAL", 5*time.Second, time.Second, 10*time.Minute),
			Timeout:     l.duration("WEBHOOK_TIMEOUT", 10*time.Second, time.Second, 2*time.Minute),
			MaxAttempts: l.intVal("WEBHOOK_MAX_ATTEMPTS", 12, 1, 50),
			Retention:   l.duration("WEBHOOK_RETENTION", 7*24*time.Hour, time.Hour, 365*24*time.Hour),
		},
		SecretKey:       l.key32("PANEL_SECRET_KEY"),
		BillingLocation: l.location("BILLING_TIMEZONE", "UTC"),
		TOTPIssuer:      l.str("TOTP_ISSUER", "xraypanel"),
	}

	l.errs = append(l.errs, validate(cfg)...)

	if len(l.errs) > 0 {
		// Sorting keeps the report stable across runs, which matters when an
		// operator is comparing output between two attempts.
		msgs := make([]string, 0, len(l.errs))
		for _, err := range l.errs {
			msgs = append(msgs, "  - "+err.Error())
		}
		slices.Sort(msgs)
		return nil, fmt.Errorf("invalid configuration (%d problem(s)):\n%s",
			len(msgs), strings.Join(msgs, "\n"))
	}

	return cfg, nil
}

// validate holds the cross-field rules that a single-key loader cannot express.
func validate(cfg *Config) []error {
	var errs []error

	if cfg.DB.MinConns > cfg.DB.MaxConns {
		errs = append(errs, fmt.Errorf(
			"DB_MIN_CONNS: must not exceed DB_MAX_CONNS (%d > %d)",
			cfg.DB.MinConns, cfg.DB.MaxConns))
	}

	if cfg.DB.DSN != "" && !isPostgresDSN(cfg.DB.DSN) {
		errs = append(errs, errors.New(
			"DATABASE_URL: must be a postgres:// or postgresql:// URL"))
	}

	// A refresh token that outlives its access token by less than an order of
	// magnitude means the SPA re-authenticates constantly; the reverse ordering
	// is outright broken.
	if cfg.Auth.RefreshTTL <= cfg.Auth.AccessTTL {
		errs = append(errs, fmt.Errorf(
			"AUTH_REFRESH_TTL: must be longer than AUTH_ACCESS_TTL (%s <= %s)",
			cfg.Auth.RefreshTTL, cfg.Auth.AccessTTL))
	}

	// A timeout at or below the interval disconnects every node on schedule: the panel
	// would give up before the next heartbeat was even due.
	if cfg.GRPC.HeartbeatTimeout <= cfg.GRPC.HeartbeatInterval {
		errs = append(errs, fmt.Errorf(
			"NODE_HEARTBEAT_TIMEOUT: must be longer than NODE_HEARTBEAT_INTERVAL (%s <= %s)",
			cfg.GRPC.HeartbeatTimeout, cfg.GRPC.HeartbeatInterval))
	}

	if cfg.HTTP.Addr != "" && cfg.HTTP.Addr == cfg.GRPC.Addr {
		errs = append(errs, fmt.Errorf(
			"GRPC_ADDR: must differ from HTTP_ADDR (both %q)", cfg.GRPC.Addr))
	}

	// Half-configured bootstrap is a typo, not an intent to disable seeding.
	switch {
	case cfg.Bootstrap.AdminUsername != "" && cfg.Bootstrap.AdminPassword == "":
		errs = append(errs, errors.New(
			"BOOTSTRAP_ADMIN_PASSWORD: is required when BOOTSTRAP_ADMIN_USERNAME is set"))
	case cfg.Bootstrap.AdminPassword != "" && cfg.Bootstrap.AdminUsername == "":
		errs = append(errs, errors.New(
			"BOOTSTRAP_ADMIN_USERNAME: is required when BOOTSTRAP_ADMIN_PASSWORD is set"))
	case cfg.Bootstrap.Enabled() && len(cfg.Bootstrap.AdminPassword) < MinPasswordLength:
		errs = append(errs, fmt.Errorf(
			"BOOTSTRAP_ADMIN_PASSWORD: must be at least %d characters, got %d",
			MinPasswordLength, len(cfg.Bootstrap.AdminPassword)))
	}

	if cfg.IsProd() {
		if !cfg.Auth.SecureCookies {
			errs = append(errs, errors.New(
				"AUTH_SECURE_COOKIES: cannot be disabled when APP_ENV=prod"))
		}
		if cfg.Log.Level == "debug" {
			errs = append(errs, errors.New(
				"LOG_LEVEL: debug is not allowed when APP_ENV=prod"))
		}
	}

	return errs
}

func isPostgresDSN(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}
