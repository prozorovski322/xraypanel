// Command panel is the control plane: the REST API, the public subscription
// endpoint, and (from M6 onwards) the gRPC server that nodes dial into.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xraypanel/panel/internal/auth"
	"github.com/xraypanel/panel/internal/config"
	"github.com/xraypanel/panel/internal/crypto"
	"github.com/xraypanel/panel/internal/httpapi"
	"github.com/xraypanel/panel/internal/logging"
	"github.com/xraypanel/panel/internal/nodegrpc"
	"github.com/xraypanel/panel/internal/postgres"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
	"github.com/xraypanel/panel/internal/ratelimit"
	"github.com/xraypanel/panel/internal/service"
	"github.com/xraypanel/panel/internal/worker"
)

// Build metadata, set with -ldflags at release time.
var (
	version = "dev"
	commit  = "none"
)

const usage = `panel - Xray control plane

Usage:
  panel serve                      Run the HTTP server (default)
  panel migrate                    Apply pending database migrations
  panel migrate-status             Show which migrations are applied
  panel admin create <user> [role] Create an administrator, password read from stdin
  panel admin list                 List administrators
  panel admin reset-2fa <user>     Clear a lost second factor and revoke sessions
  panel version                    Print build information

Configuration is read from the environment; see .env.example.

The password for "admin create" is read from standard input rather than taken as an
argument, so it does not land in shell history or in the process list:

  printf '%s' 'correct horse battery staple' | panel admin create root superadmin
`

// printUsage writes the help text. It bypasses the fmt.Print family because the
// text contains a literal %s in a shell example, which vet reads as a stray
// formatting directive.
func printUsage() {
	_, _ = os.Stdout.WriteString(usage)
}

func main() {
	if err := run(); err != nil {
		// The logger may not exist yet when configuration itself is the problem,
		// so the last-resort report goes straight to stderr.
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	args := os.Args[1:]
	command := "serve"
	if len(args) > 0 {
		command = args[0]
		args = args[1:]
	}

	switch command {
	case "version":
		fmt.Printf("panel %s (commit %s)\n", version, commit)
		return nil
	case "help", "-h", "--help":
		printUsage()
		return nil
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := logging.New(os.Stdout, logging.Options{
		Level:     cfg.Log.Level,
		Format:    cfg.Log.Format,
		AddSource: !cfg.IsProd(),
	})

	// Signals are handled for every long-running command, so a migration waiting on
	// a lock can still be interrupted cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch command {
	case "serve":
		return serve(ctx, cfg, logger)

	case "migrate":
		logger.InfoContext(ctx, "applying migrations",
			slog.String("database", logging.RedactDSN(cfg.DB.DSN)))
		if err := postgres.Migrate(ctx, cfg.DB.DSN); err != nil {
			return err
		}
		logger.InfoContext(ctx, "migrations applied")
		return nil

	case "migrate-status":
		return postgres.MigrationStatus(ctx, cfg.DB.DSN)

	case "admin":
		return adminCommand(ctx, cfg, logger, args)

	default:
		printUsage()
		return fmt.Errorf("unknown command %q", command)
	}
}

// app holds the wired-up dependencies shared by serve and the CLI commands.
type app struct {
	pool    *pgxpool.Pool
	auth    *auth.Service
	service *service.Service
}

func (a *app) close() {
	if a.pool != nil {
		a.pool.Close()
	}
}

// build connects to the database and assembles the services.
func build(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*app, error) {
	pool, err := postgres.Connect(ctx, postgres.PoolConfig{
		DSN:             cfg.DB.DSN,
		MaxConns:        cfg.DB.MaxConns,
		MinConns:        cfg.DB.MinConns,
		ConnMaxLifetime: cfg.DB.ConnMaxLifetime,
		ConnMaxIdleTime: cfg.DB.ConnMaxIdleTime,
		ConnectTimeout:  cfg.DB.ConnectTimeout,
	})
	if err != nil {
		return nil, err
	}

	// Refuse to run against a schema the binary was not written for. Operating on
	// an older schema corrupts data in ways far harder to notice than a failed start.
	pending, err := postgres.PendingMigrations(ctx, cfg.DB.DSN)
	if err != nil {
		pool.Close()
		return nil, err
	}
	if pending > 0 {
		pool.Close()
		return nil, fmt.Errorf("database has %d pending migration(s); run `panel migrate` first", pending)
	}

	cipher, err := crypto.NewCipher(cfg.SecretKey)
	if err != nil {
		pool.Close()
		return nil, err
	}

	signer, err := auth.NewTokenSigner(cfg.SecretKey, cfg.Auth.AccessTTL)
	if err != nil {
		pool.Close()
		return nil, err
	}

	authSvc, err := auth.NewService(pool, dbgen.New(pool), signer, cipher, logger, auth.Config{
		RefreshTTL:        cfg.Auth.RefreshTTL,
		LoginMaxAttempts:  cfg.Auth.LoginMaxAttempts,
		LoginWindow:       cfg.Auth.LoginWindow,
		LoginLockout:      cfg.Auth.LoginLockout,
		MinPasswordLength: config.MinPasswordLength,
		TOTPIssuer:        cfg.TOTPIssuer,
		Argon:             crypto.DefaultArgon2Params(),
	})
	if err != nil {
		pool.Close()
		return nil, err
	}

	resourceSvc := service.New(pool, dbgen.New(pool), cipher, logger, nil, service.Config{
		SubscriptionUpdateHours: cfg.Subscription.UpdateHours,
		ProfileTitle:            cfg.Subscription.ProfileTitle,
		EnrollmentTTL:           cfg.GRPC.EnrollmentTTL,
		BillingLocation:         cfg.BillingLocation,
	})

	return &app{pool: pool, auth: authSvc, service: resourceSvc}, nil
}

func serve(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	logger.InfoContext(ctx, "starting panel",
		slog.String("version", version),
		slog.String("commit", commit),
		slog.String("env", cfg.Env),
		slog.String("database", logging.RedactDSN(cfg.DB.DSN)),
		slog.String("billing_timezone", cfg.BillingLocation.String()),
	)

	application, err := build(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer application.close()

	// Behind a reverse proxy with no trusted proxies configured, every request appears to
	// come from the proxy: the subscription limit then throttles all clients as one, and
	// the audit trail records the proxy's address. Not an error, since a panel exposed
	// directly is a legitimate setup, but in production it is almost always a mistake.
	if cfg.IsProd() && len(cfg.HTTP.TrustedProxies) == 0 {
		logger.WarnContext(ctx, "HTTP_TRUSTED_PROXIES is empty; behind a reverse proxy every "+
			"client will share one address for rate limiting and audit")
	}

	if cfg.Bootstrap.Enabled() {
		created, err := application.auth.EnsureBootstrapAdmin(ctx,
			cfg.Bootstrap.AdminUsername, cfg.Bootstrap.AdminPassword)
		if err != nil {
			return fmt.Errorf("bootstrap administrator: %w", err)
		}
		if !created {
			logger.InfoContext(ctx, "bootstrap administrator skipped; one already exists")
		}
	}

	// A node's status means "a control stream is open to this process", and this
	// process has just started, so any row still claiming otherwise is stale.
	if reset, err := application.service.ResetNodeConnectionState(ctx); err != nil {
		return fmt.Errorf("reset node connection state: %w", err)
	} else if reset > 0 {
		logger.InfoContext(ctx, "cleared stale node connection state",
			slog.Int64("nodes", reset))
	}

	nodeServer, err := nodegrpc.New(ctx, application.service, logger, nodegrpc.Config{
		HeartbeatInterval: cfg.GRPC.HeartbeatInterval,
		HeartbeatTimeout:  cfg.GRPC.HeartbeatTimeout,
		ExtraServerNames:  cfg.GRPC.ExtraServerNames,
	})
	if err != nil {
		return err
	}

	var listenConfig net.ListenConfig
	grpcListener, err := listenConfig.Listen(ctx, "tcp", cfg.GRPC.Addr)
	if err != nil {
		return fmt.Errorf("listen for nodes on %s: %w", cfg.GRPC.Addr, err)
	}

	handler := httpapi.NewRouter(httpapi.Deps{
		Logger:         logger,
		DB:             application.pool,
		Auth:           application.auth,
		Service:        application.service,
		Pool:           application.pool,
		Nodes:          nodeServer.Registry(),
		Version:        version,
		TrustedProxies: cfg.HTTP.TrustedProxies,
		SecureCookies:  cfg.Auth.SecureCookies,
		RefreshTTL:     cfg.Auth.RefreshTTL,
		LoginLockout:   cfg.Auth.LoginLockout,
		SubscriptionLimiter: ratelimit.New(
			cfg.Subscription.RatePerMinute, cfg.Subscription.RateBurst),
	})

	server := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           handler,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		ReadHeaderTimeout: cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}

	// Housekeeping for the accounting tables: the daily rollup, next month's partitions,
	// and dropping what has aged out. It runs in this process rather than as a cron job so
	// that deploying the panel deploys it too — a rollup nobody scheduled is a chart that
	// is silently empty.
	maintenance, err := worker.NewTraffic(application.pool, logger, worker.Config{
		Interval:        cfg.Traffic.MaintenanceInterval,
		RecordRetention: cfg.Traffic.RecordRetention,
		BatchRetention:  cfg.Traffic.BatchRetention,
		PartitionsAhead: cfg.Traffic.PartitionsAhead,
	})
	if err != nil {
		return err
	}

	// Enforcement is what gives a traffic limit or an expiry date any meaning: it switches
	// users off, and the nodes then drop them from the running core.
	enforcement, err := worker.NewEnforcement(application.service, logger, cfg.Enforcement.Interval)
	if err != nil {
		return err
	}

	deliveries, err := worker.NewWebhooks(application.pool, application.service, logger, worker.WebhookConfig{
		Interval:    cfg.Webhooks.Interval,
		Timeout:     cfg.Webhooks.Timeout,
		MaxAttempts: cfg.Webhooks.MaxAttempts,
		Retention:   cfg.Webhooks.Retention,
	})
	if err != nil {
		return err
	}

	workerCtx, stopWorkers := context.WithCancel(ctx)
	defer stopWorkers()

	var workers sync.WaitGroup
	for _, run := range []func(context.Context){maintenance.Run, enforcement.Run, deliveries.Run} {
		workers.Go(func() { run(workerCtx) })
	}
	workersDone := make(chan struct{})
	go func() {
		workers.Wait()
		close(workersDone)
	}()

	// Buffered for both servers: whichever fails first must not block writing its
	// error while the other is still running.
	serverErr := make(chan error, 2)

	go func() {
		logger.InfoContext(ctx, "http server listening", slog.String("addr", cfg.HTTP.Addr))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- fmt.Errorf("http server: %w", err)
			return
		}
		serverErr <- nil
	}()

	go func() {
		logger.InfoContext(ctx, "node control server listening",
			slog.String("addr", cfg.GRPC.Addr))
		if err := nodeServer.Serve(grpcListener); err != nil {
			serverErr <- fmt.Errorf("node control server: %w", err)
			return
		}
		serverErr <- nil
	}()

	select {
	case err := <-serverErr:
		// One of the two stopped on its own. Bring the other down rather than leaving
		// half a panel running, which is harder to diagnose than a clean exit.
		nodeServer.Stop()
		_ = server.Close()
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining connections",
			slog.Duration("timeout", cfg.HTTP.ShutdownTimeout))
	}

	// A fresh context: the signal already cancelled the one above, and shutdown
	// needs its own budget to drain in-flight requests.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancel()

	// The node streams are ended first. They are long-lived by design, so a graceful
	// stop that waits for them to finish on their own would wait for ever; and a node
	// whose stream closes reconnects, which is the behaviour a restart wants.
	nodeStopped := make(chan struct{})
	go func() {
		nodeServer.GracefulStop()
		close(nodeStopped)
	}()

	httpErr := server.Shutdown(shutdownCtx)

	select {
	case <-nodeStopped:
	case <-shutdownCtx.Done():
		logger.Warn("node streams did not end within the shutdown budget; stopping them")
		nodeServer.Stop()
	}

	// The housekeeping is stopped last and waited for: a pass interrupted halfway is safe
	// to repeat, but killing it while it holds a transaction open would leave the database
	// to roll it back on its own time.
	stopWorkers()
	select {
	case <-workersDone:
	case <-shutdownCtx.Done():
		logger.Warn("the maintenance worker did not stop within the shutdown budget")
	}

	if httpErr != nil {
		return fmt.Errorf("http server shutdown: %w", httpErr)
	}

	logger.Info("shutdown complete")
	return nil
}

func adminCommand(ctx context.Context, cfg *config.Config, logger *slog.Logger, args []string) error {
	if len(args) == 0 {
		printUsage()
		return errors.New("admin: expected a subcommand")
	}

	application, err := build(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer application.close()

	switch args[0] {
	case "create":
		if len(args) < 2 {
			return errors.New("admin create: expected a username")
		}
		role := auth.RoleSuperadmin
		if len(args) > 2 {
			role = args[2]
		}

		password, err := readPasswordFromStdin()
		if err != nil {
			return err
		}

		admin, err := application.auth.CreateAdmin(ctx, auth.CreateAdminInput{
			Username: args[1],
			Password: password,
			Role:     role,
		})
		if err != nil {
			return err
		}
		fmt.Printf("created administrator %q with role %s\n", admin.Username, admin.Role)
		return nil

	case "list":
		admins, err := application.auth.ListAdmins(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "USERNAME\tROLE\tACTIVE\t2FA\tLAST LOGIN")
		for _, a := range admins {
			lastLogin := "never"
			if a.LastLoginAt != nil {
				lastLogin = a.LastLoginAt.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%t\t%t\t%s\n",
				a.Username, a.Role, a.IsActive, a.TotpEnabled, lastLogin)
		}
		return tw.Flush()

	case "reset-2fa":
		if len(args) < 2 {
			return errors.New("admin reset-2fa: expected a username")
		}
		if err := application.auth.ResetTOTPByUsername(ctx, args[1]); err != nil {
			return err
		}
		fmt.Printf("cleared two-factor authentication for %q and revoked its sessions\n", args[1])
		fmt.Println("the administrator can sign in with their password alone and should enrol again")
		return nil

	default:
		return fmt.Errorf("admin: unknown subcommand %q", args[0])
	}
}

// readPasswordFromStdin reads a password from standard input.
//
// Stdin rather than an argument, because an argument is visible in the process list
// to every user on the machine and is kept in shell history. There is no
// terminal-echo handling: the intended use is a pipe, and adding a dependency to
// turn off echo would matter only for the interactive case this deliberately does
// not encourage.
func readPasswordFromStdin() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read password from stdin: %w", err)
	}

	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return "", errors.New("password read from stdin was empty")
	}
	return password, nil
}
