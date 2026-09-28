// Package supervisor owns the Xray process on a node.
//
// The agent is PID 1 in the node container and Xray is its child, so everything about
// that child's life is decided here: validating a configuration before it replaces a
// working one, starting the core and waiting until it is actually listening, restarting
// it when it dies on its own, and rolling back a configuration that turns out to be
// unstartable.
//
// The rollback is the part worth arguing about. The panel is the only source of truth
// for what a node should run (ADR-003), so a node deciding to run something else looks
// wrong. It is not: a configuration that passes `xray run -test` and then fails to start
// would otherwise leave the node dead until a human noticed. Falling back to the last
// configuration that did start keeps users online and reports the failure upwards, which
// is what a supervisor is for.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Defaults for the knobs a caller usually leaves alone.
const (
	defaultReadyTimeout   = 20 * time.Second
	defaultStopTimeout    = 10 * time.Second
	defaultRestartMin     = time.Second
	defaultRestartMax     = time.Minute
	defaultValidateBudget = 30 * time.Second

	// aliveGrace is how long a started process has to stay alive when there is no API
	// port to probe. A configuration Xray rejects at startup kills it well inside this.
	aliveGrace = 500 * time.Millisecond
)

// ErrNotStarted means an operation needs a running core and there is none.
var ErrNotStarted = errors.New("supervisor: xray is not running")

// Config describes how to run Xray.
type Config struct {
	// Binary is the xray executable.
	Binary string

	// ConfigPath is where the configuration is written. Its directory is created if
	// needed and must be on the node's own volume, so that a restart without the panel
	// still finds it.
	ConfigPath string

	Logger *slog.Logger

	// ReadyTimeout bounds waiting for the core to listen after a start.
	ReadyTimeout time.Duration

	// StopTimeout is how long a polite shutdown gets before the process is killed.
	StopTimeout time.Duration

	// RestartMin and RestartMax bound the delay between crash restarts. The delay
	// grows so that a core which cannot start does not become a busy loop, and is
	// capped so that recovery does not take longer than an operator's patience.
	RestartMin time.Duration
	RestartMax time.Duration
}

// State is what the agent reports about the core.
type State struct {
	Running bool

	// Version is what `xray version` printed, empty if it has not been asked yet.
	Version string

	// Restarts counts unrequested restarts since the agent started. A rising number is
	// a core that keeps dying, which is worth seeing from the panel.
	Restarts int

	// LastError is the reason the core last stopped when it was not asked to.
	LastError string

	StartedAt time.Time
}

// child is one launched process.
//
// done is closed by the watcher after Wait returns, and is the only thing anybody else
// waits on. Polling cmd.ProcessState instead would be a data race with the Wait that
// sets it, which is exactly the kind of bug that shows up once under -race and never
// again in production until it corrupts something.
type child struct {
	cmd        *exec.Cmd
	done       chan struct{}
	generation uint64

	// ready is set once this process has been seen serving. Only a process that got
	// that far is restarted when it dies.
	//
	// Without this distinction a start that fails inside Apply is picked up by the
	// watcher as a crash, and the supervisor begins restarting a core that Apply is at
	// the same moment rolling back — two goroutines starting processes on the same
	// port, which is how it was found. A core that never became ready is the caller's
	// failure to report; a core that was healthy and then died is the supervisor's to
	// bring back.
	ready bool
}

// Supervisor manages one Xray process.
type Supervisor struct {
	cfg Config
	log *slog.Logger

	// life bounds crash restarts. Stop cancels it, so a restart cannot outlive the
	// decision to stop.
	life   context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	cur     *child
	running bool

	// generation increments on every start. A watcher whose generation is stale belongs
	// to a process that has already been replaced, and must not restart anything.
	generation uint64

	stopping  bool
	restarts  int
	lastError string
	startedAt time.Time
	version   string
}

// New builds a supervisor. Nothing is started until Apply is called.
func New(cfg Config) (*Supervisor, error) {
	if strings.TrimSpace(cfg.Binary) == "" {
		return nil, errors.New("supervisor: no xray binary configured")
	}
	if strings.TrimSpace(cfg.ConfigPath) == "" {
		return nil, errors.New("supervisor: no configuration path configured")
	}
	if cfg.Logger == nil {
		return nil, errors.New("supervisor: no logger")
	}
	if cfg.ReadyTimeout <= 0 {
		cfg.ReadyTimeout = defaultReadyTimeout
	}
	if cfg.StopTimeout <= 0 {
		cfg.StopTimeout = defaultStopTimeout
	}
	if cfg.RestartMin <= 0 {
		cfg.RestartMin = defaultRestartMin
	}
	if cfg.RestartMax < cfg.RestartMin {
		cfg.RestartMax = defaultRestartMax
	}

	if err := os.MkdirAll(filepath.Dir(cfg.ConfigPath), 0o700); err != nil {
		return nil, fmt.Errorf("supervisor: create configuration directory: %w", err)
	}

	life, cancel := context.WithCancel(context.Background())

	return &Supervisor{
		cfg:    cfg,
		log:    cfg.Logger,
		life:   life,
		cancel: cancel,
	}, nil
}

// State reports what the core is doing.
func (s *Supervisor) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()

	return State{
		Running:   s.running,
		Version:   s.version,
		Restarts:  s.restarts,
		LastError: s.lastError,
		StartedAt: s.startedAt,
	}
}

// Running reports whether the core is up.
func (s *Supervisor) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Version returns the core's version, asking the binary the first time.
//
// Asked by running the binary rather than read from the running process, because the
// agent has to be able to report it before the core has ever started successfully —
// which is exactly when an operator wants to know which version is installed.
func (s *Supervisor) Version(ctx context.Context) string {
	s.mu.Lock()
	cached := s.version
	s.mu.Unlock()
	if cached != "" {
		return cached
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	output, err := exec.CommandContext(ctx, s.cfg.Binary, "version").CombinedOutput()
	if err != nil {
		s.log.WarnContext(ctx, "could not read the xray version",
			slog.String("binary", s.cfg.Binary), slog.Any("error", err))
		return ""
	}

	version := parseVersion(string(output))
	s.mu.Lock()
	s.version = version
	s.mu.Unlock()
	return version
}

// Apply validates a configuration, writes it, and (re)starts the core.
//
// The order matters. Validation happens on a temporary file, so a configuration Xray
// rejects never replaces the one that works. Only then is the file moved into place, and
// only then is the core restarted.
func (s *Supervisor) Apply(ctx context.Context, configJSON []byte) error {
	if len(configJSON) == 0 {
		return errors.New("supervisor: refusing to apply an empty configuration")
	}

	if err := s.validate(ctx, configJSON); err != nil {
		return err
	}

	previous, hadPrevious := s.readCurrentConfig()

	if err := writeFileAtomic(s.cfg.ConfigPath, configJSON); err != nil {
		return err
	}

	if err := s.restart(ctx, configJSON); err == nil {
		return nil
	} else if !hadPrevious {
		return err
	} else {
		// The configuration passed validation and still would not run. Rather than
		// leave the node dead, go back to what was working and report the failure.
		startErr := err
		s.log.ErrorContext(ctx, "the new configuration would not start; rolling back",
			slog.Any("error", startErr))

		if err := writeFileAtomic(s.cfg.ConfigPath, previous); err != nil {
			return fmt.Errorf("supervisor: %w (and the rollback failed: %v)", startErr, err)
		}
		if err := s.restart(ctx, previous); err != nil {
			return fmt.Errorf("supervisor: %w (and the previous configuration would not restart either: %v)",
				startErr, err)
		}
		return fmt.Errorf("supervisor: rolled back to the previous configuration: %w", startErr)
	}
}

// SwapConfig validates a configuration and puts it on disk without touching the running
// core.
//
// It is the disk half of a runtime reconciliation: the changes themselves go to the core
// over its API, and this is what makes them survive a restart. Written after validation
// and before the API calls, so that a core which dies at any point during the
// reconciliation comes back on the configuration the panel asked for rather than on the
// one it replaced.
func (s *Supervisor) SwapConfig(ctx context.Context, configJSON []byte) error {
	if len(configJSON) == 0 {
		return errors.New("supervisor: refusing to write an empty configuration")
	}
	if err := s.validate(ctx, configJSON); err != nil {
		return err
	}
	return writeFileAtomic(s.cfg.ConfigPath, configJSON)
}

// Endpoint is where the running core's API is listening, read from the configuration on
// disk.
func (s *Supervisor) Endpoint() (string, bool) {
	configJSON, ok := s.readCurrentConfig()
	if !ok {
		return "", false
	}
	return APIEndpoint(configJSON)
}

// Stop shuts the core down and stops supervising it.
//
// After this, a process that exits is not restarted: the caller has said it wants
// nothing running. It is also what an empty desired configuration means.
func (s *Supervisor) Stop(ctx context.Context) error {
	s.mu.Lock()
	s.stopping = true
	current := s.cur
	s.mu.Unlock()

	if current == nil {
		s.mu.Lock()
		s.stopping = false
		s.mu.Unlock()
		return nil
	}

	err := s.terminate(ctx, current)

	s.mu.Lock()
	s.running = false
	s.cur = nil
	s.stopping = false
	s.mu.Unlock()

	return err
}

// Close stops the core and releases the supervisor for good.
func (s *Supervisor) Close(ctx context.Context) error {
	err := s.Stop(ctx)
	s.cancel()
	return err
}

// restart stops any running core and starts one on the current configuration.
func (s *Supervisor) restart(ctx context.Context, configJSON []byte) error {
	if err := s.Stop(ctx); err != nil {
		// Worth knowing, not worth refusing to start over: the old process is gone
		// either way by the time terminate returns.
		s.log.WarnContext(ctx, "stopping the previous core was not clean", slog.Any("error", err))
	}
	return s.start(ctx, configJSON)
}

// start launches the core and waits until it is actually serving.
func (s *Supervisor) start(ctx context.Context, configJSON []byte) error {
	cmd := exec.Command(s.cfg.Binary, "run", "-config", s.cfg.ConfigPath)

	// Inherited rather than captured: the agent is PID 1 in the container, so the
	// core's own log belongs in the container's log where an operator already looks.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("supervisor: start xray: %w", err)
	}

	s.mu.Lock()
	s.generation++
	current := &child{cmd: cmd, done: make(chan struct{}), generation: s.generation}
	s.cur = current
	s.running = true
	s.startedAt = time.Now().UTC()
	s.mu.Unlock()

	go s.watch(current)

	if err := s.waitReady(ctx, configJSON); err != nil {
		// A core that started and is not serving is not running as far as anyone is
		// concerned, so it is stopped rather than left behind. It is never restarted:
		// current.ready was never set.
		_ = s.Stop(ctx)
		return err
	}

	s.mu.Lock()
	current.ready = true
	s.mu.Unlock()

	s.log.InfoContext(ctx, "xray is running",
		slog.Int("pid", cmd.Process.Pid),
		slog.String("config", s.cfg.ConfigPath))
	return nil
}

// watch reaps the child and restarts it when it was not asked to stop.
func (s *Supervisor) watch(current *child) {
	waitErr := current.cmd.Wait()
	// Closed before any state is read by anyone else, so a waiter that sees this
	// channel closed is guaranteed the process is reaped.
	close(current.done)

	s.mu.Lock()
	superseded := s.generation != current.generation
	requested := s.stopping
	wasReady := current.ready
	if !superseded {
		s.running = false
	}
	if !superseded && !requested {
		s.lastError = exitReason(waitErr)
		if wasReady {
			s.restarts++
		}
	}
	restarts := s.restarts
	s.mu.Unlock()

	switch {
	case superseded:
		// This process was already replaced by a newer start; its exit is history.
		return
	case requested:
		return
	case !wasReady:
		// It never served. Whoever called start is reporting this failure and may be
		// rolling back; a restart here would race with that.
		return
	}

	delay := s.backoff(restarts)
	s.log.Warn("xray exited on its own; restarting",
		slog.String("reason", exitReason(waitErr)),
		slog.Int("restarts", restarts),
		slog.Duration("in", delay))

	select {
	case <-time.After(delay):
	case <-s.life.Done():
		return
	}

	configJSON, ok := s.readCurrentConfig()
	if !ok {
		s.log.Error("cannot restart xray: no configuration on disk")
		return
	}

	ctx, cancel := context.WithTimeout(s.life, s.cfg.ReadyTimeout+aliveGrace)
	defer cancel()

	if err := s.start(ctx, configJSON); err != nil {
		s.log.Error("restarting xray failed", slog.Any("error", err))
	}
}

// backoff grows the delay with consecutive failures, capped.
func (s *Supervisor) backoff(restarts int) time.Duration {
	delay := s.cfg.RestartMin
	for i := 1; i < restarts && delay < s.cfg.RestartMax; i++ {
		delay *= 2
	}
	if delay > s.cfg.RestartMax {
		delay = s.cfg.RestartMax
	}
	return delay
}

// waitReady blocks until the core is listening on its API port.
//
// The API port is the right thing to probe: it is the interface the agent itself needs
// in order to add users and read counters, so a core that is not answering there is of
// no use even if it is technically alive. When the configuration has no API inbound —
// which a config patch can do — all that can be checked is that the process stayed up.
func (s *Supervisor) waitReady(ctx context.Context, configJSON []byte) error {
	endpoint, ok := APIEndpoint(configJSON)
	if !ok {
		select {
		case <-time.After(aliveGrace):
		case <-ctx.Done():
			return ctx.Err()
		}
		if !s.Running() {
			return fmt.Errorf("supervisor: xray exited immediately: %s", s.State().LastError)
		}
		return nil
	}

	deadline := time.Now().Add(s.cfg.ReadyTimeout)
	for {
		if !s.Running() {
			return fmt.Errorf("supervisor: xray exited while starting: %s", s.State().LastError)
		}

		conn, err := net.DialTimeout("tcp", endpoint, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("supervisor: xray did not accept connections on %s within %s",
				endpoint, s.cfg.ReadyTimeout)
		}

		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// validate runs the configuration past Xray without starting it.
//
// On a temporary file, so the working configuration is untouched until this passes. This
// is the check that turns "the node stopped answering after a change" into "the change
// was refused".
func (s *Supervisor) validate(ctx context.Context, configJSON []byte) error {
	file, err := os.CreateTemp(filepath.Dir(s.cfg.ConfigPath), "config-*.json")
	if err != nil {
		return fmt.Errorf("supervisor: create temporary configuration: %w", err)
	}
	path := file.Name()
	defer func() { _ = os.Remove(path) }()

	if _, err := file.Write(configJSON); err != nil {
		_ = file.Close()
		return fmt.Errorf("supervisor: write temporary configuration: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("supervisor: close temporary configuration: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, defaultValidateBudget)
	defer cancel()

	output, err := exec.CommandContext(ctx, s.cfg.Binary, "run", "-test", "-config", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("supervisor: xray rejected the configuration: %w: %s",
			err, strings.TrimSpace(string(output)))
	}
	return nil
}

// terminate asks the process to stop, then insists.
func (s *Supervisor) terminate(ctx context.Context, current *child) error {
	if current.cmd.Process == nil {
		return nil
	}

	// Already gone: a core that crashed a moment ago needs no signalling.
	select {
	case <-current.done:
		return nil
	default:
	}

	// Interrupt first so Xray can close its listeners itself. Windows does not
	// implement it, and there the kill below is the only option.
	if err := current.cmd.Process.Signal(os.Interrupt); err != nil {
		s.log.DebugContext(ctx, "interrupting xray is not supported here; killing instead",
			slog.Any("error", err))
		return killAndWait(current)
	}

	select {
	case <-current.done:
		return nil
	case <-time.After(s.cfg.StopTimeout):
		s.log.WarnContext(ctx, "xray did not exit in time; killing it",
			slog.Duration("after", s.cfg.StopTimeout))
		return killAndWait(current)
	}
}

// killAndWait kills the process and waits for the watcher to reap it.
func killAndWait(current *child) error {
	if err := current.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("supervisor: kill xray: %w", err)
	}

	select {
	case <-current.done:
		return nil
	case <-time.After(10 * time.Second):
		// The process is unkillable, which on a node means something outside this
		// program's control. Reported rather than waited on for ever.
		return errors.New("supervisor: xray did not exit after being killed")
	}
}

// readCurrentConfig reads the configuration on disk.
func (s *Supervisor) readCurrentConfig() ([]byte, bool) {
	data, err := os.ReadFile(s.cfg.ConfigPath)
	if err != nil || len(data) == 0 {
		return nil, false
	}
	return data, true
}

// writeFileAtomic replaces a file without ever leaving it half-written.
//
// A truncated config.json is worse than an old one: the node would come back from a
// reboot with a configuration Xray cannot parse, and the last thing the agent did
// before the crash would be the thing that broke it.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("supervisor: create temporary file: %w", err)
	}
	tmp := file.Name()

	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("supervisor: write %s: %w", tmp, err)
	}
	// Flushed before the rename: a rename that lands before the data does leaves an
	// empty file after a power cut.
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("supervisor: flush %s: %w", tmp, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("supervisor: close %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("supervisor: set permissions on %s: %w", tmp, err)
	}

	// Windows refuses to rename onto an existing file, so the target is removed first.
	// That opens a window where the file is missing, which is acceptable here: the
	// running core has already read it, and a node is not restarted mid-apply.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(tmp)
		return fmt.Errorf("supervisor: replace %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("supervisor: rename %s: %w", tmp, err)
	}
	return nil
}

// APIEndpoint finds the local API listener in a configuration.
//
// Read out of the configuration rather than assumed, because a config patch can move it
// and the agent has to reach the port that is actually there.
func APIEndpoint(configJSON []byte) (string, bool) {
	var document struct {
		Inbounds []struct {
			Tag    string `json:"tag"`
			Listen string `json:"listen"`
			Port   int    `json:"port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(configJSON, &document); err != nil {
		return "", false
	}

	for _, inbound := range document.Inbounds {
		if inbound.Tag != "api" || inbound.Port == 0 {
			continue
		}
		host := inbound.Listen
		if host == "" {
			host = "127.0.0.1"
		}
		return net.JoinHostPort(host, fmt.Sprint(inbound.Port)), true
	}
	return "", false
}

// parseVersion pulls the version out of `xray version` output, whose first line is
// "Xray 26.3.27 (Xray, Penetrates Everything.) ...".
//
// Anything that is not that shape is returned verbatim rather than guessed at: the
// version is only ever shown to an operator, and what the binary actually printed is
// more useful to them than a field picked out of an unfamiliar format.
func parseVersion(output string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(output), "\n")
	line = strings.TrimSpace(line)

	fields := strings.Fields(line)
	if len(fields) >= 2 && strings.EqualFold(fields[0], "xray") {
		return fields[1]
	}
	return line
}

// exitReason renders why a process stopped.
func exitReason(err error) string {
	if err == nil {
		return "exited with status 0"
	}
	return err.Error()
}
