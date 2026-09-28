package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// The supervisor is entirely about a real child process, so these tests run one. The
// stand-in under testdata is a real binary that can be told to misbehave: reject a
// configuration, refuse to start, never listen, or die on its own. Mocking the process
// would leave the interesting half — waiting, noticing, killing, rolling back —
// untested.

var (
	fakeOnce     sync.Once
	fakePath     string
	fakeBuildErr error
)

// fakeXray builds the stand-in once per test binary.
func fakeXray(t *testing.T) string {
	t.Helper()

	fakeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fakexray-*")
		if err != nil {
			fakeBuildErr = err
			return
		}

		name := "fakexray"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		fakePath = filepath.Join(dir, name)

		build := exec.Command("go", "build", "-o", fakePath, "./testdata/fakexray")
		if output, err := build.CombinedOutput(); err != nil {
			fakeBuildErr = fmt.Errorf("%w: %s", err, output)
		}
	})

	if fakeBuildErr != nil {
		t.Fatalf("build the fake xray: %v", fakeBuildErr)
	}
	return fakePath
}

func newSupervisor(t *testing.T) (*Supervisor, string) {
	t.Helper()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	supervisor, err := New(Config{
		Binary:       fakeXray(t),
		ConfigPath:   configPath,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReadyTimeout: 10 * time.Second,
		StopTimeout:  2 * time.Second,
		RestartMin:   50 * time.Millisecond,
		RestartMax:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = supervisor.Close(context.Background()) })

	return supervisor, configPath
}

// freePort asks the operating system for a port nobody is using, so two tests running
// side by side do not fight over one.
func freePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// configFor builds a configuration shaped like the generator's output, with whatever
// misbehaviour a test needs mixed in.
func configFor(t *testing.T, port int, extra map[string]any) []byte {
	t.Helper()

	document := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{
			map[string]any{
				"tag": "api", "listen": "127.0.0.1", "port": port,
				"protocol": "dokodemo-door",
			},
		},
	}
	for key, value := range extra {
		document[key] = value
	}

	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return encoded
}

func TestApplyStartsTheCoreAndWaitsForIt(t *testing.T) {
	supervisor, configPath := newSupervisor(t)
	port := freePort(t)

	if err := supervisor.Apply(t.Context(), configFor(t, port, nil)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if !supervisor.Running() {
		t.Error("the core is not running after Apply returned")
	}

	// Apply returning means the core is serving, not merely spawned. That distinction is
	// what lets the agent report a version as applied without lying.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("the api port is not accepting connections: %v", err)
	}
	_ = conn.Close()

	written, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read the written config: %v", err)
	}
	if !strings.Contains(string(written), `"api"`) {
		t.Error("the configuration on disk is not the one applied")
	}

	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if supervisor.Running() {
		t.Error("the core is still running after Stop")
	}
}

// A configuration Xray rejects must never replace one that works. Otherwise a typo in
// the panel takes the node down on the next reboot, long after anyone connects the two.
func TestApplyLeavesAWorkingConfigurationInPlaceWhenValidationFails(t *testing.T) {
	supervisor, configPath := newSupervisor(t)
	port := freePort(t)

	good := configFor(t, port, nil)
	if err := supervisor.Apply(t.Context(), good); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	bad := configFor(t, port, map[string]any{"fake_reject": true})
	err := supervisor.Apply(t.Context(), bad)
	if err == nil {
		t.Fatal("a configuration the core rejects was applied")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("unexpected failure: %v", err)
	}

	onDisk, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatalf("read config: %v", readErr)
	}
	if strings.Contains(string(onDisk), "fake_reject") {
		t.Error("the rejected configuration was written to disk anyway")
	}
	if !supervisor.Running() {
		t.Error("the running core was disturbed by a configuration that never applied")
	}
}

// The case validation cannot catch: a configuration the core accepts on paper and then
// will not start on. Without a rollback the node stays dead until somebody notices.
func TestApplyRollsBackAConfigurationThatWillNotStart(t *testing.T) {
	supervisor, configPath := newSupervisor(t)
	port := freePort(t)

	good := configFor(t, port, nil)
	if err := supervisor.Apply(t.Context(), good); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Passes `run -test`, dies on `run`.
	unstartable := configFor(t, port, map[string]any{"fake_crash": true})
	err := supervisor.Apply(t.Context(), unstartable)
	if err == nil {
		t.Fatal("a configuration that cannot start was reported as applied")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("the failure does not say it rolled back: %v", err)
	}

	onDisk, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatalf("read config: %v", readErr)
	}
	if strings.Contains(string(onDisk), "fake_crash") {
		t.Error("the unstartable configuration was left on disk")
	}

	// And the node is serving again on the configuration that worked.
	if !supervisor.Running() {
		t.Fatal("the core is not running after the rollback")
	}
	conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if dialErr != nil {
		t.Fatalf("the rolled-back core is not serving: %v", dialErr)
	}
	_ = conn.Close()
}

// With nothing to roll back to, the failure is simply reported. Inventing a
// configuration would be the agent deciding what the node runs, which is the panel's
// job (ADR-003).
func TestApplyReportsFailureWhenThereIsNothingToRollBackTo(t *testing.T) {
	supervisor, _ := newSupervisor(t)

	err := supervisor.Apply(t.Context(), configFor(t, freePort(t), map[string]any{"fake_crash": true}))
	if err == nil {
		t.Fatal("Apply succeeded on a core that cannot start")
	}
	if strings.Contains(err.Error(), "rolled back") {
		t.Errorf("claimed a rollback with nothing to roll back to: %v", err)
	}
	if supervisor.Running() {
		t.Error("the supervisor thinks a core that never started is running")
	}
}

// A core that starts and never listens is not serving anyone. Reporting it as applied
// would tell the panel a node is healthy while every user's connection fails.
func TestApplyFailsWhenTheCoreNeverListens(t *testing.T) {
	dir := t.TempDir()
	supervisor, err := New(Config{
		Binary:       fakeXray(t),
		ConfigPath:   filepath.Join(dir, "config.json"),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReadyTimeout: 700 * time.Millisecond,
		StopTimeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer supervisor.Close(context.Background())

	err = supervisor.Apply(t.Context(), configFor(t, freePort(t), map[string]any{"fake_no_listen": true}))
	if err == nil {
		t.Fatal("a core that never listened was reported as applied")
	}
	if !strings.Contains(err.Error(), "did not accept connections") {
		t.Errorf("unexpected failure: %v", err)
	}
}

// The supervising part: a core that dies on its own comes back without anybody asking.
func TestCoreThatDiesIsRestarted(t *testing.T) {
	supervisor, _ := newSupervisor(t)
	port := freePort(t)

	// Serves, then exits by itself shortly after.
	if err := supervisor.Apply(t.Context(), configFor(t, port, map[string]any{
		"fake_exit_after_ms": 300,
	})); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// It has to be seen down, and then seen back up on its own.
	waitFor(t, "the core to die", 5*time.Second, func() bool { return !supervisor.Running() })
	waitFor(t, "the core to be restarted", 10*time.Second, func() bool { return supervisor.Running() })

	state := supervisor.State()
	if state.Restarts == 0 {
		t.Error("the restart was not counted, so the panel would never see a flapping core")
	}
	if state.LastError == "" {
		t.Error("no reason recorded for the exit")
	}
}

// Stop means stop. A supervisor that restarts a core it was told to shut down would
// fight the panel, and on shutdown would keep the container alive.
func TestStopPreventsFurtherRestarts(t *testing.T) {
	supervisor, _ := newSupervisor(t)
	port := freePort(t)

	if err := supervisor.Apply(t.Context(), configFor(t, port, nil)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Long enough for a restart to have happened if one were coming.
	time.Sleep(600 * time.Millisecond)

	if supervisor.Running() {
		t.Error("the core came back after being told to stop")
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Error("something is still listening on the api port")
	}
}

func TestStopOnANeverStartedSupervisorIsHarmless(t *testing.T) {
	supervisor, _ := newSupervisor(t)

	if err := supervisor.Stop(t.Context()); err != nil {
		t.Errorf("Stop with no core running returned %v", err)
	}
	// And a later Apply still works, which it would not if stopping had left the
	// supervisor believing a stop was in progress.
	if err := supervisor.Apply(t.Context(), configFor(t, freePort(t), nil)); err != nil {
		t.Errorf("Apply after a no-op Stop: %v", err)
	}
}

func TestVersionIsReadFromTheBinary(t *testing.T) {
	supervisor, _ := newSupervisor(t)

	// Readable before anything has started, which is when an operator most wants to
	// know which core is installed.
	if got := supervisor.Version(t.Context()); got != "26.3.27" {
		t.Errorf("Version returned %q, want 26.3.27", got)
	}
}

func TestVersionParsing(t *testing.T) {
	tests := map[string]string{
		"Xray 26.3.27 (Xray, Penetrates Everything.) Custom\nA unified platform.": "26.3.27",
		"Xray 1.8.4": "1.8.4",
		// Not Xray's shape, so it is reported as printed rather than guessed at: what
		// the binary said is more use to an operator than a field picked out of a
		// format nobody recognises.
		"weird output": "weird output",
		"":             "",
	}

	for output, want := range tests {
		if got := parseVersion(output); got != want {
			t.Errorf("parseVersion(%q) = %q, want %q", output, got, want)
		}
	}
}

// The agent has to reach the API port that is actually in the configuration, not the one
// it assumes: a config patch can move it, and then every user-add would go nowhere.
func TestAPIEndpointIsReadFromTheConfiguration(t *testing.T) {
	endpoint, ok := APIEndpoint([]byte(`{"inbounds":[
		{"tag":"vless","listen":"0.0.0.0","port":443},
		{"tag":"api","listen":"127.0.0.1","port":10085}]}`))
	if !ok || endpoint != "127.0.0.1:10085" {
		t.Errorf("APIEndpoint returned %q, %v", endpoint, ok)
	}

	// A moved port has to be followed.
	endpoint, ok = APIEndpoint([]byte(`{"inbounds":[{"tag":"api","listen":"127.0.0.1","port":21085}]}`))
	if !ok || endpoint != "127.0.0.1:21085" {
		t.Errorf("APIEndpoint returned %q, %v", endpoint, ok)
	}

	// A missing listen address means loopback, which is what the generator relies on.
	endpoint, ok = APIEndpoint([]byte(`{"inbounds":[{"tag":"api","port":10085}]}`))
	if !ok || endpoint != "127.0.0.1:10085" {
		t.Errorf("APIEndpoint returned %q, %v", endpoint, ok)
	}

	for _, input := range []string{
		`{"inbounds":[{"tag":"vless","port":443}]}`,
		`{"inbounds":[]}`,
		`not json`,
		`{}`,
	} {
		if _, ok := APIEndpoint([]byte(input)); ok {
			t.Errorf("APIEndpoint found an endpoint in %q", input)
		}
	}
}

func TestApplyRejectsAnEmptyConfiguration(t *testing.T) {
	supervisor, _ := newSupervisor(t)

	if err := supervisor.Apply(t.Context(), nil); err == nil {
		t.Error("an empty configuration was applied")
	}
}

func TestNewValidatesItsConfiguration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()

	cases := map[string]Config{
		"no binary": {ConfigPath: filepath.Join(dir, "c.json"), Logger: logger},
		"no path":   {Binary: "xray", Logger: logger},
		"no logger": {Binary: "xray", ConfigPath: filepath.Join(dir, "c.json")},
	}

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Error("New accepted an unusable configuration")
			}
		})
	}
}

// Backoff has to grow, so a core that cannot start is not a busy loop, and has to stop
// growing, so recovery does not outlast the operator's patience.
func TestBackoffGrowsAndIsCapped(t *testing.T) {
	supervisor := &Supervisor{cfg: Config{RestartMin: time.Second, RestartMax: 8 * time.Second}}

	for restarts, want := range map[int]time.Duration{
		1: time.Second,
		2: 2 * time.Second,
		3: 4 * time.Second,
		4: 8 * time.Second,
		5: 8 * time.Second,
		9: 8 * time.Second,
	} {
		if got := supervisor.backoff(restarts); got != want {
			t.Errorf("backoff(%d) = %s, want %s", restarts, got, want)
		}
	}
}

// A truncated config.json is worse than a stale one: the node comes back from a reboot
// with something the core cannot parse.
func TestWriteFileAtomicReplacesWithoutTruncating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	if err := writeFileAtomic(path, []byte("first")); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	if err := writeFileAtomic(path, []byte("second")); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "second" {
		t.Errorf("file holds %q, want second", data)
	}

	// No temporary files left behind: the data directory is a volume an operator reads.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Errorf("directory holds %v, want only config.json", names)
	}
}

// waitFor polls until the condition holds.
func waitFor(t *testing.T, what string, budget time.Duration, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
