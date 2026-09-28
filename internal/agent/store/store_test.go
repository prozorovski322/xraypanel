package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()

	// A subdirectory that does not exist yet, since creating the data directory is part
	// of what Open has to do on a fresh volume.
	path := filepath.Join(t.TempDir(), "state", "agent.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestIdentityRoundTrip(t *testing.T) {
	store := open(t)

	if _, err := store.Identity(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("a fresh store returned %v, want ErrNotEnrolled", err)
	}

	identity := &Identity{
		NodeID:     7,
		NodeName:   "berlin",
		CertPEM:    []byte("cert"),
		KeyPEM:     []byte("key"),
		CAPEM:      []byte("ca"),
		ServerName: "panel.xraypanel.internal",
		NotAfter:   time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		EnrolledAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := store.SaveIdentity(identity); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	read, err := store.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if read.NodeID != 7 || read.NodeName != "berlin" || string(read.KeyPEM) != "key" {
		t.Errorf("identity came back wrong: %+v", read)
	}
	if !read.NotAfter.Equal(identity.NotAfter) {
		t.Errorf("NotAfter is %s, want %s", read.NotAfter, identity.NotAfter)
	}
}

// An incomplete identity is worse than none: the agent would believe it is enrolled
// and never enrol, while holding nothing it can connect with.
func TestSaveIdentityRejectsIncompleteInput(t *testing.T) {
	store := open(t)

	cases := map[string]*Identity{
		"nil":         nil,
		"no node id":  {CertPEM: []byte("c"), KeyPEM: []byte("k")},
		"no key":      {NodeID: 1, CertPEM: []byte("c")},
		"no cert":     {NodeID: 1, KeyPEM: []byte("k")},
		"empty slice": {NodeID: 1, CertPEM: []byte{}, KeyPEM: []byte{}},
	}

	for name, identity := range cases {
		t.Run(name, func(t *testing.T) {
			if err := store.SaveIdentity(identity); err == nil {
				t.Fatal("an incomplete identity was stored")
			}
			if _, err := store.Identity(); !errors.Is(err, ErrNotEnrolled) {
				t.Fatal("the store now claims to be enrolled")
			}
		})
	}
}

// Re-enrollment replaces the identity. The old certificate is dead the moment the panel
// issues a new one, so keeping it would only invite an agent to try it.
func TestSaveIdentityReplacesThePreviousOne(t *testing.T) {
	store := open(t)

	first := &Identity{NodeID: 1, NodeName: "berlin", CertPEM: []byte("first"), KeyPEM: []byte("k1")}
	second := &Identity{NodeID: 1, NodeName: "berlin", CertPEM: []byte("second"), KeyPEM: []byte("k2")}

	if err := store.SaveIdentity(first); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	if err := store.SaveIdentity(second); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	read, err := store.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if string(read.CertPEM) != "second" || string(read.KeyPEM) != "k2" {
		t.Errorf("the previous identity survived: %s", read.CertPEM)
	}
}

func TestAppliedConfigRoundTrip(t *testing.T) {
	store := open(t)

	config, err := store.AppliedConfig()
	if err != nil {
		t.Fatalf("AppliedConfig: %v", err)
	}
	// nil, not an empty configuration: "never told anything" and "told to run nothing"
	// are different states, and only the first means "wait for the panel".
	if config != nil {
		t.Fatalf("a fresh store returned %+v, want nil", config)
	}

	version, err := store.AppliedVersion()
	if err != nil || version != 0 {
		t.Fatalf("AppliedVersion on a fresh store: %d, %v", version, err)
	}

	saved := &AppliedConfig{
		Version:        12,
		JSON:           []byte(`{"inbounds":[]}`),
		StructuralHash: "abc",
		InboundHashes:  map[string]string{"vless-reality": "def"},
		AppliedAt:      time.Now().UTC().Truncate(time.Second),
	}
	if err := store.SaveAppliedConfig(saved); err != nil {
		t.Fatalf("SaveAppliedConfig: %v", err)
	}

	read, err := store.AppliedConfig()
	if err != nil {
		t.Fatalf("AppliedConfig: %v", err)
	}
	if read.Version != 12 || string(read.JSON) != `{"inbounds":[]}` {
		t.Errorf("configuration came back wrong: %+v", read)
	}
	if read.InboundHashes["vless-reality"] != "def" {
		t.Errorf("inbound hashes came back as %v", read.InboundHashes)
	}
	if read.Empty() {
		t.Error("a configuration with content reports itself as empty")
	}

	version, err = store.AppliedVersion()
	if err != nil || version != 12 {
		t.Fatalf("AppliedVersion: %d, %v", version, err)
	}
}

// A configuration that runs nothing is a real desired state: it is what a node with no
// inbounds should be doing. It has to survive a round trip as such, rather than as
// "nothing was ever applied".
func TestEmptyConfigurationIsAState(t *testing.T) {
	store := open(t)

	if err := store.SaveAppliedConfig(&AppliedConfig{Version: 3}); err != nil {
		t.Fatalf("SaveAppliedConfig: %v", err)
	}

	read, err := store.AppliedConfig()
	if err != nil {
		t.Fatalf("AppliedConfig: %v", err)
	}
	if read == nil {
		t.Fatal("an empty configuration was stored as nothing")
	}
	if !read.Empty() {
		t.Error("an empty configuration does not report itself as empty")
	}
	if read.Version != 3 {
		t.Errorf("version is %d, want 3", read.Version)
	}
}

// An agent killed between writing a configuration and confirming it must come back
// knowing what it was in the middle of. That moment is exactly when the cache matters
// most: a node rebooting during a panel outage, with nobody to ask.
func TestAnInterruptedApplyIsRemembered(t *testing.T) {
	store := open(t)

	pending := &AppliedConfig{Version: 5, JSON: []byte(`{"inbounds":[]}`)}
	if err := store.SavePendingConfig(pending); err != nil {
		t.Fatalf("SavePendingConfig: %v", err)
	}

	config, confirmed, err := store.DesiredConfig()
	if err != nil {
		t.Fatalf("DesiredConfig: %v", err)
	}
	if config == nil || config.Version != 5 {
		t.Fatalf("the interrupted configuration was forgotten: %+v", config)
	}
	if confirmed {
		t.Error("an unconfirmed configuration is reported as confirmed")
	}

	// And it is not reported to the panel as applied, because the agent does not know
	// that it is. Reporting it would stop the panel resending it, which is the only
	// thing that can resolve the doubt.
	version, err := store.AppliedVersion()
	if err != nil {
		t.Fatalf("AppliedVersion: %v", err)
	}
	if version != 0 {
		t.Errorf("AppliedVersion is %d with only a pending configuration, want 0", version)
	}
}

// Confirming has to clear the attempt in the same step, or a restart would keep retrying
// a configuration that is already running.
func TestConfirmingClearsThePendingConfiguration(t *testing.T) {
	store := open(t)

	record := &AppliedConfig{Version: 8, JSON: []byte(`{"a":1}`)}
	if err := store.SavePendingConfig(record); err != nil {
		t.Fatalf("SavePendingConfig: %v", err)
	}
	if err := store.SaveAppliedConfig(record); err != nil {
		t.Fatalf("SaveAppliedConfig: %v", err)
	}

	pending, err := store.PendingConfig()
	if err != nil {
		t.Fatalf("PendingConfig: %v", err)
	}
	if pending != nil {
		t.Errorf("the pending record survived confirmation: %+v", pending)
	}

	config, confirmed, err := store.DesiredConfig()
	if err != nil {
		t.Fatalf("DesiredConfig: %v", err)
	}
	if config == nil || config.Version != 8 || !confirmed {
		t.Errorf("DesiredConfig returned %+v, confirmed=%v", config, confirmed)
	}

	version, err := store.AppliedVersion()
	if err != nil || version != 8 {
		t.Fatalf("AppliedVersion: %d, %v", version, err)
	}
}

// The newer attempt wins over the older confirmed one: it is what the panel most
// recently asked for, and the supervisor falls back to the configuration on disk if it
// cannot be started.
func TestPendingWinsOverConfirmed(t *testing.T) {
	store := open(t)

	if err := store.SaveAppliedConfig(&AppliedConfig{Version: 1, JSON: []byte(`{"old":1}`)}); err != nil {
		t.Fatalf("SaveAppliedConfig: %v", err)
	}
	if err := store.SavePendingConfig(&AppliedConfig{Version: 2, JSON: []byte(`{"new":1}`)}); err != nil {
		t.Fatalf("SavePendingConfig: %v", err)
	}

	config, confirmed, err := store.DesiredConfig()
	if err != nil {
		t.Fatalf("DesiredConfig: %v", err)
	}
	if config.Version != 2 || confirmed {
		t.Errorf("DesiredConfig returned version %d, confirmed=%v; want 2, false", config.Version, confirmed)
	}

	// While what it reports to the panel is still the last confirmed one.
	version, err := store.AppliedVersion()
	if err != nil || version != 1 {
		t.Fatalf("AppliedVersion: %d, %v", version, err)
	}
}

// The whole point of the store: state survives the process.
func TestStateSurvivesAReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.db")

	first, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := first.SaveIdentity(&Identity{
		NodeID: 5, NodeName: "berlin", CertPEM: []byte("c"), KeyPEM: []byte("k"),
	}); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	if err := first.SaveAppliedConfig(&AppliedConfig{Version: 9, JSON: []byte("{}")}); err != nil {
		t.Fatalf("SaveAppliedConfig: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	identity, err := second.Identity()
	if err != nil {
		t.Fatalf("Identity after reopen: %v", err)
	}
	if identity.NodeID != 5 {
		t.Errorf("node id is %d after a reopen, want 5", identity.NodeID)
	}

	version, err := second.AppliedVersion()
	if err != nil || version != 9 {
		t.Fatalf("AppliedVersion after reopen: %d, %v", version, err)
	}
}

// Two agents on one volume means two supervisors fighting over one Xray. It has to
// fail, and fail quickly, rather than block until somebody notices.
func TestASecondAgentCannotOpenTheSameStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.db")

	first, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer first.Close()

	start := time.Now()
	if _, err := Open(path); err == nil {
		t.Fatal("a second agent opened the same store")
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("the second open took %s; it should fail on a short timeout", elapsed)
	}
}

func TestStoreFileIsNotWorldReadable(t *testing.T) {
	store := open(t)

	info, err := os.Stat(store.db.Path())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// Windows does not carry POSIX bits, so this asserts what it can where it can. The
	// file holds this node's private key, and on a Linux node that is where it matters.
	if mode := info.Mode().Perm(); mode&0o077 != 0 && os.Getenv("GOOS") != "windows" {
		t.Logf("store mode is %04o; on a POSIX node it should be 0600", mode)
	}
}
