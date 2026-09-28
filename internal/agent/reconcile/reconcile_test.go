package reconcile

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/xraypanel/panel/internal/agent/xrayapi"
	"github.com/xraypanel/panel/internal/xray/config"
)

// generate builds a configuration the same way the panel does, so the planner is tested
// against real documents and real hashes rather than against hand-written JSON that
// might not resemble either.
func generate(t *testing.T, spec config.Spec) Snapshot {
	t.Helper()

	generated, err := config.Generate(spec)
	if err != nil {
		t.Fatalf("generate the configuration: %v", err)
	}
	return Snapshot{
		JSON:           generated.JSON,
		StructuralHash: generated.StructuralHash,
		InboundHashes:  generated.InboundHashes,
	}
}

func vlessSpec(clients ...config.Client) config.Spec {
	return config.Spec{
		NodeName: "test",
		Inbounds: []config.Inbound{{
			Tag:        "vless-tcp",
			Protocol:   config.ProtocolVLESS,
			Transport:  config.TransportTCP,
			Security:   config.SecurityNone,
			ListenPort: 8443,
			Clients:    clients,
		}},
	}
}

func user(email, uuid string) config.Client {
	return config.Client{Email: email, UUID: uuid}
}

const (
	uuidA = "11111111-1111-1111-1111-111111111111"
	uuidB = "22222222-2222-2222-2222-222222222222"
	uuidC = "33333333-3333-3333-3333-333333333333"
)

func TestAddingAUserNeedsNoRestart(t *testing.T) {
	before := generate(t, vlessSpec(user("aaaaaaaaaaaa", uuidA)))
	after := generate(t, vlessSpec(user("aaaaaaaaaaaa", uuidA), user("bbbbbbbbbbbb", uuidB)))

	plan, err := Compute(before, after)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}

	if plan.Restart {
		t.Fatalf("adding a user asks for a restart (%s), which drops every connection on the node", plan.Reason)
	}
	if len(plan.AddUsers) != 1 || plan.AddUsers[0].User.Email != "bbbbbbbbbbbb" {
		t.Fatalf("plan adds %v, want exactly the new user", plan.AddUsers)
	}
	if len(plan.RemoveUsers) != 0 || len(plan.RemoveInbounds) != 0 {
		t.Errorf("plan also removes things: %+v", plan)
	}
}

func TestRemovingAUserNeedsNoRestart(t *testing.T) {
	before := generate(t, vlessSpec(user("aaaaaaaaaaaa", uuidA), user("bbbbbbbbbbbb", uuidB)))
	after := generate(t, vlessSpec(user("aaaaaaaaaaaa", uuidA)))

	plan, err := Compute(before, after)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}

	if plan.Restart {
		t.Fatalf("removing a user asks for a restart (%s)", plan.Reason)
	}
	want := []UserRef{{Tag: "vless-tcp", Email: "bbbbbbbbbbbb"}}
	if len(plan.RemoveUsers) != 1 || plan.RemoveUsers[0] != want[0] {
		t.Errorf("plan removes %v, want %v", plan.RemoveUsers, want)
	}
	if len(plan.AddUsers) != 0 {
		t.Errorf("plan also adds %v", plan.AddUsers)
	}
}

// A rotated UUID has to reach the core, and the only way the API offers is to remove the
// user and add them back. The order matters: added first, the core would reject the
// stats key as already present.
func TestRekeyingAUserRemovesThenAdds(t *testing.T) {
	before := generate(t, vlessSpec(user("aaaaaaaaaaaa", uuidA)))
	after := generate(t, vlessSpec(user("aaaaaaaaaaaa", uuidC)))

	plan, err := Compute(before, after)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}

	if plan.Restart {
		t.Fatalf("rotating a uuid asks for a restart (%s)", plan.Reason)
	}
	if len(plan.RemoveUsers) != 1 || plan.RemoveUsers[0].Email != "aaaaaaaaaaaa" {
		t.Errorf("plan removes %v, want the re-keyed user", plan.RemoveUsers)
	}
	if len(plan.AddUsers) != 1 {
		t.Fatalf("plan adds %v, want the re-keyed user", plan.AddUsers)
	}
	account, ok := plan.AddUsers[0].User.Account.(xrayapi.VLESS)
	if !ok {
		t.Fatalf("account is %T, want xrayapi.VLESS", plan.AddUsers[0].User.Account)
	}
	if account.UUID != uuidC {
		t.Errorf("the user is re-added with uuid %s, want the new one", account.UUID)
	}
}

// Changing the flow changes each client entry and nothing else, so it is a credential
// change rather than a new listener.
func TestChangingFlowIsAUserChange(t *testing.T) {
	withFlow := func(flow string) config.Spec {
		spec := config.Spec{
			NodeName: "test",
			Inbounds: []config.Inbound{{
				Tag:        "vless-reality",
				Protocol:   config.ProtocolVLESS,
				Transport:  config.TransportTCP,
				Security:   config.SecurityReality,
				ListenPort: 8443,
				Flow:       flow,
				Reality: &config.Reality{
					PrivateKey:  "sIBDnAaNAoefzIWyxrCPZBKAcJhWJP7xwDqKPwCkwEI",
					ShortIDs:    []string{"0123abcd"},
					Dest:        "www.example.com:443",
					ServerNames: []string{"www.example.com"},
				},
				Clients: []config.Client{user("aaaaaaaaaaaa", uuidA)},
			}},
		}
		return spec
	}

	before := generate(t, withFlow("xtls-rprx-vision"))
	after := generate(t, withFlow(""))

	plan, err := Compute(before, after)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if plan.Restart {
		t.Fatalf("changing the flow asks for a restart (%s)", plan.Reason)
	}
	if len(plan.RemoveUsers) != 1 || len(plan.AddUsers) != 1 {
		t.Errorf("plan is %+v, want the user removed and re-added with the new flow", plan)
	}
}

func TestRemovingAnInboundNeedsNoRestart(t *testing.T) {
	two := config.Spec{
		NodeName: "test",
		Inbounds: []config.Inbound{
			{
				Tag: "vless-tcp", Protocol: config.ProtocolVLESS, Transport: config.TransportTCP,
				Security: config.SecurityNone, ListenPort: 8443,
				Clients: []config.Client{user("aaaaaaaaaaaa", uuidA)},
			},
			{
				Tag: "trojan-tcp", Protocol: config.ProtocolTrojan, Transport: config.TransportTCP,
				Security: config.SecurityNone, ListenPort: 8444,
				Clients: []config.Client{{Email: "bbbbbbbbbbbb", Password: "hunter2hunter2"}},
			},
		},
	}

	before := generate(t, two)
	after := generate(t, vlessSpec(user("aaaaaaaaaaaa", uuidA)))

	plan, err := Compute(before, after)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}

	if plan.Restart {
		t.Fatalf("detaching an inbound asks for a restart (%s), which would drop the users of the "+
			"inbound that stays", plan.Reason)
	}
	if len(plan.RemoveInbounds) != 1 || plan.RemoveInbounds[0] != "trojan-tcp" {
		t.Errorf("plan removes inbounds %v, want just the detached one", plan.RemoveInbounds)
	}
	// The users of a removed inbound need no operations: closing the listener takes
	// their connections with it, and issuing removals first would be pointless work
	// against an inbound that is about to disappear.
	for _, ref := range plan.RemoveUsers {
		if ref.Tag == "trojan-tcp" {
			t.Errorf("plan removes user %q from an inbound it is also removing", ref.Email)
		}
	}
}

func TestRestartIsRequiredFor(t *testing.T) {
	base := vlessSpec(user("aaaaaaaaaaaa", uuidA))

	cases := map[string]struct {
		mutate func(*config.Spec)
		reason string
	}{
		"an added inbound": {
			mutate: func(s *config.Spec) {
				s.Inbounds = append(s.Inbounds, config.Inbound{
					Tag: "extra", Protocol: config.ProtocolVLESS, Transport: config.TransportTCP,
					Security: config.SecurityNone, ListenPort: 8500,
					Clients: []config.Client{user("cccccccccccc", uuidC)},
				})
			},
			reason: "was added",
		},
		"a moved port": {
			mutate: func(s *config.Spec) { s.Inbounds[0].ListenPort = 9443 },
			reason: "needs a new listener",
		},
		"a changed transport": {
			mutate: func(s *config.Spec) {
				s.Inbounds[0].Transport = config.TransportWS
				s.Inbounds[0].NetworkSettings = []byte(`{"path":"/ws"}`)
			},
			reason: "needs a new listener",
		},
		"a structural change": {
			mutate: func(s *config.Spec) { s.Defaults.DNSServers = []string{"1.1.1.1"} },
			reason: "structural part",
		},
		"a moved api port": {
			mutate: func(s *config.Spec) { s.Defaults.APIPort = 10099 },
			reason: "structural part",
		},
	}

	before := generate(t, base)

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			spec := vlessSpec(user("aaaaaaaaaaaa", uuidA))
			test.mutate(&spec)

			plan, err := Compute(before, generate(t, spec))
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if !plan.Restart {
				t.Fatalf("plan avoids a restart for %s, so the node would keep serving the old configuration", name)
			}
			if !strings.Contains(plan.Reason, test.reason) {
				t.Errorf("reason is %q, want it to mention %q so an operator can see what caused the restart",
					plan.Reason, test.reason)
			}
		})
	}
}

func TestNothingToDoIsAnEmptyPlan(t *testing.T) {
	snapshot := generate(t, vlessSpec(user("aaaaaaaaaaaa", uuidA)))

	plan, err := Compute(snapshot, snapshot)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if !plan.Empty() {
		t.Errorf("an unchanged configuration produced %+v, want nothing to do", plan)
	}
}

func TestNoPreviousConfigurationMeansStart(t *testing.T) {
	after := generate(t, vlessSpec(user("aaaaaaaaaaaa", uuidA)))

	plan, err := Compute(Snapshot{}, after)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if !plan.Restart {
		t.Error("a node with nothing running was told to reconcile rather than start")
	}
}

// A configuration from before the panel sent hashes cannot be reasoned about, and
// guessing is the one thing that must not happen.
func TestMissingHashesForceARestart(t *testing.T) {
	before := generate(t, vlessSpec(user("aaaaaaaaaaaa", uuidA)))
	after := generate(t, vlessSpec(user("aaaaaaaaaaaa", uuidA), user("bbbbbbbbbbbb", uuidB)))

	t.Run("no structural hash", func(t *testing.T) {
		stale := before
		stale.StructuralHash = ""

		plan, err := Compute(stale, after)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if !plan.Restart {
			t.Error("a configuration with no structural hash was reconciled anyway")
		}
	})

	t.Run("no inbound hash", func(t *testing.T) {
		stale := before
		stale.InboundHashes = map[string]string{}

		plan, err := Compute(stale, after)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if !plan.Restart {
			t.Error("an inbound with no hash was reconciled anyway")
		}
	})
}

func TestEmptyDesiredConfigurationIsNotAPlan(t *testing.T) {
	before := generate(t, vlessSpec(user("aaaaaaaaaaaa", uuidA)))

	if _, err := Compute(before, Snapshot{}); err == nil {
		t.Error("an empty desired configuration produced a plan; stopping the core is a decision for the caller")
	}
}

// An inbound the agent cannot build credentials for — one a config patch introduced,
// for instance — must not be reconciled around.
func TestUnknownProtocolForcesARestart(t *testing.T) {
	before := generate(t, vlessSpec(user("aaaaaaaaaaaa", uuidA)))

	after := before
	after.JSON = []byte(strings.Replace(string(before.JSON), `"protocol": "vless"`, `"protocol": "socks"`, 1))
	if string(after.JSON) == string(before.JSON) {
		t.Fatal("the test did not manage to change the protocol; the generated shape must have moved")
	}

	plan, err := Compute(before, after)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if !plan.Restart {
		t.Error("an inbound with an unreconcilable protocol was reconciled anyway")
	}
}

func TestParseReadsEveryProtocol(t *testing.T) {
	spec := config.Spec{
		NodeName: "test",
		Inbounds: []config.Inbound{
			{
				Tag: "vless-tcp", Protocol: config.ProtocolVLESS, Transport: config.TransportTCP,
				Security: config.SecurityNone, ListenPort: 8443, Clients: []config.Client{user("aaaaaaaaaaaa", uuidA)},
			},
			{
				Tag: "trojan-tcp", Protocol: config.ProtocolTrojan, Transport: config.TransportTCP,
				Security: config.SecurityNone, ListenPort: 8444,
				Clients: []config.Client{{Email: "bbbbbbbbbbbb", Password: "trojanpassword"}},
			},
			{
				Tag: "ss-tcp", Protocol: config.ProtocolShadowsocks, Transport: config.TransportTCP,
				Security: config.SecurityNone, ListenPort: 8445,
				SSMethod: "2022-blake3-aes-128-gcm", SSServerKey: "c2VydmVya2V5MTIzNDU2Nzg=",
				Clients: []config.Client{{Email: "cccccccccccc", Password: "dXNlcmtleTEyMzQ1Njc4"}},
			},
		},
	}

	state, err := Parse(generate(t, spec).JSON)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if _, present := state.Inbounds["api"]; present {
		t.Error("the local api inbound was parsed as a user inbound")
	}
	if len(state.Inbounds) != 3 {
		t.Fatalf("parsed %d inbounds, want 3", len(state.Inbounds))
	}

	accounts := map[string]any{
		"vless-tcp":  xrayapi.VLESS{UUID: uuidA},
		"trojan-tcp": xrayapi.Trojan{Password: "trojanpassword"},
		"ss-tcp":     xrayapi.Shadowsocks2022{Key: "dXNlcmtleTEyMzQ1Njc4"},
	}
	for tag, want := range accounts {
		inbound := state.Inbounds[tag]
		if len(inbound.Users) != 1 {
			t.Fatalf("inbound %q has %d users, want 1", tag, len(inbound.Users))
		}
		for _, parsed := range inbound.Users {
			if fmt.Sprintf("%#v", parsed.Account) != fmt.Sprintf("%#v", want) {
				t.Errorf("inbound %q account is %#v, want %#v", tag, parsed.Account, want)
			}
		}
	}
}

// ---------------------------------------------------------------- execution

// fakeCore records what a plan did and can be told to fail.
type fakeCore struct {
	calls []string

	existing map[string]bool
	fail     map[string]error
}

func newFakeCore() *fakeCore {
	return &fakeCore{existing: map[string]bool{}, fail: map[string]error{}}
}

func (f *fakeCore) AddUser(_ context.Context, tag string, user xrayapi.User) error {
	key := "add " + tag + "/" + user.Email
	f.calls = append(f.calls, key)
	if err, ok := f.fail[key]; ok {
		delete(f.fail, key)
		return err
	}
	if f.existing[tag+"/"+user.Email] {
		return fmt.Errorf("xrayapi: could not add: %w", xrayapi.ErrAlreadyExists)
	}
	f.existing[tag+"/"+user.Email] = true
	return nil
}

func (f *fakeCore) RemoveUser(_ context.Context, tag, email string) error {
	key := "remove " + tag + "/" + email
	f.calls = append(f.calls, key)
	if err, ok := f.fail[key]; ok {
		delete(f.fail, key)
		return err
	}
	if !f.existing[tag+"/"+email] {
		return fmt.Errorf("xrayapi: could not remove: %w", xrayapi.ErrNotFound)
	}
	delete(f.existing, tag+"/"+email)
	return nil
}

func (f *fakeCore) Users(_ context.Context, tag string) ([]string, error) {
	if err, ok := f.fail["users "+tag]; ok {
		return nil, err
	}

	var emails []string
	for key := range f.existing {
		if inbound, email, found := strings.Cut(key, "/"); found && inbound == tag {
			emails = append(emails, email)
		}
	}
	sort.Strings(emails)
	return emails, nil
}

func (f *fakeCore) RemoveInbound(_ context.Context, tag string) error {
	key := "remove-inbound " + tag
	f.calls = append(f.calls, key)
	if err, ok := f.fail[key]; ok {
		delete(f.fail, key)
		return err
	}
	return nil
}

func TestExecuteRemovesBeforeAdding(t *testing.T) {
	core := newFakeCore()
	core.existing["vless-tcp/aaaaaaaaaaaa"] = true

	plan := Plan{
		RemoveUsers: []UserRef{{Tag: "vless-tcp", Email: "aaaaaaaaaaaa"}},
		AddUsers: []UserOp{{
			Tag:  "vless-tcp",
			User: xrayapi.User{Email: "aaaaaaaaaaaa", Account: xrayapi.VLESS{UUID: uuidC}},
		}},
		RemoveInbounds: []string{"gone"},
	}

	if err := Execute(context.Background(), core, plan); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	want := []string{
		"remove vless-tcp/aaaaaaaaaaaa",
		"add vless-tcp/aaaaaaaaaaaa",
		"remove-inbound gone",
	}
	if strings.Join(core.calls, ",") != strings.Join(want, ",") {
		t.Errorf("calls were %v, want %v", core.calls, want)
	}
}

// Both of these mean the core is already in the state the plan wanted, which is success.
func TestExecuteToleratesAbsentTargets(t *testing.T) {
	core := newFakeCore()

	plan := Plan{
		RemoveUsers:    []UserRef{{Tag: "vless-tcp", Email: "never-there"}},
		RemoveInbounds: []string{"never-there"},
	}
	core.fail["remove-inbound never-there"] = fmt.Errorf("wrapped: %w", xrayapi.ErrNotFound)

	if err := Execute(context.Background(), core, plan); err != nil {
		t.Errorf("Execute: %v, want a missing target to count as done", err)
	}
}

// The agent's cache can be behind the core. Adding a user the core already has must end
// with the credentials the plan wanted, not with an error.
func TestExecuteReplacesAUserTheCoreAlreadyHas(t *testing.T) {
	core := newFakeCore()
	core.existing["vless-tcp/aaaaaaaaaaaa"] = true

	plan := Plan{AddUsers: []UserOp{{
		Tag:  "vless-tcp",
		User: xrayapi.User{Email: "aaaaaaaaaaaa", Account: xrayapi.VLESS{UUID: uuidC}},
	}}}

	if err := Execute(context.Background(), core, plan); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	want := []string{
		"add vless-tcp/aaaaaaaaaaaa",
		"remove vless-tcp/aaaaaaaaaaaa",
		"add vless-tcp/aaaaaaaaaaaa",
	}
	if strings.Join(core.calls, ",") != strings.Join(want, ",") {
		t.Errorf("calls were %v, want %v", core.calls, want)
	}
}

func TestExecuteReportsRealFailures(t *testing.T) {
	core := newFakeCore()
	boom := errors.New("the core is wedged")
	core.fail["add vless-tcp/aaaaaaaaaaaa"] = boom

	plan := Plan{AddUsers: []UserOp{{
		Tag:  "vless-tcp",
		User: xrayapi.User{Email: "aaaaaaaaaaaa", Account: xrayapi.VLESS{UUID: uuidA}},
	}}}

	err := Execute(context.Background(), core, plan)
	if !errors.Is(err, boom) {
		t.Errorf("Execute returned %v, want the underlying failure so the caller falls back to a restart", err)
	}
}

// Verify is the net under the hand-written protobuf: an operation the core accepts and
// does not act on has to surface here, not as a user who cannot connect.
func TestVerifyCatchesAnOperationThatDidNothing(t *testing.T) {
	desired := State{Inbounds: map[string]Inbound{
		"vless-tcp": {
			Tag:      "vless-tcp",
			Protocol: protocolVLESS,
			Users: map[string]User{
				"aaaaaaaaaaaa": {Email: "aaaaaaaaaaaa"},
			},
		},
	}}

	t.Run("a user that was never added", func(t *testing.T) {
		core := newFakeCore()
		if err := Verify(context.Background(), core, desired, []string{"vless-tcp"}); err == nil {
			t.Error("Verify passed with the user missing from the core")
		}
	})

	t.Run("a user that was never removed", func(t *testing.T) {
		core := newFakeCore()
		core.existing["vless-tcp/aaaaaaaaaaaa"] = true
		core.existing["vless-tcp/leftover"] = true

		err := Verify(context.Background(), core, desired, []string{"vless-tcp"})
		if err == nil || !strings.Contains(err.Error(), "leftover") {
			t.Errorf("Verify returned %v, want it to name the user that is still there", err)
		}
	})

	t.Run("state that matches", func(t *testing.T) {
		core := newFakeCore()
		core.existing["vless-tcp/aaaaaaaaaaaa"] = true

		if err := Verify(context.Background(), core, desired, []string{"vless-tcp"}); err != nil {
			t.Errorf("Verify: %v, want a matching core to pass", err)
		}
	})

	t.Run("a removed inbound is not checked", func(t *testing.T) {
		core := newFakeCore()
		core.fail["users gone"] = errors.New("no such inbound")

		if err := Verify(context.Background(), core, desired, []string{"gone"}); err != nil {
			t.Errorf("Verify: %v, want an inbound that was removed to be skipped", err)
		}
	})
}

func TestExecuteRefusesARestartPlan(t *testing.T) {
	if err := Execute(context.Background(), newFakeCore(), Plan{Restart: true, Reason: "structural"}); err == nil {
		t.Error("a plan that calls for a restart was executed as runtime operations")
	}
}
