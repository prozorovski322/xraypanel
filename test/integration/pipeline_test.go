//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/service"
	"github.com/xraypanel/panel/internal/sublink"
)

// scenario is a fully configured panel: one Reality inbound and one websocket inbound,
// each with a host, both in a group, both on a node, and one user with access.
type scenario struct {
	nodeID           int64
	realityInboundID int64
	wsInboundID      int64
	groupID          int64
	userID           int64
}

// buildScenario wires up a working installation through the service layer, the same way
// an operator would through the API.
func (e *env) buildScenario(t *testing.T) scenario {
	t.Helper()
	ctx := context.Background()
	actor := audit.SystemActor("test")

	key, err := e.res.CreateRealityKey(ctx, actor, service.CreateRealityKeyInput{
		Name:        "primary",
		Dest:        "www.cloudflare.com:443",
		ServerNames: []string{"www.cloudflare.com"},
	})
	if err != nil {
		t.Fatalf("CreateRealityKey: %v", err)
	}

	realityInbound, err := e.res.CreateInbound(ctx, actor, service.CreateInboundInput{
		Tag:          "vless-reality",
		Protocol:     "vless",
		Transport:    "tcp",
		Security:     "reality",
		ListenPort:   443,
		Flow:         "xtls-rprx-vision",
		RealityKeyID: &key.ID,
		Sniffing:     json.RawMessage(`{"enabled":true,"destOverride":["http","tls"]}`),
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("CreateInbound reality: %v", err)
	}

	wsInbound, err := e.res.CreateInbound(ctx, actor, service.CreateInboundInput{
		Tag:             "vless-ws",
		Protocol:        "vless",
		Transport:       "ws",
		Security:        "tls",
		ListenPort:      8443,
		NetworkSettings: json.RawMessage(`{"path":"/ws","host":"cdn.example.com"}`),
		TLSSettings:     json.RawMessage(`{"alpn":["h2","http/1.1"],"certificates":[{"certificateFile":"/tmp/cert.pem","keyFile":"/tmp/key.pem"}]}`),
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("CreateInbound ws: %v", err)
	}

	// Templates in the remark and address: resolution has to expand them per user.
	if _, err := e.res.CreateHost(ctx, actor, service.CreateHostInput{
		InboundID:   realityInbound.ID,
		Remark:      "{COUNTRY}-{NODE}",
		Address:     "{NODE}.example.com",
		SNI:         strptr("www.cloudflare.com"),
		Fingerprint: strptr("chrome"),
		Enabled:     true,
	}); err != nil {
		t.Fatalf("CreateHost reality: %v", err)
	}
	if _, err := e.res.CreateHost(ctx, actor, service.CreateHostInput{
		InboundID: wsInbound.ID,
		Remark:    "{COUNTRY} CDN ({USERNAME})",
		Address:   "cdn.example.com",
		Path:      strptr("/ws"),
		SNI:       strptr("cdn.example.com"),
		ALPN:      strptr("h2,http/1.1"),
		SortOrder: 2,
		Enabled:   true,
	}); err != nil {
		t.Fatalf("CreateHost ws: %v", err)
	}

	group, err := e.res.CreateGroup(ctx, actor, service.CreateGroupInput{
		Name:       "everything",
		IsDefault:  true,
		InboundIDs: []int64{realityInbound.ID, wsInbound.ID},
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	node, err := e.res.CreateNode(ctx, actor, service.CreateNodeInput{
		Name:        "de-1",
		Address:     "de1.example.com",
		CountryCode: "DE",
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	for _, inboundID := range []int64{realityInbound.ID, wsInbound.ID} {
		if err := e.res.AttachInbound(ctx, actor, node.ID, inboundID); err != nil {
			t.Fatalf("AttachInbound: %v", err)
		}
	}

	// No group ids given, so the default group applies. That is what makes a bare "create
	// this user" request produce someone who can actually connect.
	user, err := e.res.CreateUser(ctx, actor, service.CreateUserInput{Username: "alice"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	return scenario{
		nodeID:           node.ID,
		realityInboundID: realityInbound.ID,
		wsInboundID:      wsInbound.ID,
		groupID:          group.ID,
		userID:           user.ID,
	}
}

func strptr(s string) *string { return &s }

// TestPipelineProducesAConfigXrayAccepts is the end-to-end check for this milestone: real
// rows in a real database, through resolution and generation, into a config the real Xray
// binary accepts.
//
// Every layer has its own tests. This one exists because they can all pass while the
// joins between them are wrong, and the first symptom of that is a node that will not
// start.
func TestPipelineProducesAConfigXrayAccepts(t *testing.T) {
	e := newEnv(t)
	scenario := e.buildScenario(t)

	generated, err := e.res.PreviewNodeConfig(context.Background(), scenario.nodeID)
	if err != nil {
		t.Fatalf("PreviewNodeConfig: %v", err)
	}

	// Both inbounds resolved, each with the one user who has access.
	var document map[string]any
	if err := json.Unmarshal(generated.JSON, &document); err != nil {
		t.Fatalf("generated config is not valid JSON: %v", err)
	}
	inbounds, _ := document["inbounds"].([]any)
	// Two user inbounds plus the local api inbound.
	if len(inbounds) != 3 {
		t.Errorf("got %d inbounds, want 3 (two user inbounds and the api inbound)", len(inbounds))
	}
	if len(generated.InboundHashes) != 2 {
		t.Errorf("got %d inbound hashes, want 2", len(generated.InboundHashes))
	}

	// The Reality private key has to have been decrypted on the way through.
	if !strings.Contains(string(generated.JSON), "privateKey") {
		t.Error("the generated config carries no reality private key")
	}

	binary := os.Getenv(xrayBinaryEnv)
	if binary == "" {
		t.Skipf("%s is not set; generated the config but did not validate it", xrayBinaryEnv)
	}

	// The websocket inbound names certificate files, and Xray reads them while parsing.
	dir := t.TempDir()
	writeDummyCert(t, dir)
	config := strings.ReplaceAll(string(generated.JSON), "/tmp/cert.pem", filepath.ToSlash(filepath.Join(dir, "cert.pem")))
	config = strings.ReplaceAll(config, "/tmp/key.pem", filepath.ToSlash(filepath.Join(dir, "key.pem")))

	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if output, err := exec.Command(binary, "run", "-test", "-config", path).CombinedOutput(); err != nil {
		t.Fatalf("xray rejected the config the panel built from the database: %v\n%s\n--- config ---\n%s",
			err, output, config)
	}
}

const xrayBinaryEnv = "XRAY_BINARY"

// TestPipelineProducesASubscriptionClientsAccept is the other half: the same rows resolved
// into what a client imports, validated by the real sing-box.
func TestPipelineProducesASubscriptionClientsAccept(t *testing.T) {
	e := newEnv(t)
	scenario := e.buildScenario(t)
	ctx := context.Background()

	user, err := e.res.GetUser(ctx, scenario.userID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	sub, err := e.res.BuildSubscription(ctx, user)
	if err != nil {
		t.Fatalf("BuildSubscription: %v", err)
	}

	if len(sub.Endpoints) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(sub.Endpoints))
	}

	// Templates must have been expanded, or the user sees literal braces in their client.
	remarks := map[string]bool{}
	for _, endpoint := range sub.Endpoints {
		if strings.ContainsAny(endpoint.Remark, "{}") {
			t.Errorf("remark %q still contains a placeholder", endpoint.Remark)
		}
		remarks[endpoint.Remark] = true
	}
	if !remarks["DE-de-1"] {
		t.Errorf("expected a remark expanded to DE-de-1, got %v", keysOf(remarks))
	}
	if !remarks["DE CDN (alice)"] {
		t.Errorf("expected a remark expanded to DE CDN (alice), got %v", keysOf(remarks))
	}

	// The Reality endpoint must carry the public key, a short id and an SNI. Reality
	// without an SNI would send the client's real target in the handshake.
	var checkedReality bool
	for _, endpoint := range sub.Endpoints {
		if endpoint.Security != sublink.SecurityReality {
			continue
		}
		checkedReality = true
		if endpoint.PublicKey == "" {
			t.Error("reality endpoint has no public key")
		}
		if endpoint.ShortID == "" {
			t.Error("reality endpoint has no short id")
		}
		if endpoint.SNI == "" {
			t.Error("reality endpoint has no sni")
		}
		if endpoint.Flow != "xtls-rprx-vision" {
			t.Errorf("reality endpoint flow = %q, want xtls-rprx-vision", endpoint.Flow)
		}
		// The address came from a template, not from the node's own address.
		if endpoint.Address != "de-1.example.com" {
			t.Errorf("address = %q, want the templated de-1.example.com", endpoint.Address)
		}
	}
	if !checkedReality {
		t.Fatal("no reality endpoint in the subscription")
	}

	// Every link has to be renderable.
	links, err := sublink.RenderPlainLinks(sub)
	if err != nil {
		t.Fatalf("RenderPlainLinks: %v", err)
	}
	for _, link := range links {
		if !strings.HasPrefix(link, "vless://") {
			t.Errorf("unexpected link scheme: %s", link)
		}
	}

	binary := os.Getenv("SINGBOX_BINARY")
	if binary == "" {
		t.Skip("SINGBOX_BINARY is not set; built the subscription but did not validate it")
	}

	body, err := sublink.Render(sub, sublink.FormatSingBox)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	if output, err := exec.Command(binary, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("sing-box rejected the profile the panel built from the database: %v\n%s\n%s",
			err, output, body)
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestDisabledUserDisappearsFromNodeConfig is the enforcement path: the panel changing a
// status has to be what actually removes the user from what a node runs.
func TestDisabledUserDisappearsFromNodeConfig(t *testing.T) {
	e := newEnv(t)
	scenario := e.buildScenario(t)
	ctx := context.Background()
	actor := audit.SystemActor("test")

	user, err := e.res.GetUser(ctx, scenario.userID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	before, err := e.res.PreviewNodeConfig(ctx, scenario.nodeID)
	if err != nil {
		t.Fatalf("PreviewNodeConfig: %v", err)
	}
	if !strings.Contains(string(before.JSON), user.XrayEmail) {
		t.Fatal("the active user is not in the node config")
	}

	disabled := "disabled"
	if _, err := e.res.UpdateUser(ctx, actor, scenario.userID, service.UpdateUserInput{
		Status: &disabled,
	}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	// With the only user disabled there is nothing to configure, which is reported rather
	// than yielding an inbound with no clients that Xray would reject.
	if _, err := e.res.PreviewNodeConfig(ctx, scenario.nodeID); err == nil {
		t.Error("a node whose only user is disabled produced a config anyway")
	}

	// And the user is gone from the resolution, not merely marked.
	rows, err := e.q.ListInboundClients(ctx, scenario.realityInboundID)
	if err != nil {
		t.Fatalf("ListInboundClients: %v", err)
	}
	for _, row := range rows {
		if row.XrayEmail == user.XrayEmail {
			t.Error("a disabled user is still listed as a client of the inbound")
		}
	}
}

// TestConfigVersionBumpsOnEveryChangeThatMatters guards the signal a node uses to decide
// whether to fetch. A missed bump is a change that silently never arrives.
//
// Each case gets its own environment. Sharing one would make the cases order-dependent, and
// Go randomises map iteration: an earlier case that clears a user's groups leaves them
// reaching no node, so a later case would correctly bump nothing and fail for the wrong
// reason. A test that fails depending on its own ordering is worse than no test.
func TestConfigVersionBumpsOnEveryChangeThatMatters(t *testing.T) {
	cases := []struct {
		name   string
		change func(t *testing.T, e *env, s scenario)
	}{
		{"creating a user", func(t *testing.T, e *env, s scenario) {
			if _, err := e.res.CreateUser(context.Background(), audit.SystemActor("test"),
				service.CreateUserInput{Username: "bob"}); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
		}},
		{"rotating credentials", func(t *testing.T, e *env, s scenario) {
			if _, err := e.res.RotateUserCredentials(context.Background(), audit.SystemActor("test"),
				s.userID); err != nil {
				t.Fatalf("RotateUserCredentials: %v", err)
			}
		}},
		{"disabling a user", func(t *testing.T, e *env, s scenario) {
			disabled := "disabled"
			if _, err := e.res.UpdateUser(context.Background(), audit.SystemActor("test"),
				s.userID, service.UpdateUserInput{Status: &disabled}); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
		}},
		{"revoking a user's groups", func(t *testing.T, e *env, s scenario) {
			if err := e.res.SetUserGroups(context.Background(), audit.SystemActor("test"),
				s.userID, nil); err != nil {
				t.Fatalf("SetUserGroups: %v", err)
			}
		}},
		{"disabling an inbound", func(t *testing.T, e *env, s scenario) {
			enabled := false
			if _, err := e.res.UpdateInbound(context.Background(), audit.SystemActor("test"),
				s.wsInboundID, service.UpdateInboundInput{Enabled: &enabled}); err != nil {
				t.Fatalf("UpdateInbound: %v", err)
			}
		}},
		{"detaching an inbound", func(t *testing.T, e *env, s scenario) {
			if err := e.res.DetachInbound(context.Background(), audit.SystemActor("test"),
				s.nodeID, s.wsInboundID); err != nil {
				t.Fatalf("DetachInbound: %v", err)
			}
		}},
		{"changing the node's config patch", func(t *testing.T, e *env, s scenario) {
			if _, err := e.res.UpdateNode(context.Background(), audit.SystemActor("test"),
				s.nodeID, service.UpdateNodeInput{
					SetConfigPatch: true,
					ConfigPatch:    []byte(`{"log":{"loglevel":"debug"}}`),
				}); err != nil {
				t.Fatalf("UpdateNode: %v", err)
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			scenario := e.buildScenario(t)

			version := func() int64 {
				node, err := e.q.GetNode(context.Background(), scenario.nodeID)
				if err != nil {
					t.Fatalf("GetNode: %v", err)
				}
				return node.ConfigVersion
			}

			before := version()
			tc.change(t, e, scenario)

			if after := version(); after <= before {
				t.Errorf("%s did not bump the node config version (%d -> %d)", tc.name, before, after)
			}
		})
	}
}

// TestHostChangeDoesNotBumpNodeConfig is the converse: a host only affects what clients
// are told, so it must not make every node refetch and reconcile for nothing.
func TestHostChangeDoesNotBumpNodeConfig(t *testing.T) {
	e := newEnv(t)
	scenario := e.buildScenario(t)
	ctx := context.Background()

	hosts, err := e.q.ListHostsForInbound(ctx, scenario.realityInboundID)
	if err != nil {
		t.Fatalf("ListHostsForInbound: %v", err)
	}
	if len(hosts) == 0 {
		t.Fatal("no hosts to change")
	}

	nodeBefore, err := e.q.GetNode(ctx, scenario.nodeID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}

	remark := "a different remark"
	if _, err := e.res.UpdateHost(ctx, audit.SystemActor("test"), hosts[0].ID, service.UpdateHostInput{
		Remark: &remark,
	}); err != nil {
		t.Fatalf("UpdateHost: %v", err)
	}

	nodeAfter, err := e.q.GetNode(ctx, scenario.nodeID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if nodeAfter.ConfigVersion != nodeBefore.ConfigVersion {
		t.Errorf("a host change bumped the node config version (%d -> %d); nodes would reconcile for nothing",
			nodeBefore.ConfigVersion, nodeAfter.ConfigVersion)
	}
}

// writeDummyCert produces a certificate and key so a config naming them parses.
func writeDummyCert(t *testing.T, dir string) {
	t.Helper()

	certPEM, keyPEM := selfSignedPEM(t)
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

// TestGeneratedConfigIsStableAcrossReads guards the hash the node compares. If resolution
// ordered rows differently between reads, every poll would look like a change and restart
// the core.
func TestGeneratedConfigIsStableAcrossReads(t *testing.T) {
	e := newEnv(t)
	scenario := e.buildScenario(t)
	ctx := context.Background()

	first, err := e.res.PreviewNodeConfig(ctx, scenario.nodeID)
	if err != nil {
		t.Fatalf("PreviewNodeConfig: %v", err)
	}

	for i := 0; i < 5; i++ {
		next, err := e.res.PreviewNodeConfig(ctx, scenario.nodeID)
		if err != nil {
			t.Fatalf("PreviewNodeConfig: %v", err)
		}
		if next.StructuralHash != first.StructuralHash {
			t.Fatal("the structural hash changed between two reads of unchanged data")
		}
		for tag, hash := range first.InboundHashes {
			if next.InboundHashes[tag] != hash {
				t.Fatalf("the hash of inbound %q changed between two reads of unchanged data", tag)
			}
		}
	}
}
