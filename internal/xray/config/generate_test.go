package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// update rewrites the golden files instead of comparing against them:
//
//	go test ./internal/xray/config -update
//
// Review the resulting diff. A golden file is only useful while somebody still reads
// the change it records.
var update = flag.Bool("update", false, "rewrite golden files")

// Fixed key material, so generated output is byte-for-byte reproducible. None of it
// is secret and none of it is usable: the private key is the bytes 1 through 32.
var (
	testRealityPrivateKey = base64.RawURLEncoding.EncodeToString(sequentialBytes(32))
	testUUID              = "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37"
	testUUID2             = "b1d4e7f0-2a35-4c68-8e9b-7f0a3c5d1e42"
)

func sequentialBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i + 1)
	}
	return out
}

func rawJSON(t *testing.T, s string) json.RawMessage {
	t.Helper()
	if !json.Valid([]byte(s)) {
		t.Fatalf("test fixture is not valid JSON: %s", s)
	}
	return json.RawMessage(s)
}

// baseDefaults pins the values that would otherwise vary with configuration, so the
// golden files record the generator's decisions rather than the defaults of the day.
func baseDefaults() Defaults {
	return Defaults{
		LogLevel:   "warning",
		APIAddress: "127.0.0.1",
		APIPort:    10085,
	}
}

func testSniffing(t *testing.T) json.RawMessage {
	return rawJSON(t, `{"enabled":true,"destOverride":["http","tls","quic"]}`)
}

func testTLSSettings(t *testing.T) json.RawMessage {
	return rawJSON(t, `{
		"alpn": ["h2", "http/1.1"],
		"minVersion": "1.2",
		"certificates": [
			{"certificateFile": "/etc/xray/cert.pem", "keyFile": "/etc/xray/key.pem"}
		]
	}`)
}

func testReality() *Reality {
	return &Reality{
		PrivateKey:  testRealityPrivateKey,
		ShortIDs:    []string{"0123456789abcdef", "aabb"},
		Dest:        "www.cloudflare.com:443",
		ServerNames: []string{"www.cloudflare.com"},
	}
}

func vlessClients() []Client {
	return []Client{
		{Email: "k3m9qp2wxd7f", UUID: testUUID, Level: 0},
		{Email: "q7w2e9r4t6y8", UUID: testUUID2, Level: 0},
	}
}

// goldenCases are the six transport and security combinations the milestone commits
// to supporting, one per file.
func goldenCases(t *testing.T) map[string]Spec {
	t.Helper()

	return map[string]Spec{
		// The combination that matters most in practice, and the one that needs flow.
		"vless-reality-tcp": {
			NodeName: "de-1",
			Defaults: baseDefaults(),
			Inbounds: []Inbound{{
				Tag:        "vless-reality",
				Protocol:   ProtocolVLESS,
				Transport:  TransportTCP,
				Security:   SecurityReality,
				ListenPort: 443,
				Flow:       "xtls-rprx-vision",
				Reality:    testReality(),
				Sniffing:   testSniffing(t),
				Clients:    vlessClients(),
			}},
		},

		"vless-ws-tls": {
			NodeName: "de-1",
			Defaults: baseDefaults(),
			Inbounds: []Inbound{{
				Tag:             "vless-ws",
				Protocol:        ProtocolVLESS,
				Transport:       TransportWS,
				Security:        SecurityTLS,
				ListenPort:      8443,
				NetworkSettings: rawJSON(t, `{"path":"/ws","host":"cdn.example.com"}`),
				TLSSettings:     testTLSSettings(t),
				Sniffing:        testSniffing(t),
				Clients:         vlessClients(),
			}},
		},

		"vless-xhttp-reality": {
			NodeName: "de-1",
			Defaults: baseDefaults(),
			Inbounds: []Inbound{{
				Tag:             "vless-xhttp",
				Protocol:        ProtocolVLESS,
				Transport:       TransportXHTTP,
				Security:        SecurityReality,
				ListenPort:      2053,
				NetworkSettings: rawJSON(t, `{"path":"/xh","mode":"auto"}`),
				Reality:         testReality(),
				Clients:         vlessClients(),
			}},
		},

		"vless-grpc-tls": {
			NodeName: "de-1",
			Defaults: baseDefaults(),
			Inbounds: []Inbound{{
				Tag:             "vless-grpc",
				Protocol:        ProtocolVLESS,
				Transport:       TransportGRPC,
				Security:        SecurityTLS,
				ListenPort:      2083,
				NetworkSettings: rawJSON(t, `{"serviceName":"GunService"}`),
				TLSSettings:     testTLSSettings(t),
				Clients:         vlessClients(),
			}},
		},

		"trojan-ws-tls": {
			NodeName: "de-1",
			Defaults: baseDefaults(),
			Inbounds: []Inbound{{
				Tag:             "trojan-ws",
				Protocol:        ProtocolTrojan,
				Transport:       TransportWS,
				Security:        SecurityTLS,
				ListenPort:      9443,
				NetworkSettings: rawJSON(t, `{"path":"/tj","host":"cdn.example.com"}`),
				TLSSettings:     testTLSSettings(t),
				Clients: []Client{
					{Email: "k3m9qp2wxd7f", Password: "trojan-secret-one", Level: 0},
					{Email: "q7w2e9r4t6y8", Password: "trojan-secret-two", Level: 0},
				},
			}},
		},

		"ss2022-tcp": {
			NodeName: "de-1",
			Defaults: baseDefaults(),
			Inbounds: []Inbound{{
				Tag:         "ss-2022",
				Protocol:    ProtocolShadowsocks,
				Transport:   TransportTCP,
				Security:    SecurityNone,
				ListenPort:  8388,
				SSMethod:    "2022-blake3-aes-128-gcm",
				SSServerKey: base64.StdEncoding.EncodeToString(sequentialBytes(16)),
				Clients: []Client{
					{Email: "k3m9qp2wxd7f", Password: base64.StdEncoding.EncodeToString(sequentialBytes(16)), Level: 0},
				},
			}},
		},

		// A node carrying several inbounds at once, which is the normal case and the
		// one where port collisions and tag collisions would show up.
		"multi-inbound": {
			NodeName: "de-1",
			Defaults: Defaults{
				LogLevel:   "info",
				APIAddress: "127.0.0.1",
				APIPort:    10085,
				DNSServers: []string{"1.1.1.1", "8.8.8.8"},
			},
			Inbounds: []Inbound{
				{
					Tag:        "vless-reality",
					Protocol:   ProtocolVLESS,
					Transport:  TransportTCP,
					Security:   SecurityReality,
					ListenPort: 443,
					Flow:       "xtls-rprx-vision",
					Reality:    testReality(),
					Sniffing:   testSniffing(t),
					Clients:    vlessClients(),
				},
				{
					Tag:             "vless-ws",
					Protocol:        ProtocolVLESS,
					Transport:       TransportWS,
					Security:        SecurityTLS,
					ListenPort:      8443,
					NetworkSettings: rawJSON(t, `{"path":"/ws"}`),
					TLSSettings:     testTLSSettings(t),
					Clients:         vlessClients()[:1],
				},
			},
		},

		// The escape hatches, so their precedence is recorded rather than assumed.
		"patched-and-extra": {
			NodeName:    "de-1",
			Defaults:    baseDefaults(),
			ConfigPatch: rawJSON(t, `{"log":{"loglevel":"debug"},"outbounds":[{"protocol":"freedom","tag":"direct"}]}`),
			Inbounds: []Inbound{{
				Tag:        "vless-reality",
				Protocol:   ProtocolVLESS,
				Transport:  TransportTCP,
				Security:   SecurityReality,
				ListenPort: 443,
				Reality:    testReality(),
				Extra:      rawJSON(t, `{"listen":"10.0.0.5","settings":{"decryption":"none","fallbacks":[{"dest":8080}]}}`),
				Clients:    vlessClients()[:1],
			}},
		},
	}
}

func TestGenerateGolden(t *testing.T) {
	for name, spec := range goldenCases(t) {
		t.Run(name, func(t *testing.T) {
			generated, err := Generate(spec)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}

			path := filepath.Join("testdata", name+".json")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatalf("create testdata: %v", err)
				}
				if err := os.WriteFile(path, append(generated.JSON, '\n'), 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				t.Logf("golden file rewritten: %s", path)
				return
			}

			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run with -update to create it): %v", err)
			}

			got := append(generated.JSON, '\n')
			if !bytes.Equal(got, want) {
				t.Errorf("generated config differs from %s\n--- got ---\n%s", path, got)
			}
		})
	}
}

// TestGenerateIsDeterministic matters because the node compares hashes to decide
// whether to restart the core. A generator that reorders its own output would make
// every poll look like a configuration change.
func TestGenerateIsDeterministic(t *testing.T) {
	for name, spec := range goldenCases(t) {
		t.Run(name, func(t *testing.T) {
			first, err := Generate(spec)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			for i := 0; i < 5; i++ {
				next, err := Generate(spec)
				if err != nil {
					t.Fatalf("Generate: %v", err)
				}
				if !bytes.Equal(first.JSON, next.JSON) {
					t.Fatal("two generations of the same spec produced different bytes")
				}
				if first.StructuralHash != next.StructuralHash {
					t.Fatal("the structural hash is not stable across generations")
				}
			}
		})
	}
}

// TestStatsPlumbingIsPresent guards the three pieces that traffic accounting needs.
// Any one of them missing gives a config that starts cleanly and reports nothing,
// which surfaces much later as "billing does not work".
func TestStatsPlumbingIsPresent(t *testing.T) {
	generated, err := Generate(goldenCases(t)["vless-reality-tcp"])
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(generated.JSON, &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, ok := document["stats"]; !ok {
		t.Error("the stats section is missing, so no counters are collected at all")
	}

	policy, _ := document["policy"].(map[string]any)
	levels, _ := policy["levels"].(map[string]any)
	level0, _ := levels["0"].(map[string]any)
	for _, flag := range []string{"statsUserUplink", "statsUserDownlink"} {
		if level0[flag] != true {
			t.Errorf("policy.levels.0.%s is not true, so per-user counters are absent", flag)
		}
	}

	system, _ := policy["system"].(map[string]any)
	for _, flag := range []string{"statsInboundUplink", "statsInboundDownlink"} {
		if system[flag] != true {
			t.Errorf("policy.system.%s is not true, so per-inbound totals are absent", flag)
		}
	}

	api, _ := document["api"].(map[string]any)
	services, _ := api["services"].([]any)
	present := map[string]bool{}
	for _, service := range services {
		if name, ok := service.(string); ok {
			present[name] = true
		}
	}
	for _, service := range []string{"HandlerService", "StatsService", "LoggerService"} {
		if !present[service] {
			t.Errorf("api.services is missing %s", service)
		}
	}
}

// TestAPIInboundIsLoopbackOnly is a security check. The API can add and remove users
// and read every counter, so a reachable API port is administrative access to the node.
func TestAPIInboundIsLoopbackOnly(t *testing.T) {
	generated, err := Generate(goldenCases(t)["vless-reality-tcp"])
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(generated.JSON, &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	inbounds, _ := document["inbounds"].([]any)

	var found bool
	for _, entry := range inbounds {
		object, _ := entry.(map[string]any)
		if object["tag"] != apiTag {
			continue
		}
		found = true
		if listen := object["listen"]; listen != "127.0.0.1" {
			t.Errorf("the api inbound listens on %v, want 127.0.0.1", listen)
		}
	}
	if !found {
		t.Error("there is no api inbound, so the agent cannot manage users at runtime")
	}

	// And the routing rule that actually connects it, without which the port accepts
	// connections and answers nothing.
	routing, _ := document["routing"].(map[string]any)
	rules, _ := routing["rules"].([]any)
	var routed bool
	for _, entry := range rules {
		rule, _ := entry.(map[string]any)
		tags, _ := rule["inboundTag"].([]any)
		if len(tags) == 1 && tags[0] == apiTag && rule["outboundTag"] == apiTag {
			routed = true
		}
	}
	if !routed {
		t.Error("no routing rule sends the api inbound to the api handler")
	}
}

// TestFlowReachesTheClients is the config half of ADR-010. The link half is M4.
func TestFlowReachesTheClients(t *testing.T) {
	generated, err := Generate(goldenCases(t)["vless-reality-tcp"])
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(generated.JSON, &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	clients := clientsOf(t, document, "vless-reality")
	if len(clients) == 0 {
		t.Fatal("no clients were generated")
	}
	for _, entry := range clients {
		client, _ := entry.(map[string]any)
		if client["flow"] != "xtls-rprx-vision" {
			t.Errorf("client %v has flow %v, want xtls-rprx-vision", client["email"], client["flow"])
		}
	}

	// And it must be absent where Xray would reject it.
	wsGenerated, err := Generate(goldenCases(t)["vless-ws-tls"])
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var wsDocument map[string]any
	if err := json.Unmarshal(wsGenerated.JSON, &wsDocument); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, entry := range clientsOf(t, wsDocument, "vless-ws") {
		client, _ := entry.(map[string]any)
		if _, present := client["flow"]; present {
			t.Error("flow was emitted on a websocket inbound, where Xray does not accept it")
		}
	}
}

func clientsOf(t *testing.T, document map[string]any, tag string) []any {
	t.Helper()

	inbounds, _ := document["inbounds"].([]any)
	for _, entry := range inbounds {
		object, _ := entry.(map[string]any)
		if object["tag"] != tag {
			continue
		}
		settings, _ := object["settings"].(map[string]any)
		clients, _ := settings["clients"].([]any)
		return clients
	}
	t.Fatalf("no inbound tagged %q", tag)
	return nil
}

// TestStructuralHashIgnoresUserChanges is the property ADR-009 depends on: adding or
// removing a user must not look like a change that needs the core restarted.
func TestStructuralHashIgnoresUserChanges(t *testing.T) {
	base := goldenCases(t)["vless-reality-tcp"]

	original, err := Generate(base)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	withExtraUser := goldenCases(t)["vless-reality-tcp"]
	withExtraUser.Inbounds[0].Clients = append(withExtraUser.Inbounds[0].Clients,
		Client{Email: "z9x8c7v6b5n4", UUID: "11111111-2222-3333-4444-555555555555"})

	changed, err := Generate(withExtraUser)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if changed.StructuralHash != original.StructuralHash {
		t.Error("adding a user changed the structural hash, which would restart the core and drop every connection")
	}

	// The inbound hash must not move either. Users are reconciled against the running
	// core one by one (ADR-065), so a hash that reacted to them would report every user
	// edit as an inbound that needs rebuilding — the restart this hash exists to avoid.
	if changed.InboundHashes["vless-reality"] != original.InboundHashes["vless-reality"] {
		t.Error("adding a user changed the inbound hash, which the node reads as a change it must restart for")
	}
}

// TestInboundHashReactsToShapeChanges is the other half of the same contract: anything
// about an inbound that is not its user list cannot be changed on a running core, so it
// has to move the hash.
//
// Flow is deliberately not in this list. Xray carries it on each client entry rather
// than on the inbound, so changing it is a change of credentials: the node re-adds each
// user with the new flow and nothing restarts.
func TestInboundHashReactsToShapeChanges(t *testing.T) {
	const tag = "vless-reality"

	original, err := Generate(goldenCases(t)["vless-reality-tcp"])
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	cases := map[string]func(*Spec){
		"listen port":    func(s *Spec) { s.Inbounds[0].ListenPort = 9443 },
		"listen address": func(s *Spec) { s.Inbounds[0].ListenAddr = "127.0.0.1" },
		"reality dest":   func(s *Spec) { s.Inbounds[0].Reality.Dest = "www.bing.com:443" },
		"sniffing": func(s *Spec) {
			s.Inbounds[0].Sniffing = rawJSON(t, `{"enabled":false}`)
		},
		"extra override": func(s *Spec) {
			s.Inbounds[0].Extra = rawJSON(t, `{"listen":"10.0.0.1"}`)
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := goldenCases(t)["vless-reality-tcp"]
			mutate(&spec)

			changed, err := Generate(spec)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if changed.InboundHashes[tag] == original.InboundHashes[tag] {
				t.Error("a change the core cannot take at runtime left the inbound hash alone, " +
					"so the node would never restart for it")
			}
		})
	}
}

// TestStructuralHashReactsToStructuralChanges is the other half.
func TestStructuralHashReactsToStructuralChanges(t *testing.T) {
	base := goldenCases(t)["vless-reality-tcp"]
	original, err := Generate(base)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	cases := map[string]func(*Spec){
		"log level":   func(s *Spec) { s.Defaults.LogLevel = "debug" },
		"api port":    func(s *Spec) { s.Defaults.APIPort = 10086 },
		"dns servers": func(s *Spec) { s.Defaults.DNSServers = []string{"1.1.1.1"} },
		"routing via patch": func(s *Spec) {
			s.ConfigPatch = json.RawMessage(`{"routing":{"domainStrategy":"IPIfNonMatch"}}`)
		},
		"outbounds via patch": func(s *Spec) {
			s.ConfigPatch = json.RawMessage(`{"outbounds":[{"protocol":"freedom","tag":"direct"}]}`)
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := goldenCases(t)["vless-reality-tcp"]
			mutate(&spec)

			changed, err := Generate(spec)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if changed.StructuralHash == original.StructuralHash {
				t.Error("a structural change did not move the structural hash, so the core would never be restarted for it")
			}
		})
	}
}

// TestAddingAnInboundLeavesOthersAlone is what lets a new inbound be added without
// touching the users already connected to the existing ones.
func TestAddingAnInboundLeavesOthersAlone(t *testing.T) {
	single, err := Generate(goldenCases(t)["vless-reality-tcp"])
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	multi, err := Generate(goldenCases(t)["multi-inbound"])
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if single.InboundHashes["vless-reality"] != multi.InboundHashes["vless-reality"] {
		t.Error("the hash of an untouched inbound changed when another inbound was added")
	}
	if _, present := multi.InboundHashes["vless-ws"]; !present {
		t.Error("the added inbound has no hash")
	}
	if len(single.InboundHashes) != 1 {
		t.Errorf("single-inbound node has %d inbound hashes, want 1 (the api inbound must not be counted)",
			len(single.InboundHashes))
	}
}

func TestExtraOverridesGeneratedFields(t *testing.T) {
	generated, err := Generate(goldenCases(t)["patched-and-extra"])
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(generated.JSON, &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	inbounds, _ := document["inbounds"].([]any)
	var found bool
	for _, entry := range inbounds {
		object, _ := entry.(map[string]any)
		if object["tag"] != "vless-reality" {
			continue
		}
		found = true
		// An escape hatch that cannot override is not an escape hatch.
		if object["listen"] != "10.0.0.5" {
			t.Errorf("extra did not override listen: got %v", object["listen"])
		}
		settings, _ := object["settings"].(map[string]any)
		if _, present := settings["fallbacks"]; !present {
			t.Error("extra did not add fallbacks to settings")
		}
		// And it must not have destroyed what it did not mention.
		if settings["decryption"] != "none" {
			t.Error("merging extra dropped the generated decryption field")
		}
		if _, present := settings["clients"]; !present {
			t.Error("merging extra dropped the generated clients")
		}
	}
	if !found {
		t.Fatal("the inbound is missing from the generated config")
	}

	// The document-level patch must have landed too.
	log, _ := document["log"].(map[string]any)
	if log["loglevel"] != "debug" {
		t.Errorf("the config patch did not change the log level: %v", log["loglevel"])
	}
}

func TestGenerateRejectsBadSpecs(t *testing.T) {
	valid := func(t *testing.T) Spec { return goldenCases(t)["vless-reality-tcp"] }

	cases := map[string]struct {
		mutate  func(*Spec)
		wantSub string
	}{
		"port collision between inbounds": {
			mutate: func(s *Spec) {
				second := s.Inbounds[0]
				second.Tag = "second"
				s.Inbounds = append(s.Inbounds, second)
			},
			wantSub: "both listen on port",
		},
		"collision with the api port": {
			mutate:  func(s *Spec) { s.Inbounds[0].ListenPort = s.Defaults.APIPort },
			wantSub: "both listen on port",
		},
		"reserved api tag": {
			mutate:  func(s *Spec) { s.Inbounds[0].Tag = "api" },
			wantSub: "reserved",
		},
		"duplicate tag": {
			mutate: func(s *Spec) {
				s.Inbounds = append(s.Inbounds, s.Inbounds[0])
				s.Inbounds[1].ListenPort = 444
			},
			wantSub: "used twice",
		},
		"no inbounds": {
			mutate:  func(s *Spec) { s.Inbounds = nil },
			wantSub: "at least one inbound",
		},
		"no clients": {
			mutate:  func(s *Spec) { s.Inbounds[0].Clients = nil },
			wantSub: "no clients",
		},
		"duplicate stats key": {
			mutate: func(s *Spec) {
				s.Inbounds[0].Clients[1].Email = s.Inbounds[0].Clients[0].Email
			},
			wantSub: "twice",
		},
		"flow on websocket": {
			mutate: func(s *Spec) {
				s.Inbounds[0].Transport = TransportWS
				s.Inbounds[0].NetworkSettings = json.RawMessage(`{"path":"/ws"}`)
			},
			wantSub: "flow",
		},
		"flow on trojan": {
			mutate: func(s *Spec) {
				s.Inbounds[0].Protocol = ProtocolTrojan
				s.Inbounds[0].Clients[0].Password = "x"
				s.Inbounds[0].Clients[1].Password = "y"
			},
			wantSub: "flow",
		},
		"reality without key material": {
			mutate:  func(s *Spec) { s.Inbounds[0].Reality = nil },
			wantSub: "without key material",
		},
		"reality with a broken private key": {
			mutate:  func(s *Spec) { s.Inbounds[0].Reality.PrivateKey = "not-a-key" },
			wantSub: "key",
		},
		"reality with an empty short id": {
			mutate:  func(s *Spec) { s.Inbounds[0].Reality.ShortIDs = []string{""} },
			wantSub: "short id",
		},
		"reality dest without a port": {
			mutate:  func(s *Spec) { s.Inbounds[0].Reality.Dest = "www.cloudflare.com" },
			wantSub: "host:port",
		},
		"tls without settings": {
			mutate: func(s *Spec) {
				s.Inbounds[0].Security = SecurityTLS
				s.Inbounds[0].Reality = nil
				s.Inbounds[0].TLSSettings = nil
			},
			wantSub: "without tlsSettings",
		},
		"reality material with security none": {
			mutate: func(s *Spec) {
				s.Inbounds[0].Security = SecurityNone
				s.Inbounds[0].Flow = ""
			},
			wantSub: "security is none",
		},
		"unknown protocol": {
			mutate:  func(s *Spec) { s.Inbounds[0].Protocol = "vmess" },
			wantSub: "unknown protocol",
		},
		"unknown transport": {
			mutate:  func(s *Spec) { s.Inbounds[0].Transport = "quic" },
			wantSub: "unknown transport",
		},
		"vless client without a uuid": {
			mutate:  func(s *Spec) { s.Inbounds[0].Clients[0].UUID = "" },
			wantSub: "without a uuid",
		},
		"client without a stats key": {
			mutate:  func(s *Spec) { s.Inbounds[0].Clients[0].Email = "" },
			wantSub: "stats key",
		},
		"bad log level": {
			mutate:  func(s *Spec) { s.Defaults.LogLevel = "verbose" },
			wantSub: "log level",
		},
		"network settings that are not an object": {
			mutate:  func(s *Spec) { s.Inbounds[0].NetworkSettings = json.RawMessage(`["nope"]`) },
			wantSub: "must be a JSON object",
		},
		"patch that is not json": {
			mutate:  func(s *Spec) { s.ConfigPatch = json.RawMessage(`{not json`) },
			wantSub: "not valid JSON",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			spec := valid(t)
			tc.mutate(&spec)

			_, err := Generate(spec)
			if err == nil {
				t.Fatalf("Generate accepted an invalid spec; expected an error mentioning %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}

func TestShadowsocksRejectsLegacyMethods(t *testing.T) {
	spec := goldenCases(t)["ss2022-tcp"]

	// The older AEAD ciphers have no per-user keys, so a multi-user inbound cannot
	// attribute traffic to anyone, and they lack the 2022 replay protection.
	for _, method := range []string{"aes-128-gcm", "chacha20-ietf-poly1305", "", "2022"} {
		spec.Inbounds[0].SSMethod = method
		if _, err := Generate(spec); err == nil {
			t.Errorf("method %q was accepted", method)
		}
	}
}
