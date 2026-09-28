package sublink

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Environment variables pointing at real client binaries. The tests skip when a
// variable is unset, so `go test ./...` still runs without them.
//
// These are the checks that matter in this package. A YAML or JSON profile can look
// perfectly reasonable to a reviewer and be rejected by the client that has to load it,
// and when that happens the user sees an import failure with no explanation. Field
// names here come from documentation; only the binary confirms them.
const (
	singBoxBinaryEnv = "SINGBOX_BINARY"
	mihomoBinaryEnv  = "MIHOMO_BINARY"
)

func binaryFromEnv(t *testing.T, name string) string {
	t.Helper()

	binary := os.Getenv(name)
	if binary == "" {
		t.Skipf("%s is not set; skipping validation against the real client", name)
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("%s=%q is not usable: %v", name, binary, err)
	}
	return binary
}

// everyCombination is one endpoint per protocol, transport and security shape the panel
// can produce, so a profile renderer is exercised across all of them at once.
func everyCombination() []Endpoint {
	const uuid = "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37"
	const publicKey = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"

	return []Endpoint{
		{
			Remark: "vless reality tcp", Address: "de1.example.com", Port: 443,
			Protocol: ProtocolVLESS, Transport: TransportTCP, Security: SecurityReality,
			UUID: uuid, Flow: "xtls-rprx-vision",
			SNI: "www.cloudflare.com", Fingerprint: "chrome",
			PublicKey: publicKey, ShortID: "0123456789abcdef",
		},
		{
			Remark: "vless ws tls", Address: "cdn.example.com", Port: 8443,
			Protocol: ProtocolVLESS, Transport: TransportWS, Security: SecurityTLS,
			UUID: uuid, SNI: "cdn.example.com", ALPN: []string{"h2", "http/1.1"},
			Fingerprint: "chrome", Path: "/ws", Host: "cdn.example.com",
		},
		{
			Remark: "vless grpc tls", Address: "grpc.example.com", Port: 2083,
			Protocol: ProtocolVLESS, Transport: TransportGRPC, Security: SecurityTLS,
			UUID: uuid, SNI: "grpc.example.com", ServiceName: "GunService",
		},
		{
			Remark: "vless httpupgrade tls", Address: "hu.example.com", Port: 2087,
			Protocol: ProtocolVLESS, Transport: TransportHTTPUpgrade, Security: SecurityTLS,
			UUID: uuid, SNI: "hu.example.com", Path: "/hu", Host: "hu.example.com",
		},
		{
			Remark: "trojan ws tls", Address: "tj.example.com", Port: 9443,
			Protocol: ProtocolTrojan, Transport: TransportWS, Security: SecurityTLS,
			Password: "trojan-secret", SNI: "tj.example.com", Path: "/tj",
		},
		{
			Remark: "shadowsocks 2022", Address: "ss.example.com", Port: 8388,
			Protocol:    ProtocolShadowsocks,
			SSMethod:    "2022-blake3-aes-128-gcm",
			SSServerKey: "YctPZ6U7xPPcU+gp3u+0tw==",
			SSUserKey:   "tx/tRizJN9K8y+uKlW2qjg==",
		},
	}
}

func testSubscription() *Subscription {
	return &Subscription{
		Endpoints:      everyCombination(),
		Title:          "xraypanel",
		UpdateInterval: 12,
	}
}

// TestSingBoxAcceptsGeneratedProfile runs `sing-box check` over the rendered profile.
func TestSingBoxAcceptsGeneratedProfile(t *testing.T) {
	binary := binaryFromEnv(t, singBoxBinaryEnv)

	body, err := Render(testSubscription(), FormatSingBox)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	output, err := exec.Command(binary, "check", "-c", path).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box rejected the generated profile: %v\n--- output ---\n%s\n--- profile ---\n%s",
			err, output, body)
	}
}

// TestSingBoxAcceptsEachEndpointAlone isolates a failure to one shape. Checking them
// together would report only the first problem and hide the rest.
func TestSingBoxAcceptsEachEndpointAlone(t *testing.T) {
	binary := binaryFromEnv(t, singBoxBinaryEnv)

	for _, endpoint := range everyCombination() {
		t.Run(endpoint.Remark, func(t *testing.T) {
			sub := &Subscription{Endpoints: []Endpoint{endpoint}}

			body, err := Render(sub, FormatSingBox)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}

			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatalf("write profile: %v", err)
			}

			if output, err := exec.Command(binary, "check", "-c", path).CombinedOutput(); err != nil {
				t.Fatalf("sing-box rejected %q: %v\n%s\n--- profile ---\n%s",
					endpoint.Remark, err, output, body)
			}
		})
	}
}

// TestMihomoAcceptsGeneratedProfile runs mihomo's own config test over the rendered
// YAML.
func TestMihomoAcceptsGeneratedProfile(t *testing.T) {
	binary := binaryFromEnv(t, mihomoBinaryEnv)

	body, err := Render(testSubscription(), FormatClash)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	// -d keeps mihomo from writing into the user's real home directory while testing.
	output, err := exec.Command(binary, "-t", "-f", path, "-d", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("mihomo rejected the generated profile: %v\n--- output ---\n%s\n--- profile ---\n%s",
			err, output, body)
	}
	// mihomo exits zero on some soft failures, so the output is checked too.
	if strings.Contains(strings.ToLower(string(output)), "error") {
		t.Errorf("mihomo reported an error while accepting the profile:\n%s\n--- profile ---\n%s", output, body)
	}
}

func TestMihomoAcceptsEachEndpointAlone(t *testing.T) {
	binary := binaryFromEnv(t, mihomoBinaryEnv)

	for _, endpoint := range everyCombination() {
		t.Run(endpoint.Remark, func(t *testing.T) {
			sub := &Subscription{Endpoints: []Endpoint{endpoint}}

			body, err := Render(sub, FormatClash)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}

			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatalf("write profile: %v", err)
			}

			output, err := exec.Command(binary, "-t", "-f", path, "-d", dir).CombinedOutput()
			if err != nil {
				t.Fatalf("mihomo rejected %q: %v\n%s\n--- profile ---\n%s",
					endpoint.Remark, err, output, body)
			}
			if strings.Contains(strings.ToLower(string(output)), "error") {
				t.Errorf("mihomo reported an error for %q:\n%s\n--- profile ---\n%s",
					endpoint.Remark, output, body)
			}
		})
	}
}

// TestEmptySubscriptionIsStillLoadable covers a user with no access at all. Both
// clients reject a selector with no members, so an empty subscription has to be a
// valid profile with no groups rather than a profile with empty ones.
func TestEmptySubscriptionIsStillLoadable(t *testing.T) {
	empty := &Subscription{}

	t.Run("sing-box", func(t *testing.T) {
		binary := binaryFromEnv(t, singBoxBinaryEnv)

		body, err := Render(empty, FormatSingBox)
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if output, err := exec.Command(binary, "check", "-c", path).CombinedOutput(); err != nil {
			t.Fatalf("sing-box rejected an empty profile: %v\n%s\n%s", err, output, body)
		}
	})

	t.Run("mihomo", func(t *testing.T) {
		binary := binaryFromEnv(t, mihomoBinaryEnv)

		body, err := Render(empty, FormatClash)
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if output, err := exec.Command(binary, "-t", "-f", path, "-d", dir).CombinedOutput(); err != nil {
			t.Fatalf("mihomo rejected an empty profile: %v\n%s\n%s", err, output, body)
		}
	})
}

// TestXHTTPIsDroppedFromSingBox documents the one shape sing-box cannot express.
// Emitting an unknown transport would make the whole profile unloadable rather than
// costing the user one entry.
func TestXHTTPIsDroppedFromSingBox(t *testing.T) {
	sub := &Subscription{Endpoints: []Endpoint{
		{
			Remark: "xhttp", Address: "xh.example.com", Port: 2053,
			Protocol: ProtocolVLESS, Transport: TransportXHTTP, Security: SecurityReality,
			UUID:      "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37",
			PublicKey: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
			ShortID:   "aabb",
			Path:      "/xh", Mode: "auto",
		},
		{
			Remark: "ws", Address: "cdn.example.com", Port: 8443,
			Protocol: ProtocolVLESS, Transport: TransportWS, Security: SecurityTLS,
			UUID: "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37", Path: "/ws",
		},
	}}

	body, err := Render(sub, FormatSingBox)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(string(body), "xhttp") {
		t.Errorf("an xhttp endpoint reached the sing-box profile:\n%s", body)
	}
	if !strings.Contains(string(body), "cdn.example.com") {
		t.Errorf("dropping the xhttp endpoint also dropped the supported one:\n%s", body)
	}

	// The link list keeps it, because clients that read links do support xhttp.
	links, err := RenderPlainLinks(sub)
	if err != nil {
		t.Fatalf("RenderPlainLinks: %v", err)
	}
	if len(links) != 2 {
		t.Errorf("got %d links, want 2: the link list must keep every endpoint", len(links))
	}
}
