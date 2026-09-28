package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xraypanel/panel/internal/xray/reality"
)

// xrayBinaryEnv points at an xray executable. The tests here skip when it is unset,
// so `go test ./...` still works on a machine without it.
//
// This is the check that matters most in this package: golden files prove the
// generator is stable, but only the real binary proves the config is one Xray will
// accept. A hand-reviewed config that Xray rejects is a node that will not start.
const xrayBinaryEnv = "XRAY_BINARY"

func xrayBinary(t *testing.T) string {
	t.Helper()

	binary := os.Getenv(xrayBinaryEnv)
	if binary == "" {
		t.Skipf("%s is not set; skipping validation against the real xray binary", xrayBinaryEnv)
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("%s=%q is not usable: %v", xrayBinaryEnv, binary, err)
	}
	return binary
}

// writeSelfSignedCert produces a certificate and key on disk.
//
// Xray reads certificate files while parsing the config, so a config naming a file
// that does not exist fails validation for a reason that has nothing to do with the
// generator. Real files keep the test honest about what it is checking.
func writeSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cdn.example.com"},
		DNSNames:              []string{"cdn.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// withRealCertificates repoints every tls inbound at files that exist.
func withRealCertificates(t *testing.T, spec Spec, certPath, keyPath string) Spec {
	t.Helper()

	settings := map[string]any{
		"alpn":       []any{"h2", "http/1.1"},
		"minVersion": "1.2",
		"certificates": []any{
			map[string]any{"certificateFile": certPath, "keyFile": keyPath},
		},
	}
	encoded, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal tls settings: %v", err)
	}

	for i := range spec.Inbounds {
		if spec.Inbounds[i].Security == SecurityTLS {
			spec.Inbounds[i].TLSSettings = encoded
		}
	}
	return spec
}

// TestGeneratedConfigsAreAcceptedByXray runs every golden combination through
// `xray run -test`, which parses and validates a config without starting anything.
func TestGeneratedConfigsAreAcceptedByXray(t *testing.T) {
	binary := xrayBinary(t)

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	for name, spec := range goldenCases(t) {
		t.Run(name, func(t *testing.T) {
			generated, err := Generate(withRealCertificates(t, spec, certPath, keyPath))
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}

			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, generated.JSON, 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			output, err := exec.Command(binary, "run", "-test", "-config", path).CombinedOutput()
			if err != nil {
				t.Fatalf("xray rejected the generated config: %v\n--- xray output ---\n%s\n--- config ---\n%s",
					err, output, generated.JSON)
			}
			t.Logf("xray accepted the config: %s", strings.TrimSpace(string(output)))
		})
	}
}

// TestRealityKeysMatchXray is an interoperability check on our own X25519 handling.
//
// The panel derives the public key that goes into every client link. If its encoding
// or derivation disagreed with Xray's by even the base64 alphabet, the server would
// start cleanly and every client would fail the handshake, with nothing useful in any
// log. Cross-checking against `xray x25519` is the only way to be sure.
func TestRealityKeysMatchXray(t *testing.T) {
	binary := xrayBinary(t)

	for i := 0; i < 5; i++ {
		pair, err := reality.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}

		output, err := exec.Command(binary, "x25519", "-i", pair.PrivateKey).CombinedOutput()
		if err != nil {
			t.Fatalf("xray x25519 rejected our private key %q: %v\n%s", pair.PrivateKey, err, output)
		}

		got := parseXrayPublicKey(string(output))
		if got == "" {
			t.Fatalf("could not find a public key in xray output:\n%s", output)
		}
		if got != pair.PublicKey {
			t.Errorf("public key disagrees with xray:\n  ours: %s\n  xray: %s", pair.PublicKey, got)
		}
	}
}

// parseXrayPublicKey pulls the public key out of `xray x25519` output. The wording has
// changed between releases, so the value is located by label rather than by line.
func parseXrayPublicKey(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "public") {
			continue
		}
		if _, value, found := strings.Cut(line, ":"); found {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// TestXrayAcceptsRuntimeUserShape checks that a config with several users on one
// inbound is accepted, which is the shape M8 will mutate through HandlerService.
func TestXrayAcceptsRuntimeUserShape(t *testing.T) {
	binary := xrayBinary(t)

	spec := goldenCases(t)["vless-reality-tcp"]
	for i := 0; i < 50; i++ {
		spec.Inbounds[0].Clients = append(spec.Inbounds[0].Clients, Client{
			Email: "user" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + itoa(i),
			UUID:  uuidFor(i),
		})
	}

	generated, err := Generate(spec)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, generated.JSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if output, err := exec.Command(binary, "run", "-test", "-config", path).CombinedOutput(); err != nil {
		t.Fatalf("xray rejected a config with 52 users: %v\n%s", err, output)
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	return string(digits)
}

// uuidFor builds a deterministic, syntactically valid UUID.
func uuidFor(i int) string {
	const hexDigits = "0123456789abcdef"
	raw := make([]byte, 32)
	for j := range raw {
		raw[j] = hexDigits[(i+j)%16]
	}
	s := string(raw)
	return s[0:8] + "-" + s[8:12] + "-4" + s[13:16] + "-8" + s[17:20] + "-" + s[20:32]
}
