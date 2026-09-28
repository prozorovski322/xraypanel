package httpapi

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func mustCIDR(t *testing.T, s string) net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return *network
}

// capturedAddr runs the realIP middleware and reports the RemoteAddr a handler
// downstream would observe.
func capturedAddr(t *testing.T, trusted []net.IPNet, peer, forwardedFor string) string {
	t.Helper()

	var seen string
	handler := realIP(trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		seen = host
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = peer
	if forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", forwardedFor)
	}

	handler.ServeHTTP(httptest.NewRecorder(), req)
	return seen
}

// TestRealIPIgnoresUntrustedPeer is the security property: this address feeds login
// throttling and the audit trail, so a client that is not a configured proxy must
// not be able to choose it.
func TestRealIPIgnoresUntrustedPeer(t *testing.T) {
	trusted := []net.IPNet{mustCIDR(t, "10.0.0.0/8")}

	got := capturedAddr(t, trusted, "203.0.113.9:44321", "1.2.3.4")
	if got != "203.0.113.9" {
		t.Errorf("RemoteAddr = %q, want the socket peer 203.0.113.9: an untrusted client spoofed it", got)
	}
}

// TestRealIPDisabledWithoutConfiguration pins the safe default: with no trusted
// proxies configured the header is ignored entirely.
func TestRealIPDisabledWithoutConfiguration(t *testing.T) {
	got := capturedAddr(t, nil, "10.0.0.7:5555", "1.2.3.4")
	if got != "10.0.0.7" {
		t.Errorf("RemoteAddr = %q, want 10.0.0.7; the header was honoured with no trusted proxies set", got)
	}
}

func TestRealIPHonoursTrustedProxy(t *testing.T) {
	trusted := []net.IPNet{mustCIDR(t, "10.0.0.0/8")}

	got := capturedAddr(t, trusted, "10.0.0.2:44321", "198.51.100.23")
	if got != "198.51.100.23" {
		t.Errorf("RemoteAddr = %q, want the forwarded client 198.51.100.23", got)
	}
}

// TestRealIPSkipsOwnProxyChain walks past addresses belonging to our own proxies:
// the first untrusted hop from the right is the closest thing to a real client we
// can prove.
func TestRealIPSkipsOwnProxyChain(t *testing.T) {
	trusted := []net.IPNet{
		mustCIDR(t, "10.0.0.0/8"),
		mustCIDR(t, "172.16.0.0/12"),
	}

	got := capturedAddr(t, trusted, "10.0.0.2:44321", "198.51.100.23, 172.16.4.4, 10.0.0.3")
	if got != "198.51.100.23" {
		t.Errorf("RemoteAddr = %q, want 198.51.100.23", got)
	}
}

// TestRealIPRejectsMalformedChain falls back to the socket peer rather than
// trusting a header an attacker managed to make unparsable.
func TestRealIPRejectsMalformedChain(t *testing.T) {
	trusted := []net.IPNet{mustCIDR(t, "10.0.0.0/8")}

	for _, header := range []string{
		"not-an-ip",
		"198.51.100.23, garbage, 10.0.0.3",
		"",
	} {
		got := capturedAddr(t, trusted, "10.0.0.2:44321", header)
		if header != "" && got != "10.0.0.2" {
			t.Errorf("X-Forwarded-For %q: RemoteAddr = %q, want the peer 10.0.0.2", header, got)
		}
	}
}

// TestRealIPAllTrustedFallsBackToPeer covers a chain that contains only our own
// proxies, which means no client address was ever recorded.
func TestRealIPAllTrustedFallsBackToPeer(t *testing.T) {
	trusted := []net.IPNet{mustCIDR(t, "10.0.0.0/8")}

	got := capturedAddr(t, trusted, "10.0.0.2:44321", "10.0.0.5, 10.0.0.3")
	if got != "10.0.0.2" {
		t.Errorf("RemoteAddr = %q, want the peer 10.0.0.2", got)
	}
}

func TestRealIPHandlesIPv6Peer(t *testing.T) {
	trusted := []net.IPNet{mustCIDR(t, "2001:db8::/32")}

	got := capturedAddr(t, trusted, "[2001:db8::1]:44321", "198.51.100.23")
	if got != "198.51.100.23" {
		t.Errorf("RemoteAddr = %q, want 198.51.100.23", got)
	}
}
