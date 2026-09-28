package httpapi

import (
	"strings"
	"testing"

	"github.com/xraypanel/panel/internal/sublink"
)

func TestRedactPathHidesTheSubscriptionToken(t *testing.T) {
	cases := map[string]string{
		"/sub/abcdefghijkmnpqrstuvwx":      "/sub/[token]",
		"/sub/abcdefghijkmnpqrstuvwx/info": "/sub/[token]/info",
		"/sub/":                            "/sub/[token]",
		"/api/v1/users/7":                  "/api/v1/users/7",
		"/subscriptions":                   "/subscriptions",
	}
	for in, want := range cases {
		if got := redactPath(in); got != want {
			t.Errorf("redactPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientKeyGroupsIPv6ByPrefix(t *testing.T) {
	cases := []struct{ remote, want string }{
		{"203.0.113.7:51234", "203.0.113.7"},
		{"[2001:db8:1:2:aaaa::1]:443", "2001:db8:1:2::/64"},
		{"[2001:db8:1:2:bbbb::9]:443", "2001:db8:1:2::/64"},
		// IPv4-mapped addresses count as the IPv4 client they are.
		{"[::ffff:203.0.113.7]:1", "203.0.113.7"},
	}
	for _, c := range cases {
		if got := clientKey(c.remote); got != c.want {
			t.Errorf("clientKey(%q) = %q, want %q", c.remote, got, c.want)
		}
	}
}

func TestContentDisposition(t *testing.T) {
	if got := contentDisposition("xraypanel", sublink.FormatBase64); got != "" {
		t.Errorf("a link list got a disposition %q; a browser would download what it could show", got)
	}
	if got := contentDisposition("xraypanel", sublink.FormatClash); got != `attachment; filename=xraypanel.yaml` {
		t.Errorf("clash disposition = %q", got)
	}
	if got := contentDisposition("", sublink.FormatSingBox); got != `attachment; filename=subscription.json` {
		t.Errorf("an empty title gave %q", got)
	}
	// A non-ASCII title must not reach the header raw.
	got := contentDisposition("Мой VPN", sublink.FormatClash)
	if !strings.Contains(got, "filename*=utf-8''") {
		t.Errorf("a non-ASCII title gave %q, want an RFC 2231 filename*", got)
	}
}
