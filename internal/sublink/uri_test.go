package sublink

import (
	"net/url"
	"strings"
	"testing"
)

// realityEndpoint is the flagship combination: VLESS over raw TCP with Reality and
// Vision flow.
func realityEndpoint() Endpoint {
	return Endpoint{
		Remark:      "DE-1",
		Address:     "de1.example.com",
		Port:        443,
		Protocol:    ProtocolVLESS,
		Transport:   TransportTCP,
		Security:    SecurityReality,
		UUID:        "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37",
		Flow:        "xtls-rprx-vision",
		SNI:         "www.cloudflare.com",
		Fingerprint: "chrome",
		PublicKey:   "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
		ShortID:     "0123456789abcdef",
	}
}

// parseURI splits a share link so assertions can name parameters instead of matching
// whole strings.
func parseURI(t *testing.T, raw string) (*url.URL, url.Values) {
	t.Helper()

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("generated link does not parse as a URI (%v): %s", err, raw)
	}
	return parsed, parsed.Query()
}

// TestVLESSRealityURI pins every parameter name against the VLESS share link
// specification. The names are the whole contract: a client given "publicKey" instead
// of "pbk" fails to connect and says nothing useful about why.
func TestVLESSRealityURI(t *testing.T) {
	endpoint := realityEndpoint()

	raw, err := endpoint.URI()
	if err != nil {
		t.Fatalf("URI: %v", err)
	}

	parsed, params := parseURI(t, raw)

	if parsed.Scheme != "vless" {
		t.Errorf("scheme = %q, want vless", parsed.Scheme)
	}
	if parsed.User.Username() != endpoint.UUID {
		t.Errorf("userinfo = %q, want the uuid %q", parsed.User.Username(), endpoint.UUID)
	}
	if parsed.Host != "de1.example.com:443" {
		t.Errorf("host = %q, want de1.example.com:443", parsed.Host)
	}
	if parsed.Fragment != "DE-1" {
		t.Errorf("fragment = %q, want DE-1", parsed.Fragment)
	}

	want := map[string]string{
		"type":       "tcp",
		"security":   "reality",
		"encryption": "none",
		"flow":       "xtls-rprx-vision",
		"sni":        "www.cloudflare.com",
		"fp":         "chrome",
		"pbk":        "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
		"sid":        "0123456789abcdef",
	}
	for key, value := range want {
		if got := params.Get(key); got != value {
			t.Errorf("param %s = %q, want %q", key, got, value)
		}
	}

	// Parameters that only make sense elsewhere must be absent, not empty.
	for _, key := range []string{"path", "host", "serviceName", "mode", "allowInsecure", "spx"} {
		if _, present := params[key]; present {
			t.Errorf("param %s should be absent for tcp+reality, got %q", key, params.Get(key))
		}
	}
}

// TestParamsAreSorted keeps a link byte-stable. A link that changes shape between
// requests looks to a client like a different server.
func TestParamsAreSorted(t *testing.T) {
	endpoint := realityEndpoint()
	raw, err := endpoint.URI()
	if err != nil {
		t.Fatalf("URI: %v", err)
	}

	query := raw[strings.Index(raw, "?")+1 : strings.Index(raw, "#")]
	pairs := strings.Split(query, "&")

	var previous string
	for _, pair := range pairs {
		key := strings.SplitN(pair, "=", 2)[0]
		if previous != "" && key < previous {
			t.Errorf("parameters are not sorted: %q comes after %q in %s", key, previous, query)
		}
		previous = key
	}
}

// TestEncodeURIComponentSemantics is the encoding contract from the specification:
// values use encodeURIComponent, where a space is %20 and a slash is %2F. Form
// encoding would put a literal plus sign in a client's path or remark.
func TestEncodeURIComponentSemantics(t *testing.T) {
	endpoint := Endpoint{
		Remark:    "DE 1 / Berlin",
		Address:   "de1.example.com",
		Port:      8443,
		Protocol:  ProtocolVLESS,
		Transport: TransportWS,
		Security:  SecurityTLS,
		UUID:      "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37",
		Path:      "/ws path",
		Host:      "cdn.example.com",
		SNI:       "cdn.example.com",
		ALPN:      []string{"h2", "http/1.1"},
	}

	raw, err := endpoint.URI()
	if err != nil {
		t.Fatalf("URI: %v", err)
	}

	if strings.Contains(raw, "+") {
		t.Errorf("link contains a literal plus, so form encoding leaked in: %s", raw)
	}
	if !strings.Contains(raw, "%20") {
		t.Errorf("a space was not encoded as %%20: %s", raw)
	}
	if !strings.Contains(raw, "%2F") {
		t.Errorf("a slash in a value was not encoded as %%2F: %s", raw)
	}

	// And it must all decode back to the original values.
	_, params := parseURI(t, raw)
	if got := params.Get("path"); got != "/ws path" {
		t.Errorf("path decoded to %q, want %q", got, "/ws path")
	}
	if got := params.Get("alpn"); got != "h2,http/1.1" {
		t.Errorf("alpn = %q, want comma separated with no spaces", got)
	}

	parsed, _ := parseURI(t, raw)
	if parsed.Fragment != "DE 1 / Berlin" {
		t.Errorf("fragment decoded to %q, want %q", parsed.Fragment, "DE 1 / Berlin")
	}
}

func TestTransportParams(t *testing.T) {
	base := func() Endpoint {
		return Endpoint{
			Remark:   "n",
			Address:  "a.example.com",
			Port:     443,
			Protocol: ProtocolVLESS,
			Security: SecurityTLS,
			UUID:     "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37",
			SNI:      "a.example.com",
		}
	}

	cases := map[string]struct {
		mutate func(*Endpoint)
		want   map[string]string
		absent []string
	}{
		"websocket": {
			mutate: func(e *Endpoint) {
				e.Transport = TransportWS
				e.Path = "/ws"
				e.Host = "cdn.example.com"
			},
			want:   map[string]string{"type": "ws", "path": "/ws", "host": "cdn.example.com"},
			absent: []string{"serviceName", "mode"},
		},
		"grpc": {
			mutate: func(e *Endpoint) {
				e.Transport = TransportGRPC
				e.ServiceName = "GunService"
			},
			want:   map[string]string{"type": "grpc", "serviceName": "GunService"},
			absent: []string{"path", "host"},
		},
		"httpupgrade": {
			mutate: func(e *Endpoint) {
				e.Transport = TransportHTTPUpgrade
				e.Path = "/hu"
				e.Host = "cdn.example.com"
			},
			want:   map[string]string{"type": "httpupgrade", "path": "/hu", "host": "cdn.example.com"},
			absent: []string{"serviceName"},
		},
		"xhttp": {
			mutate: func(e *Endpoint) {
				e.Transport = TransportXHTTP
				e.Path = "/xh"
				e.Mode = "auto"
			},
			want:   map[string]string{"type": "xhttp", "path": "/xh", "mode": "auto"},
			absent: []string{"serviceName"},
		},
		"raw tcp": {
			mutate: func(e *Endpoint) { e.Transport = TransportTCP },
			want:   map[string]string{"type": "tcp"},
			absent: []string{"path", "host", "serviceName", "mode"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			endpoint := base()
			tc.mutate(&endpoint)

			raw, err := endpoint.URI()
			if err != nil {
				t.Fatalf("URI: %v", err)
			}
			_, params := parseURI(t, raw)

			for key, value := range tc.want {
				if got := params.Get(key); got != value {
					t.Errorf("param %s = %q, want %q", key, got, value)
				}
			}
			for _, key := range tc.absent {
				if _, present := params[key]; present {
					t.Errorf("param %s should be absent", key)
				}
			}
		})
	}
}

func TestTrojanURI(t *testing.T) {
	endpoint := Endpoint{
		Remark:    "TJ",
		Address:   "tj.example.com",
		Port:      9443,
		Protocol:  ProtocolTrojan,
		Transport: TransportWS,
		Security:  SecurityTLS,
		Password:  "p@ss:word/with+specials",
		Path:      "/tj",
		SNI:       "tj.example.com",
	}

	raw, err := endpoint.URI()
	if err != nil {
		t.Fatalf("URI: %v", err)
	}

	parsed, params := parseURI(t, raw)
	if parsed.Scheme != "trojan" {
		t.Errorf("scheme = %q, want trojan", parsed.Scheme)
	}
	// The password sits in userinfo and has to survive characters that would otherwise
	// terminate it.
	if got := parsed.User.Username(); got != endpoint.Password {
		t.Errorf("password decoded to %q, want %q", got, endpoint.Password)
	}
	if params.Get("type") != "ws" {
		t.Errorf("type = %q, want ws", params.Get("type"))
	}
	// A trojan link must not claim an encryption parameter; that one is VLESS only.
	if _, present := params["encryption"]; present {
		t.Error("encryption parameter leaked into a trojan link")
	}
}

// TestShadowsocks2022URI pins the SIP002 rule for the 2022 methods: userinfo is NOT
// base64url encoded, and method and password are percent encoded instead.
func TestShadowsocks2022URI(t *testing.T) {
	endpoint := Endpoint{
		Remark:      "SS",
		Address:     "ss.example.com",
		Port:        8388,
		Protocol:    ProtocolShadowsocks,
		SSMethod:    "2022-blake3-aes-128-gcm",
		SSServerKey: "YctPZ6U7xPPcU+gp3u+0tw==",
		SSUserKey:   "tx/tRizJN9K8y+uKlW2qjg==",
	}

	raw, err := endpoint.URI()
	if err != nil {
		t.Fatalf("URI: %v", err)
	}

	if !strings.HasPrefix(raw, "ss://2022-blake3-aes-128-gcm:") {
		t.Errorf("the method is not in clear userinfo, so the link is not SIP002 compliant for 2022: %s", raw)
	}

	// Base64 characters in the keys must be percent encoded, since they are not
	// unreserved and would otherwise break the URI.
	for _, encoded := range []string{"%2B", "%2F", "%3D", "%3A"} {
		if !strings.Contains(raw, encoded) {
			t.Errorf("expected %s in the percent-encoded userinfo: %s", encoded, raw)
		}
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("link does not parse: %v", err)
	}
	if parsed.Scheme != "ss" {
		t.Errorf("scheme = %q, want ss", parsed.Scheme)
	}

	// The password is the server key and the user key joined by a colon, per the
	// identity-header convention, and it has to survive the round trip intact.
	password, hasPassword := parsed.User.Password()
	if !hasPassword {
		t.Fatalf("no password in userinfo: %s", raw)
	}
	want := endpoint.SSServerKey + ":" + endpoint.SSUserKey
	if password != want {
		t.Errorf("password decoded to %q, want %q", password, want)
	}
	if parsed.User.Username() != endpoint.SSMethod {
		t.Errorf("method decoded to %q, want %q", parsed.User.Username(), endpoint.SSMethod)
	}
}

func TestShadowsocksRejectsLegacyAndMissingKeys(t *testing.T) {
	base := Endpoint{
		Remark:      "SS",
		Address:     "ss.example.com",
		Port:        8388,
		Protocol:    ProtocolShadowsocks,
		SSMethod:    "2022-blake3-aes-128-gcm",
		SSServerKey: "c2VydmVy",
		SSUserKey:   "dXNlcg==",
	}

	cases := map[string]func(*Endpoint){
		"legacy method": func(e *Endpoint) { e.SSMethod = "aes-128-gcm" },
		"no method":     func(e *Endpoint) { e.SSMethod = "" },
		"no server key": func(e *Endpoint) { e.SSServerKey = "" },
		"no user key":   func(e *Endpoint) { e.SSUserKey = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			endpoint := base
			mutate(&endpoint)
			if _, err := endpoint.URI(); err == nil {
				t.Error("URI accepted an endpoint it should have refused")
			}
		})
	}
}

func TestURIRejectsMissingCredentials(t *testing.T) {
	cases := map[string]Endpoint{
		"vless without uuid": {
			Remark: "x", Address: "a", Port: 1, Protocol: ProtocolVLESS,
			Transport: TransportTCP, Security: SecurityNone,
		},
		"trojan without password": {
			Remark: "x", Address: "a", Port: 1, Protocol: ProtocolTrojan,
			Transport: TransportTCP, Security: SecurityTLS,
		},
		"unknown protocol": {
			Remark: "x", Address: "a", Port: 1, Protocol: "vmess",
		},
	}
	for name, endpoint := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := endpoint.URI(); err == nil {
				t.Error("URI accepted an endpoint with no usable credentials")
			}
		})
	}
}

// TestIPv6AddressIsBracketed keeps the port parsable.
func TestIPv6AddressIsBracketed(t *testing.T) {
	endpoint := realityEndpoint()
	endpoint.Address = "2001:db8::1"

	raw, err := endpoint.URI()
	if err != nil {
		t.Fatalf("URI: %v", err)
	}
	if !strings.Contains(raw, "[2001:db8::1]:443") {
		t.Errorf("IPv6 address is not bracketed: %s", raw)
	}

	parsed, _ := parseURI(t, raw)
	if parsed.Port() != "443" {
		t.Errorf("port parsed as %q, want 443", parsed.Port())
	}
}

func TestAlreadyBracketedIPv6IsNotDoubled(t *testing.T) {
	endpoint := realityEndpoint()
	endpoint.Address = "[2001:db8::1]"

	raw, err := endpoint.URI()
	if err != nil {
		t.Fatalf("URI: %v", err)
	}
	if strings.Contains(raw, "[[") {
		t.Errorf("an already bracketed address was bracketed again: %s", raw)
	}
}

func TestAllowInsecureAndSpiderX(t *testing.T) {
	endpoint := realityEndpoint()
	endpoint.AllowInsecure = true
	endpoint.SpiderX = "/spider path"

	raw, err := endpoint.URI()
	if err != nil {
		t.Fatalf("URI: %v", err)
	}
	_, params := parseURI(t, raw)

	if params.Get("allowInsecure") != "1" {
		t.Errorf("allowInsecure = %q, want 1", params.Get("allowInsecure"))
	}
	if params.Get("spx") != "/spider path" {
		t.Errorf("spx = %q, want the decoded spider path", params.Get("spx"))
	}
}
