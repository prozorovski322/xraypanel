package sublink

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRenderBase64(t *testing.T) {
	sub := testSubscription()

	body, err := Render(sub, FormatBase64)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// Standard base64 with padding: this is a body, and clients decode it with a plain
	// decoder rather than a URL-safe one.
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Fatalf("body is not standard base64: %v", err)
	}

	lines := strings.Split(string(decoded), "\n")
	if len(lines) != len(sub.Endpoints) {
		t.Fatalf("got %d links, want %d", len(lines), len(sub.Endpoints))
	}

	schemes := map[string]bool{}
	for _, line := range lines {
		if line == "" {
			t.Error("the decoded list contains an empty line")
			continue
		}
		scheme, _, found := strings.Cut(line, "://")
		if !found {
			t.Errorf("line is not a share link: %q", line)
			continue
		}
		schemes[scheme] = true
	}

	for _, want := range []string{"vless", "trojan", "ss"} {
		if !schemes[want] {
			t.Errorf("no %s:// link in the list", want)
		}
	}
}

func TestRenderBase64Empty(t *testing.T) {
	body, err := Render(&Subscription{}, FormatBase64)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Fatalf("empty body is not valid base64: %v", err)
	}
	if len(decoded) != 0 {
		t.Errorf("an empty subscription decoded to %q, want nothing", decoded)
	}
}

func TestRenderJSON(t *testing.T) {
	sub := testSubscription()
	sub.UserInfo = UserInfo{
		Upload:   1 << 30,
		Download: 5 << 30,
		Total:    100 << 30,
		Expire:   time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	body, err := Render(sub, FormatJSON)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	var parsed struct {
		Title     string `json:"title"`
		Endpoints []struct {
			Remark   string `json:"remark"`
			Link     string `json:"link"`
			Protocol string `json:"protocol"`
			Port     int    `json:"port"`
		} `json:"endpoints"`
		UserInfo struct {
			Upload   int64  `json:"upload"`
			Download int64  `json:"download"`
			Total    int64  `json:"total"`
			Used     int64  `json:"used"`
			Expire   string `json:"expire"`
		} `json:"user_info"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body is not valid JSON (%v): %s", err, body)
	}

	if len(parsed.Endpoints) != len(sub.Endpoints) {
		t.Errorf("got %d endpoints, want %d", len(parsed.Endpoints), len(sub.Endpoints))
	}
	for _, endpoint := range parsed.Endpoints {
		if endpoint.Link == "" {
			t.Errorf("endpoint %q has no link", endpoint.Remark)
		}
	}
	if parsed.UserInfo.Used != parsed.UserInfo.Upload+parsed.UserInfo.Download {
		t.Error("used is not the sum of upload and download")
	}
	if parsed.UserInfo.Expire != "2026-12-31T23:59:59Z" {
		t.Errorf("expire = %q, want RFC3339 in UTC", parsed.UserInfo.Expire)
	}
}

// TestUserInfoHeader pins the de facto format every client parses.
func TestUserInfoHeader(t *testing.T) {
	expire := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)

	info := UserInfo{Upload: 123, Download: 456, Total: 789, Expire: expire}
	got := info.UserInfoHeader()

	want := "upload=123; download=456; total=789; expire=" + itoa64(expire.Unix())
	if got != want {
		t.Errorf("UserInfoHeader() = %q, want %q", got, want)
	}

	// All four fields are always present: an omitted one shows in a client as unknown
	// rather than as zero.
	for _, field := range []string{"upload=", "download=", "total=", "expire="} {
		if !strings.Contains(got, field) {
			t.Errorf("header is missing %s: %q", field, got)
		}
	}
}

// TestUserInfoHeaderUnlimited covers the case a client renders as "no quota".
func TestUserInfoHeaderUnlimited(t *testing.T) {
	got := UserInfo{Upload: 10, Download: 20}.UserInfoHeader()

	if !strings.Contains(got, "total=0") {
		t.Errorf("an unlimited account must report total=0: %q", got)
	}
	if !strings.Contains(got, "expire=0") {
		t.Errorf("a non-expiring account must report expire=0: %q", got)
	}
}

func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	negative := v < 0
	if negative {
		v = -v
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}

// TestProfileTitleHeader covers the encoding rule: a raw UTF-8 header value is not
// legal and gets mangled or dropped in transit.
func TestProfileTitleHeader(t *testing.T) {
	if got := ProfileTitleHeader(""); got != "" {
		t.Errorf("an empty title produced %q", got)
	}
	if got := ProfileTitleHeader("xraypanel"); got != "xraypanel" {
		t.Errorf("an ASCII title was encoded unnecessarily: %q", got)
	}

	got := ProfileTitleHeader("Моя подписка")
	if !strings.HasPrefix(got, "base64:") {
		t.Fatalf("a non-ASCII title was not base64 encoded: %q", got)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "base64:"))
	if err != nil {
		t.Fatalf("encoded title does not decode: %v", err)
	}
	if string(decoded) != "Моя подписка" {
		t.Errorf("decoded title = %q, want the original", decoded)
	}
}

func TestExpandTemplate(t *testing.T) {
	ctx := TemplateContext{Username: "alice", NodeName: "de-1", Country: "DE"}

	cases := map[string]string{
		"{NODE}":                        "de-1",
		"{COUNTRY} {NODE}":              "DE de-1",
		"{USERNAME}@{NODE}":             "alice@de-1",
		"{COUNTRY}-{NODE} ({USERNAME})": "DE-de-1 (alice)",
		"no placeholders":               "no placeholders",
		"":                              "",
		// Repeated placeholders all expand.
		"{NODE}/{NODE}": "de-1/de-1",
	}
	for template, want := range cases {
		if got := ExpandTemplate(template, ctx); got != want {
			t.Errorf("ExpandTemplate(%q) = %q, want %q", template, got, want)
		}
	}
}

// TestExpandTemplateLeavesUnknownPlaceholders is deliberate: a typo shows up in the
// client as a visible {NDOE} rather than silently leaving a hole in the remark.
func TestExpandTemplateLeavesUnknownPlaceholders(t *testing.T) {
	ctx := TemplateContext{Username: "alice", NodeName: "de-1", Country: "DE"}

	got := ExpandTemplate("{NDOE} {NODE} {CITY}", ctx)
	want := "{NDOE} de-1 {CITY}"
	if got != want {
		t.Errorf("ExpandTemplate = %q, want %q", got, want)
	}
}

func TestExpandTemplateWithEmptyContext(t *testing.T) {
	// An unnamed node or a user without a country yields an empty substitution rather
	// than a literal placeholder, so the remark stays presentable.
	got := ExpandTemplate("{COUNTRY}-{NODE}", TemplateContext{})
	if got != "-" {
		t.Errorf("ExpandTemplate = %q, want %q", got, "-")
	}
}

func TestRenderRejectsUnknownFormat(t *testing.T) {
	if _, err := Render(testSubscription(), Format("surge")); err == nil {
		t.Error("Render accepted an unknown format")
	}
}

// TestRenderPropagatesEndpointErrors keeps a broken endpoint from being silently
// dropped from a profile: a user who is missing one server would never know.
func TestRenderPropagatesEndpointErrors(t *testing.T) {
	sub := &Subscription{Endpoints: []Endpoint{
		{Remark: "ok", Address: "a.example.com", Port: 443, Protocol: ProtocolVLESS,
			Transport: TransportTCP, Security: SecurityNone,
			UUID: "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37"},
		{Remark: "broken", Address: "b.example.com", Port: 443, Protocol: ProtocolVLESS,
			Transport: TransportTCP, Security: SecurityNone},
	}}

	for _, format := range []Format{FormatBase64, FormatJSON} {
		if _, err := Render(sub, format); err == nil {
			t.Errorf("format %q silently skipped an endpoint with no uuid", format)
		}
	}
}

// TestClashNamesAreMadeUnique matters because Clash keys proxies by name and keeps only
// one of a duplicate pair, so a user with two hosts sharing a remark would silently
// lose one.
func TestClashNamesAreMadeUnique(t *testing.T) {
	sub := &Subscription{Endpoints: []Endpoint{
		{Remark: "DE", Address: "a.example.com", Port: 443, Protocol: ProtocolVLESS,
			Transport: TransportTCP, Security: SecurityNone, UUID: "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37"},
		{Remark: "DE", Address: "b.example.com", Port: 443, Protocol: ProtocolVLESS,
			Transport: TransportTCP, Security: SecurityNone, UUID: "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37"},
		{Remark: "DE", Address: "c.example.com", Port: 443, Protocol: ProtocolVLESS,
			Transport: TransportTCP, Security: SecurityNone, UUID: "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37"},
	}}

	body, err := Render(sub, FormatClash)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	text := string(body)

	for _, want := range []string{"name: DE\n", "DE (2)", "DE (3)"} {
		if !strings.Contains(text, want) {
			t.Errorf("expected a proxy named %q in:\n%s", want, text)
		}
	}
}

func TestSingBoxTagsAreMadeUnique(t *testing.T) {
	sub := &Subscription{Endpoints: []Endpoint{
		{Remark: "DE", Address: "a.example.com", Port: 443, Protocol: ProtocolVLESS,
			Transport: TransportTCP, Security: SecurityNone, UUID: "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37"},
		{Remark: "DE", Address: "b.example.com", Port: 443, Protocol: ProtocolVLESS,
			Transport: TransportTCP, Security: SecurityNone, UUID: "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37"},
	}}

	body, err := Render(sub, FormatSingBox)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(string(body), `"DE (2)"`) {
		t.Errorf("duplicate sing-box tags were not disambiguated:\n%s", body)
	}
}

// TestRealityAlwaysCarriesUTLSInSingBox guards a combination that loads and then fails
// every handshake.
func TestRealityAlwaysCarriesUTLSInSingBox(t *testing.T) {
	sub := &Subscription{Endpoints: []Endpoint{{
		Remark: "R", Address: "a.example.com", Port: 443,
		Protocol: ProtocolVLESS, Transport: TransportTCP, Security: SecurityReality,
		UUID:      "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37",
		PublicKey: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
		ShortID:   "aabb",
		// Fingerprint deliberately left empty.
	}}}

	body, err := Render(sub, FormatSingBox)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	outbounds, _ := document["outbounds"].([]any)

	var checked bool
	for _, entry := range outbounds {
		outbound, _ := entry.(map[string]any)
		if outbound["type"] != "vless" {
			continue
		}
		checked = true

		tls, _ := outbound["tls"].(map[string]any)
		reality, _ := tls["reality"].(map[string]any)
		if reality["enabled"] != true {
			t.Error("reality is not enabled")
		}
		utls, _ := tls["utls"].(map[string]any)
		if utls["enabled"] != true {
			t.Error("reality without an enabled utls block would fail every handshake")
		}
		if utls["fingerprint"] == "" || utls["fingerprint"] == nil {
			t.Error("utls has no fingerprint")
		}
	}
	if !checked {
		t.Fatal("no vless outbound in the profile")
	}
}
