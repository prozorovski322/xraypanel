package sublink

import (
	"strings"
	"testing"
)

// TestFormatForRealUserAgents uses agent strings as real clients actually send them.
//
// Made-up agents would test the matcher against itself. These are the strings that
// decide whether a user's import works, so they are the ones worth pinning.
func TestFormatForRealUserAgents(t *testing.T) {
	cases := []struct {
		agent string
		want  Format
	}{
		// Link-list clients.
		{"v2rayNG/1.8.23", FormatBase64},
		{"v2rayN/6.45", FormatBase64},
		{"v2rayU/4.0.1", FormatBase64},
		{"nekoray/3.26", FormatBase64},
		{"NekoBox/Android/1.2.0", FormatBase64},
		{"Shadowrocket/2.2.36 CFNetwork/1410 Darwin/22.6.0", FormatBase64},
		{"Streisand/1.6.0", FormatBase64},
		{"Happ/1.10.0", FormatBase64},
		{"Loon/637", FormatBase64},
		{"Quantumult%20X/1.0.30", FormatBase64},
		{"V2Box/1.0.0", FormatBase64},

		// NekoBox announces the format it wants, and we honour that rather than
		// overriding it with the lowest common denominator.
		{"NekoBox/Android/1.3.1 (Prefer ClashMeta Format)", FormatClash},

		// Clash family.
		{"Clash/1.11.0", FormatClash},
		{"ClashforWindows/0.19.23", FormatClash},
		{"clash-verge/1.3.8", FormatClash},
		{"Clash.Meta/1.16.0", FormatClash},
		{"mihomo/1.18.1", FormatClash},
		{"Stash/2.5.0 Clash/1.11.0", FormatClash},
		{"FlClash/0.8.60", FormatClash},

		// sing-box family. SFI, SFA and SFM are the official iOS, Android and macOS
		// builds.
		{"sing-box 1.8.0", FormatSingBox},
		{"SFI/1.9.0 (239; sing-box 1.8.9)", FormatSingBox},
		{"SFA/1.8.0 (35; sing-box 1.8.0)", FormatSingBox},
		{"SFM/1.8.0", FormatSingBox},
		{"Hiddify-Next/2.0.5", FormatSingBox},
		{"karing/1.0.20", FormatSingBox},

		// Anything unrecognised gets the widest format rather than a guess.
		{"", FormatBase64},
		{"   ", FormatBase64},
		{"curl/8.4.0", FormatBase64},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", FormatBase64},
		{"Go-http-client/2.0", FormatBase64},
		{"some-client-nobody-has-heard-of/1.0", FormatBase64},
	}

	for _, tc := range cases {
		t.Run(tc.agent, func(t *testing.T) {
			if got := FormatFor(tc.agent); got != tc.want {
				t.Errorf("FormatFor(%q) = %q, want %q", tc.agent, got, tc.want)
			}
		})
	}
}

// TestFormatForIsCaseInsensitive matters because agent capitalisation varies between
// builds of the same client.
func TestFormatForIsCaseInsensitive(t *testing.T) {
	variants := []string{"CLASH/1.11.0", "clash/1.11.0", "Clash/1.11.0", "cLaSh/1.11.0"}
	for _, agent := range variants {
		if got := FormatFor(agent); got != FormatClash {
			t.Errorf("FormatFor(%q) = %q, want clash", agent, got)
		}
	}
}

func TestParseFormat(t *testing.T) {
	valid := map[string]Format{
		"base64":     FormatBase64,
		"BASE64":     FormatBase64,
		" links ":    FormatBase64,
		"v2ray":      FormatBase64,
		"clash":      FormatClash,
		"mihomo":     FormatClash,
		"clash.meta": FormatClash,
		"singbox":    FormatSingBox,
		"sing-box":   FormatSingBox,
		"json":       FormatJSON,
	}
	for value, want := range valid {
		got, ok := ParseFormat(value)
		if !ok {
			t.Errorf("ParseFormat(%q) reported it as unknown", value)
			continue
		}
		if got != want {
			t.Errorf("ParseFormat(%q) = %q, want %q", value, got, want)
		}
	}

	// An unrecognised value is reported rather than silently defaulted: a typo in a
	// query parameter should not look like it worked.
	for _, value := range []string{"", "yaml", "xray", "surge", "clashx"} {
		if _, ok := ParseFormat(value); ok {
			t.Errorf("ParseFormat(%q) accepted an unknown format", value)
		}
	}
}

func TestContentType(t *testing.T) {
	cases := map[Format]string{
		FormatBase64:  "text/plain; charset=utf-8",
		FormatClash:   "text/yaml; charset=utf-8",
		FormatSingBox: "application/json; charset=utf-8",
		FormatJSON:    "application/json; charset=utf-8",
	}
	for format, want := range cases {
		if got := format.ContentType(); got != want {
			t.Errorf("%q.ContentType() = %q, want %q", format, got, want)
		}
	}
}

// TestEveryMarkerIsReachable catches a marker shadowed by an earlier, broader one,
// which would silently make an entry in the table dead.
func TestEveryMarkerIsReachable(t *testing.T) {
	for i, candidate := range clientMarkers {
		got := FormatFor(candidate.marker)
		if got == candidate.format {
			continue
		}
		// Find which earlier marker swallowed it, so the failure names the culprit.
		for j := 0; j < i; j++ {
			if strings.Contains(candidate.marker, clientMarkers[j].marker) {
				t.Errorf("marker %q (index %d) is shadowed by %q (index %d): resolves to %q, not %q",
					candidate.marker, i, clientMarkers[j].marker, j, got, candidate.format)
				break
			}
		}
	}
}
