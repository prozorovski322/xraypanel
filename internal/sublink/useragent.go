package sublink

import "strings"

// Format is a subscription output format.
type Format string

// Formats.
const (
	// FormatBase64 is base64 of a newline-separated list of share links. It is what
	// v2rayNG, Nekobox, Streisand and most other clients expect, and the default for
	// anything unrecognised.
	FormatBase64 Format = "base64"

	// FormatClash is a Clash / Clash.Meta / mihomo YAML profile.
	FormatClash Format = "clash"

	// FormatSingBox is a sing-box JSON profile.
	FormatSingBox Format = "singbox"

	// FormatJSON is the panel's own structured format, for our own tooling. No client
	// asks for it by user agent; it is reachable only through ?format=json.
	FormatJSON Format = "json"
)

// clientMarkers maps a lowercased user agent substring to a format.
//
// Order matters, so this is a slice rather than a map: several agents carry more than
// one recognisable name.
//
// The Clash markers deliberately sit above Nekobox and Nekoray. Those clients announce
// themselves as "NekoBox/Android/1.3.1 (Prefer ClashMeta Format)", which is the client
// stating which format it wants, and honouring that is better than overriding it with
// the lowest common denominator. A build whose agent carries no such hint falls through
// to its own marker and gets base64.
var clientMarkers = []struct {
	marker string
	format Format
}{
	// sing-box and its wrappers come first: SFI, SFA and SFM are the official
	// Apple and Android builds and their agents are short enough to collide with
	// substrings of other names.
	{"sing-box", FormatSingBox},
	{"sing_box", FormatSingBox},
	{"singbox", FormatSingBox},
	{"sfi/", FormatSingBox},
	{"sfa/", FormatSingBox},
	{"sfm/", FormatSingBox},
	{"sft/", FormatSingBox},
	{"hiddify", FormatSingBox},
	{"karing", FormatSingBox},

	// Clash family. mihomo is the current name of Clash.Meta.
	{"mihomo", FormatClash},
	{"clash.meta", FormatClash},
	{"clash-meta", FormatClash},
	{"clashmeta", FormatClash},
	{"clash", FormatClash},
	{"stash", FormatClash},
	{"flclash", FormatClash},

	// Everything below reads base64 link lists. They are listed explicitly rather
	// than left to the default so that the parser's coverage is visible and testable.
	{"nekobox", FormatBase64},
	{"nekoray", FormatBase64},
	{"v2rayng", FormatBase64},
	{"v2rayn", FormatBase64},
	{"v2rayu", FormatBase64},
	{"v2box", FormatBase64},
	{"shadowrocket", FormatBase64},
	{"streisand", FormatBase64},
	{"happ", FormatBase64},
	{"loon", FormatBase64},
	{"surge", FormatBase64},
	{"quantumult", FormatBase64},
	{"xray", FormatBase64},
}

// FormatFor picks an output format from a User-Agent header.
//
// An unknown or empty agent gets base64. That is the widest format: a client that
// cannot read it is unusual, whereas handing an unknown client YAML guarantees
// failure. Being wrong towards base64 costs a client that could have had a richer
// profile; being wrong the other way costs a client that cannot connect at all.
func FormatFor(userAgent string) Format {
	agent := strings.ToLower(strings.TrimSpace(userAgent))
	if agent == "" {
		return FormatBase64
	}

	for _, candidate := range clientMarkers {
		if strings.Contains(agent, candidate.marker) {
			return candidate.format
		}
	}
	return FormatBase64
}

// ParseFormat resolves an explicit ?format= value.
//
// An explicit request wins over the user agent: it is the escape hatch for a client
// whose agent is unhelpful, and for anyone debugging with curl. An unrecognised value
// is reported rather than silently defaulted, because a typo in a query parameter
// should not look like it worked.
func ParseFormat(value string) (Format, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "base64", "v2ray", "links":
		return FormatBase64, true
	case "clash", "mihomo", "clash.meta", "clashmeta":
		return FormatClash, true
	case "singbox", "sing-box", "sing_box":
		return FormatSingBox, true
	case "json":
		return FormatJSON, true
	default:
		return "", false
	}
}

// ContentType is the media type a format should be served as.
func (f Format) ContentType() string {
	switch f {
	case FormatClash:
		// Clash clients are tolerant here, but the correct type is what a browser
		// needs to display the profile rather than download it.
		return "text/yaml; charset=utf-8"
	case FormatSingBox, FormatJSON:
		return "application/json; charset=utf-8"
	default:
		// A base64 blob is not text a browser should try to render.
		return "text/plain; charset=utf-8"
	}
}
