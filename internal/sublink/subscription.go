package sublink

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Subscription is everything a rendered profile needs.
type Subscription struct {
	Endpoints []Endpoint
	UserInfo  UserInfo

	// Title names the profile in clients that show one.
	Title string

	// UpdateInterval is how often a client should refetch, in hours. Zero omits the
	// header and leaves the client's own default in place.
	UpdateInterval int
}

// UserInfo is the quota summary clients display.
type UserInfo struct {
	Upload   int64
	Download int64

	// Total is the traffic limit in bytes. Zero means unlimited, which is expressed to
	// clients as a total of 0.
	Total int64

	// Expire is when the subscription lapses. The zero time means never.
	Expire time.Time
}

// Render produces the body for a format.
func Render(sub *Subscription, format Format) ([]byte, error) {
	switch format {
	case FormatBase64:
		return RenderBase64(sub)
	case FormatClash:
		return RenderClash(sub)
	case FormatSingBox:
		return RenderSingBox(filterForSingBox(sub))
	case FormatJSON:
		return RenderJSON(sub)
	default:
		return nil, fmt.Errorf("sublink: unknown format %q", format)
	}
}

// RenderBase64 renders the share links as base64 of a newline-separated list.
//
// Standard base64 with padding, not the URL-safe alphabet: this is a body, not a URL
// component, and clients decode it with a plain base64 decoder.
func RenderBase64(sub *Subscription) ([]byte, error) {
	links := make([]string, 0, len(sub.Endpoints))
	for i := range sub.Endpoints {
		uri, err := sub.Endpoints[i].URI()
		if err != nil {
			return nil, err
		}
		links = append(links, uri)
	}

	// A trailing newline keeps clients that split naively from producing an empty
	// final entry, and joining with "\n" is what every client expects.
	joined := strings.Join(links, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(joined))
	return []byte(encoded), nil
}

// RenderPlainLinks renders the share links without base64. Useful for debugging and
// for the public page, which shows the links to a human.
func RenderPlainLinks(sub *Subscription) ([]string, error) {
	links := make([]string, 0, len(sub.Endpoints))
	for i := range sub.Endpoints {
		uri, err := sub.Endpoints[i].URI()
		if err != nil {
			return nil, err
		}
		links = append(links, uri)
	}
	return links, nil
}

// jsonEndpoint is the structured representation of one endpoint.
//
// It is a hand-written shape rather than the Endpoint struct itself, so that adding an
// internal field does not silently change a published API.
type jsonEndpoint struct {
	Remark    string `json:"remark"`
	Link      string `json:"link"`
	Protocol  string `json:"protocol"`
	Transport string `json:"transport"`
	Security  string `json:"security"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
}

type jsonSubscription struct {
	Title     string         `json:"title,omitempty"`
	Endpoints []jsonEndpoint `json:"endpoints"`
	UserInfo  jsonUserInfo   `json:"user_info"`
}

type jsonUserInfo struct {
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
	Total    int64  `json:"total"`
	Used     int64  `json:"used"`
	Expire   string `json:"expire,omitempty"`
}

// RenderJSON renders the panel's own structured format.
func RenderJSON(sub *Subscription) ([]byte, error) {
	endpoints := make([]jsonEndpoint, 0, len(sub.Endpoints))
	for i := range sub.Endpoints {
		endpoint := &sub.Endpoints[i]

		uri, err := endpoint.URI()
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, jsonEndpoint{
			Remark:    endpoint.Remark,
			Link:      uri,
			Protocol:  string(endpoint.Protocol),
			Transport: string(endpoint.Transport),
			Security:  string(endpoint.Security),
			Address:   endpoint.Address,
			Port:      endpoint.Port,
		})
	}

	info := jsonUserInfo{
		Upload:   sub.UserInfo.Upload,
		Download: sub.UserInfo.Download,
		Total:    sub.UserInfo.Total,
		Used:     sub.UserInfo.Upload + sub.UserInfo.Download,
	}
	if !sub.UserInfo.Expire.IsZero() {
		info.Expire = sub.UserInfo.Expire.UTC().Format(time.RFC3339)
	}

	encoded, err := json.MarshalIndent(jsonSubscription{
		Title:     sub.Title,
		Endpoints: endpoints,
		UserInfo:  info,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sublink: encode json subscription: %w", err)
	}
	return encoded, nil
}

// filterForSingBox drops endpoints sing-box cannot express, leaving the rest usable.
func filterForSingBox(sub *Subscription) *Subscription {
	filtered := *sub
	filtered.Endpoints = make([]Endpoint, 0, len(sub.Endpoints))

	for i := range sub.Endpoints {
		if SupportedBySingBox(&sub.Endpoints[i]) {
			filtered.Endpoints = append(filtered.Endpoints, sub.Endpoints[i])
		}
	}
	return &filtered
}

// UserInfoHeader renders the subscription-userinfo header value.
//
// The format is the de facto one every client implements: semicolon-separated
// key=value pairs with byte counts and a Unix expiry. Clients parse it loosely, but an
// omitted field shows as unknown rather than as zero, so all four are always present.
func (u UserInfo) UserInfoHeader() string {
	expire := "0"
	if !u.Expire.IsZero() {
		expire = strconv.FormatInt(u.Expire.Unix(), 10)
	}

	return strings.Join([]string{
		"upload=" + strconv.FormatInt(u.Upload, 10),
		"download=" + strconv.FormatInt(u.Download, 10),
		// Zero total is how "unlimited" is expressed; clients show no quota bar.
		"total=" + strconv.FormatInt(u.Total, 10),
		"expire=" + expire,
	}, "; ")
}

// ProfileTitleHeader renders the profile-title header value.
//
// Non-ASCII titles are base64-encoded with the "base64:" prefix, which is the
// convention clients understand. A raw UTF-8 header value is not legal and gets
// mangled or dropped by proxies.
func ProfileTitleHeader(title string) string {
	if title == "" {
		return ""
	}
	if isASCIIPrintable(title) {
		return title
	}
	return "base64:" + base64.StdEncoding.EncodeToString([]byte(title))
}

func isASCIIPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// TemplateContext holds the values a remark or address template can reference.
type TemplateContext struct {
	Username string
	NodeName string
	Country  string
}

// ExpandTemplate substitutes the supported placeholders.
//
// Unknown placeholders are left alone rather than blanked. A typo then shows up in the
// client as a visible {NDOE} instead of silently producing a remark with a hole in it,
// which is the difference between a mistake someone notices and one they do not.
func ExpandTemplate(template string, ctx TemplateContext) string {
	if template == "" {
		return ""
	}
	return strings.NewReplacer(
		"{USERNAME}", ctx.Username,
		"{NODE}", ctx.NodeName,
		"{COUNTRY}", ctx.Country,
	).Replace(template)
}
