// Package sublink turns a user's access into the formats real clients import:
// share links, a Clash profile, a sing-box profile, and structured JSON.
//
// The parameter names here are not guesses. They come from the VLESS share link
// specification (XTLS/Xray-core discussion 716) and from SIP002 for Shadowsocks, and
// the values are the same ones the config generator puts on the server side. A link
// whose parameter names are wrong produces a client that fails to connect with no
// useful error anywhere, which is why the names are pinned by tests.
package sublink

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Protocol, Transport and Security mirror the config generator's vocabulary. They are
// redeclared rather than imported so that the link format is free to name things the
// way clients do without dragging the server-side types along.
type (
	Protocol  string
	Transport string
	Security  string
)

// Protocols.
const (
	ProtocolVLESS       Protocol = "vless"
	ProtocolTrojan      Protocol = "trojan"
	ProtocolShadowsocks Protocol = "shadowsocks"
)

// Transports, named as they appear in the type= parameter.
const (
	TransportTCP         Transport = "tcp"
	TransportWS          Transport = "ws"
	TransportGRPC        Transport = "grpc"
	TransportHTTPUpgrade Transport = "httpupgrade"
	TransportXHTTP       Transport = "xhttp"
)

// Security layers.
const (
	SecurityNone    Security = "none"
	SecurityTLS     Security = "tls"
	SecurityReality Security = "reality"
)

// Endpoint is one connectable entry for one user: an inbound as a particular host
// presents it, with that user's credentials filled in.
//
// Remark and Address are already expanded; template substitution happens before an
// Endpoint exists.
type Endpoint struct {
	Remark  string
	Address string
	Port    int

	Protocol  Protocol
	Transport Transport
	Security  Security

	// Credentials. Which ones matter depends on Protocol.
	UUID        string
	Password    string
	SSMethod    string
	SSServerKey string
	SSUserKey   string

	Flow string

	// TLS and Reality.
	SNI           string
	ALPN          []string
	Fingerprint   string
	AllowInsecure bool
	PublicKey     string
	ShortID       string
	SpiderX       string

	// Transport specifics.
	Path        string
	Host        string
	ServiceName string
	Mode        string
}

// URI renders the endpoint as a share link.
func (e *Endpoint) URI() (string, error) {
	switch e.Protocol {
	case ProtocolVLESS:
		return e.vlessURI()
	case ProtocolTrojan:
		return e.trojanURI()
	case ProtocolShadowsocks:
		return e.shadowsocksURI()
	default:
		return "", fmt.Errorf("sublink: unknown protocol %q", e.Protocol)
	}
}

// vlessURI builds vless://uuid@host:port?params#remark.
func (e *Endpoint) vlessURI() (string, error) {
	if e.UUID == "" {
		return "", fmt.Errorf("sublink: endpoint %q has no uuid", e.Remark)
	}

	params := e.streamParams()
	// VLESS carries no encryption of its own; the field is mandatory and "none" is
	// the only value the current protocol accepts.
	params["encryption"] = "none"
	if e.Flow != "" {
		params["flow"] = e.Flow
	}

	return buildURI("vless", e.UUID, "", e.Address, e.Port, params, e.Remark), nil
}

// trojanURI builds trojan://password@host:port?params#remark.
func (e *Endpoint) trojanURI() (string, error) {
	if e.Password == "" {
		return "", fmt.Errorf("sublink: endpoint %q has no trojan password", e.Remark)
	}
	return buildURI("trojan", e.Password, "", e.Address, e.Port, e.streamParams(), e.Remark), nil
}

// shadowsocksURI builds an SIP002 link.
//
// For the 2022 methods SIP002 is explicit that userinfo MUST NOT be base64url
// encoded, and that method and password must be percent encoded instead. With
// identity headers the password is the server key and the user key joined by a colon
// (SIP023); percent encoding that inner colon is what keeps it from being mistaken
// for the method separator.
func (e *Endpoint) shadowsocksURI() (string, error) {
	if e.SSMethod == "" {
		return "", fmt.Errorf("sublink: endpoint %q has no shadowsocks method", e.Remark)
	}
	if e.SSUserKey == "" {
		return "", fmt.Errorf("sublink: endpoint %q has no shadowsocks user key", e.Remark)
	}
	if !strings.HasPrefix(e.SSMethod, "2022-") {
		return "", fmt.Errorf("sublink: shadowsocks method %q is not supported; only 2022-* methods are",
			e.SSMethod)
	}
	if e.SSServerKey == "" {
		return "", fmt.Errorf("sublink: endpoint %q has no shadowsocks server key", e.Remark)
	}

	password := e.SSServerKey + ":" + e.SSUserKey

	// Shadowsocks has no stream security of its own in this shape, so no stream
	// parameters are emitted.
	return buildURI("ss", e.SSMethod, password, e.Address, e.Port, nil, e.Remark), nil
}

// streamParams builds the transport and security query parameters shared by VLESS and
// Trojan.
func (e *Endpoint) streamParams() map[string]string {
	params := map[string]string{
		"type":     string(e.Transport),
		"security": string(e.Security),
	}

	switch e.Transport {
	case TransportWS, TransportHTTPUpgrade:
		if e.Path != "" {
			params["path"] = e.Path
		}
		if e.Host != "" {
			params["host"] = e.Host
		}

	case TransportXHTTP:
		if e.Path != "" {
			params["path"] = e.Path
		}
		if e.Host != "" {
			params["host"] = e.Host
		}
		if e.Mode != "" {
			params["mode"] = e.Mode
		}

	case TransportGRPC:
		if e.ServiceName != "" {
			params["serviceName"] = e.ServiceName
		}
		if e.Mode != "" {
			params["mode"] = e.Mode
		}
	}

	switch e.Security {
	case SecurityTLS:
		e.addTLSParams(params)

	case SecurityReality:
		e.addTLSParams(params)
		params["pbk"] = e.PublicKey
		if e.ShortID != "" {
			params["sid"] = e.ShortID
		}
		if e.SpiderX != "" {
			params["spx"] = e.SpiderX
		}
	}

	return params
}

func (e *Endpoint) addTLSParams(params map[string]string) {
	if e.SNI != "" {
		params["sni"] = e.SNI
	}
	if len(e.ALPN) > 0 {
		// Comma separated with no spaces, per the specification.
		params["alpn"] = strings.Join(e.ALPN, ",")
	}
	if e.Fingerprint != "" {
		params["fp"] = e.Fingerprint
	}
	if e.AllowInsecure {
		params["allowInsecure"] = "1"
	}
}

// buildURI assembles a share link.
//
// The URI is built by hand rather than through net/url. url.Values.Encode uses form
// encoding, where a space becomes "+", while the specification calls for
// encodeURIComponent, where it becomes "%20". A client that reads the value with
// decodeURIComponent would show a literal plus sign in a path or a remark.
func buildURI(scheme, user, password, address string, port int, params map[string]string, remark string) string {
	var b strings.Builder

	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(escapeComponent(user))
	if password != "" {
		b.WriteByte(':')
		b.WriteString(escapeComponent(password))
	}
	b.WriteByte('@')
	b.WriteString(hostPort(address, port))

	if len(params) > 0 {
		keys := make([]string, 0, len(params))
		for key := range params {
			keys = append(keys, key)
		}
		// Sorted so the same endpoint always renders identically; a link that changes
		// shape between requests looks to a client like a different server.
		sort.Strings(keys)

		b.WriteByte('?')
		for i, key := range keys {
			if i > 0 {
				b.WriteByte('&')
			}
			b.WriteString(key)
			b.WriteByte('=')
			b.WriteString(escapeComponent(params[key]))
		}
	}

	if remark != "" {
		b.WriteByte('#')
		b.WriteString(escapeComponent(remark))
	}

	return b.String()
}

// hostPort joins an address and port, bracketing a bare IPv6 literal.
func hostPort(address string, port int) string {
	if strings.Contains(address, ":") && !strings.HasPrefix(address, "[") {
		// A bare IPv6 address would otherwise make the port unparsable.
		return net.JoinHostPort(address, strconv.Itoa(port))
	}
	return address + ":" + strconv.Itoa(port)
}

// escapeComponent percent-encodes exactly as JavaScript's encodeURIComponent does,
// which is what the VLESS share link specification calls for.
//
// The unreserved set is ALPHA / DIGIT / - _ . ! ~ * ' ( ). Everything else is
// escaped, including "/" in paths, which clients decode back.
func escapeComponent(s string) string {
	const upperhex = "0123456789ABCDEF"

	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreservedComponent(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperhex[c>>4])
		b.WriteByte(upperhex[c&0x0f])
	}
	return b.String()
}

func isUnreservedComponent(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '-', '_', '.', '!', '~', '*', '\'', '(', ')':
		return true
	}
	return false
}
