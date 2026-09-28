// Package config turns the panel's view of a node into a complete Xray
// configuration.
//
// The panel generates the whole config.json and the node applies it verbatim
// (ADR-003). That keeps every decision and every test in one place, and means two
// nodes carrying the same inbounds cannot drift apart.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/xraypanel/panel/internal/xray/reality"
)

// Protocol is an inbound protocol.
type Protocol string

// Supported protocols.
const (
	ProtocolVLESS       Protocol = "vless"
	ProtocolTrojan      Protocol = "trojan"
	ProtocolShadowsocks Protocol = "shadowsocks"
)

// Transport is a stream transport.
type Transport string

// Supported transports. The names match the values Xray expects in
// streamSettings.network.
const (
	TransportTCP         Transport = "tcp"
	TransportWS          Transport = "ws"
	TransportGRPC        Transport = "grpc"
	TransportHTTPUpgrade Transport = "httpupgrade"
	TransportXHTTP       Transport = "xhttp"
)

// Security is the transport security layer.
type Security string

// Supported security layers.
const (
	SecurityNone    Security = "none"
	SecurityTLS     Security = "tls"
	SecurityReality Security = "reality"
)

// Spec is everything needed to generate one node's configuration.
type Spec struct {
	// NodeName appears only in generated comments and error messages.
	NodeName string

	Inbounds []Inbound

	// ConfigPatch is an RFC 7386 merge patch applied to the finished document. It is
	// the only supported way to make one node differ from another.
	ConfigPatch json.RawMessage

	Defaults Defaults
}

// Defaults are the parts of the config that are not derived from inbounds.
type Defaults struct {
	// LogLevel is one of debug, info, warning, error, none.
	LogLevel string

	// APIAddress and APIPort are where the node agent reaches Xray's gRPC API. It
	// listens on loopback only: the API can add and remove users, so exposing it
	// would hand that to anyone who can reach the port.
	APIAddress string
	APIPort    int

	// DNSServers, when set, produces a dns section. Empty leaves Xray on its own
	// defaults rather than emitting an empty section that overrides them.
	DNSServers []string
}

// Inbound is one generated inbound and the clients allowed on it.
type Inbound struct {
	Tag        string
	Protocol   Protocol
	Transport  Transport
	Security   Security
	ListenAddr string
	ListenPort int

	// Flow is the XTLS flow, in practice xtls-rprx-vision. Only valid for VLESS over
	// raw TCP with TLS or Reality; see ADR-010.
	Flow string

	// SSMethod and SSServerKey apply to Shadowsocks only.
	SSMethod    string
	SSServerKey string

	// NetworkSettings is the transport settings object, verbatim: wsSettings,
	// grpcSettings, xhttpSettings and so on, depending on Transport.
	NetworkSettings json.RawMessage

	// TLSSettings is the tlsSettings object, verbatim. Ignored unless Security is
	// tls.
	TLSSettings json.RawMessage

	Reality *Reality

	Sniffing json.RawMessage

	// Extra is merged into the finished inbound object last, as an escape hatch for
	// settings the schema does not model yet.
	Extra json.RawMessage

	Clients []Client
}

// Reality is the key material for a Reality inbound.
type Reality struct {
	PrivateKey  string
	ShortIDs    []string
	Dest        string
	ServerNames []string
}

// Client is one user's credentials on one inbound.
type Client struct {
	// Email is the stats key. Xray reports traffic under
	// user>>>{email}>>>traffic>>>uplink, so this is what the billing pipeline joins
	// on; it is users.xray_email and never changes (ADR-007).
	Email string

	// UUID is used by VLESS.
	UUID string

	// Password is used by Trojan, and is the per-user key for Shadowsocks-2022.
	Password string

	Level int
}

// defaultLogLevel keeps the node's log useful without recording every connection.
const defaultLogLevel = "warning"

// Defaults for the local API listener.
const (
	defaultAPIAddress = "127.0.0.1"
	defaultAPIPort    = 10085

	// apiTag is used both as the api section's tag and as the tag of the
	// dokodemo-door inbound that fronts it, which is what the routing rule joins.
	apiTag = "api"
)

// validLogLevels is the set Xray accepts.
var validLogLevels = map[string]struct{}{
	"debug": {}, "info": {}, "warning": {}, "error": {}, "none": {},
}

// withDefaults fills in the values an operator did not set.
func (d Defaults) withDefaults() Defaults {
	if d.LogLevel == "" {
		d.LogLevel = defaultLogLevel
	}
	if d.APIAddress == "" {
		d.APIAddress = defaultAPIAddress
	}
	if d.APIPort == 0 {
		d.APIPort = defaultAPIPort
	}
	return d
}

// Validate checks a spec before anything is generated.
//
// Everything that can be caught here is caught here, because the alternative is an
// Xray process that refuses to start on a remote node, which from the panel looks
// like "the node broke" with no reason attached.
func (s *Spec) Validate() error {
	defaults := s.Defaults.withDefaults()

	if _, ok := validLogLevels[defaults.LogLevel]; !ok {
		return fmt.Errorf("xray/config: log level %q is not one of debug, info, warning, error, none",
			defaults.LogLevel)
	}
	if defaults.APIPort < 1 || defaults.APIPort > 65535 {
		return fmt.Errorf("xray/config: api port %d is out of range", defaults.APIPort)
	}
	if len(s.Inbounds) == 0 {
		return errors.New("xray/config: a node needs at least one inbound")
	}

	// Port collisions are the failure this check exists for. Two inbounds on one port
	// mean Xray does not start at all, and the panel would report a healthy
	// configuration pushed to a node that is down. See ADR-011.
	usedPorts := map[int]string{defaults.APIPort: apiTag}
	usedTags := map[string]struct{}{apiTag: {}}

	for i := range s.Inbounds {
		inbound := &s.Inbounds[i]
		if err := inbound.validate(); err != nil {
			return err
		}

		if owner, taken := usedPorts[inbound.ListenPort]; taken {
			return fmt.Errorf(
				"xray/config: inbounds %q and %q both listen on port %d",
				owner, inbound.Tag, inbound.ListenPort)
		}
		usedPorts[inbound.ListenPort] = inbound.Tag

		if _, taken := usedTags[inbound.Tag]; taken {
			return fmt.Errorf("xray/config: inbound tag %q is used twice", inbound.Tag)
		}
		usedTags[inbound.Tag] = struct{}{}
	}

	if len(s.ConfigPatch) > 0 && !json.Valid(s.ConfigPatch) {
		return errors.New("xray/config: config patch is not valid JSON")
	}
	return nil
}

func (in *Inbound) validate() error {
	if strings.TrimSpace(in.Tag) == "" {
		return errors.New("xray/config: every inbound needs a tag")
	}
	if in.Tag == apiTag {
		// The api tag is taken by the local API inbound, and the routing rule keys
		// off it. A user inbound with the same tag would receive API traffic.
		return fmt.Errorf("xray/config: inbound tag %q is reserved", apiTag)
	}
	if in.ListenPort < 1 || in.ListenPort > 65535 {
		return fmt.Errorf("xray/config: inbound %q has port %d out of range", in.Tag, in.ListenPort)
	}
	if len(in.Clients) == 0 {
		// An inbound with no clients is valid Xray but always useless, and it is
		// usually a sign that group membership was not resolved.
		return fmt.Errorf("xray/config: inbound %q has no clients", in.Tag)
	}

	switch in.Protocol {
	case ProtocolVLESS, ProtocolTrojan, ProtocolShadowsocks:
	default:
		return fmt.Errorf("xray/config: inbound %q has unknown protocol %q", in.Tag, in.Protocol)
	}

	switch in.Transport {
	case TransportTCP, TransportWS, TransportGRPC, TransportHTTPUpgrade, TransportXHTTP:
	default:
		return fmt.Errorf("xray/config: inbound %q has unknown transport %q", in.Tag, in.Transport)
	}

	switch in.Security {
	case SecurityNone, SecurityTLS, SecurityReality:
	default:
		return fmt.Errorf("xray/config: inbound %q has unknown security %q", in.Tag, in.Security)
	}

	if err := in.validateFlow(); err != nil {
		return err
	}
	if err := in.validateProtocolSettings(); err != nil {
		return err
	}
	if err := in.validateSecuritySettings(); err != nil {
		return err
	}
	return in.validateRawJSON()
}

// validateFlow mirrors the database constraint from ADR-010.
//
// Checked again here because the generator is also reachable from paths that bypass
// the service layer, and because a flow on the wrong transport produces a config that
// starts fine and fails only on a live client.
func (in *Inbound) validateFlow() error {
	if in.Flow == "" {
		return nil
	}
	if in.Protocol != ProtocolVLESS {
		return fmt.Errorf("xray/config: inbound %q sets flow on protocol %q; only vless supports it",
			in.Tag, in.Protocol)
	}
	if in.Transport != TransportTCP {
		return fmt.Errorf("xray/config: inbound %q sets flow on transport %q; only raw tcp supports it",
			in.Tag, in.Transport)
	}
	if in.Security != SecurityTLS && in.Security != SecurityReality {
		return fmt.Errorf("xray/config: inbound %q sets flow with security %q; it needs tls or reality",
			in.Tag, in.Security)
	}
	return nil
}

func (in *Inbound) validateProtocolSettings() error {
	switch in.Protocol {
	case ProtocolVLESS:
		for _, client := range in.Clients {
			if client.UUID == "" {
				return fmt.Errorf("xray/config: inbound %q has a vless client without a uuid", in.Tag)
			}
			if client.Email == "" {
				return fmt.Errorf("xray/config: inbound %q has a client without a stats key", in.Tag)
			}
		}

	case ProtocolTrojan:
		for _, client := range in.Clients {
			if client.Password == "" {
				return fmt.Errorf("xray/config: inbound %q has a trojan client without a password", in.Tag)
			}
			if client.Email == "" {
				return fmt.Errorf("xray/config: inbound %q has a client without a stats key", in.Tag)
			}
		}

	case ProtocolShadowsocks:
		// Only the 2022 methods are supported. The older AEAD ciphers have no
		// per-user keys at all, so a multi-user inbound cannot attribute traffic,
		// and they lack the replay protection the 2022 methods added.
		if !strings.HasPrefix(in.SSMethod, "2022-") {
			return fmt.Errorf(
				"xray/config: inbound %q uses shadowsocks method %q; only 2022-* methods are supported",
				in.Tag, in.SSMethod)
		}
		if in.SSServerKey == "" {
			return fmt.Errorf("xray/config: inbound %q has no shadowsocks server key", in.Tag)
		}
		for _, client := range in.Clients {
			if client.Password == "" {
				return fmt.Errorf("xray/config: inbound %q has a shadowsocks client without a key", in.Tag)
			}
			if client.Email == "" {
				return fmt.Errorf("xray/config: inbound %q has a client without a stats key", in.Tag)
			}
		}
	}

	seen := make(map[string]struct{}, len(in.Clients))
	for _, client := range in.Clients {
		if _, dup := seen[client.Email]; dup {
			// Two clients under one stats key would have their traffic merged into a
			// single counter, and the billing pipeline would bill one of them for both.
			return fmt.Errorf("xray/config: inbound %q lists stats key %q twice", in.Tag, client.Email)
		}
		seen[client.Email] = struct{}{}
	}
	return nil
}

func (in *Inbound) validateSecuritySettings() error {
	switch in.Security {
	case SecurityReality:
		if in.Reality == nil {
			return fmt.Errorf("xray/config: inbound %q uses reality without key material", in.Tag)
		}
		if _, err := reality.PublicKeyFor(in.Reality.PrivateKey); err != nil {
			return fmt.Errorf("xray/config: inbound %q: %w", in.Tag, err)
		}
		if err := reality.ValidateShortIDs(in.Reality.ShortIDs); err != nil {
			return fmt.Errorf("xray/config: inbound %q: %w", in.Tag, err)
		}
		if err := reality.ValidateDest(in.Reality.Dest); err != nil {
			return fmt.Errorf("xray/config: inbound %q: %w", in.Tag, err)
		}
		if err := reality.ValidateServerNames(in.Reality.ServerNames); err != nil {
			return fmt.Errorf("xray/config: inbound %q: %w", in.Tag, err)
		}

	case SecurityTLS:
		if len(in.TLSSettings) == 0 {
			return fmt.Errorf("xray/config: inbound %q uses tls without tlsSettings", in.Tag)
		}

	case SecurityNone:
		if in.Reality != nil {
			return fmt.Errorf("xray/config: inbound %q carries reality key material but security is none", in.Tag)
		}
	}
	return nil
}

// validateRawJSON checks that every passthrough field really is a JSON object.
//
// A string or an array here would be spliced into the config and rejected by Xray on
// startup, which is a long way from where the mistake was made.
func (in *Inbound) validateRawJSON() error {
	fields := map[string]json.RawMessage{
		"network_settings": in.NetworkSettings,
		"tls_settings":     in.TLSSettings,
		"sniffing":         in.Sniffing,
		"extra":            in.Extra,
	}
	for name, raw := range fields {
		if len(raw) == 0 {
			continue
		}
		var object map[string]any
		if err := json.Unmarshal(raw, &object); err != nil {
			return fmt.Errorf("xray/config: inbound %q: %s must be a JSON object: %w", in.Tag, name, err)
		}
	}
	return nil
}
