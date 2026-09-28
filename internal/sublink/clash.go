package sublink

import (
	"fmt"

	yaml "go.yaml.in/yaml/v3"
)

// Clash profile scaffolding. These are the values a subscription is expected to carry;
// a profile without them loads but leaves the client with no way to select a proxy.
const (
	clashMixedPort = 7890
	clashMode      = "rule"
	clashLogLevel  = "info"
)

// Proxy group names. Clash needs at least one selector for the user to pick from, and
// a final rule pointing at it.
const (
	clashSelectorName = "Proxies"
	clashAutoName     = "Auto"
)

// RenderClash builds a Clash / mihomo YAML profile.
//
// Field names follow mihomo's schema: servername rather than sni, client-fingerprint
// rather than fp, and reality-opts as a nested map. They differ from the share link
// parameter names, which is the reason this is a separate renderer rather than a
// transformation of the URI.
func RenderClash(sub *Subscription) ([]byte, error) {
	proxies := make([]map[string]any, 0, len(sub.Endpoints))
	names := make([]string, 0, len(sub.Endpoints))

	for i := range sub.Endpoints {
		endpoint := &sub.Endpoints[i]

		proxy, err := clashProxy(endpoint)
		if err != nil {
			return nil, err
		}
		// Clash keys proxies by name and silently keeps only one of a duplicate pair,
		// so names are made unique before they reach the client.
		name := uniqueName(names, endpoint.Remark)
		proxy["name"] = name

		proxies = append(proxies, proxy)
		names = append(names, name)
	}

	if len(proxies) == 0 {
		// A selector with no members is rejected by mihomo, so an empty subscription
		// has to be a profile with no groups rather than empty groups.
		document := map[string]any{
			"mixed-port": clashMixedPort,
			"mode":       clashMode,
			"log-level":  clashLogLevel,
			"proxies":    []any{},
			"rules":      []any{"MATCH,DIRECT"},
		}
		return marshalYAML(document)
	}

	selectorMembers := make([]any, 0, len(names)+1)
	selectorMembers = append(selectorMembers, clashAutoName)
	for _, name := range names {
		selectorMembers = append(selectorMembers, name)
	}

	autoMembers := make([]any, 0, len(names))
	for _, name := range names {
		autoMembers = append(autoMembers, name)
	}

	document := map[string]any{
		"mixed-port":          clashMixedPort,
		"allow-lan":           false,
		"mode":                clashMode,
		"log-level":           clashLogLevel,
		"external-controller": "",
		"proxies":             proxies,
		"proxy-groups": []any{
			map[string]any{
				"name":    clashSelectorName,
				"type":    "select",
				"proxies": selectorMembers,
			},
			map[string]any{
				"name":     clashAutoName,
				"type":     "url-test",
				"proxies":  autoMembers,
				"url":      "https://www.gstatic.com/generate_204",
				"interval": 300,
			},
		},
		"rules": []any{"MATCH," + clashSelectorName},
	}

	return marshalYAML(document)
}

func clashProxy(e *Endpoint) (map[string]any, error) {
	proxy := map[string]any{
		"server": e.Address,
		"port":   e.Port,
		"udp":    true,
	}

	switch e.Protocol {
	case ProtocolVLESS:
		proxy["type"] = "vless"
		proxy["uuid"] = e.UUID
		if e.Flow != "" {
			proxy["flow"] = e.Flow
		}

	case ProtocolTrojan:
		proxy["type"] = "trojan"
		proxy["password"] = e.Password

	case ProtocolShadowsocks:
		proxy["type"] = "ss"
		proxy["cipher"] = e.SSMethod
		// mihomo takes the joined server and user key as one password, the same shape
		// the SIP002 link carries.
		proxy["password"] = e.SSServerKey + ":" + e.SSUserKey

	default:
		return nil, fmt.Errorf("sublink: clash: unknown protocol %q", e.Protocol)
	}

	if e.Protocol != ProtocolShadowsocks {
		addClashTransport(proxy, e)
		addClashSecurity(proxy, e)
	}

	return proxy, nil
}

func addClashTransport(proxy map[string]any, e *Endpoint) {
	switch e.Transport {
	case TransportWS:
		proxy["network"] = "ws"
		opts := map[string]any{}
		if e.Path != "" {
			opts["path"] = e.Path
		}
		if e.Host != "" {
			opts["headers"] = map[string]any{"Host": e.Host}
		}
		if len(opts) > 0 {
			proxy["ws-opts"] = opts
		}

	case TransportGRPC:
		proxy["network"] = "grpc"
		if e.ServiceName != "" {
			proxy["grpc-opts"] = map[string]any{"grpc-service-name": e.ServiceName}
		}

	case TransportHTTPUpgrade:
		proxy["network"] = "httpupgrade"
		opts := map[string]any{}
		if e.Path != "" {
			opts["path"] = e.Path
		}
		if e.Host != "" {
			opts["host"] = e.Host
		}
		if len(opts) > 0 {
			proxy["http-upgrade-opts"] = opts
		}

	case TransportXHTTP:
		proxy["network"] = "xhttp"
		opts := map[string]any{}
		if e.Path != "" {
			opts["path"] = e.Path
		}
		if e.Host != "" {
			opts["host"] = e.Host
		}
		if e.Mode != "" {
			opts["mode"] = e.Mode
		}
		if len(opts) > 0 {
			proxy["xhttp-opts"] = opts
		}

	case TransportTCP:
		proxy["network"] = "tcp"
	}
}

func addClashSecurity(proxy map[string]any, e *Endpoint) {
	if e.Security == SecurityNone {
		return
	}

	proxy["tls"] = true
	if e.SNI != "" {
		proxy["servername"] = e.SNI
	}
	if len(e.ALPN) > 0 {
		proxy["alpn"] = e.ALPN
	}
	if e.Fingerprint != "" {
		proxy["client-fingerprint"] = e.Fingerprint
	}
	if e.AllowInsecure {
		proxy["skip-cert-verify"] = true
	}

	if e.Security == SecurityReality {
		opts := map[string]any{"public-key": e.PublicKey}
		if e.ShortID != "" {
			opts["short-id"] = e.ShortID
		}
		proxy["reality-opts"] = opts
	}
}

// uniqueName appends a counter to a name that is already taken.
func uniqueName(existing []string, name string) string {
	if name == "" {
		name = "proxy"
	}
	taken := func(candidate string) bool {
		for _, used := range existing {
			if used == candidate {
				return true
			}
		}
		return false
	}
	if !taken(name) {
		return name
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s (%d)", name, i)
		if !taken(candidate) {
			return candidate
		}
	}
}

func marshalYAML(document map[string]any) ([]byte, error) {
	out, err := yaml.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("sublink: encode clash profile: %w", err)
	}
	return out, nil
}
