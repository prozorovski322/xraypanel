package sublink

import (
	"encoding/json"
	"fmt"
)

// sing-box selector and urltest tags. A profile needs an outbound the user can pick,
// and the final route has to point at something.
const (
	singBoxSelectorTag = "select"
	singBoxAutoTag     = "auto"
	singBoxDirectTag   = "direct"
)

// RenderSingBox builds a sing-box JSON profile.
//
// Field names follow sing-box's own schema, which differs from both the share link
// parameters and Clash: server_port rather than port, a nested tls object carrying
// utls and reality sub-objects, and transport as its own object. This is a separate
// renderer for that reason.
func RenderSingBox(sub *Subscription) ([]byte, error) {
	outbounds := make([]any, 0, len(sub.Endpoints)+3)
	tags := make([]string, 0, len(sub.Endpoints))

	for i := range sub.Endpoints {
		endpoint := &sub.Endpoints[i]

		outbound, err := singBoxOutbound(endpoint)
		if err != nil {
			return nil, err
		}
		tag := uniqueName(tags, endpoint.Remark)
		outbound["tag"] = tag

		outbounds = append(outbounds, outbound)
		tags = append(tags, tag)
	}

	proxyTags := make([]any, 0, len(tags))
	for _, tag := range tags {
		proxyTags = append(proxyTags, tag)
	}

	finalTag := singBoxSelectorTag
	if len(tags) == 0 {
		// A selector with no outbounds is rejected, so an empty subscription routes to
		// direct instead of shipping a profile that will not load.
		finalTag = singBoxDirectTag
	} else {
		selectorMembers := append([]any{singBoxAutoTag}, proxyTags...)

		outbounds = append(outbounds,
			map[string]any{
				"type":      "selector",
				"tag":       singBoxSelectorTag,
				"outbounds": selectorMembers,
				"default":   singBoxAutoTag,
			},
			map[string]any{
				"type":      "urltest",
				"tag":       singBoxAutoTag,
				"outbounds": proxyTags,
				"url":       "https://www.gstatic.com/generate_204",
				"interval":  "5m",
			},
		)
	}

	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": singBoxDirectTag})

	document := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{
			map[string]any{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      "127.0.0.1",
				"listen_port": 2080,
			},
		},
		"outbounds": outbounds,
		"route": map[string]any{
			"final": finalTag,
		},
	}

	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sublink: encode sing-box profile: %w", err)
	}
	return encoded, nil
}

func singBoxOutbound(e *Endpoint) (map[string]any, error) {
	outbound := map[string]any{
		"server":      e.Address,
		"server_port": e.Port,
	}

	switch e.Protocol {
	case ProtocolVLESS:
		outbound["type"] = "vless"
		outbound["uuid"] = e.UUID
		if e.Flow != "" {
			outbound["flow"] = e.Flow
		}
		// xudp is what lets UDP work over VLESS in sing-box; without it a client gets
		// TCP only and blames the server for broken DNS or QUIC.
		outbound["packet_encoding"] = "xudp"

	case ProtocolTrojan:
		outbound["type"] = "trojan"
		outbound["password"] = e.Password

	case ProtocolShadowsocks:
		outbound["type"] = "shadowsocks"
		outbound["method"] = e.SSMethod
		outbound["password"] = e.SSServerKey + ":" + e.SSUserKey

	default:
		return nil, fmt.Errorf("sublink: sing-box: unknown protocol %q", e.Protocol)
	}

	if e.Protocol != ProtocolShadowsocks {
		if transport := singBoxTransport(e); transport != nil {
			outbound["transport"] = transport
		}
		if tls := singBoxTLS(e); tls != nil {
			outbound["tls"] = tls
		}
	}

	return outbound, nil
}

func singBoxTransport(e *Endpoint) map[string]any {
	switch e.Transport {
	case TransportWS:
		transport := map[string]any{"type": "ws"}
		if e.Path != "" {
			transport["path"] = e.Path
		}
		if e.Host != "" {
			transport["headers"] = map[string]any{"Host": e.Host}
		}
		return transport

	case TransportGRPC:
		transport := map[string]any{"type": "grpc"}
		if e.ServiceName != "" {
			transport["service_name"] = e.ServiceName
		}
		return transport

	case TransportHTTPUpgrade:
		transport := map[string]any{"type": "httpupgrade"}
		if e.Path != "" {
			transport["path"] = e.Path
		}
		if e.Host != "" {
			transport["host"] = e.Host
		}
		return transport

	case TransportXHTTP:
		// sing-box has no xhttp transport. Emitting one would produce a profile the
		// client rejects outright, so the endpoint is skipped by the caller instead;
		// returning nil here keeps that decision in one place.
		return nil

	default:
		// Raw TCP needs no transport object at all.
		return nil
	}
}

func singBoxTLS(e *Endpoint) map[string]any {
	if e.Security == SecurityNone {
		return nil
	}

	tls := map[string]any{"enabled": true}
	if e.SNI != "" {
		tls["server_name"] = e.SNI
	}
	if len(e.ALPN) > 0 {
		tls["alpn"] = e.ALPN
	}
	if e.AllowInsecure {
		tls["insecure"] = true
	}
	if e.Fingerprint != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": e.Fingerprint}
	}

	if e.Security == SecurityReality {
		reality := map[string]any{"enabled": true, "public_key": e.PublicKey}
		if e.ShortID != "" {
			reality["short_id"] = e.ShortID
		}
		tls["reality"] = reality

		// Reality requires uTLS in sing-box; a profile with reality and no utls block
		// loads and then fails every handshake.
		if _, present := tls["utls"]; !present {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
		}
	}

	return tls
}

// SupportedBySingBox reports whether an endpoint can be expressed in a sing-box
// profile.
//
// sing-box has no xhttp transport. Silently dropping such an endpoint is better than
// emitting an outbound the client refuses, which would make the whole profile
// unusable rather than just that one entry.
func SupportedBySingBox(e *Endpoint) bool {
	return e.Transport != TransportXHTTP
}
