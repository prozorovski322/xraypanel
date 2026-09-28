package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"sort"
)

// Generated is a finished configuration plus the hashes a node needs to decide what
// to do with it.
type Generated struct {
	// JSON is the complete config.json, ready to be written to disk.
	JSON []byte

	// StructuralHash covers everything except the user inbounds: log, api, stats,
	// policy, outbounds, routing, dns, and the local API inbound.
	//
	// Xray cannot reload these at runtime, so a change here is the only thing that
	// justifies restarting the core. Inbounds and their users are added and removed
	// through HandlerService instead, which is why they are excluded. See ADR-009.
	StructuralHash string

	// InboundHashes is keyed by inbound tag and covers everything about an inbound
	// except its user list: port, transport, security, keys, sniffing, overrides.
	//
	// Users are excluded because they are the part that can be changed on a running
	// core, and a hash that moved every time a user was added would make every user
	// edit look like a change that needs a restart — which is the exact behaviour this
	// hash exists to avoid (ADR-065). The node diffs users directly instead.
	InboundHashes map[string]string
}

// Generate builds the configuration for one node.
func Generate(spec Spec) (*Generated, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}

	defaults := spec.Defaults.withDefaults()

	document := map[string]any{
		"log": map[string]any{
			"loglevel": defaults.LogLevel,
		},

		// The API is what lets the agent add and remove users without a restart, and
		// read traffic counters. HandlerService does the first, StatsService the
		// second, LoggerService allows rotating the log without a restart.
		"api": map[string]any{
			"tag":      apiTag,
			"services": []any{"HandlerService", "StatsService", "LoggerService"},
		},

		// Stats collection is off unless this section exists, even with the policy
		// flags set below.
		"stats": map[string]any{},

		// Both halves are required. The per-level flags produce the
		// user>>>{email}>>>traffic>>>* counters the billing pipeline reads; the system
		// flags produce the per-inbound totals used for node-level reporting. Leaving
		// either out yields a config that starts fine and reports nothing.
		"policy": map[string]any{
			"levels": map[string]any{
				"0": map[string]any{
					"statsUserUplink":   true,
					"statsUserDownlink": true,
				},
			},
			"system": map[string]any{
				"statsInboundUplink":   true,
				"statsInboundDownlink": true,
			},
		},

		"outbounds": []any{
			map[string]any{"protocol": "freedom", "tag": "direct"},
			map[string]any{"protocol": "blackhole", "tag": "blocked"},
		},

		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				// Traffic arriving on the local API inbound is handed to the API
				// handler. Without this rule the API port accepts connections and
				// answers nothing, which looks like a broken agent.
				map[string]any{
					"type":        "field",
					"inboundTag":  []any{apiTag},
					"outboundTag": apiTag,
				},
			},
		},
	}

	if len(defaults.DNSServers) > 0 {
		servers := make([]any, 0, len(defaults.DNSServers))
		for _, server := range defaults.DNSServers {
			servers = append(servers, server)
		}
		document["dns"] = map[string]any{"servers": servers}
	}

	inbounds := make([]any, 0, len(spec.Inbounds)+1)
	inbounds = append(inbounds, apiInbound(defaults))

	inboundObjects := make(map[string]map[string]any, len(spec.Inbounds))
	for i := range spec.Inbounds {
		object, err := buildInbound(&spec.Inbounds[i])
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, object)
		inboundObjects[spec.Inbounds[i].Tag] = object
	}
	document["inbounds"] = inbounds

	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("xray/config: encode config: %w", err)
	}

	// The patch is applied to the finished document, so an operator can override
	// anything the generator produced, including inbounds.
	patched, err := ApplyMergePatch(encoded, spec.ConfigPatch)
	if err != nil {
		return nil, err
	}

	// Hashes are computed from the patched document, because that is what the node
	// actually applies. Hashing before the patch would let a patch change the
	// structural part without the node noticing it needs a restart.
	structuralHash, inboundHashes, err := hashDocument(patched, defaults)
	if err != nil {
		return nil, err
	}

	return &Generated{
		JSON:           patched,
		StructuralHash: structuralHash,
		InboundHashes:  inboundHashes,
	}, nil
}

// apiInbound is the dokodemo-door listener that fronts Xray's gRPC API.
//
// It binds loopback only. The API can add and remove users and read every counter, so
// a reachable API port is equivalent to administrative access to the node.
func apiInbound(defaults Defaults) map[string]any {
	return map[string]any{
		"tag":      apiTag,
		"listen":   defaults.APIAddress,
		"port":     defaults.APIPort,
		"protocol": "dokodemo-door",
		"settings": map[string]any{"address": defaults.APIAddress},
	}
}

func buildInbound(in *Inbound) (map[string]any, error) {
	settings, err := buildProtocolSettings(in)
	if err != nil {
		return nil, err
	}

	listen := in.ListenAddr
	if listen == "" {
		listen = "0.0.0.0"
	}

	object := map[string]any{
		"tag":            in.Tag,
		"listen":         listen,
		"port":           in.ListenPort,
		"protocol":       string(in.Protocol),
		"settings":       settings,
		"streamSettings": buildStreamSettings(in),
	}

	if len(in.Sniffing) > 0 {
		var sniffing map[string]any
		if err := json.Unmarshal(in.Sniffing, &sniffing); err != nil {
			return nil, fmt.Errorf("xray/config: inbound %q sniffing: %w", in.Tag, err)
		}
		if len(sniffing) > 0 {
			object["sniffing"] = sniffing
		}
	}

	// Extra is merged last so it can override anything above. It is an escape hatch,
	// and an escape hatch that cannot override is not one.
	if len(in.Extra) > 0 {
		var extra map[string]any
		if err := json.Unmarshal(in.Extra, &extra); err != nil {
			return nil, fmt.Errorf("xray/config: inbound %q extra: %w", in.Tag, err)
		}
		merged := mergeValue(object, extra)
		object, _ = merged.(map[string]any)
	}

	return object, nil
}

func buildProtocolSettings(in *Inbound) (map[string]any, error) {
	clients := make([]any, 0, len(in.Clients))

	switch in.Protocol {
	case ProtocolVLESS:
		for _, client := range in.Clients {
			entry := map[string]any{
				"id":    client.UUID,
				"email": client.Email,
				"level": client.Level,
			}
			if in.Flow != "" {
				entry["flow"] = in.Flow
			}
			clients = append(clients, entry)
		}
		// VLESS carries no encryption of its own; the transport security layer does
		// that. The field is mandatory and "none" is the only accepted value.
		return map[string]any{"clients": clients, "decryption": "none"}, nil

	case ProtocolTrojan:
		for _, client := range in.Clients {
			clients = append(clients, map[string]any{
				"password": client.Password,
				"email":    client.Email,
				"level":    client.Level,
			})
		}
		return map[string]any{"clients": clients}, nil

	case ProtocolShadowsocks:
		for _, client := range in.Clients {
			clients = append(clients, map[string]any{
				"password": client.Password,
				"email":    client.Email,
				"level":    client.Level,
			})
		}
		// The method is repeated on the inbound and implied for each client: the
		// server key and the user keys are derived with the same cipher.
		return map[string]any{
			"method":   in.SSMethod,
			"password": in.SSServerKey,
			"clients":  clients,
			"network":  "tcp,udp",
		}, nil

	default:
		return nil, fmt.Errorf("xray/config: inbound %q has unknown protocol %q", in.Tag, in.Protocol)
	}
}

func buildStreamSettings(in *Inbound) map[string]any {
	stream := map[string]any{
		"network":  string(in.Transport),
		"security": string(in.Security),
	}

	if key := transportSettingsKey(in.Transport); key != "" && len(in.NetworkSettings) > 0 {
		var settings map[string]any
		if err := json.Unmarshal(in.NetworkSettings, &settings); err == nil && len(settings) > 0 {
			stream[key] = settings
		}
	}

	switch in.Security {
	case SecurityTLS:
		var settings map[string]any
		if err := json.Unmarshal(in.TLSSettings, &settings); err == nil && len(settings) > 0 {
			stream["tlsSettings"] = settings
		}

	case SecurityReality:
		stream["realitySettings"] = buildRealitySettings(in.Reality)
	}

	return stream
}

func buildRealitySettings(r *Reality) map[string]any {
	serverNames := make([]any, 0, len(r.ServerNames))
	for _, name := range r.ServerNames {
		serverNames = append(serverNames, name)
	}
	shortIDs := make([]any, 0, len(r.ShortIDs))
	for _, id := range r.ShortIDs {
		shortIDs = append(shortIDs, id)
	}

	return map[string]any{
		"dest":        r.Dest,
		"serverNames": serverNames,
		"privateKey":  r.PrivateKey,
		"shortIds":    shortIDs,
		// Off deliberately: the handshake debug output names the client and the
		// target, which is exactly what this protocol exists to keep out of a log.
		"show": false,
	}
}

// transportSettingsKey maps a transport to the streamSettings field that configures
// it. Raw TCP needs no settings object in the shapes the panel generates.
func transportSettingsKey(transport Transport) string {
	switch transport {
	case TransportWS:
		return "wsSettings"
	case TransportGRPC:
		return "grpcSettings"
	case TransportHTTPUpgrade:
		return "httpupgradeSettings"
	case TransportXHTTP:
		return "xhttpSettings"
	case TransportTCP:
		return "tcpSettings"
	default:
		return ""
	}
}

// hashDocument splits a finished config into its structural part and its user
// inbounds, and hashes each.
func hashDocument(document []byte, defaults Defaults) (string, map[string]string, error) {
	var parsed map[string]any
	if err := json.Unmarshal(document, &parsed); err != nil {
		return "", nil, fmt.Errorf("xray/config: reparse generated config: %w", err)
	}

	rawInbounds, _ := parsed["inbounds"].([]any)

	structural := maps.Clone(parsed)
	delete(structural, "inbounds")

	inboundHashes := make(map[string]string, len(rawInbounds))
	var structuralInbounds []any

	for _, entry := range rawInbounds {
		object, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := object["tag"].(string)

		// The local API inbound is structural: it is not a user inbound and cannot be
		// added or removed at runtime.
		if tag == apiTag {
			structuralInbounds = append(structuralInbounds, object)
			continue
		}

		hash, err := hashValue(withoutClients(object))
		if err != nil {
			return "", nil, err
		}
		inboundHashes[tag] = hash
	}

	// Kept inside the structural part so that moving the API port counts as a change
	// that needs a restart, which it does.
	structural["apiInbounds"] = structuralInbounds
	structural["apiPort"] = defaults.APIPort

	structuralHash, err := hashValue(structural)
	if err != nil {
		return "", nil, err
	}
	return structuralHash, inboundHashes, nil
}

// withoutClients returns a copy of an inbound with its user list removed.
//
// Shallow everywhere except on the path being changed: settings is replaced by a copy
// with no clients key, and everything else is shared with the original, which is only
// read from here.
func withoutClients(inbound map[string]any) map[string]any {
	settings, ok := inbound["settings"].(map[string]any)
	if !ok {
		return inbound
	}
	if _, has := settings["clients"]; !has {
		return inbound
	}

	trimmedSettings := maps.Clone(settings)
	delete(trimmedSettings, "clients")

	trimmed := maps.Clone(inbound)
	trimmed["settings"] = trimmedSettings
	return trimmed
}

// hashValue hashes a JSON value canonically.
//
// encoding/json sorts object keys, so marshalling the same logical value twice gives
// the same bytes regardless of how it was built. That is what makes these hashes
// comparable across panel restarts and across releases that happen to construct the
// document in a different order.
func hashValue(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("xray/config: hash value: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// SortedTags returns the inbound tags in a stable order, for logging and diffing.
func (g *Generated) SortedTags() []string {
	tags := make([]string, 0, len(g.InboundHashes))
	for tag := range g.InboundHashes {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}
