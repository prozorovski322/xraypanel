package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xraypanel/panel/internal/audit"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
	xrayconfig "github.com/xraypanel/panel/internal/xray/config"
	"github.com/xraypanel/panel/internal/xray/reality"
)

// emptyJSONObject is the stored default for the passthrough jsonb columns.
var emptyJSONObject = []byte(`{}`)

// CreateInboundInput describes a new inbound.
type CreateInboundInput struct {
	Tag        string
	Protocol   string
	Transport  string
	Security   string
	ListenPort int32
	ListenAddr string

	Flow string

	SSMethod string
	// SSServerKey is the plaintext Shadowsocks-2022 server key. It is encrypted before
	// it reaches the database.
	SSServerKey string

	NetworkSettings json.RawMessage
	TLSSettings     json.RawMessage
	Sniffing        json.RawMessage
	Extra           json.RawMessage

	RealityKeyID *int64
	Enabled      bool
}

// CreateInbound adds an inbound template.
//
// Every rule the config generator enforces is checked here too. The database has
// constraints for some of it, but a violation there arrives as a constraint name, and an
// operator configuring an inbound deserves to be told what is actually wrong.
func (s *Service) CreateInbound(ctx context.Context, actor audit.Actor, in CreateInboundInput) (*dbgen.Inbound, error) {
	params, err := s.buildInboundParams(in)
	if err != nil {
		return nil, err
	}

	var created dbgen.Inbound
	err = s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		if in.RealityKeyID != nil {
			if _, err := queries.GetRealityKey(ctx, *in.RealityKeyID); err != nil {
				return translate(err, fmt.Sprintf("reality key %d", *in.RealityKeyID))
			}
		}

		inbound, err := queries.CreateInbound(ctx, params)
		if err != nil {
			return translate(err, "inbound "+in.Tag)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "inbound.create",
			EntityType: "inbound",
			EntityID:   fmt.Sprint(inbound.ID),
			After:      audit.Redact(inboundFields(&inbound)),
		})

		created = inbound
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &created, nil
}

// UpdateInboundInput carries only the fields to change.
type UpdateInboundInput struct {
	Tag             *string
	ListenPort      *int32
	ListenAddr      *string
	NetworkSettings json.RawMessage
	TLSSettings     json.RawMessage
	Sniffing        json.RawMessage
	Extra           json.RawMessage
	Enabled         *bool

	// SetFlow distinguishes "leave the flow alone" from "clear it", which one pointer
	// cannot express.
	SetFlow bool
	Flow    string
}

// UpdateInbound changes an inbound and revalidates it.
func (s *Service) UpdateInbound(ctx context.Context, actor audit.Actor, id int64, in UpdateInboundInput) (*dbgen.Inbound, error) {
	var updated dbgen.Inbound

	err := s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		before, err := queries.GetInbound(ctx, id)
		if err != nil {
			return translate(err, "inbound")
		}

		// A port change can break nodes the caller is not looking at, so every node
		// carrying this inbound is checked before anything is written.
		if in.ListenPort != nil && *in.ListenPort != before.ListenPort {
			if err := validatePort(*in.ListenPort); err != nil {
				return err
			}
			conflicts, err := queries.ConflictingPortsForInbound(ctx, dbgen.ConflictingPortsForInboundParams{
				InboundID:  id,
				ListenPort: *in.ListenPort,
			})
			if err != nil {
				return translate(err, "port conflict check")
			}
			if len(conflicts) > 0 {
				return fmt.Errorf("%w: port %d is already used by inbound %q on node %q",
					ErrPortConflict, *in.ListenPort, conflicts[0].OtherTag, conflicts[0].NodeName)
			}
		}

		params := dbgen.UpdateInboundParams{
			ID:              id,
			Tag:             in.Tag,
			ListenPort:      in.ListenPort,
			ListenAddress:   in.ListenAddr,
			NetworkSettings: in.NetworkSettings,
			TlsSettings:     in.TLSSettings,
			Sniffing:        in.Sniffing,
			Extra:           in.Extra,
			IsEnabled:       in.Enabled,
		}
		if in.SetFlow && in.Flow != "" {
			params.Flow = &in.Flow
		}

		inbound, err := queries.UpdateInbound(ctx, params)
		if err != nil {
			return translate(err, "inbound")
		}

		if in.SetFlow && in.Flow == "" {
			inbound, err = queries.ClearInboundFlow(ctx, id)
			if err != nil {
				return translate(err, "inbound flow")
			}
		}

		// Revalidate the result as a whole. Field-by-field checks miss combinations,
		// such as a transport change that makes an existing flow invalid.
		if err := s.validateStoredInbound(ctx, queries, &inbound); err != nil {
			return err
		}

		s.bumpNodesForInbound(ctx, queries, id)

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "inbound.update",
			EntityType: "inbound",
			EntityID:   fmt.Sprint(id),
			Before:     audit.Redact(inboundFields(&before)),
			After:      audit.Redact(inboundFields(&inbound)),
		})

		updated = inbound
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// DeleteInbound removes an inbound. Group membership and node bindings cascade.
func (s *Service) DeleteInbound(ctx context.Context, actor audit.Actor, id int64) error {
	return s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		before, err := queries.GetInbound(ctx, id)
		if err != nil {
			return translate(err, "inbound")
		}

		// Bump first: after the bindings cascade away, the nodes that carried this
		// inbound are no longer reachable from it.
		s.bumpNodesForInbound(ctx, queries, id)

		rows, err := queries.DeleteInbound(ctx, id)
		if err != nil {
			return translate(err, "inbound")
		}
		if rows == 0 {
			return fmt.Errorf("%w: inbound", ErrNotFound)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "inbound.delete",
			EntityType: "inbound",
			EntityID:   fmt.Sprint(id),
			Before:     audit.Redact(inboundFields(&before)),
		})
		return nil
	})
}

// AttachInbound binds an inbound to a node.
//
// The port collision check is the reason this is a service operation rather than a bare
// insert. Two inbounds on one port mean Xray does not start at all, and from the panel
// that looks like a node that broke by itself (ADR-011).
func (s *Service) AttachInbound(ctx context.Context, actor audit.Actor, nodeID, inboundID int64) error {
	return s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		node, err := queries.GetNode(ctx, nodeID)
		if err != nil {
			return translate(err, "node")
		}
		inbound, err := queries.GetInbound(ctx, inboundID)
		if err != nil {
			return translate(err, "inbound")
		}

		conflicts, err := queries.PortConflictOnNode(ctx, dbgen.PortConflictOnNodeParams{
			NodeID:             nodeID,
			ListenPort:         inbound.ListenPort,
			ExcludingInboundID: inboundID,
		})
		if err != nil {
			return translate(err, "port conflict check")
		}
		if len(conflicts) > 0 {
			return fmt.Errorf("%w: node %q already serves %q on port %d",
				ErrPortConflict, node.Name, conflicts[0].Tag, inbound.ListenPort)
		}

		if err := queries.AttachInboundToNode(ctx, dbgen.AttachInboundToNodeParams{
			NodeID:    nodeID,
			InboundID: inboundID,
		}); err != nil {
			return translate(err, "node inbound")
		}

		if _, err := queries.BumpNodeConfigVersion(ctx, nodeID); err != nil {
			return translate(err, "node config version")
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "node.attach_inbound",
			EntityType: "node",
			EntityID:   fmt.Sprint(nodeID),
			After:      map[string]any{"inbound_tag": inbound.Tag, "port": inbound.ListenPort},
		})
		return nil
	})
}

// DetachInbound unbinds an inbound from a node.
func (s *Service) DetachInbound(ctx context.Context, actor audit.Actor, nodeID, inboundID int64) error {
	return s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		rows, err := queries.DetachInboundFromNode(ctx, dbgen.DetachInboundFromNodeParams{
			NodeID:    nodeID,
			InboundID: inboundID,
		})
		if err != nil {
			return translate(err, "node inbound")
		}
		if rows == 0 {
			return fmt.Errorf("%w: that inbound is not on that node", ErrNotFound)
		}

		if _, err := queries.BumpNodeConfigVersion(ctx, nodeID); err != nil {
			return translate(err, "node config version")
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "node.detach_inbound",
			EntityType: "node",
			EntityID:   fmt.Sprint(nodeID),
			Before:     map[string]any{"inbound_id": inboundID},
		})
		return nil
	})
}

// --- reality keys ---

// CreateRealityKeyInput describes a new Reality key set.
type CreateRealityKeyInput struct {
	Name        string
	Dest        string
	ServerNames []string

	// ShortIDCount is how many identifiers to generate. Zero uses the package default.
	ShortIDCount int
}

// CreateRealityKey generates a key pair and short ids, storing the private half
// encrypted.
func (s *Service) CreateRealityKey(ctx context.Context, actor audit.Actor, in CreateRealityKeyInput) (*dbgen.RealityKey, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, validationErrorf("reality key needs a name")
	}
	if err := reality.ValidateDest(in.Dest); err != nil {
		return nil, validationErrorf("%s", err.Error())
	}
	if err := reality.ValidateServerNames(in.ServerNames); err != nil {
		return nil, validationErrorf("%s", err.Error())
	}

	count := in.ShortIDCount
	if count == 0 {
		count = reality.DefaultShortIDCount
	}

	pair, err := reality.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("service: %w", err)
	}
	shortIDs, err := reality.GenerateShortIDs(count)
	if err != nil {
		return nil, validationErrorf("%s", err.Error())
	}

	encrypted, err := s.cipher.EncryptString(pair.PrivateKey, purposeRealityPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("service: encrypt reality private key: %w", err)
	}

	var created dbgen.RealityKey
	err = s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		key, err := queries.CreateRealityKey(ctx, dbgen.CreateRealityKeyParams{
			Name:        strings.TrimSpace(in.Name),
			PrivateEnc:  encrypted,
			PublicKey:   pair.PublicKey,
			ShortIds:    shortIDs,
			Dest:        in.Dest,
			ServerNames: in.ServerNames,
		})
		if err != nil {
			return translate(err, "reality key "+in.Name)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "reality_key.create",
			EntityType: "reality_key",
			EntityID:   fmt.Sprint(key.ID),
			// The public key and short ids are not secret; the private key is, and is
			// not recorded.
			After: map[string]any{
				"name":         key.Name,
				"public_key":   key.PublicKey,
				"short_ids":    key.ShortIds,
				"dest":         key.Dest,
				"server_names": key.ServerNames,
			},
		})

		created = key
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &created, nil
}

// DeleteRealityKey removes a key set, refusing while an inbound still uses it.
//
// The foreign key is ON DELETE RESTRICT, so the database would refuse anyway. Checking
// here turns a constraint name into a message that says how many inbounds are in the
// way.
func (s *Service) DeleteRealityKey(ctx context.Context, actor audit.Actor, id int64) error {
	return s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		used, err := queries.CountInboundsUsingRealityKey(ctx, &id)
		if err != nil {
			return translate(err, "reality key usage")
		}
		if used > 0 {
			return fmt.Errorf("%w: %d inbound(s) still use this reality key", ErrInUse, used)
		}

		rows, err := queries.DeleteRealityKey(ctx, id)
		if err != nil {
			return translate(err, "reality key")
		}
		if rows == 0 {
			return fmt.Errorf("%w: reality key", ErrNotFound)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "reality_key.delete",
			EntityType: "reality_key",
			EntityID:   fmt.Sprint(id),
		})
		return nil
	})
}

// --- validation ---

func (s *Service) buildInboundParams(in CreateInboundInput) (dbgen.CreateInboundParams, error) {
	var params dbgen.CreateInboundParams

	tag := strings.TrimSpace(in.Tag)
	if tag == "" {
		return params, validationErrorf("inbound needs a tag")
	}
	// The api tag is taken by the local Xray API inbound and the routing rule keys off
	// it, so a user inbound with that tag would receive API traffic.
	if tag == "api" {
		return params, validationErrorf("inbound tag %q is reserved", tag)
	}
	if err := validatePort(in.ListenPort); err != nil {
		return params, err
	}

	protocol, err := parseProtocol(in.Protocol)
	if err != nil {
		return params, err
	}
	transport, err := parseTransport(in.Transport)
	if err != nil {
		return params, err
	}
	security, err := parseSecurity(in.Security)
	if err != nil {
		return params, err
	}

	listenAddr := in.ListenAddr
	if listenAddr == "" {
		listenAddr = "0.0.0.0"
	}

	params = dbgen.CreateInboundParams{
		Tag:             tag,
		Protocol:        protocol,
		Transport:       transport,
		Security:        security,
		ListenPort:      in.ListenPort,
		ListenAddress:   listenAddr,
		NetworkSettings: orEmptyObject(in.NetworkSettings),
		TlsSettings:     orEmptyObject(in.TLSSettings),
		Sniffing:        orEmptyObject(in.Sniffing),
		Extra:           orEmptyObject(in.Extra),
		RealityKeyID:    in.RealityKeyID,
		IsEnabled:       in.Enabled,
	}

	if in.Flow != "" {
		// Mirrors the database constraint and the generator's check. A flow on the
		// wrong transport produces an inbound that starts fine and fails only on a live
		// client (ADR-010).
		if protocol != dbgen.InboundProtoVless || transport != dbgen.InboundNetTcp ||
			(security != dbgen.InboundSecTls && security != dbgen.InboundSecReality) {
			return params, validationErrorf(
				"flow is only valid for vless over raw tcp with tls or reality")
		}
		flow := in.Flow
		params.Flow = &flow
	}

	switch protocol {
	case dbgen.InboundProtoShadowsocks:
		if !strings.HasPrefix(in.SSMethod, "2022-") {
			// The older AEAD ciphers have no per-user keys, so a multi-user inbound
			// cannot attribute traffic and billing becomes impossible (ADR-030).
			return params, validationErrorf(
				"shadowsocks method must be one of the 2022-* methods, got %q", in.SSMethod)
		}
		if in.SSServerKey == "" {
			return params, validationErrorf("shadowsocks needs a server key")
		}
		method := in.SSMethod
		params.SsMethod = &method

		encrypted, err := s.cipher.EncryptString(in.SSServerKey, purposeSSServerKey)
		if err != nil {
			return params, fmt.Errorf("service: encrypt shadowsocks server key: %w", err)
		}
		params.SsServerKeyEnc = encrypted

	default:
		if in.SSMethod != "" || in.SSServerKey != "" {
			return params, validationErrorf("shadowsocks settings are only valid for the shadowsocks protocol")
		}
	}

	if security == dbgen.InboundSecReality && in.RealityKeyID == nil {
		return params, validationErrorf("reality needs a reality key")
	}
	if security != dbgen.InboundSecReality && in.RealityKeyID != nil {
		return params, validationErrorf("a reality key is only valid when security is reality")
	}
	if security == dbgen.InboundSecTls && len(in.TLSSettings) == 0 {
		return params, validationErrorf("tls needs tls_settings, for example certificate paths")
	}

	for name, raw := range map[string]json.RawMessage{
		"network_settings": in.NetworkSettings,
		"tls_settings":     in.TLSSettings,
		"sniffing":         in.Sniffing,
		"extra":            in.Extra,
	} {
		if len(raw) == 0 {
			continue
		}
		var object map[string]any
		if err := json.Unmarshal(raw, &object); err != nil {
			return params, validationErrorf("%s must be a JSON object", name)
		}
	}

	return params, nil
}

// validateStoredInbound runs the generator's own validation over a single stored
// inbound, using a placeholder client so credential checks pass.
//
// This is how an update is checked as a whole: the generator is the authority on what
// Xray accepts, and duplicating its rules here would let the two drift.
func (s *Service) validateStoredInbound(ctx context.Context, queries *dbgen.Queries, inbound *dbgen.Inbound) error {
	spec, err := s.inboundToSpec(ctx, queries, inbound, []xrayconfig.Client{{
		Email:    "validation-probe",
		UUID:     "00000000-0000-4000-8000-000000000000",
		Password: "validation-probe",
	}})
	if err != nil {
		return err
	}

	if err := (&xrayconfig.Spec{
		Inbounds: []xrayconfig.Inbound{*spec},
	}).Validate(); err != nil {
		return validationErrorf("%s", err.Error())
	}
	return nil
}

func validatePort(port int32) error {
	if port < 1 || port > 65535 {
		return validationErrorf("port must be between 1 and 65535")
	}
	return nil
}

func parseProtocol(value string) (dbgen.InboundProto, error) {
	switch dbgen.InboundProto(strings.ToLower(strings.TrimSpace(value))) {
	case dbgen.InboundProtoVless:
		return dbgen.InboundProtoVless, nil
	case dbgen.InboundProtoTrojan:
		return dbgen.InboundProtoTrojan, nil
	case dbgen.InboundProtoShadowsocks:
		return dbgen.InboundProtoShadowsocks, nil
	default:
		return "", validationErrorf("protocol must be one of vless, trojan, shadowsocks")
	}
}

func parseTransport(value string) (dbgen.InboundNet, error) {
	switch dbgen.InboundNet(strings.ToLower(strings.TrimSpace(value))) {
	case dbgen.InboundNetTcp:
		return dbgen.InboundNetTcp, nil
	case dbgen.InboundNetWs:
		return dbgen.InboundNetWs, nil
	case dbgen.InboundNetGrpc:
		return dbgen.InboundNetGrpc, nil
	case dbgen.InboundNetHttpupgrade:
		return dbgen.InboundNetHttpupgrade, nil
	case dbgen.InboundNetXhttp:
		return dbgen.InboundNetXhttp, nil
	default:
		return "", validationErrorf("transport must be one of tcp, ws, grpc, httpupgrade, xhttp")
	}
}

func parseSecurity(value string) (dbgen.InboundSec, error) {
	switch dbgen.InboundSec(strings.ToLower(strings.TrimSpace(value))) {
	case dbgen.InboundSecNone:
		return dbgen.InboundSecNone, nil
	case dbgen.InboundSecTls:
		return dbgen.InboundSecTls, nil
	case dbgen.InboundSecReality:
		return dbgen.InboundSecReality, nil
	default:
		return "", validationErrorf("security must be one of none, tls, reality")
	}
}

func orEmptyObject(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return emptyJSONObject
	}
	return raw
}

// inboundFields is the audit view of an inbound.
func inboundFields(inbound *dbgen.Inbound) map[string]any {
	fields := map[string]any{
		"tag":         inbound.Tag,
		"protocol":    string(inbound.Protocol),
		"transport":   string(inbound.Transport),
		"security":    string(inbound.Security),
		"listen_port": inbound.ListenPort,
		"listen_addr": inbound.ListenAddress,
		"enabled":     inbound.IsEnabled,
	}
	if inbound.Flow != nil {
		fields["flow"] = *inbound.Flow
	}
	if inbound.SsMethod != nil {
		fields["ss_method"] = *inbound.SsMethod
	}
	if inbound.RealityKeyID != nil {
		fields["reality_key_id"] = *inbound.RealityKeyID
	}
	return fields
}
