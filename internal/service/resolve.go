package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
	"github.com/xraypanel/panel/internal/sublink"
	xrayconfig "github.com/xraypanel/panel/internal/xray/config"
)

// BuildNodeSpec assembles the configuration a node should be running.
//
// This is where the panel's tables become the input to the generator: the node's
// inbounds, each with the users allowed on it, plus the node's own config patch.
func (s *Service) BuildNodeSpec(ctx context.Context, nodeID int64) (*xrayconfig.Spec, error) {
	node, err := s.q.GetNode(ctx, nodeID)
	if err != nil {
		return nil, translate(err, "node")
	}

	inbounds, err := s.q.ListNodeInbounds(ctx, nodeID)
	if err != nil {
		return nil, translate(err, "node inbounds")
	}

	spec := &xrayconfig.Spec{
		NodeName:    node.Name,
		ConfigPatch: json.RawMessage(node.ConfigPatch),
		Defaults:    xrayconfig.Defaults{},
	}

	for i := range inbounds {
		inbound := &inbounds[i]
		if !inbound.IsEnabled {
			continue
		}

		clients, err := s.inboundClients(ctx, s.q, inbound)
		if err != nil {
			return nil, err
		}
		if len(clients) == 0 {
			// An inbound with no active users is left out rather than emitted empty.
			// The generator refuses an inbound with no clients, and a node should not
			// fail to start because everyone on one of its inbounds is over quota.
			continue
		}

		built, err := s.inboundToSpec(ctx, s.q, inbound, clients)
		if err != nil {
			return nil, err
		}
		spec.Inbounds = append(spec.Inbounds, *built)
	}

	return spec, nil
}

// inboundClients reads the active users allowed on an inbound.
func (s *Service) inboundClients(ctx context.Context, queries *dbgen.Queries, inbound *dbgen.Inbound) ([]xrayconfig.Client, error) {
	rows, err := queries.ListInboundClients(ctx, inbound.ID)
	if err != nil {
		return nil, translate(err, "inbound clients")
	}

	clients := make([]xrayconfig.Client, 0, len(rows))
	for _, row := range rows {
		client := xrayconfig.Client{Email: row.XrayEmail}

		switch inbound.Protocol {
		case dbgen.InboundProtoVless:
			client.UUID = formatUUID(row.VlessUuid)
		case dbgen.InboundProtoTrojan:
			client.Password = row.TrojanPassword
		case dbgen.InboundProtoShadowsocks:
			client.Password = row.SsPassword
		}
		clients = append(clients, client)
	}
	return clients, nil
}

// inboundToSpec converts a stored inbound into the generator's input, decrypting the
// secrets it needs.
func (s *Service) inboundToSpec(
	ctx context.Context,
	queries *dbgen.Queries,
	inbound *dbgen.Inbound,
	clients []xrayconfig.Client,
) (*xrayconfig.Inbound, error) {
	built := &xrayconfig.Inbound{
		Tag:             inbound.Tag,
		Protocol:        xrayconfig.Protocol(inbound.Protocol),
		Transport:       xrayconfig.Transport(inbound.Transport),
		Security:        xrayconfig.Security(inbound.Security),
		ListenAddr:      inbound.ListenAddress,
		ListenPort:      int(inbound.ListenPort),
		NetworkSettings: json.RawMessage(inbound.NetworkSettings),
		TLSSettings:     json.RawMessage(inbound.TlsSettings),
		Sniffing:        json.RawMessage(inbound.Sniffing),
		Extra:           json.RawMessage(inbound.Extra),
		Clients:         clients,
	}

	if inbound.Flow != nil {
		built.Flow = *inbound.Flow
	}
	if inbound.SsMethod != nil {
		built.SSMethod = *inbound.SsMethod
	}
	if len(inbound.SsServerKeyEnc) > 0 {
		key, err := s.cipher.DecryptString(inbound.SsServerKeyEnc, purposeSSServerKey)
		if err != nil {
			return nil, fmt.Errorf("service: decrypt shadowsocks server key for %q: %w", inbound.Tag, err)
		}
		built.SSServerKey = key
	}

	if inbound.RealityKeyID != nil {
		key, err := queries.GetRealityKey(ctx, *inbound.RealityKeyID)
		if err != nil {
			return nil, translate(err, "reality key")
		}
		privateKey, err := s.cipher.DecryptString(key.PrivateEnc, purposeRealityPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("service: decrypt reality private key for %q: %w", inbound.Tag, err)
		}
		built.Reality = &xrayconfig.Reality{
			PrivateKey:  privateKey,
			ShortIDs:    key.ShortIds,
			Dest:        key.Dest,
			ServerNames: key.ServerNames,
		}
	}

	return built, nil
}

// BuildSubscription assembles what a user's client should be given.
func (s *Service) BuildSubscription(ctx context.Context, user *dbgen.User) (*sublink.Subscription, error) {
	rows, err := s.q.ListUserEndpoints(ctx, user.ID)
	if err != nil {
		return nil, translate(err, "user endpoints")
	}

	endpoints := make([]sublink.Endpoint, 0, len(rows))
	for i := range rows {
		endpoint, err := s.rowToEndpoint(user, &rows[i])
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, *endpoint)
	}

	return &sublink.Subscription{
		Endpoints:      endpoints,
		UserInfo:       userInfoOf(user),
		Title:          s.cfg.ProfileTitle,
		UpdateInterval: s.cfg.SubscriptionUpdateHours,
	}, nil
}

// userInfoOf is the quota summary clients display.
func userInfoOf(user *dbgen.User) sublink.UserInfo {
	info := sublink.UserInfo{
		// Xray reports uplink and downlink separately, but the panel bills the sum.
		// Splitting the stored total back into halves would be a guess, so the whole
		// amount is reported as download, which is what clients display as usage.
		Download: user.TrafficUsed,
		Total:    user.TrafficLimit,
	}
	if user.ExpiresAt != nil {
		info.Expire = *user.ExpiresAt
	}
	return info
}

// rowToEndpoint turns one resolved row into a client endpoint.
func (s *Service) rowToEndpoint(user *dbgen.User, row *dbgen.ListUserEndpointsRow) (*sublink.Endpoint, error) {
	ctx := sublink.TemplateContext{
		Username: user.Username,
		NodeName: row.NodeName,
	}
	if row.CountryCode != nil {
		ctx.Country = *row.CountryCode
	}

	address := sublink.ExpandTemplate(row.Address, ctx)
	if address == "" {
		// A host with no address falls back to the node's own, which is the common case
		// when there is no CDN in front.
		address = row.NodeAddress
	}

	// The host may present the inbound on a different port than the one Xray listens on,
	// which is what makes fronting by a CDN or a reverse proxy possible.
	port := int(row.ListenPort)
	if row.HostPort != nil {
		port = int(*row.HostPort)
	}

	endpoint := &sublink.Endpoint{
		Remark:    sublink.ExpandTemplate(row.Remark, ctx),
		Address:   address,
		Port:      port,
		Protocol:  sublink.Protocol(row.Protocol),
		Transport: sublink.Transport(row.Transport),
		Security:  sublink.Security(row.Security),
	}

	switch row.Protocol {
	case dbgen.InboundProtoVless:
		endpoint.UUID = formatUUID(user.VlessUuid)
	case dbgen.InboundProtoTrojan:
		endpoint.Password = user.TrojanPassword
	case dbgen.InboundProtoShadowsocks:
		if row.SsMethod == nil {
			return nil, fmt.Errorf("service: inbound %q has no shadowsocks method", row.InboundTag)
		}
		endpoint.SSMethod = *row.SsMethod
		endpoint.SSUserKey = user.SsPassword

		if len(row.SsServerKeyEnc) == 0 {
			return nil, fmt.Errorf("service: inbound %q has no shadowsocks server key", row.InboundTag)
		}
		key, err := s.cipher.DecryptString(row.SsServerKeyEnc, purposeSSServerKey)
		if err != nil {
			return nil, fmt.Errorf("service: decrypt shadowsocks server key for %q: %w", row.InboundTag, err)
		}
		endpoint.SSServerKey = key
	}

	if row.Flow != nil {
		endpoint.Flow = *row.Flow
	}

	applyHostTLS(endpoint, row)
	applyTransportSettings(endpoint, row)

	return endpoint, nil
}

// applyHostTLS fills the TLS and Reality parameters from the host and the inbound's key
// material.
func applyHostTLS(endpoint *sublink.Endpoint, row *dbgen.ListUserEndpointsRow) {
	if row.Sni != nil {
		endpoint.SNI = *row.Sni
	}
	if row.Fingerprint != nil {
		endpoint.Fingerprint = *row.Fingerprint
	}
	if row.Alpn != nil && *row.Alpn != "" {
		endpoint.ALPN = splitCommaList(*row.Alpn)
	}
	endpoint.AllowInsecure = row.AllowInsecure

	if row.Security == dbgen.InboundSecReality {
		if row.RealityPublicKey != nil {
			endpoint.PublicKey = *row.RealityPublicKey
		}
		if len(row.RealityShortIds) > 0 {
			// One id per client rather than the whole list: a link carries a single sid,
			// and the first is as good as any since Reality matches them individually.
			endpoint.ShortID = row.RealityShortIds[0]
		}
		// Reality without an SNI would send the client's real target in the handshake.
		// The server names the key was created with are the only correct values.
		if endpoint.SNI == "" && len(row.RealityServerNames) > 0 {
			endpoint.SNI = row.RealityServerNames[0]
		}
		// Every Reality client needs a fingerprint to imitate; chrome is the safe default
		// and what the specification suggests.
		if endpoint.Fingerprint == "" {
			endpoint.Fingerprint = "chrome"
		}
	}
}

// applyTransportSettings fills path, host and service name, preferring the host's own
// values and falling back to what the inbound was configured with.
//
// The host wins because it describes how a client reaches the inbound, which through a
// CDN is frequently not how the inbound is configured locally.
func applyTransportSettings(endpoint *sublink.Endpoint, row *dbgen.ListUserEndpointsRow) {
	settings := map[string]any{}
	if len(row.NetworkSettings) > 0 {
		_ = json.Unmarshal(row.NetworkSettings, &settings)
	}

	if row.Path != nil && *row.Path != "" {
		endpoint.Path = *row.Path
	} else if path, ok := settings["path"].(string); ok {
		endpoint.Path = path
	}

	if row.HostHeader != nil && *row.HostHeader != "" {
		endpoint.Host = *row.HostHeader
	} else if host, ok := settings["host"].(string); ok {
		endpoint.Host = host
	}

	if name, ok := settings["serviceName"].(string); ok {
		endpoint.ServiceName = name
	}
	if mode, ok := settings["mode"].(string); ok {
		endpoint.Mode = mode
	}
}

// formatUUID renders a stored uuid in the canonical hyphenated form clients expect.
func formatUUID(value pgtype.UUID) string {
	if !value.Valid {
		return ""
	}
	b := value.Bytes
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// splitCommaList parses a comma-separated ALPN list, dropping empty entries.
func splitCommaList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// MarkSubscriptionFetched records that a client pulled the subscription.
//
// Best effort: the client already has its profile, and failing the request over a
// bookkeeping write would deny service for no benefit.
func (s *Service) MarkSubscriptionFetched(ctx context.Context, userID int64) {
	fetchedAt := s.now()
	if err := s.q.TouchSubscriptionFetch(ctx, dbgen.TouchSubscriptionFetchParams{
		ID:        userID,
		FetchedAt: &fetchedAt,
	}); err != nil {
		s.log.WarnContext(ctx, "could not record subscription fetch",
			"user_id", userID, "error", err)
	}
}
