package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/xraypanel/panel/internal/audit"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// CreateHostInput describes how an inbound is presented to clients.
type CreateHostInput struct {
	InboundID int64
	Remark    string
	Address   string

	// Port overrides the inbound's listen port. Nil inherits it, which is what makes a
	// host in front of a CDN expressible: the client connects to 443 while Xray listens
	// somewhere else.
	Port *int32

	SNI           *string
	HostHeader    *string
	Path          *string
	Fingerprint   *string
	ALPN          *string
	AllowInsecure bool
	SortOrder     int32
	Enabled       bool
}

// validFingerprints are the uTLS profiles clients understand. An unknown value is
// refused rather than passed through: a client given a fingerprint it does not know
// either fails to start or silently falls back, and neither is visible from the panel.
var validFingerprints = map[string]struct{}{
	"chrome": {}, "firefox": {}, "safari": {}, "ios": {}, "android": {},
	"edge": {}, "360": {}, "qq": {}, "random": {}, "randomized": {},
}

// CreateHost adds a client-facing presentation of an inbound.
func (s *Service) CreateHost(ctx context.Context, actor audit.Actor, in CreateHostInput) (*dbgen.Host, error) {
	if strings.TrimSpace(in.Remark) == "" {
		return nil, validationErrorf("host needs a remark; it is what the user sees in their client")
	}
	if strings.TrimSpace(in.Address) == "" {
		return nil, validationErrorf("host needs an address")
	}
	if in.Port != nil {
		if err := validatePort(*in.Port); err != nil {
			return nil, err
		}
	}
	if in.Fingerprint != nil && *in.Fingerprint != "" {
		if _, ok := validFingerprints[strings.ToLower(*in.Fingerprint)]; !ok {
			return nil, validationErrorf(
				"fingerprint %q is not one clients recognise", *in.Fingerprint)
		}
	}

	var created dbgen.Host
	err := s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		inbound, err := queries.GetInbound(ctx, in.InboundID)
		if err != nil {
			return translate(err, "inbound")
		}

		host, err := queries.CreateHost(ctx, dbgen.CreateHostParams{
			InboundID:     in.InboundID,
			Remark:        in.Remark,
			Address:       in.Address,
			Port:          in.Port,
			Sni:           in.SNI,
			HostHeader:    in.HostHeader,
			Path:          in.Path,
			Fingerprint:   in.Fingerprint,
			Alpn:          in.ALPN,
			AllowInsecure: in.AllowInsecure,
			SortOrder:     in.SortOrder,
			IsEnabled:     in.Enabled,
		})
		if err != nil {
			return translate(err, "host")
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "host.create",
			EntityType: "host",
			EntityID:   fmt.Sprint(host.ID),
			After: map[string]any{
				"inbound_tag": inbound.Tag,
				"remark":      host.Remark,
				"address":     host.Address,
			},
		})

		created = host
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &created, nil
}

// UpdateHostInput carries only the fields to change.
type UpdateHostInput struct {
	Remark        *string
	Address       *string
	SNI           *string
	HostHeader    *string
	Path          *string
	Fingerprint   *string
	ALPN          *string
	AllowInsecure *bool
	SortOrder     *int32
	Enabled       *bool

	// SetPort distinguishes "leave the port alone" from "go back to inheriting the
	// inbound's", which one pointer cannot express.
	SetPort bool
	Port    *int32
}

// UpdateHost changes a host.
func (s *Service) UpdateHost(ctx context.Context, actor audit.Actor, id int64, in UpdateHostInput) (*dbgen.Host, error) {
	if in.Fingerprint != nil && *in.Fingerprint != "" {
		if _, ok := validFingerprints[strings.ToLower(*in.Fingerprint)]; !ok {
			return nil, validationErrorf("fingerprint %q is not one clients recognise", *in.Fingerprint)
		}
	}
	if in.SetPort && in.Port != nil {
		if err := validatePort(*in.Port); err != nil {
			return nil, err
		}
	}

	var updated dbgen.Host
	err := s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		before, err := queries.GetHost(ctx, id)
		if err != nil {
			return translate(err, "host")
		}

		host, err := queries.UpdateHost(ctx, dbgen.UpdateHostParams{
			ID:            id,
			Remark:        in.Remark,
			Address:       in.Address,
			Sni:           in.SNI,
			HostHeader:    in.HostHeader,
			Path:          in.Path,
			Fingerprint:   in.Fingerprint,
			Alpn:          in.ALPN,
			AllowInsecure: in.AllowInsecure,
			SortOrder:     in.SortOrder,
			IsEnabled:     in.Enabled,
		})
		if err != nil {
			return translate(err, "host")
		}

		if in.SetPort {
			host, err = queries.SetHostPort(ctx, dbgen.SetHostPortParams{ID: id, Port: in.Port})
			if err != nil {
				return translate(err, "host port")
			}
		}

		// A host only affects what clients are told, never what a node runs, so no node
		// configuration version is bumped here.
		recorder.Record(ctx, actor, audit.Entry{
			Action:     "host.update",
			EntityType: "host",
			EntityID:   fmt.Sprint(id),
			Before:     map[string]any{"remark": before.Remark, "address": before.Address},
			After:      map[string]any{"remark": host.Remark, "address": host.Address},
		})

		updated = host
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// DeleteHost removes a host.
//
// The last host of an inbound is allowed to go: the inbound keeps running on its nodes,
// and its users simply stop being told about it. Refusing would force an operator to
// delete the inbound to remove a presentation of it.
func (s *Service) DeleteHost(ctx context.Context, actor audit.Actor, id int64) error {
	return s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		before, err := queries.GetHost(ctx, id)
		if err != nil {
			return translate(err, "host")
		}

		rows, err := queries.DeleteHost(ctx, id)
		if err != nil {
			return translate(err, "host")
		}
		if rows == 0 {
			return fmt.Errorf("%w: host", ErrNotFound)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "host.delete",
			EntityType: "host",
			EntityID:   fmt.Sprint(id),
			Before:     map[string]any{"remark": before.Remark, "address": before.Address},
		})
		return nil
	})
}
