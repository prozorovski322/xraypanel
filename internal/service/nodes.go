package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xraypanel/panel/internal/audit"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
	xrayconfig "github.com/xraypanel/panel/internal/xray/config"
)

// CreateNodeInput describes a new exit server.
type CreateNodeInput struct {
	Name string

	// Address is the default connection address offered to clients. Hosts may override
	// it, which is what a CDN in front of a node looks like.
	Address string

	CountryCode string
	Tag         string

	// ConfigPatch is an RFC 7386 merge patch applied to the generated configuration. It
	// is the only supported way to make one node differ from another (ADR-003).
	ConfigPatch json.RawMessage

	Enabled bool
}

// CreateNode registers an exit server.
func (s *Service) CreateNode(ctx context.Context, actor audit.Actor, in CreateNodeInput) (*dbgen.Node, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, validationErrorf("node needs a name")
	}
	if strings.TrimSpace(in.Address) == "" {
		return nil, validationErrorf("node needs an address")
	}

	countryCode, err := normalizeCountryCode(in.CountryCode)
	if err != nil {
		return nil, err
	}
	patch, err := validateConfigPatch(in.ConfigPatch)
	if err != nil {
		return nil, err
	}

	var created dbgen.Node
	err = s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		node, err := queries.CreateNode(ctx, dbgen.CreateNodeParams{
			Name:        name,
			Address:     in.Address,
			CountryCode: countryCode,
			Tag:         in.Tag,
			ConfigPatch: patch,
			IsEnabled:   in.Enabled,
		})
		if err != nil {
			return translate(err, "node "+name)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "node.create",
			EntityType: "node",
			EntityID:   fmt.Sprint(node.ID),
			After:      map[string]any{"name": node.Name, "address": node.Address, "enabled": node.IsEnabled},
		})

		created = node
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &created, nil
}

// UpdateNodeInput carries only the fields to change.
type UpdateNodeInput struct {
	Name        *string
	Address     *string
	CountryCode *string
	Tag         *string
	Enabled     *bool

	SetConfigPatch bool
	ConfigPatch    json.RawMessage
}

// UpdateNode changes a node.
func (s *Service) UpdateNode(ctx context.Context, actor audit.Actor, id int64, in UpdateNodeInput) (*dbgen.Node, error) {
	params := dbgen.UpdateNodeParams{
		ID:      id,
		Name:    in.Name,
		Address: in.Address,
		Tag:     in.Tag,
	}
	if in.CountryCode != nil {
		code, err := normalizeCountryCode(*in.CountryCode)
		if err != nil {
			return nil, err
		}
		params.CountryCode = code
	}
	if in.SetConfigPatch {
		patch, err := validateConfigPatch(in.ConfigPatch)
		if err != nil {
			return nil, err
		}
		params.ConfigPatch = patch
	}
	params.IsEnabled = in.Enabled

	var updated dbgen.Node
	err := s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		before, err := queries.GetNode(ctx, id)
		if err != nil {
			return translate(err, "node")
		}

		node, err := queries.UpdateNode(ctx, params)
		if err != nil {
			return translate(err, "node")
		}

		// The patch and the enabled flag both change what the node should be running.
		// The address and country only affect client links, but bumping unconditionally
		// is cheap, and a missed bump is a change that silently never arrives.
		if _, err := queries.BumpNodeConfigVersion(ctx, id); err != nil {
			return translate(err, "node config version")
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "node.update",
			EntityType: "node",
			EntityID:   fmt.Sprint(id),
			Before:     map[string]any{"name": before.Name, "address": before.Address, "enabled": before.IsEnabled},
			After:      map[string]any{"name": node.Name, "address": node.Address, "enabled": node.IsEnabled},
		})

		updated = node
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// DeleteNode removes a node and its inbound bindings.
func (s *Service) DeleteNode(ctx context.Context, actor audit.Actor, id int64) error {
	return s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		before, err := queries.GetNode(ctx, id)
		if err != nil {
			return translate(err, "node")
		}

		rows, err := queries.DeleteNode(ctx, id)
		if err != nil {
			return translate(err, "node")
		}
		if rows == 0 {
			return fmt.Errorf("%w: node", ErrNotFound)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "node.delete",
			EntityType: "node",
			EntityID:   fmt.Sprint(id),
			Before:     map[string]any{"name": before.Name, "address": before.Address},
		})
		return nil
	})
}

// PreviewNodeConfig generates what a node would be sent, without sending it.
//
// This exists because the alternative way to find out is to deploy and watch whether the
// node comes back, and a config that Xray rejects means a node that does not start.
func (s *Service) PreviewNodeConfig(ctx context.Context, nodeID int64) (*xrayconfig.Generated, error) {
	spec, err := s.BuildNodeSpec(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	if len(spec.Inbounds) == 0 {
		return nil, validationErrorf(
			"node has no inbound with active users, so there is nothing to configure")
	}

	generated, err := xrayconfig.Generate(*spec)
	if err != nil {
		// A generation failure here is a configuration mistake, not a server fault: the
		// caller can fix it, so it is reported as one.
		return nil, validationErrorf("%s", err.Error())
	}
	return generated, nil
}

// normalizeCountryCode upper-cases and length-checks an ISO country code.
func normalizeCountryCode(code string) (*string, error) {
	trimmed := strings.TrimSpace(code)
	if trimmed == "" {
		return nil, nil
	}
	if len(trimmed) != 2 {
		return nil, validationErrorf("country code must be two letters, got %q", code)
	}
	upper := strings.ToUpper(trimmed)
	return &upper, nil
}

// validateConfigPatch checks that a patch is a JSON object and that it does not break the
// generated configuration.
//
// A patch is applied to the finished document, so a malformed one turns every node
// configuration into a failure. Catching it on write means the mistake is reported to
// whoever made it.
func validateConfigPatch(patch json.RawMessage) ([]byte, error) {
	if len(patch) == 0 {
		return emptyJSONObject, nil
	}

	var object map[string]any
	if err := json.Unmarshal(patch, &object); err != nil {
		return nil, validationErrorf("config_patch must be a JSON object")
	}

	// Applying it to a minimal document proves the merge itself works. It cannot prove
	// the result is a valid Xray config, which is what PreviewNodeConfig is for.
	if _, err := xrayconfig.ApplyMergePatch([]byte(`{}`), patch); err != nil {
		return nil, validationErrorf("config_patch cannot be applied: %s", err.Error())
	}
	return patch, nil
}
