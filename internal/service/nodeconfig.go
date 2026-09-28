package service

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/xraypanel/panel/internal/audit"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
	xrayconfig "github.com/xraypanel/panel/internal/xray/config"
)

// DesiredConfig is what a node should be running, and the version that labels it.
type DesiredConfig struct {
	Version int64

	// JSON is the complete config.json. Empty means "run nothing", which is the correct
	// desired state for a node with no inbounds or no active users on them: better a
	// node that is idle and manageable than one still serving a configuration the panel
	// no longer believes in.
	JSON []byte

	StructuralHash string
	InboundHashes  map[string]string
}

// Empty reports whether this asks for nothing to be running.
func (c *DesiredConfig) Empty() bool { return c == nil || len(c.JSON) == 0 }

// DesiredNodeConfig builds the configuration for a node together with its version.
//
// The version is read before the content, and that ordering is deliberate. A bump
// between the two reads then means the node is handed newer content under an older
// version: the panel still sees the node as behind and pushes again, the node applies
// the same bytes a second time, and the version catches up. The other ordering produces
// the failure that cannot heal — content labelled with a version it does not contain,
// after which the panel believes the node is up to date for ever.
func (s *Service) DesiredNodeConfig(ctx context.Context, nodeID int64) (*DesiredConfig, error) {
	node, err := s.q.GetNode(ctx, nodeID)
	if err != nil {
		return nil, translate(err, "node")
	}
	version := node.ConfigVersion

	spec, err := s.BuildNodeSpec(ctx, nodeID)
	if err != nil {
		return nil, err
	}

	if len(spec.Inbounds) == 0 {
		return &DesiredConfig{Version: version}, nil
	}

	generated, err := xrayconfig.Generate(*spec)
	if err != nil {
		// A configuration the generator refuses is an operator's mistake, not a server
		// fault, and it must not be sent: the node would either reject it or start
		// something unintended.
		return nil, validationErrorf("%s", err.Error())
	}

	return &DesiredConfig{
		Version:        version,
		JSON:           generated.JSON,
		StructuralHash: generated.StructuralHash,
		InboundHashes:  generated.InboundHashes,
	}, nil
}

// RecordNodeApplyResult stores what a node reported about applying a configuration.
//
// A failure records the reason and leaves applied_version alone: the node is still
// running whatever it was running before, and claiming otherwise would hide a node that
// is serving a stale configuration.
//
// A restart is recorded too, because it is the one part of applying a change that users
// feel: every live connection on the node is dropped. An operator who is told that a
// change went out cleanly, and whose users complain anyway, needs to be able to find out
// which change did it.
func (s *Service) RecordNodeApplyResult(
	ctx context.Context, nodeID int64, version int64, applyErr string, restarted bool,
) error {
	if len(applyErr) > 500 {
		applyErr = applyErr[:500]
	}

	params := dbgen.SetNodeAppliedVersionParams{ID: nodeID, LastError: applyErr}
	if applyErr == "" {
		params.AppliedVersion = &version
	}

	if err := s.q.SetNodeAppliedVersion(ctx, params); err != nil {
		return translate(err, "node applied version")
	}

	if applyErr == "" && restarted {
		s.log.InfoContext(ctx, "a node restarted its core to apply a configuration",
			slog.Int64("node_id", nodeID),
			slog.Int64("config_version", version))

		s.audit.Record(ctx, audit.Actor{Type: audit.ActorNode, ID: &nodeID}, audit.Entry{
			Action:     "node.core_restarted",
			EntityType: "node",
			EntityID:   fmt.Sprint(nodeID),
			After:      map[string]any{"config_version": version},
		})
	}

	if applyErr != "" {
		s.log.WarnContext(ctx, "a node could not apply its configuration",
			slog.Int64("node_id", nodeID),
			slog.Int64("config_version", version),
			slog.String("error", applyErr))

		// Audited, not just logged: an operator looking at why a node is behind should
		// find it in the same place as every other change to that node.
		s.audit.Record(ctx, audit.Actor{Type: audit.ActorNode, ID: &nodeID}, audit.Entry{
			Action:     "node.apply_failed",
			EntityType: "node",
			EntityID:   fmt.Sprint(nodeID),
			After:      map[string]any{"config_version": version, "error": applyErr},
		})
	}
	return nil
}
