// Package audit records who changed what.
//
// It is a separate package because two things need it and they must not drift apart: a
// trail where half the changes are recorded one way and half another is a trail nobody
// trusts.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// Actor kinds, matching the CHECK constraint on audit_log.actor_type.
const (
	ActorAdmin  = "admin"
	ActorAPIKey = "api_key"
	ActorSystem = "system"
	ActorNode   = "node"
)

// Actor is who performed an action.
type Actor struct {
	Type string
	ID   *int64
	// Label is the actor's name as it was at the time. It is stored alongside the id
	// because the trail has to stay readable after the admin or key that acted is gone.
	Label string
	IP    *netip.Addr
}

// SystemActor is the actor for changes the panel makes on its own initiative.
func SystemActor(label string) Actor {
	return Actor{Type: ActorSystem, Label: label}
}

// Entry is one recorded change.
type Entry struct {
	Action     string
	EntityType string
	EntityID   string

	// Before and After are marshalled into the diff column. Secrets must be removed
	// before they get here; see Redact.
	Before any
	After  any
}

// Recorder writes audit entries.
type Recorder struct {
	queries *dbgen.Queries
	logger  *slog.Logger
	now     func() time.Time
}

// NewRecorder builds a recorder. A nil clock means time.Now.
func NewRecorder(queries *dbgen.Queries, logger *slog.Logger, now func() time.Time) *Recorder {
	if now == nil {
		now = time.Now
	}
	return &Recorder{queries: queries, logger: logger, now: now}
}

// WithQueries returns a recorder bound to a different query set, for use inside a
// transaction.
//
// An audit entry written outside the transaction that made the change could survive a
// rollback, leaving the trail claiming something that never happened.
func (r *Recorder) WithQueries(queries *dbgen.Queries) *Recorder {
	clone := *r
	clone.queries = queries
	return &clone
}

// Record writes an entry.
//
// A failure is logged and swallowed. Losing an audit row is bad, but failing the
// operation that was already performed is worse: the caller would retry a change that
// has in fact been applied.
func (r *Recorder) Record(ctx context.Context, actor Actor, entry Entry) {
	diff, err := buildDiff(entry.Before, entry.After)
	if err != nil {
		r.logger.WarnContext(ctx, "could not encode audit diff",
			slog.String("action", entry.Action), slog.Any("error", err))
	}

	var entityID *string
	if entry.EntityID != "" {
		entityID = &entry.EntityID
	}

	params := dbgen.InsertAuditEntryParams{
		At:         r.now(),
		ActorType:  actor.Type,
		ActorID:    actor.ID,
		ActorLabel: actor.Label,
		Action:     entry.Action,
		EntityType: entry.EntityType,
		EntityID:   entityID,
		Ip:         actor.IP,
		Diff:       diff,
	}
	if params.ActorType == "" {
		params.ActorType = ActorSystem
	}

	if err := r.queries.InsertAuditEntry(ctx, params); err != nil {
		r.logger.WarnContext(ctx, "could not write audit entry",
			slog.String("action", entry.Action),
			slog.String("entity", entry.EntityType+":"+entry.EntityID),
			slog.Any("error", err))
	}
}

func buildDiff(before, after any) ([]byte, error) {
	if before == nil && after == nil {
		return nil, nil
	}

	payload := map[string]any{}
	if before != nil {
		payload["before"] = before
	}
	if after != nil {
		payload["after"] = after
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("audit: encode diff: %w", err)
	}
	return encoded, nil
}

// redactedKeys are field names whose values never reach the audit trail.
//
// The trail is meant to be readable by more people than the database is, and it is
// often the first thing exported when something goes wrong. A password hash or a
// private key in there defeats the point of encrypting the column it came from.
var redactedKeys = map[string]struct{}{
	"password":          {},
	"password_hash":     {},
	"trojan_password":   {},
	"ss_password":       {},
	"ss_server_key":     {},
	"ss_server_key_enc": {},
	"private_enc":       {},
	"private_key":       {},
	"key_enc":           {},
	"secret_enc":        {},
	"totp_secret":       {},
	"token_hash":        {},
	"key_hash":          {},
	"short_uuid":        {},
	"vless_uuid":        {},
}

// Redacted is the placeholder stored in place of a secret.
const Redacted = "[REDACTED]"

// Redact copies a field map with secret values replaced.
//
// Credentials are redacted even though they are the interesting part of a "rotated
// credentials" entry: knowing that they changed is the audit-worthy fact, and the new
// value adds nothing an auditor needs while adding something an attacker wants.
func Redact(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}

	out := make(map[string]any, len(fields))
	for key, value := range fields {
		if _, secret := redactedKeys[key]; secret {
			out[key] = Redacted
			continue
		}
		// Nested maps are walked, since an entity is often recorded as a tree.
		if nested, ok := value.(map[string]any); ok {
			out[key] = Redact(nested)
			continue
		}
		out[key] = value
	}
	return out
}

// IsSecretField reports whether a field name is redacted. Exported so tests and other
// packages can agree on the list rather than keeping their own copy.
func IsSecretField(name string) bool {
	_, secret := redactedKeys[name]
	return secret
}
