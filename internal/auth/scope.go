// Package auth implements administrator authentication: password login with
// throttling, TOTP second factor, rotating refresh tokens with replay detection,
// and API keys with scopes.
package auth

import "slices"

// Roles. A role is coarse and applies to a human administrator; scopes are fine
// and apply to an API key.
const (
	RoleSuperadmin = "superadmin"
	RoleAdmin      = "admin"
	RoleViewer     = "viewer"
)

// Scopes, in "resource:action" form. Write implies read for the same resource,
// which is checked in [HasScope] rather than duplicated at every call site.
const (
	ScopeUsersRead     = "users:read"
	ScopeUsersWrite    = "users:write"
	ScopeNodesRead     = "nodes:read"
	ScopeNodesWrite    = "nodes:write"
	ScopeInboundsRead  = "inbounds:read"
	ScopeInboundsWrite = "inbounds:write"
	ScopeStatsRead     = "stats:read"
	ScopeAdminsRead    = "admins:read"
	ScopeAdminsWrite   = "admins:write"
	ScopeAuditRead     = "audit:read"

	// Webhook scopes are their own, rather than folded into users:write, because an
	// endpoint receives a stream of events about every user: the ability to point that
	// stream somewhere is worth granting on purpose, not as a side effect.
	ScopeWebhooksRead  = "webhooks:read"
	ScopeWebhooksWrite = "webhooks:write"
)

// AllScopes is the set an API key may be granted. Anything outside it is rejected
// at creation time: silently storing an unknown scope would produce a key that
// looks privileged in the UI and is powerless in practice.
var AllScopes = []string{
	ScopeUsersRead, ScopeUsersWrite,
	ScopeNodesRead, ScopeNodesWrite,
	ScopeInboundsRead, ScopeInboundsWrite,
	ScopeStatsRead,
	ScopeAdminsRead, ScopeAdminsWrite,
	ScopeAuditRead,
	ScopeWebhooksRead, ScopeWebhooksWrite,
}

// writeImpliesRead maps a write scope to the read scope it subsumes.
var writeImpliesRead = map[string]string{
	ScopeUsersWrite:    ScopeUsersRead,
	ScopeNodesWrite:    ScopeNodesRead,
	ScopeInboundsWrite: ScopeInboundsRead,
	ScopeAdminsWrite:   ScopeAdminsRead,
	ScopeWebhooksWrite: ScopeWebhooksRead,
}

// IsKnownScope reports whether s is a scope this build understands.
func IsKnownScope(s string) bool { return slices.Contains(AllScopes, s) }

// HasScope reports whether granted covers required.
func HasScope(granted []string, required string) bool {
	if slices.Contains(granted, required) {
		return true
	}
	// A key granted users:write can read users without also listing users:read.
	for write, read := range writeImpliesRead {
		if read == required && slices.Contains(granted, write) {
			return true
		}
	}
	return false
}

// RoleAllows reports whether a human administrator's role covers a scope.
//
// Viewer is read-only, and that is decided by the scope's suffix rather than by a
// per-role list: a new write scope added in a later milestone is then denied to
// viewers by default instead of being accidentally granted.
func RoleAllows(role, scope string) bool {
	switch role {
	case RoleSuperadmin, RoleAdmin:
		return IsKnownScope(scope)
	case RoleViewer:
		return IsKnownScope(scope) && !isWriteScope(scope)
	default:
		return false
	}
}

func isWriteScope(scope string) bool {
	_, ok := writeImpliesRead[scope]
	return ok
}
