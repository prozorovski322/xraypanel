package auth

import "testing"

func TestHasScopeExactMatch(t *testing.T) {
	granted := []string{ScopeUsersRead, ScopeStatsRead}

	if !HasScope(granted, ScopeUsersRead) {
		t.Error("an explicitly granted scope was denied")
	}
	if HasScope(granted, ScopeUsersWrite) {
		t.Error("read access was treated as write access")
	}
	if HasScope(nil, ScopeUsersRead) {
		t.Error("a key with no scopes was granted one")
	}
}

// TestWriteImpliesRead keeps call sites from having to grant both halves of every
// resource, which is the usual source of a key that can create but not list.
func TestWriteImpliesRead(t *testing.T) {
	pairs := map[string]string{
		ScopeUsersWrite:    ScopeUsersRead,
		ScopeNodesWrite:    ScopeNodesRead,
		ScopeInboundsWrite: ScopeInboundsRead,
		ScopeAdminsWrite:   ScopeAdminsRead,
	}

	for write, read := range pairs {
		if !HasScope([]string{write}, read) {
			t.Errorf("%s does not imply %s", write, read)
		}
		// The implication must not run the other way.
		if HasScope([]string{read}, write) {
			t.Errorf("%s wrongly implies %s", read, write)
		}
	}
}

func TestIsKnownScope(t *testing.T) {
	for _, s := range AllScopes {
		if !IsKnownScope(s) {
			t.Errorf("%q is in AllScopes but IsKnownScope says otherwise", s)
		}
	}
	for _, s := range []string{"", "users", "users:delete", "USERS:READ", "*"} {
		if IsKnownScope(s) {
			t.Errorf("IsKnownScope(%q) = true", s)
		}
	}
}

func TestRoleAllows(t *testing.T) {
	cases := []struct {
		role  string
		scope string
		want  bool
	}{
		{RoleSuperadmin, ScopeUsersWrite, true},
		{RoleSuperadmin, ScopeAdminsWrite, true},
		{RoleAdmin, ScopeUsersWrite, true},
		{RoleAdmin, ScopeStatsRead, true},

		// Viewer is read-only.
		{RoleViewer, ScopeUsersRead, true},
		{RoleViewer, ScopeStatsRead, true},
		{RoleViewer, ScopeUsersWrite, false},
		{RoleViewer, ScopeNodesWrite, false},
		{RoleViewer, ScopeInboundsWrite, false},
		{RoleViewer, ScopeAdminsWrite, false},

		// Unknown scopes and unknown roles are denied, never defaulted.
		{RoleSuperadmin, "users:delete", false},
		{"", ScopeUsersRead, false},
		{"root", ScopeUsersRead, false},
	}

	for _, tc := range cases {
		if got := RoleAllows(tc.role, tc.scope); got != tc.want {
			t.Errorf("RoleAllows(%q, %q) = %v, want %v", tc.role, tc.scope, got, tc.want)
		}
	}
}

// TestViewerDeniedEveryWriteScope is the reason isWriteScope is derived rather than
// listed per role: a write scope added in a later milestone must be denied to
// viewers by default, not accidentally granted.
func TestViewerDeniedEveryWriteScope(t *testing.T) {
	for _, scope := range AllScopes {
		if !isWriteScope(scope) {
			continue
		}
		if RoleAllows(RoleViewer, scope) {
			t.Errorf("viewer was allowed the write scope %q", scope)
		}
	}
}

// TestEveryWriteScopeImpliesARead catches a write scope added to AllScopes without
// a matching entry in writeImpliesRead, which would silently break the implication.
func TestEveryWriteScopeImpliesARead(t *testing.T) {
	for _, scope := range AllScopes {
		if len(scope) < 6 || scope[len(scope)-6:] != ":write" {
			continue
		}
		if _, ok := writeImpliesRead[scope]; !ok {
			t.Errorf("%q looks like a write scope but has no read counterpart in writeImpliesRead", scope)
		}
	}
}

func TestPrincipalCan(t *testing.T) {
	admin := &Principal{IsAdmin: true, Role: RoleAdmin}
	viewer := &Principal{IsAdmin: true, Role: RoleViewer}
	key := &Principal{IsAPIKey: true, Scopes: []string{ScopeUsersRead}}
	empty := &Principal{}

	if !admin.Can(ScopeUsersWrite) {
		t.Error("admin denied users:write")
	}
	if viewer.Can(ScopeUsersWrite) {
		t.Error("viewer allowed users:write")
	}
	if !key.Can(ScopeUsersRead) {
		t.Error("api key denied its own scope")
	}
	if key.Can(ScopeUsersWrite) {
		t.Error("api key allowed a scope it was not granted")
	}
	if empty.Can(ScopeUsersRead) {
		t.Error("a principal that is neither admin nor api key was allowed something")
	}

	// A nil principal is an unauthenticated caller and must be denied rather than
	// panicking, since that is the path a missing middleware would take.
	var nilPrincipal *Principal
	if nilPrincipal.Can(ScopeUsersRead) {
		t.Error("a nil principal was allowed a scope")
	}
}

func TestPrincipalLabel(t *testing.T) {
	var nilPrincipal *Principal
	cases := map[string]*Principal{
		"anonymous":  nilPrincipal,
		"root":       {IsAdmin: true, Username: "root"},
		"api-key:ci": {IsAPIKey: true, APIKeyName: "ci"},
		"unknown":    {},
	}
	for want, p := range cases {
		if got := p.Label(); got != want {
			t.Errorf("Label() = %q, want %q", got, want)
		}
	}
}
