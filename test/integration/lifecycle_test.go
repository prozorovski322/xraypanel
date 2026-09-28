//go:build integration

package integration

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// TestFullResourceLifecycleOverHTTP walks every resource through create, read, list,
// update and delete over HTTP.
//
// The service layer has its own tests, but the handlers in between hold the request and
// response mapping, and that is where a field silently fails to arrive. A double-pointer
// nullable, a defaulted boolean or a renamed JSON tag all pass a service test and break the
// API.
func TestFullResourceLifecycleOverHTTP(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	token := e.adminToken(server)

	call := func(method, path string, body any) *httptest.ResponseRecorder {
		return e.do(server, apiCall{method: method, path: path, body: body, bearer: token})
	}
	expect := func(t *testing.T, rec *httptest.ResponseRecorder, want int) {
		t.Helper()
		if rec.Code != want {
			t.Fatalf("status = %d, want %d: %s", rec.Code, want, rec.Body.String())
		}
	}

	var realityKeyID, inboundID, hostID, groupID, nodeID, userID int64

	t.Run("reality key", func(t *testing.T) {
		rec := call(http.MethodPost, "/api/v1/reality-keys", map[string]any{
			"name":         "primary",
			"dest":         "www.cloudflare.com:443",
			"server_names": []string{"www.cloudflare.com"},
		})
		expect(t, rec, http.StatusCreated)

		var created struct {
			ID        int64    `json:"id"`
			PublicKey string   `json:"public_key"`
			ShortIDs  []string `json:"short_ids"`
		}
		decodeInto(t, rec, &created)
		realityKeyID = created.ID

		if created.PublicKey == "" {
			t.Error("no public key in the response")
		}
		if len(created.ShortIDs) == 0 {
			t.Error("no short ids in the response")
		}
		// The private key is what lets anyone run an identical server.
		if bodyContains(rec, "private") {
			t.Errorf("the response mentions a private key: %s", rec.Body.String())
		}

		expect(t, call(http.MethodGet, "/api/v1/reality-keys", nil), http.StatusOK)
	})

	t.Run("inbound", func(t *testing.T) {
		rec := call(http.MethodPost, "/api/v1/inbounds", map[string]any{
			"tag":            "vless-reality",
			"protocol":       "vless",
			"transport":      "tcp",
			"security":       "reality",
			"listen_port":    443,
			"flow":           "xtls-rprx-vision",
			"reality_key_id": realityKeyID,
		})
		expect(t, rec, http.StatusCreated)

		var created struct {
			ID      int64  `json:"id"`
			Flow    string `json:"flow"`
			Enabled bool   `json:"enabled"`
		}
		decodeInto(t, rec, &created)
		inboundID = created.ID

		if created.Flow != "xtls-rprx-vision" {
			t.Errorf("flow = %q, want it echoed back", created.Flow)
		}
		// Enabled defaults to true: an inbound created switched off is almost never meant.
		if !created.Enabled {
			t.Error("a new inbound is disabled by default")
		}

		expect(t, call(http.MethodGet, "/api/v1/inbounds/"+id(inboundID), nil), http.StatusOK)
		expect(t, call(http.MethodGet, "/api/v1/inbounds", nil), http.StatusOK)

		// Clearing the flow needs an explicit null, which is the case a single pointer
		// could not express.
		cleared := call(http.MethodPatch, "/api/v1/inbounds/"+id(inboundID), map[string]any{
			"flow": nil,
		})
		expect(t, cleared, http.StatusOK)
		var afterClear struct {
			Flow string `json:"flow"`
		}
		decodeInto(t, cleared, &afterClear)
		if afterClear.Flow != "" {
			t.Errorf("flow = %q after an explicit null, want it cleared", afterClear.Flow)
		}

		// And restoring it works.
		restored := call(http.MethodPatch, "/api/v1/inbounds/"+id(inboundID), map[string]any{
			"flow": "xtls-rprx-vision",
		})
		expect(t, restored, http.StatusOK)
	})

	t.Run("host", func(t *testing.T) {
		rec := call(http.MethodPost, "/api/v1/hosts", map[string]any{
			"inbound_id":  inboundID,
			"remark":      "{COUNTRY}-{NODE}",
			"address":     "{NODE}.example.com",
			"sni":         "www.cloudflare.com",
			"fingerprint": "chrome",
			"port":        8443,
		})
		expect(t, rec, http.StatusCreated)

		var created struct {
			ID   int64  `json:"id"`
			Port *int32 `json:"port"`
		}
		decodeInto(t, rec, &created)
		hostID = created.ID

		if created.Port == nil || *created.Port != 8443 {
			t.Errorf("port = %v, want 8443", created.Port)
		}

		// A null port goes back to inheriting the inbound's, which is the other case a
		// single pointer could not express.
		inherited := call(http.MethodPatch, "/api/v1/hosts/"+id(hostID), map[string]any{"port": nil})
		expect(t, inherited, http.StatusOK)
		var afterInherit struct {
			Port *int32 `json:"port"`
		}
		decodeInto(t, inherited, &afterInherit)
		if afterInherit.Port != nil {
			t.Errorf("port = %v after an explicit null, want it inherited", *afterInherit.Port)
		}

		// An unrecognised fingerprint is refused: a client given one it does not know
		// either fails to start or silently falls back, and neither is visible here.
		bad := call(http.MethodPatch, "/api/v1/hosts/"+id(hostID), map[string]any{
			"fingerprint": "netscape",
		})
		expect(t, bad, http.StatusUnprocessableEntity)

		expect(t, call(http.MethodGet, "/api/v1/hosts/"+id(hostID), nil), http.StatusOK)
		expect(t, call(http.MethodGet, "/api/v1/inbounds/"+id(inboundID)+"/hosts", nil), http.StatusOK)
	})

	t.Run("group", func(t *testing.T) {
		rec := call(http.MethodPost, "/api/v1/groups", map[string]any{
			"name":        "everything",
			"is_default":  true,
			"inbound_ids": []int64{inboundID},
		})
		expect(t, rec, http.StatusCreated)

		var created struct {
			ID int64 `json:"id"`
		}
		decodeInto(t, rec, &created)
		groupID = created.ID

		read := call(http.MethodGet, "/api/v1/groups/"+id(groupID), nil)
		expect(t, read, http.StatusOK)
		var full struct {
			InboundTags []string `json:"inbound_tags"`
		}
		decodeInto(t, read, &full)
		if len(full.InboundTags) != 1 {
			t.Errorf("group has %d inbounds, want 1", len(full.InboundTags))
		}

		expect(t, call(http.MethodPatch, "/api/v1/groups/"+id(groupID), map[string]any{
			"description": "all inbounds",
		}), http.StatusOK)
	})

	t.Run("node", func(t *testing.T) {
		rec := call(http.MethodPost, "/api/v1/nodes", map[string]any{
			"name":         "de-1",
			"address":      "de1.example.com",
			"country_code": "de",
		})
		expect(t, rec, http.StatusCreated)

		var created struct {
			ID          int64  `json:"id"`
			CountryCode string `json:"country_code"`
		}
		decodeInto(t, rec, &created)
		nodeID = created.ID

		// Normalised on write, so a link never carries a lowercase country.
		if created.CountryCode != "DE" {
			t.Errorf("country_code = %q, want it upper-cased", created.CountryCode)
		}

		// A malformed merge patch would break every configuration this node generates, so
		// it is refused on write.
		// Syntactically valid JSON carrying a semantically wrong value, so 422 rather
		// than 400.
		expect(t, call(http.MethodPatch, "/api/v1/nodes/"+id(nodeID), map[string]any{
			"config_patch": []string{"not an object"},
		}), http.StatusUnprocessableEntity)

		expect(t, call(http.MethodPatch, "/api/v1/nodes/"+id(nodeID), map[string]any{
			"config_patch": map[string]any{"log": map[string]any{"loglevel": "debug"}},
		}), http.StatusOK)

		expect(t, call(http.MethodPut,
			"/api/v1/nodes/"+id(nodeID)+"/inbounds/"+id(inboundID), nil), http.StatusNoContent)
		expect(t, call(http.MethodGet, "/api/v1/nodes/"+id(nodeID)+"/inbounds", nil), http.StatusOK)
		expect(t, call(http.MethodGet, "/api/v1/nodes/"+id(nodeID), nil), http.StatusOK)
		expect(t, call(http.MethodGet, "/api/v1/nodes", nil), http.StatusOK)
	})

	t.Run("user", func(t *testing.T) {
		rec := call(http.MethodPost, "/api/v1/users", map[string]any{
			"username":      "alice",
			"traffic_limit": 107374182400,
			"expires_at":    "2027-01-01T00:00:00Z",
		})
		expect(t, rec, http.StatusCreated)

		var created struct {
			ID                int64  `json:"id"`
			ExpiresAt         string `json:"expires_at"`
			SubscriptionToken string `json:"subscription_token"`
		}
		decodeInto(t, rec, &created)
		userID = created.ID

		if created.ExpiresAt == "" {
			t.Error("expires_at did not round-trip")
		}
		if created.SubscriptionToken == "" {
			t.Error("a create must return the subscription token; there is no other way to learn it")
		}

		// An explicit null clears the expiry, which is what "never expires" has to look
		// like over the wire.
		cleared := call(http.MethodPatch, "/api/v1/users/"+id(userID), map[string]any{
			"expires_at": nil,
		})
		expect(t, cleared, http.StatusOK)
		var afterClear struct {
			ExpiresAt string `json:"expires_at"`
		}
		decodeInto(t, cleared, &afterClear)
		if afterClear.ExpiresAt != "" {
			t.Errorf("expires_at = %q after an explicit null, want it cleared", afterClear.ExpiresAt)
		}

		// Omitting it must leave it alone rather than clearing it again.
		renewed := call(http.MethodPost, "/api/v1/users/"+id(userID)+"/renew",
			map[string]any{"extend_by": "720h"})
		expect(t, renewed, http.StatusOK)

		noted := call(http.MethodPatch, "/api/v1/users/"+id(userID), map[string]any{"note": "vip"})
		expect(t, noted, http.StatusOK)
		var afterNote struct {
			ExpiresAt string `json:"expires_at"`
			Note      string `json:"note"`
		}
		decodeInto(t, noted, &afterNote)
		if afterNote.ExpiresAt == "" {
			t.Error("an unrelated patch cleared the expiry")
		}
		if afterNote.Note != "vip" {
			t.Errorf("note = %q, want vip", afterNote.Note)
		}

		expect(t, call(http.MethodGet, "/api/v1/users/"+id(userID), nil), http.StatusOK)
		expect(t, call(http.MethodGet, "/api/v1/users", nil), http.StatusOK)

		// The default group was granted, so resolution finds an endpoint.
		sub := call(http.MethodGet, "/api/v1/users/"+id(userID)+"/subscription", nil)
		expect(t, sub, http.StatusOK)
		var subscription struct {
			Links    []string `json:"links"`
			UserInfo string   `json:"user_info"`
		}
		decodeInto(t, sub, &subscription)
		if len(subscription.Links) == 0 {
			t.Error("the user has no endpoints; the default group was not granted")
		}
		if subscription.UserInfo == "" {
			t.Error("no subscription-userinfo value")
		}

		expect(t, call(http.MethodPut, "/api/v1/users/"+id(userID)+"/groups",
			map[string]any{"group_ids": []int64{groupID}}), http.StatusNoContent)
		expect(t, call(http.MethodPost, "/api/v1/users/"+id(userID)+"/reset-traffic", nil), http.StatusOK)

		rotated := call(http.MethodPost, "/api/v1/users/"+id(userID)+"/rotate-credentials", nil)
		expect(t, rotated, http.StatusOK)
		var afterRotate struct {
			SubscriptionToken string `json:"subscription_token"`
		}
		decodeInto(t, rotated, &afterRotate)
		if afterRotate.SubscriptionToken == created.SubscriptionToken {
			t.Error("rotation returned the same subscription token")
		}

		expect(t, call(http.MethodPost, "/api/v1/users/bulk/status",
			map[string]any{"user_ids": []int64{userID}, "status": "disabled"}), http.StatusOK)
		expect(t, call(http.MethodPost, "/api/v1/groups/"+id(groupID)+"/users",
			map[string]any{"user_ids": []int64{userID}}), http.StatusOK)
	})

	// Teardown in dependency order, which is itself the test: a delete refused here means a
	// cascade is missing or a guard is wrong.
	t.Run("teardown", func(t *testing.T) {
		expect(t, call(http.MethodDelete, "/api/v1/users/"+id(userID), nil), http.StatusNoContent)
		expect(t, call(http.MethodDelete,
			"/api/v1/nodes/"+id(nodeID)+"/inbounds/"+id(inboundID), nil), http.StatusNoContent)
		expect(t, call(http.MethodDelete, "/api/v1/nodes/"+id(nodeID), nil), http.StatusNoContent)
		expect(t, call(http.MethodDelete, "/api/v1/hosts/"+id(hostID), nil), http.StatusNoContent)
		expect(t, call(http.MethodDelete, "/api/v1/groups/"+id(groupID), nil), http.StatusNoContent)
		expect(t, call(http.MethodDelete, "/api/v1/inbounds/"+id(inboundID), nil), http.StatusNoContent)
		expect(t, call(http.MethodDelete, "/api/v1/reality-keys/"+id(realityKeyID), nil), http.StatusNoContent)

		// And they are really gone.
		for _, path := range []string{
			"/api/v1/users/" + id(userID),
			"/api/v1/nodes/" + id(nodeID),
			"/api/v1/hosts/" + id(hostID),
			"/api/v1/inbounds/" + id(inboundID),
		} {
			if rec := call(http.MethodGet, path, nil); rec.Code != http.StatusNotFound {
				t.Errorf("GET %s after delete: status = %d, want 404", path, rec.Code)
			}
		}
	})
}

// TestMalformedRequestsAreRejected covers the shared decoding path.
func TestMalformedRequestsAreRejected(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	token := e.adminToken(server)

	cases := map[string]struct {
		body any
		want int
	}{
		"unknown field":    {body: `{"username":"a","nope":1}`, want: http.StatusBadRequest},
		"not json":         {body: `{not json`, want: http.StatusBadRequest},
		"empty body":       {body: ``, want: http.StatusBadRequest},
		"wrong type":       {body: `{"username":123}`, want: http.StatusBadRequest},
		"missing required": {body: `{}`, want: http.StatusUnprocessableEntity},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := e.do(server, apiCall{
				method: http.MethodPost, path: "/api/v1/users", bearer: token, body: tc.body,
			})
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	// A bad path id must not reach the database.
	for _, path := range []string{"/api/v1/users/abc", "/api/v1/users/0", "/api/v1/users/-1"} {
		rec := e.do(server, apiCall{method: http.MethodGet, path: path, bearer: token})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s: status = %d, want 400", path, rec.Code)
		}
	}
}

func id(v int64) string { return strconv.FormatInt(v, 10) }

// bodyContains looks for a needle in a response, case-insensitively.
func bodyContains(rec *httptest.ResponseRecorder, needle string) bool {
	return strings.Contains(strings.ToLower(rec.Body.String()), strings.ToLower(needle))
}
