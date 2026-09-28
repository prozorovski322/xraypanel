//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/postgres/listbuilder"
	"github.com/xraypanel/panel/internal/service"
)

func testActor() audit.Actor { return audit.SystemActor("test") }

// --- idempotency ---

// TestIdempotentCreateRunsOnce is the property the whole mechanism exists for: the clients
// that retry are a payment webhook, a bot, or a script behind a flaky connection, and a
// retry must not create a second subscriber.
func TestIdempotentCreateRunsOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	body := []byte(`{"username":"alice"}`)
	run := func() (service.StoredResponse, error) {
		return e.res.Idempotent(ctx, "key-1", service.ScopeUserCreate, body,
			func(ctx context.Context) (service.StoredResponse, error) {
				user, err := e.res.CreateUser(ctx, testActor(), service.CreateUserInput{Username: "alice"})
				if err != nil {
					return service.StoredResponse{}, err
				}
				encoded, _ := json.Marshal(map[string]any{"id": user.ID, "username": user.Username})
				return service.StoredResponse{StatusCode: http.StatusCreated, Body: encoded}, nil
			})
	}

	first, err := run()
	if err != nil {
		t.Fatalf("first attempt: %v", err)
	}

	second, err := run()
	if err != nil {
		t.Fatalf("retry: %v", err)
	}

	if string(first.Body) != string(second.Body) {
		t.Errorf("the retry returned a different body:\n first: %s\nsecond: %s", first.Body, second.Body)
	}
	if second.StatusCode != first.StatusCode {
		t.Errorf("status differs: %d vs %d", first.StatusCode, second.StatusCode)
	}

	count, err := e.q.CountUsers(ctx)
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if count != 1 {
		t.Errorf("got %d users, want 1: the retry created another one", count)
	}
}

// TestIdempotentKeyReuseWithDifferentBodyIsRejected catches a client bug rather than
// hiding it. Replaying the old result would quietly not perform the new request.
func TestIdempotentKeyReuseWithDifferentBodyIsRejected(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	create := func(username string) (service.StoredResponse, error) {
		body := []byte(`{"username":"` + username + `"}`)
		return e.res.Idempotent(ctx, "key-2", service.ScopeUserCreate, body,
			func(ctx context.Context) (service.StoredResponse, error) {
				user, err := e.res.CreateUser(ctx, testActor(), service.CreateUserInput{Username: username})
				if err != nil {
					return service.StoredResponse{}, err
				}
				encoded, _ := json.Marshal(map[string]any{"id": user.ID})
				return service.StoredResponse{StatusCode: http.StatusCreated, Body: encoded}, nil
			})
	}

	if _, err := create("alice"); err != nil {
		t.Fatalf("first attempt: %v", err)
	}
	if _, err := create("bob"); !errors.Is(err, service.ErrIdempotencyMismatch) {
		t.Errorf("err = %v, want ErrIdempotencyMismatch", err)
	}

	// And bob must not exist: the request was refused, not partially applied.
	if _, err := e.q.GetUserByUsername(ctx, "bob"); err == nil {
		t.Error("the mismatched request created a user anyway")
	}
}

// TestFailedIdempotentOperationReleasesTheClaim keeps a failure from being remembered as a
// success. Leaving the claim would tell the next attempt the work was already done.
func TestFailedIdempotentOperationReleasesTheClaim(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	body := []byte(`{"username":""}`)

	// First attempt fails on validation.
	_, err := e.res.Idempotent(ctx, "key-3", service.ScopeUserCreate, body,
		func(ctx context.Context) (service.StoredResponse, error) {
			_, err := e.res.CreateUser(ctx, testActor(), service.CreateUserInput{Username: ""})
			return service.StoredResponse{}, err
		})
	if err == nil {
		t.Fatal("an invalid request succeeded")
	}

	// The same key must now be usable, because nothing happened the first time.
	_, err = e.res.Idempotent(ctx, "key-3", service.ScopeUserCreate, body,
		func(ctx context.Context) (service.StoredResponse, error) {
			user, createErr := e.res.CreateUser(ctx, testActor(), service.CreateUserInput{Username: "recovered"})
			if createErr != nil {
				return service.StoredResponse{}, createErr
			}
			encoded, _ := json.Marshal(map[string]any{"id": user.ID})
			return service.StoredResponse{StatusCode: http.StatusCreated, Body: encoded}, nil
		})
	if err != nil {
		t.Fatalf("retrying after a failure was refused: %v", err)
	}
}

// TestIdempotentRenewIsSafeToRetry covers the operation where a double application is
// visible to the customer as twice the time they paid for.
func TestIdempotentRenewIsSafeToRetry(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	user, err := e.res.CreateUser(ctx, testActor(), service.CreateUserInput{Username: "alice"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	body := []byte(`{"extend_by":"720h"}`)
	renew := func() (service.StoredResponse, error) {
		return e.res.Idempotent(ctx, "renew-1", service.ScopeUserRenew, body,
			func(ctx context.Context) (service.StoredResponse, error) {
				renewed, err := e.res.RenewUser(ctx, testActor(), user.ID, service.RenewUserInput{ExtendBy: "720h"})
				if err != nil {
					return service.StoredResponse{}, err
				}
				encoded, _ := json.Marshal(map[string]any{"expires_at": renewed.ExpiresAt})
				return service.StoredResponse{StatusCode: http.StatusOK, Body: encoded}, nil
			})
	}

	if _, err := renew(); err != nil {
		t.Fatalf("first renew: %v", err)
	}
	after, err := e.q.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if after.ExpiresAt == nil {
		t.Fatal("renewal set no expiry")
	}
	firstExpiry := *after.ExpiresAt

	if _, err := renew(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	final, err := e.q.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !final.ExpiresAt.Equal(firstExpiry) {
		t.Errorf("the retry extended the subscription again: %s then %s", firstExpiry, *final.ExpiresAt)
	}
}

// TestRenewExtendsFromNowWhenLapsed is the arithmetic a customer notices before the
// operator does: adding to a past expiry would hand back less time than was paid for.
func TestRenewExtendsFromNowWhenLapsed(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	user, err := e.res.CreateUser(ctx, testActor(), service.CreateUserInput{Username: "alice"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Expire the subscription a month ago.
	past := e.clock.Now().Add(-30 * 24 * time.Hour)
	if _, err := e.pool.Exec(ctx,
		`UPDATE users SET expires_at = $1, status = 'expired' WHERE id = $2`, past, user.ID); err != nil {
		t.Fatalf("set past expiry: %v", err)
	}

	renewed, err := e.res.RenewUser(ctx, testActor(), user.ID, service.RenewUserInput{ExtendBy: "24h"})
	if err != nil {
		t.Fatalf("RenewUser: %v", err)
	}
	if renewed.ExpiresAt == nil {
		t.Fatal("no expiry after renewal")
	}

	// A day from now, not a day from a month ago.
	if !renewed.ExpiresAt.After(e.clock.Now()) {
		t.Errorf("expiry %s is not in the future; the extension was added to the lapsed date",
			*renewed.ExpiresAt)
	}
	if renewed.Status != "active" {
		t.Errorf("status = %q, want active: a renewal that leaves the account off is pointless", renewed.Status)
	}
}

// --- port conflicts ---

// TestAttachRefusesAPortCollision is the failure this check exists for: two inbounds on
// one port mean Xray does not start at all, and from the panel that looks like a node that
// broke by itself.
func TestAttachRefusesAPortCollision(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	node, err := e.res.CreateNode(ctx, testActor(), service.CreateNodeInput{
		Name: "de-1", Address: "de1.example.com", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	first, err := e.res.CreateInbound(ctx, testActor(), service.CreateInboundInput{
		Tag: "first", Protocol: "vless", Transport: "tcp", Security: "none",
		ListenPort: 8443, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateInbound: %v", err)
	}
	second, err := e.res.CreateInbound(ctx, testActor(), service.CreateInboundInput{
		Tag: "second", Protocol: "vless", Transport: "tcp", Security: "none",
		ListenPort: 8443, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateInbound: %v", err)
	}

	if err := e.res.AttachInbound(ctx, testActor(), node.ID, first.ID); err != nil {
		t.Fatalf("AttachInbound: %v", err)
	}

	err = e.res.AttachInbound(ctx, testActor(), node.ID, second.ID)
	if !errors.Is(err, service.ErrPortConflict) {
		t.Fatalf("err = %v, want ErrPortConflict", err)
	}
	// The message has to name the other inbound, or an operator has to go looking.
	if !strings.Contains(err.Error(), "first") {
		t.Errorf("the error does not name the occupying inbound: %v", err)
	}

	// Two inbounds on the same port are fine on different nodes.
	other, err := e.res.CreateNode(ctx, testActor(), service.CreateNodeInput{
		Name: "nl-1", Address: "nl1.example.com", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if err := e.res.AttachInbound(ctx, testActor(), other.ID, second.ID); err != nil {
		t.Errorf("attaching to a different node was refused: %v", err)
	}
}

// TestPortChangeChecksEveryNode covers the case an operator cannot see: changing a port
// can collide on a node they are not looking at.
func TestPortChangeChecksEveryNode(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	node, err := e.res.CreateNode(ctx, testActor(), service.CreateNodeInput{
		Name: "de-1", Address: "de1.example.com", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	occupied, err := e.res.CreateInbound(ctx, testActor(), service.CreateInboundInput{
		Tag: "occupied", Protocol: "vless", Transport: "tcp", Security: "none",
		ListenPort: 443, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateInbound: %v", err)
	}
	moving, err := e.res.CreateInbound(ctx, testActor(), service.CreateInboundInput{
		Tag: "moving", Protocol: "vless", Transport: "tcp", Security: "none",
		ListenPort: 8443, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateInbound: %v", err)
	}

	for _, id := range []int64{occupied.ID, moving.ID} {
		if err := e.res.AttachInbound(ctx, testActor(), node.ID, id); err != nil {
			t.Fatalf("AttachInbound: %v", err)
		}
	}

	newPort := int32(443)
	_, err = e.res.UpdateInbound(ctx, testActor(), moving.ID, service.UpdateInboundInput{
		ListenPort: &newPort,
	})
	if !errors.Is(err, service.ErrPortConflict) {
		t.Fatalf("err = %v, want ErrPortConflict", err)
	}

	// And the port must not have changed: the check happens before the write.
	after, err := e.q.GetInbound(ctx, moving.ID)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	if after.ListenPort != 8443 {
		t.Errorf("port = %d, want 8443: the refused update was applied anyway", after.ListenPort)
	}
}

// --- validation ---

func TestInboundValidationRejectsBadCombinations(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	cases := map[string]service.CreateInboundInput{
		"flow on websocket": {
			Tag: "a", Protocol: "vless", Transport: "ws", Security: "tls", ListenPort: 443,
			Flow: "xtls-rprx-vision", TLSSettings: json.RawMessage(`{"alpn":["h2"]}`),
		},
		"flow on trojan": {
			Tag: "b", Protocol: "trojan", Transport: "tcp", Security: "tls", ListenPort: 443,
			Flow: "xtls-rprx-vision", TLSSettings: json.RawMessage(`{"alpn":["h2"]}`),
		},
		"reality without a key": {
			Tag: "c", Protocol: "vless", Transport: "tcp", Security: "reality", ListenPort: 443,
		},
		"tls without settings": {
			Tag: "d", Protocol: "vless", Transport: "tcp", Security: "tls", ListenPort: 443,
		},
		"legacy shadowsocks method": {
			Tag: "e", Protocol: "shadowsocks", Transport: "tcp", Security: "none", ListenPort: 8388,
			SSMethod: "aes-128-gcm", SSServerKey: "c2VydmVy",
		},
		"shadowsocks without a server key": {
			Tag: "f", Protocol: "shadowsocks", Transport: "tcp", Security: "none", ListenPort: 8388,
			SSMethod: "2022-blake3-aes-128-gcm",
		},
		"shadowsocks settings on vless": {
			Tag: "g", Protocol: "vless", Transport: "tcp", Security: "none", ListenPort: 443,
			SSMethod: "2022-blake3-aes-128-gcm",
		},
		"reserved api tag": {
			Tag: "api", Protocol: "vless", Transport: "tcp", Security: "none", ListenPort: 443,
		},
		"port out of range": {
			Tag: "h", Protocol: "vless", Transport: "tcp", Security: "none", ListenPort: 70000,
		},
		"unknown protocol": {
			Tag: "i", Protocol: "vmess", Transport: "tcp", Security: "none", ListenPort: 443,
		},
		"settings that are not an object": {
			Tag: "j", Protocol: "vless", Transport: "ws", Security: "none", ListenPort: 443,
			NetworkSettings: json.RawMessage(`["nope"]`),
		},
	}

	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := e.res.CreateInbound(ctx, testActor(), in); err == nil {
				t.Error("CreateInbound accepted it")
			} else if !errors.Is(err, service.ErrValidation) {
				t.Errorf("err = %v, want a validation error", err)
			}
		})
	}
}

// TestRealityKeyInUseCannotBeDeleted turns a constraint name into a usable message.
func TestRealityKeyInUseCannotBeDeleted(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	key, err := e.res.CreateRealityKey(ctx, testActor(), service.CreateRealityKeyInput{
		Name: "k", Dest: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"},
	})
	if err != nil {
		t.Fatalf("CreateRealityKey: %v", err)
	}

	inbound, err := e.res.CreateInbound(ctx, testActor(), service.CreateInboundInput{
		Tag: "r", Protocol: "vless", Transport: "tcp", Security: "reality",
		ListenPort: 443, RealityKeyID: &key.ID, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateInbound: %v", err)
	}

	err = e.res.DeleteRealityKey(ctx, testActor(), key.ID)
	if !errors.Is(err, service.ErrInUse) {
		t.Fatalf("err = %v, want ErrInUse", err)
	}

	if err := e.res.DeleteInbound(ctx, testActor(), inbound.ID); err != nil {
		t.Fatalf("DeleteInbound: %v", err)
	}
	if err := e.res.DeleteRealityKey(ctx, testActor(), key.ID); err != nil {
		t.Errorf("deleting an unused reality key was refused: %v", err)
	}
}

func TestDuplicateNamesConflict(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if _, err := e.res.CreateUser(ctx, testActor(), service.CreateUserInput{Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := e.res.CreateUser(ctx, testActor(), service.CreateUserInput{Username: "alice"}); !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate username: err = %v, want ErrConflict", err)
	}

	if _, err := e.res.CreateNode(ctx, testActor(), service.CreateNodeInput{Name: "n", Address: "a"}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if _, err := e.res.CreateNode(ctx, testActor(), service.CreateNodeInput{Name: "n", Address: "b"}); !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate node name: err = %v, want ErrConflict", err)
	}
}

// --- listing ---

func TestListUsersFilters(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	group, err := e.res.CreateGroup(ctx, testActor(), service.CreateGroupInput{Name: "g"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	for i, spec := range []struct {
		username string
		limit    int64
		note     string
		status   string
		inGroup  bool
	}{
		{"alice", 100, "vip customer", "active", true},
		{"bob", 0, "", "active", false},
		{"carol", 50, "trial", "disabled", true},
		{"dave", 10, "", "limited", false},
	} {
		in := service.CreateUserInput{Username: spec.username, TrafficLimit: spec.limit, Note: spec.note}
		if spec.inGroup {
			in.GroupIDs = []int64{group.ID}
		}
		user, err := e.res.CreateUser(ctx, testActor(), in)
		if err != nil {
			t.Fatalf("CreateUser %d: %v", i, err)
		}
		if spec.status != "active" {
			if _, err := e.pool.Exec(ctx, `UPDATE users SET status = $1 WHERE id = $2`, spec.status, user.ID); err != nil {
				t.Fatalf("set status: %v", err)
			}
		}
	}

	// Push one user over quota.
	if _, err := e.pool.Exec(ctx,
		`UPDATE users SET traffic_used = traffic_limit WHERE username = 'alice'`); err != nil {
		t.Fatalf("set usage: %v", err)
	}

	cases := map[string]struct {
		filter    listbuilder.UserFilter
		wantNames []string
	}{
		"everything": {
			filter:    listbuilder.UserFilter{Sort: "username"},
			wantNames: []string{"alice", "bob", "carol", "dave"},
		},
		"by status": {
			filter:    listbuilder.UserFilter{Statuses: []string{"active"}, Sort: "username"},
			wantNames: []string{"alice", "bob"},
		},
		"two statuses": {
			filter:    listbuilder.UserFilter{Statuses: []string{"disabled", "limited"}, Sort: "username"},
			wantNames: []string{"carol", "dave"},
		},
		"search matches the note as well as the name": {
			filter:    listbuilder.UserFilter{Search: "trial", Sort: "username"},
			wantNames: []string{"carol"},
		},
		"search is case insensitive": {
			filter:    listbuilder.UserFilter{Search: "ALICE", Sort: "username"},
			wantNames: []string{"alice"},
		},
		"by group": {
			filter:    listbuilder.UserFilter{GroupID: &group.ID, Sort: "username"},
			wantNames: []string{"alice", "carol"},
		},
		"over quota": {
			filter: listbuilder.UserFilter{OverQuota: true, Sort: "username"},
			// bob has no limit and so is never over quota, however much he uses.
			wantNames: []string{"alice"},
		},
		"descending": {
			filter:    listbuilder.UserFilter{Sort: "username", Desc: true},
			wantNames: []string{"dave", "carol", "bob", "alice"},
		},
		"limit": {
			filter:    listbuilder.UserFilter{Sort: "username", Limit: 2},
			wantNames: []string{"alice", "bob"},
		},
		"offset": {
			filter:    listbuilder.UserFilter{Sort: "username", Limit: 2, Offset: 2},
			wantNames: []string{"carol", "dave"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			page, err := listbuilder.ListUsers(ctx, e.pool, tc.filter)
			if err != nil {
				t.Fatalf("ListUsers: %v", err)
			}

			got := make([]string, 0, len(page.Rows))
			for _, row := range page.Rows {
				got = append(got, row.Username)
			}
			if strings.Join(got, ",") != strings.Join(tc.wantNames, ",") {
				t.Errorf("got %v, want %v", got, tc.wantNames)
			}
		})
	}

	// Total counts matches, not the page.
	page, err := listbuilder.ListUsers(ctx, e.pool, listbuilder.UserFilter{Limit: 1})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if page.Total != 4 {
		t.Errorf("Total = %d, want 4", page.Total)
	}
	if len(page.Rows) != 1 {
		t.Errorf("got %d rows, want 1", len(page.Rows))
	}
}

// TestSearchWildcardsAreEscaped keeps a search term from behaving like a pattern.
func TestSearchWildcardsAreEscaped(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	for _, username := range []string{"alice", "bob"} {
		if _, err := e.res.CreateUser(ctx, testActor(), service.CreateUserInput{
			Username: username,
			Note:     "plain",
		}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
	}
	if _, err := e.res.CreateUser(ctx, testActor(), service.CreateUserInput{
		Username: "carol",
		Note:     "100% off",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	page, err := listbuilder.ListUsers(ctx, e.pool, listbuilder.UserFilter{Search: "100%"})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(page.Rows) != 1 || page.Rows[0].Username != "carol" {
		names := make([]string, 0, len(page.Rows))
		for _, row := range page.Rows {
			names = append(names, row.Username)
		}
		t.Errorf("searching for %q matched %v; the wildcard was not escaped", "100%", names)
	}
}

func TestListUsersRejectsUnknownSortColumn(t *testing.T) {
	e := newEnv(t)

	_, err := listbuilder.ListUsers(context.Background(), e.pool, listbuilder.UserFilter{
		Sort: "password_hash; DROP TABLE users",
	})
	if err == nil {
		t.Fatal("an arbitrary sort expression was accepted")
	}
	if !strings.Contains(err.Error(), "cannot sort by") {
		t.Errorf("unexpected error: %v", err)
	}

	// And the table is still there.
	if _, err := e.q.CountUsers(context.Background()); err != nil {
		t.Fatalf("the users table is gone: %v", err)
	}
}

// TestListingNeverReturnsCredentials guards the difference between a list view and a
// breach: one careless log of a list response should not expose every subscription.
func TestListingNeverReturnsCredentials(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	user, err := e.res.CreateUser(ctx, testActor(), service.CreateUserInput{Username: "alice"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	page, err := listbuilder.ListUsers(ctx, e.pool, listbuilder.UserFilter{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}

	encoded, err := json.Marshal(page.Rows)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for name, secret := range map[string]string{
		"subscription token": user.ShortUuid,
		"trojan password":    user.TrojanPassword,
		"shadowsocks key":    user.SsPassword,
		"stats key":          user.XrayEmail,
	} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("the listing exposes the %s", name)
		}
	}
}

// --- audit ---

func TestAuditRecordsChangesWithoutSecrets(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	user, err := e.res.CreateUser(ctx, testActor(), service.CreateUserInput{Username: "alice"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := e.res.RotateUserCredentials(ctx, testActor(), user.ID); err != nil {
		t.Fatalf("RotateUserCredentials: %v", err)
	}
	if err := e.res.DeleteUser(ctx, testActor(), user.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	for _, action := range []string{"user.create", "user.rotate_credentials", "user.delete"} {
		if e.countAuditEntries(action) == 0 {
			t.Errorf("no audit entry for %s", action)
		}
	}

	// The trail is read by more people than the database is, and it is the first thing
	// exported when something goes wrong.
	var diffs string
	if err := e.pool.QueryRow(ctx,
		`SELECT coalesce(string_agg(diff::text, ' '), '') FROM audit_log`).Scan(&diffs); err != nil {
		t.Fatalf("read audit diffs: %v", err)
	}
	for name, secret := range map[string]string{
		"subscription token": user.ShortUuid,
		"trojan password":    user.TrojanPassword,
		"shadowsocks key":    user.SsPassword,
	} {
		if strings.Contains(diffs, secret) {
			t.Errorf("the audit trail contains the %s", name)
		}
	}
	if !strings.Contains(diffs, "REDACTED") {
		t.Error("no redaction marker in the audit diffs, so nothing was redacted at all")
	}

	// The entry survives the entity it describes: the trail has to outlive what it records.
	var remaining int
	if err := e.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE entity_type = 'user' AND entity_id = $1`,
		strconv.FormatInt(user.ID, 10)).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining == 0 {
		t.Error("the audit entries vanished with the user they described")
	}
}

// TestRollbackTakesTheAuditEntryWithIt keeps the trail from claiming something that never
// happened.
func TestRollbackTakesTheAuditEntryWithIt(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if _, err := e.res.CreateUser(ctx, testActor(), service.CreateUserInput{Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	before := e.countAuditEntries("user.create")

	// A duplicate username fails after the audit entry would have been written inside the
	// same transaction.
	if _, err := e.res.CreateUser(ctx, testActor(), service.CreateUserInput{Username: "alice"}); err == nil {
		t.Fatal("the duplicate was accepted")
	}

	if after := e.countAuditEntries("user.create"); after != before {
		t.Errorf("a failed create left an audit entry behind (%d -> %d)", before, after)
	}
}
