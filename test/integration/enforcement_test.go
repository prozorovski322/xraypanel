//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/service"
	"github.com/xraypanel/panel/internal/webhook"
	"github.com/xraypanel/panel/internal/worker"
)

// A traffic limit or an expiry date means nothing until something enforces it. These tests
// drive the enforcement pass on the harness clock, so period boundaries can be crossed
// without waiting a month, and check the three things enforcement must get right: the user
// is switched off exactly once, the nodes are told, and the outside world is told.

// userStatus reads a user's status as the database has it.
func (e *env) userStatus(t *testing.T, userID int64) string {
	t.Helper()

	var status string
	if err := e.pool.QueryRow(context.Background(),
		`SELECT status::text FROM users WHERE id = $1`, userID).Scan(&status); err != nil {
		t.Fatalf("read user status: %v", err)
	}
	return status
}

// auditCount counts audit rows for one action on one user.
func (e *env) auditCount(t *testing.T, action string, userID int64) int {
	t.Helper()

	var count int
	if err := e.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action = $1 AND entity_id = $2`,
		action, fmt.Sprint(userID)).Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return count
}

// queuedEvents counts deliveries queued for one event.
func (e *env) queuedEvents(t *testing.T, event string) int {
	t.Helper()

	var count int
	if err := e.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM webhook_deliveries WHERE event = $1`, event).Scan(&count); err != nil {
		t.Fatalf("count queued events: %v", err)
	}
	return count
}

// limitedUser builds a node that actually serves a user with a small allowance.
//
// Serves: the user is in the default group whose inbound is attached to the node. Without
// that, the node has nothing to do with the user and no reason to hear about their status —
// and a test asserting that it does would be asserting the wrong thing.
func (e *env) limitedUser(t *testing.T, limit int64, strategy string) trafficFixture {
	t.Helper()

	ctx := context.Background()
	actor := audit.SystemActor("test")

	node := e.buildPlainNode(t)
	user, err := e.res.CreateUser(ctx, actor, service.CreateUserInput{
		Username:      "limited-" + uuid.NewString()[:8],
		TrafficLimit:  limit,
		ResetStrategy: strategy,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return trafficFixture{nodeID: node.nodeID, userID: user.ID, email: e.xrayEmailOf(t, user.ID)}
}

// spend accounts traffic for a user the way a node would report it.
func (e *env) spend(t *testing.T, fixture trafficFixture, bytes int64) {
	t.Helper()

	_, err := e.res.IngestTrafficBatch(context.Background(), fixture.nodeID, uuid.NewString(),
		[]service.TrafficDelta{{
			XrayEmail: fixture.email,
			Uplink:    bytes / 2,
			Downlink:  bytes - bytes/2,
			Hour:      e.clock.Now().UTC().Truncate(time.Hour),
		}})
	if err != nil {
		t.Fatalf("IngestTrafficBatch: %v", err)
	}
}

// subscribe registers an endpoint for every event and returns it.
func (e *env) subscribe(t *testing.T, url string) *service.WebhookEndpoint {
	t.Helper()

	endpoint, err := e.res.CreateWebhookEndpoint(context.Background(), audit.SystemActor("test"),
		service.CreateWebhookEndpointInput{URL: url, Events: service.KnownWebhookEvents, Enabled: true})
	if err != nil {
		t.Fatalf("CreateWebhookEndpoint: %v", err)
	}
	return endpoint
}

func TestAUserOverTheirLimitIsSwitchedOffOnce(t *testing.T) {
	e := newEnv(t)
	e.subscribe(t, "https://receiver.example.com/hook")

	fixture := e.limitedUser(t, 1_000_000, "never")
	versionBefore := e.configVersion(fixture.nodeID)

	// Under the limit: nothing happens.
	e.spend(t, fixture, 999_999)
	if result, err := e.res.EnforceLimits(context.Background()); err != nil || !result.Empty() {
		t.Fatalf("EnforceLimits under the limit = %+v, %v; want nothing done", result, err)
	}
	if status := e.userStatus(t, fixture.userID); status != "active" {
		t.Fatalf("a user one byte under their limit is %s", status)
	}

	// Reaching it exactly is using it up.
	e.spend(t, fixture, 1)
	result, err := e.res.EnforceLimits(context.Background())
	if err != nil {
		t.Fatalf("EnforceLimits: %v", err)
	}
	if result.Limited != 1 {
		t.Fatalf("EnforceLimits limited %d users, want 1", result.Limited)
	}
	if status := e.userStatus(t, fixture.userID); status != "limited" {
		t.Errorf("a user at their limit is %s, want limited", status)
	}

	// The nodes have to hear about it, or the limit is only a word in the database.
	if after := e.configVersion(fixture.nodeID); after <= versionBefore {
		t.Errorf("limiting a user left the node's config version at %d; the node would keep serving them", after)
	}

	// And a second pass must not announce the same thing again.
	result, err = e.res.EnforceLimits(context.Background())
	if err != nil {
		t.Fatalf("EnforceLimits (again): %v", err)
	}
	if !result.Empty() {
		t.Errorf("a second pass did %+v; an already limited user was limited again", result)
	}
	if count := e.auditCount(t, "user.limited", fixture.userID); count != 1 {
		t.Errorf("the transition was audited %d times, want once", count)
	}
	if count := e.queuedEvents(t, service.EventUserLimited); count != 1 {
		t.Errorf("user.limited was queued %d times, want once", count)
	}
}

func TestAnExpiredSubscriptionIsSwitchedOff(t *testing.T) {
	e := newEnv(t)
	e.subscribe(t, "https://receiver.example.com/hook")

	expires := e.clock.Now().Add(24 * time.Hour)
	user, err := e.res.CreateUser(context.Background(), audit.SystemActor("test"),
		service.CreateUserInput{Username: "expiring", ExpiresAt: &expires})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if result, _ := e.res.EnforceLimits(context.Background()); result.Expired != 0 {
		t.Fatal("a user with a day left was expired")
	}

	e.clock.Advance(24*time.Hour + time.Second)

	result, err := e.res.EnforceLimits(context.Background())
	if err != nil {
		t.Fatalf("EnforceLimits: %v", err)
	}
	if result.Expired != 1 {
		t.Fatalf("EnforceLimits expired %d users, want 1", result.Expired)
	}
	if status := e.userStatus(t, user.ID); status != "expired" {
		t.Errorf("a user past their expiry is %s, want expired", status)
	}
	if count := e.queuedEvents(t, service.EventUserExpired); count != 1 {
		t.Errorf("user.expired was queued %d times, want once", count)
	}
}

// Renewal is what brings a user back, and it has to say so to the outside world too.
func TestRenewalReactivatesAndIsAnnounced(t *testing.T) {
	e := newEnv(t)
	e.subscribe(t, "https://receiver.example.com/hook")

	expires := e.clock.Now().Add(time.Hour)
	user, err := e.res.CreateUser(context.Background(), audit.SystemActor("test"),
		service.CreateUserInput{Username: "renewing", ExpiresAt: &expires})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	e.clock.Advance(2 * time.Hour)
	if _, err := e.res.EnforceLimits(context.Background()); err != nil {
		t.Fatalf("EnforceLimits: %v", err)
	}
	if status := e.userStatus(t, user.ID); status != "expired" {
		t.Fatalf("setup: the user is %s, want expired", status)
	}

	if _, err := e.res.RenewUser(context.Background(), audit.SystemActor("test"), user.ID,
		service.RenewUserInput{ExtendBy: "720h"}); err != nil {
		t.Fatalf("RenewUser: %v", err)
	}

	if status := e.userStatus(t, user.ID); status != "active" {
		t.Errorf("a renewed user is %s, want active", status)
	}
	if count := e.queuedEvents(t, service.EventUserRenewed); count != 1 {
		t.Errorf("user.renewed was queued %d times, want once", count)
	}
	if count := e.queuedEvents(t, service.EventUserCreated); count != 1 {
		t.Errorf("user.created was queued %d times, want once", count)
	}
}

// A new billing period clears the counter and lifts a traffic limit, and only once.
func TestAMonthlyResetLiftsTheLimitOncePerPeriod(t *testing.T) {
	e := newEnv(t)

	fixture := e.limitedUser(t, 1_000, "monthly")
	e.spend(t, fixture, 5_000)

	if _, err := e.res.EnforceLimits(context.Background()); err != nil {
		t.Fatalf("EnforceLimits: %v", err)
	}
	if status := e.userStatus(t, fixture.userID); status != "limited" {
		t.Fatalf("setup: the user is %s, want limited", status)
	}

	// Still the same month: nothing to reset. The user was created this month, so their
	// counter already belongs to the current period.
	if result, err := e.res.ResetDueTraffic(context.Background()); err != nil || result.Reset != 0 {
		t.Fatalf("ResetDueTraffic in the same month = %+v, %v; want nothing reset", result, err)
	}

	// Into next month.
	e.clock.Advance(32 * 24 * time.Hour)
	versionBefore := e.configVersion(fixture.nodeID)

	result, err := e.res.ResetDueTraffic(context.Background())
	if err != nil {
		t.Fatalf("ResetDueTraffic: %v", err)
	}
	if result.Reset != 1 {
		t.Fatalf("ResetDueTraffic reset %d users, want 1", result.Reset)
	}

	traffic := e.userTraffic(t, fixture.userID)
	if traffic.used != 0 {
		t.Errorf("after the reset the user has used %d, want 0", traffic.used)
	}
	if traffic.lifetime != 5_000 {
		t.Errorf("the reset touched traffic_lifetime (%d); it must never go down", traffic.lifetime)
	}
	if status := e.userStatus(t, fixture.userID); status != "active" {
		t.Errorf("after the reset the user is %s, want active again", status)
	}
	if after := e.configVersion(fixture.nodeID); after <= versionBefore {
		t.Error("lifting the limit did not tell the node, which would keep refusing the user")
	}

	// A second pass in the same period is a no-op: the worker runs every thirty seconds.
	if result, err := e.res.ResetDueTraffic(context.Background()); err != nil || result.Reset != 0 {
		t.Errorf("a second reset in the same period = %+v, %v; want nothing", result, err)
	}
}

// A reset clears the counter; it does not bring back a subscription that has ended, and it
// does not switch on an account an operator switched off.
func TestAResetDoesNotReviveExpiredOrDisabledUsers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	actor := audit.SystemActor("test")

	expires := e.clock.Now().Add(time.Hour)
	expired, err := e.res.CreateUser(ctx, actor, service.CreateUserInput{
		Username: "gone", ResetStrategy: "daily", ExpiresAt: &expires,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	disabled, err := e.res.CreateUser(ctx, actor, service.CreateUserInput{
		Username: "paused", ResetStrategy: "daily",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := e.res.SetUsersStatus(ctx, actor, []int64{disabled.ID}, "disabled"); err != nil {
		t.Fatalf("SetUsersStatus: %v", err)
	}

	e.clock.Advance(2 * 24 * time.Hour)
	if _, err := e.res.EnforceLimits(ctx); err != nil {
		t.Fatalf("EnforceLimits: %v", err)
	}
	if _, err := e.res.ResetDueTraffic(ctx); err != nil {
		t.Fatalf("ResetDueTraffic: %v", err)
	}

	if status := e.userStatus(t, expired.ID); status != "expired" {
		t.Errorf("a traffic reset turned an expired user %s", status)
	}
	if status := e.userStatus(t, disabled.ID); status != "disabled" {
		t.Errorf("a traffic reset turned a disabled user %s", status)
	}
}

// The enforcement worker runs resets before limits, so a user whose period ended while they
// were over the limit comes back rather than being limited again for the old period.
func TestTheWorkerResetsBeforeItLimits(t *testing.T) {
	e := newEnv(t)
	e.subscribe(t, "https://receiver.example.com/hook")

	fixture := e.limitedUser(t, 1_000, "daily")
	e.spend(t, fixture, 5_000)

	// A new day arrives before anything has enforced the old one.
	e.clock.Advance(25 * time.Hour)

	enforcer, err := worker.NewEnforcement(e.res, testLogger(t), time.Hour)
	if err != nil {
		t.Fatalf("worker.NewEnforcement: %v", err)
	}
	enforcer.Once(context.Background())

	if status := e.userStatus(t, fixture.userID); status != "active" {
		t.Errorf("the user is %s; they were limited for a day that had already ended", status)
	}
	if count := e.queuedEvents(t, service.EventUserLimited); count != 0 {
		t.Errorf("user.limited was announced %d times for a period that was over", count)
	}
}

// ---------------------------------------------------------------- delivery

// receiver is a webhook endpoint that records what it was sent and can be told to fail.
type receiver struct {
	server *httptest.Server
	secret []byte

	mu         sync.Mutex
	failNext   int
	deliveries []receivedDelivery
}

type receivedDelivery struct {
	ID      string
	Event   string
	Body    []byte
	Checked error
}

func startReceiver(t *testing.T) *receiver {
	t.Helper()

	r := &receiver{}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)

		r.mu.Lock()
		defer r.mu.Unlock()

		if r.failNext > 0 {
			r.failNext--
			http.Error(w, "receiver is down for maintenance", http.StatusInternalServerError)
			return
		}

		r.deliveries = append(r.deliveries, receivedDelivery{
			ID:    req.Header.Get(webhook.HeaderDelivery),
			Event: req.Header.Get(webhook.HeaderEvent),
			Body:  body,
			// Verified with the same code a receiver is documented to use.
			Checked: webhook.Verify(r.secret, body,
				req.Header.Get(webhook.HeaderTimestamp), req.Header.Get(webhook.HeaderSignature),
				time.Now(), webhook.DefaultTolerance),
		})
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *receiver) received() []receivedDelivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]receivedDelivery(nil), r.deliveries...)
}

// forceDue makes every pending delivery due now, so a test can step through retries without
// waiting out the real backoff.
func (e *env) forceDue(t *testing.T) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE webhook_deliveries SET next_try_at = now() - interval '1 second' WHERE delivered_at IS NULL`); err != nil {
		t.Fatalf("make deliveries due: %v", err)
	}
}

func TestWebhooksAreSignedRetriedAndNotDuplicated(t *testing.T) {
	e := newEnv(t)
	recv := startReceiver(t)

	endpoint := e.subscribe(t, recv.server.URL)
	recv.secret = []byte(endpoint.Secret)
	if endpoint.Secret == "" {
		t.Fatal("creating an endpoint without a secret did not return the generated one")
	}

	// The receiver is down for the first two attempts.
	recv.mu.Lock()
	recv.failNext = 2
	recv.mu.Unlock()

	if _, err := e.res.CreateUser(context.Background(), audit.SystemActor("test"),
		service.CreateUserInput{Username: "announced"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	deliveries, err := worker.NewWebhooks(e.pool, e.res, testLogger(t), worker.WebhookConfig{
		Timeout:     5 * time.Second,
		MaxAttempts: 5,
	})
	if err != nil {
		t.Fatalf("worker.NewWebhooks: %v", err)
	}

	for attempt := 1; attempt <= 3; attempt++ {
		e.forceDue(t)
		if _, err := deliveries.Once(context.Background()); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}

	got := recv.received()
	if len(got) != 1 {
		t.Fatalf("the receiver accepted %d deliveries, want exactly one after two failures", len(got))
	}
	if got[0].Checked != nil {
		t.Errorf("the delivery does not verify: %v", got[0].Checked)
	}
	if got[0].Event != service.EventUserCreated {
		t.Errorf("event header is %q, want %q", got[0].Event, service.EventUserCreated)
	}

	var payload struct {
		Event string         `json:"event"`
		User  map[string]any `json:"user"`
	}
	if err := json.Unmarshal(got[0].Body, &payload); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if payload.User["username"] != "announced" {
		t.Errorf("payload user is %v", payload.User)
	}
	// No credentials leave the panel in an event.
	for _, forbidden := range []string{"vless_uuid", "trojan_password", "ss_password", "short_uuid"} {
		if _, present := payload.User[forbidden]; present {
			t.Errorf("the payload carries %s; webhook events must not contain credentials", forbidden)
		}
	}

	// Once delivered, never again — however many more passes run.
	for i := 0; i < 3; i++ {
		e.forceDue(t)
		if _, err := deliveries.Once(context.Background()); err != nil {
			t.Fatalf("extra pass: %v", err)
		}
	}
	if count := len(recv.received()); count != 1 {
		t.Errorf("a delivered event was sent %d times", count)
	}

	var attempts int
	if err := e.pool.QueryRow(context.Background(),
		`SELECT attempts FROM webhook_deliveries`).Scan(&attempts); err != nil {
		t.Fatalf("read attempts: %v", err)
	}
	if attempts != 3 {
		t.Errorf("the delivery took %d attempts, want 3 (two failures and a success)", attempts)
	}
}

// A receiver that never comes back is given up on after the configured number of attempts.
func TestWebhooksGiveUpAfterTheLastAttempt(t *testing.T) {
	e := newEnv(t)
	recv := startReceiver(t)
	recv.mu.Lock()
	recv.failNext = 1_000
	recv.mu.Unlock()

	e.subscribe(t, recv.server.URL)
	if _, err := e.res.CreateUser(context.Background(), audit.SystemActor("test"),
		service.CreateUserInput{Username: "unheard"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	deliveries, err := worker.NewWebhooks(e.pool, e.res, testLogger(t), worker.WebhookConfig{
		Timeout:     5 * time.Second,
		MaxAttempts: 3,
	})
	if err != nil {
		t.Fatalf("worker.NewWebhooks: %v", err)
	}

	for i := 0; i < 6; i++ {
		e.forceDue(t)
		if _, err := deliveries.Once(context.Background()); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}

	var attempts int
	var lastError string
	if err := e.pool.QueryRow(context.Background(),
		`SELECT attempts, last_error FROM webhook_deliveries`).Scan(&attempts, &lastError); err != nil {
		t.Fatalf("read the delivery: %v", err)
	}
	if attempts != 3 {
		t.Errorf("the delivery was attempted %d times, want exactly the configured 3", attempts)
	}
	if lastError == "" {
		t.Error("a failed delivery records no reason, which is the first thing an operator looks for")
	}
}

// An unknown event is refused when the endpoint is created, not discovered when nothing
// ever arrives.
func TestWebhookEndpointsRejectUnknownEvents(t *testing.T) {
	e := newEnv(t)

	_, err := e.res.CreateWebhookEndpoint(context.Background(), audit.SystemActor("test"),
		service.CreateWebhookEndpointInput{URL: "https://r.example.com", Events: []string{"user.limitted"}})
	if err == nil {
		t.Error("an endpoint subscribing to a misspelt event was accepted")
	}

	_, err = e.res.CreateWebhookEndpoint(context.Background(), audit.SystemActor("test"),
		service.CreateWebhookEndpointInput{URL: "ftp://r.example.com", Events: []string{service.EventUserCreated}})
	if err == nil {
		t.Error("an endpoint with an ftp url was accepted")
	}
}

// The secret comes back exactly once, and a listing never carries it.
func TestWebhookSecretsAreShownOnce(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	token := e.adminToken(server)

	rec := e.do(server, apiCall{
		method: http.MethodPost, path: "/api/v1/webhooks", bearer: token,
		body: map[string]any{"url": "https://r.example.com/hook", "events": []string{"user.limited"}},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID     int64  `json:"id"`
		Secret string `json:"secret"`
	}
	decodeInto(t, rec, &created)
	if created.Secret == "" {
		t.Error("the generated secret was not returned on create; the receiver could never verify anything")
	}

	rec = e.do(server, apiCall{method: http.MethodGet, path: "/api/v1/webhooks", bearer: token})
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); created.Secret != "" && strings.Contains(body, created.Secret) {
		t.Error("the listing returned the signing secret")
	}

	rec = e.do(server, apiCall{
		method: http.MethodPatch, path: fmt.Sprintf("/api/v1/webhooks/%d", created.ID), bearer: token,
		body: map[string]any{"secret": "something new"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("changing the secret in place returned %d, want 400", rec.Code)
	}
}
