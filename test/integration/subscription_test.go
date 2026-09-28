//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/httpapi"
	"github.com/xraypanel/panel/internal/ratelimit"
	"github.com/xraypanel/panel/internal/service"
)

// The public endpoint is the one part of the panel every subscriber touches. These tests go
// through the real router, the way a client does, with no credential but the token.

// subscriber is a user who can actually reach an endpoint: a node carries the inbound and a
// host presents it, so the subscription has something in it.
type subscriber struct {
	userID int64
	token  string
}

func (e *env) subscriber(t *testing.T) subscriber {
	t.Helper()

	ctx := context.Background()
	actor := audit.SystemActor("test")

	node := e.buildPlainNode(t)
	if _, err := e.res.CreateHost(ctx, actor, service.CreateHostInput{
		InboundID: node.inboundID,
		Remark:    "{COUNTRY} {USERNAME}",
		Address:   "edge.example.com",
		Enabled:   true,
	}); err != nil {
		t.Fatalf("CreateHost: %v", err)
	}

	user, err := e.res.CreateUser(ctx, actor, service.CreateUserInput{
		Username:     "alice",
		TrafficLimit: 10 << 30,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return subscriber{userID: user.ID, token: user.ShortUuid}
}

func (e *env) publicGet(handler http.Handler, path, userAgent string) *httptest.ResponseRecorder {
	e.t.Helper()
	headers := map[string]string{}
	if userAgent != "" {
		headers["User-Agent"] = userAgent
	}
	return e.do(handler, apiCall{method: http.MethodGet, path: path, headers: headers})
}

func (e *env) subFetchedAt(t *testing.T, userID int64) *time.Time {
	t.Helper()
	var fetched *time.Time
	if err := e.pool.QueryRow(context.Background(),
		`SELECT sub_fetched_at FROM users WHERE id = $1`, userID).Scan(&fetched); err != nil {
		t.Fatalf("read sub_fetched_at: %v", err)
	}
	return fetched
}

func TestSubscriptionServesEveryFormatWithItsHeaders(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	sub := e.subscriber(t)
	path := "/sub/" + sub.token

	// HEAD first: it must answer with the quota and not count as a fetch.
	head := e.do(server, apiCall{method: http.MethodHead, path: path})
	if head.Code != http.StatusOK {
		t.Fatalf("HEAD: %d", head.Code)
	}
	if head.Header().Get("Subscription-Userinfo") == "" {
		t.Error("HEAD carries no Subscription-Userinfo")
	}
	if head.Body.Len() != 0 {
		t.Errorf("HEAD returned a %d-byte body", head.Body.Len())
	}
	if fetched := e.subFetchedAt(t, sub.userID); fetched != nil {
		t.Error("a HEAD request was recorded as a fetch")
	}

	rec := e.publicGet(server, path, "v2rayNG/1.10.2")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET as v2rayNG: %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("content type %q, want text/plain", got)
	}
	decoded, err := base64.StdEncoding.DecodeString(rec.Body.String())
	if err != nil {
		t.Fatalf("the body is not base64: %v", err)
	}
	links := strings.Split(string(decoded), "\n")
	if len(links) != 1 || !strings.HasPrefix(links[0], "vless://") {
		t.Fatalf("links are %q, want one vless link", links)
	}
	if !strings.Contains(links[0], "@edge.example.com:") {
		t.Errorf("the link does not use the host's address: %s", links[0])
	}
	if !strings.HasSuffix(links[0], "#DE%20alice") {
		t.Errorf("the remark template was not expanded: %s", links[0])
	}

	headers := rec.Header()
	wantUserInfo := "upload=0; download=0; total=10737418240; expire=0"
	if got := headers.Get("Subscription-Userinfo"); got != wantUserInfo {
		t.Errorf("Subscription-Userinfo = %q, want %q", got, wantUserInfo)
	}
	if headers.Get("Profile-Update-Interval") == "" || headers.Get("Profile-Title") == "" {
		t.Errorf("profile headers missing: %v", headers)
	}
	if got := headers.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q; a profile is credentials and must not be cached", got)
	}
	if headers.Get("Content-Disposition") != "" {
		t.Error("a link list was sent as an attachment")
	}
	if e.subFetchedAt(t, sub.userID) == nil {
		t.Error("the fetch was not recorded")
	}

	clash := e.publicGet(server, path, "mihomo/1.19.31")
	if !strings.HasPrefix(clash.Header().Get("Content-Type"), "text/yaml") {
		t.Errorf("mihomo got %q, want YAML", clash.Header().Get("Content-Type"))
	}
	if !strings.Contains(clash.Header().Get("Content-Disposition"), ".yaml") {
		t.Errorf("mihomo got disposition %q", clash.Header().Get("Content-Disposition"))
	}
	if !strings.Contains(clash.Body.String(), "proxies:") {
		t.Errorf("the Clash profile has no proxies section:\n%s", clash.Body.String())
	}

	// An explicit format beats the agent.
	singbox := e.publicGet(server, path+"?format=singbox", "v2rayNG/1.10.2")
	var profile map[string]any
	if err := json.Unmarshal(singbox.Body.Bytes(), &profile); err != nil {
		t.Fatalf("?format=singbox is not JSON: %v", err)
	}
	if _, ok := profile["outbounds"]; !ok {
		t.Error("the sing-box profile has no outbounds")
	}

	if bad := e.publicGet(server, path+"?format=wireguard", ""); bad.Code != http.StatusBadRequest {
		t.Errorf("an unknown format returned %d, want 400", bad.Code)
	}
}

func TestSubscriptionInfoFeedsThePage(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	sub := e.subscriber(t)

	rec := e.publicGet(server, "/sub/"+sub.token+"/info", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET info: %d %s", rec.Code, rec.Body.String())
	}

	var info struct {
		Username     string  `json:"username"`
		Status       string  `json:"status"`
		TrafficLimit int64   `json:"traffic_limit"`
		ExpiresAt    *string `json:"expires_at"`
		Links        []struct {
			Remark string `json:"remark"`
			Link   string `json:"link"`
		} `json:"links"`
	}
	decodeInto(t, rec, &info)

	if info.Username != "alice" || info.Status != "active" || info.TrafficLimit != 10<<30 {
		t.Errorf("info is %+v", info)
	}
	if info.ExpiresAt != nil {
		t.Errorf("expires_at = %q for a user with no expiry", *info.ExpiresAt)
	}
	if len(info.Links) != 1 || info.Links[0].Remark != "DE alice" {
		t.Errorf("links are %+v, want the one expanded endpoint", info.Links)
	}
	if e.subFetchedAt(t, sub.userID) != nil {
		t.Error("looking at the page was recorded as a client fetch")
	}
}

// A user who may not connect gets an answer, but nothing to connect with.
func TestInactiveUsersGetNoEndpoints(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	ctx := context.Background()

	cases := map[string]func(t *testing.T, userID int64){
		"disabled": func(t *testing.T, userID int64) {
			status := "disabled"
			if _, err := e.res.UpdateUser(ctx, audit.SystemActor("test"), userID,
				service.UpdateUserInput{Status: &status}); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
		},
		// Past the expiry but before enforcement has run: the stored status still says
		// active, and the subscription must not.
		"expired": func(t *testing.T, userID int64) {
			if _, err := e.pool.Exec(ctx, `UPDATE users SET expires_at = $2 WHERE id = $1`,
				userID, e.clock.Now().Add(-time.Minute)); err != nil {
				t.Fatalf("expire: %v", err)
			}
		},
		"limited": func(t *testing.T, userID int64) {
			if _, err := e.pool.Exec(ctx,
				`UPDATE users SET traffic_used = traffic_limit WHERE id = $1`, userID); err != nil {
				t.Fatalf("exhaust: %v", err)
			}
		},
	}

	for want, apply := range cases {
		t.Run(want, func(t *testing.T) {
			truncate(t, e.pool)
			sub := e.subscriber(t)
			apply(t, sub.userID)

			profile := e.publicGet(server, "/sub/"+sub.token, "v2rayNG/1.10.2")
			if profile.Code != http.StatusOK {
				t.Fatalf("GET: %d %s", profile.Code, profile.Body.String())
			}
			if profile.Body.Len() != 0 {
				decoded, _ := base64.StdEncoding.DecodeString(profile.Body.String())
				t.Errorf("a %s user was given links: %q", want, decoded)
			}
			if profile.Header().Get("Subscription-Userinfo") == "" {
				t.Error("the quota header is missing, so the client cannot say why")
			}

			// Every profile format has to stay loadable with nothing in it.
			for _, format := range []string{"clash", "singbox", "json"} {
				rec := e.publicGet(server, "/sub/"+sub.token+"?format="+format, "")
				if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "edge.example.com") {
					t.Errorf("format %s: %d, body mentions the server: %t",
						format, rec.Code, strings.Contains(rec.Body.String(), "edge.example.com"))
				}
			}

			info := e.publicGet(server, "/sub/"+sub.token+"/info", "")
			var body struct {
				Status string `json:"status"`
				Links  []any  `json:"links"`
			}
			decodeInto(t, info, &body)
			if body.Status != want || len(body.Links) != 0 {
				t.Errorf("info says %q with %d links, want %q with none", body.Status, len(body.Links), want)
			}
		})
	}
}

func TestRotatedAndUnknownTokensAreIndistinguishable(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	sub := e.subscriber(t)

	rotated, err := e.res.RotateUserCredentials(context.Background(), audit.SystemActor("test"), sub.userID)
	if err != nil {
		t.Fatalf("RotateUserCredentials: %v", err)
	}

	old := e.publicGet(server, "/sub/"+sub.token, "")
	unknown := e.publicGet(server, "/sub/"+strings.Repeat("a", len(sub.token)), "")
	malformed := e.publicGet(server, "/sub/NOT-A-TOKEN", "")

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"rotated": old, "unknown": unknown, "malformed": malformed,
	} {
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s token: %d, want 404", name, rec.Code)
		}
		var body httpapi.ErrorBody
		decodeInto(t, rec, &body)
		if body.Message != "" {
			t.Errorf("%s token: the 404 explains itself (%q), which tells a prober what it hit", name, body.Message)
		}
	}
	if info := e.publicGet(server, "/sub/"+sub.token+"/info", ""); info.Code != http.StatusNotFound {
		t.Errorf("the page still resolves the rotated token: %d", info.Code)
	}

	if fresh := e.publicGet(server, "/sub/"+rotated.ShortUuid, ""); fresh.Code != http.StatusOK {
		t.Errorf("the new token: %d, want 200", fresh.Code)
	}
}

func TestSubscriptionIsRateLimitedPerClient(t *testing.T) {
	e := newEnv(t)
	sub := e.subscriber(t)

	server := httpapi.NewRouter(httpapi.Deps{
		Logger:              slog.New(slog.NewJSONHandler(io.Discard, nil)),
		DB:                  e.pool,
		Service:             e.res,
		Version:             "test",
		SubscriptionLimiter: ratelimit.New(60, 2),
	})

	from := func(addr, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		return rec
	}

	path := "/sub/" + sub.token
	for i := range 2 {
		if rec := from("198.51.100.1:1000", path); rec.Code != http.StatusOK {
			t.Fatalf("request %d within the burst: %d", i+1, rec.Code)
		}
	}

	// Unknown tokens count too: scanning is exactly what the limit is for.
	limited := from("198.51.100.1:1001", "/sub/"+strings.Repeat("z", 22))
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("past the burst: %d, want 429", limited.Code)
	}
	if limited.Header().Get("Retry-After") == "" {
		t.Error("the 429 has no Retry-After")
	}
	var body httpapi.ErrorBody
	decodeInto(t, limited, &body)
	if body.Code != "rate_limited" {
		t.Errorf("error code %q, want rate_limited", body.Code)
	}

	if rec := from("198.51.100.2:1000", path); rec.Code != http.StatusOK {
		t.Errorf("another client was limited by the first one's requests: %d", rec.Code)
	}
}
