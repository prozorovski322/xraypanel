//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/service"
)

// The audit screen's one job is to be exact: every entry once, in order, however many are
// written while somebody is paging through it.
func TestAuditPagesAreExactWhileTheLogGrows(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	token := e.adminToken(server)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := e.res.CreateUser(ctx, audit.SystemActor("test"),
			service.CreateUserInput{Username: fmt.Sprintf("paged-%d", i)}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
	}

	type page struct {
		Items []struct {
			ID     int64  `json:"id"`
			Action string `json:"action"`
		} `json:"items"`
		NextBefore *int64 `json:"next_before"`
	}

	get := func(path string) page {
		t.Helper()
		rec := e.do(server, apiCall{method: http.MethodGet, path: path, bearer: token})
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body.String())
		}
		var p page
		decodeInto(t, rec, &p)
		return p
	}

	first := get("/api/v1/audit?action=user.create&limit=2")
	if len(first.Items) != 2 || first.NextBefore == nil {
		t.Fatalf("first page is %+v, want two entries and a cursor", first)
	}

	// More entries arrive between pages. An offset-paged log would now show the second
	// page shifted by one; a keyset-paged one does not notice.
	if _, err := e.res.CreateUser(ctx, audit.SystemActor("test"),
		service.CreateUserInput{Username: "arrived-late"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	seen := map[int64]bool{}
	for _, item := range first.Items {
		seen[item.ID] = true
	}

	cursor := first.NextBefore
	for cursor != nil {
		next := get(fmt.Sprintf("/api/v1/audit?action=user.create&limit=2&before=%d", *cursor))
		for _, item := range next.Items {
			if seen[item.ID] {
				t.Errorf("entry %d appeared on two pages", item.ID)
			}
			if item.Action != "user.create" {
				t.Errorf("the action filter let through %q", item.Action)
			}
			seen[item.ID] = true
		}
		cursor = next.NextBefore
	}

	// The five that existed when paging began, and not the one that arrived after.
	if len(seen) != 5 {
		t.Errorf("paging from the first page saw %d entries, want the 5 that existed when it started", len(seen))
	}

	rec := e.do(server, apiCall{method: http.MethodGet, path: "/api/v1/audit?before=-3", bearer: token})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a negative cursor returned %d, want 400", rec.Code)
	}
}

// The dashboard's figures have to agree with the rows they summarise.
func TestTheSummaryAgreesWithTheData(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	token := e.adminToken(server)
	ctx := context.Background()
	actor := audit.SystemActor("test")

	fixture := e.limitedUser(t, 1_000, "never")
	e.spend(t, fixture, 4_000)
	if _, err := e.res.EnforceLimits(ctx); err != nil {
		t.Fatalf("EnforceLimits: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := e.res.CreateUser(ctx, actor, service.CreateUserInput{Username: "active-" + uuid.NewString()[:6]}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
	}

	rec := e.do(server, apiCall{method: http.MethodGet, path: "/api/v1/stats/summary", bearer: token})
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /stats/summary: %d %s", rec.Code, rec.Body.String())
	}

	var summary struct {
		Users        map[string]int64 `json:"users"`
		Nodes        map[string]int64 `json:"nodes"`
		OnlineUsers  int64            `json:"online_users"`
		TrafficToday struct {
			Uplink   int64  `json:"uplink"`
			Downlink int64  `json:"downlink"`
			Since    string `json:"since"`
		} `json:"traffic_today"`
		TrafficMonth struct {
			Uplink   int64 `json:"uplink"`
			Downlink int64 `json:"downlink"`
		} `json:"traffic_month"`
	}
	decodeInto(t, rec, &summary)

	if summary.Users["active"] != 2 || summary.Users["limited"] != 1 {
		t.Errorf("users by status are %v, want 2 active and 1 limited", summary.Users)
	}
	// Every status is present even at zero, so a dashboard never has to guess whether a
	// missing key means none or means unknown.
	for _, status := range []string{"active", "limited", "expired", "disabled"} {
		if _, present := summary.Users[status]; !present {
			t.Errorf("status %q is missing from the summary", status)
		}
	}
	if summary.Nodes["disconnected"] != 1 {
		t.Errorf("nodes by status are %v, want the one test node disconnected", summary.Nodes)
	}
	if total := summary.TrafficToday.Uplink + summary.TrafficToday.Downlink; total != 4_000 {
		t.Errorf("traffic today is %d, want the 4000 bytes accounted", total)
	}
	if total := summary.TrafficMonth.Uplink + summary.TrafficMonth.Downlink; total != 4_000 {
		t.Errorf("traffic this month is %d, want 4000", total)
	}
	if summary.OnlineUsers != 1 {
		t.Errorf("online users is %d, want the one who just moved traffic", summary.OnlineUsers)
	}
	if _, err := time.Parse(time.RFC3339, summary.TrafficToday.Since); err != nil {
		t.Errorf("traffic_today.since %q is not a timestamp", summary.TrafficToday.Since)
	}
}
