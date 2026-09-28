//go:build integration

package integration

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/service"
	"github.com/xraypanel/panel/internal/worker"
)

// Traffic accounting is what users are billed by, so these tests are about the arithmetic
// surviving the things that actually happen: a node resending a batch it was not sure
// arrived, a user deleted between being served and being reported, a node with a wrong
// clock, and a panel that has to keep months of hourly rows from becoming the largest thing
// in the database.

// testLogger routes a worker's log into the test output, where a warning about a partition
// or a rollup is worth seeing when something fails.
func testLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// userTraffic reads what the panel believes a user has used.
type userTrafficRow struct {
	used     int64
	lifetime int64
	onlineAt *time.Time
}

func (e *env) userTraffic(t *testing.T, userID int64) userTrafficRow {
	t.Helper()

	var row userTrafficRow
	err := e.pool.QueryRow(context.Background(),
		`SELECT traffic_used, traffic_lifetime, online_at FROM users WHERE id = $1`, userID).
		Scan(&row.used, &row.lifetime, &row.onlineAt)
	if err != nil {
		t.Fatalf("read user traffic: %v", err)
	}
	return row
}

func (e *env) nodeTraffic(t *testing.T, nodeID int64) int64 {
	t.Helper()

	var used int64
	err := e.pool.QueryRow(context.Background(),
		`SELECT traffic_used FROM nodes WHERE id = $1`, nodeID).Scan(&used)
	if err != nil {
		t.Fatalf("read node traffic: %v", err)
	}
	return used
}

// xrayEmailOf returns the stats key a node would report a user under.
func (e *env) xrayEmailOf(t *testing.T, userID int64) string {
	t.Helper()

	var email string
	err := e.pool.QueryRow(context.Background(),
		`SELECT xray_email FROM users WHERE id = $1`, userID).Scan(&email)
	if err != nil {
		t.Fatalf("read xray_email: %v", err)
	}
	return email
}

// trafficRows returns the hourly rows for a user, with the partition each one landed in.
func (e *env) trafficRows(t *testing.T, userID int64) map[string]struct {
	Uplink    int64
	Downlink  int64
	Partition string
} {
	t.Helper()

	rows, err := e.pool.Query(context.Background(), `
		SELECT hour, uplink, downlink, tableoid::regclass::text
		FROM traffic_records
		WHERE user_id = $1
		ORDER BY hour`, userID)
	if err != nil {
		t.Fatalf("read traffic records: %v", err)
	}
	defer rows.Close()

	out := map[string]struct {
		Uplink    int64
		Downlink  int64
		Partition string
	}{}
	for rows.Next() {
		var hour time.Time
		var uplink, downlink int64
		var partition string
		if err := rows.Scan(&hour, &uplink, &downlink, &partition); err != nil {
			t.Fatalf("scan traffic record: %v", err)
		}
		out[hour.UTC().Format(time.RFC3339)] = struct {
			Uplink    int64
			Downlink  int64
			Partition string
		}{uplink, downlink, partition}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read traffic records: %v", err)
	}
	return out
}

// trafficFixture is a node and a user to account traffic for.
type trafficFixture struct {
	nodeID int64
	userID int64
	email  string
}

func (e *env) trafficFixture(t *testing.T, suffix string) trafficFixture {
	t.Helper()

	ctx := context.Background()
	actor := audit.SystemActor("test")

	node, err := e.res.CreateNode(ctx, actor, service.CreateNodeInput{
		Name: "traffic-" + suffix, Address: "t.example.com", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	user, err := e.res.CreateUser(ctx, actor, service.CreateUserInput{Username: "user-" + suffix})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	return trafficFixture{nodeID: node.ID, userID: user.ID, email: e.xrayEmailOf(t, user.ID)}
}

// A node resends a batch whenever it did not hear the panel confirm the last one. Applying
// one twice would charge a user for bytes they moved once.
func TestATrafficBatchIsAppliedExactlyOnce(t *testing.T) {
	e := newEnv(t)
	fixture := e.trafficFixture(t, "once")

	batch := uuid.NewString()
	deltas := []service.TrafficDelta{
		{XrayEmail: fixture.email, Uplink: 1_000, Downlink: 9_000, Hour: time.Now().UTC().Truncate(time.Hour)},
	}

	first, err := e.res.IngestTrafficBatch(context.Background(), fixture.nodeID, batch, deltas)
	if err != nil {
		t.Fatalf("IngestTrafficBatch: %v", err)
	}
	if first.Duplicate || first.Applied != 1 || first.Bytes != 10_000 {
		t.Fatalf("first attempt is %+v, want one delta of 10000 bytes applied", first)
	}

	second, err := e.res.IngestTrafficBatch(context.Background(), fixture.nodeID, batch, deltas)
	if err != nil {
		t.Fatalf("IngestTrafficBatch (resend): %v", err)
	}
	if !second.Duplicate {
		t.Error("the resent batch was applied again rather than recognised as a duplicate")
	}

	traffic := e.userTraffic(t, fixture.userID)
	if traffic.used != 10_000 || traffic.lifetime != 10_000 {
		t.Errorf("after a resend the user has used %d / lifetime %d, want 10000 each",
			traffic.used, traffic.lifetime)
	}
	if got := e.nodeTraffic(t, fixture.nodeID); got != 10_000 {
		t.Errorf("the node has %d bytes, want 10000", got)
	}
	if traffic.onlineAt == nil {
		t.Error("traffic did not mark the user as having been online")
	}

	// A different batch id with the same traffic is real traffic, not a duplicate: a user
	// can move the same number of bytes twice.
	third, err := e.res.IngestTrafficBatch(context.Background(), fixture.nodeID, uuid.NewString(), deltas)
	if err != nil {
		t.Fatalf("IngestTrafficBatch (new batch): %v", err)
	}
	if third.Duplicate || third.Applied != 1 {
		t.Fatalf("a new batch is %+v, want it applied", third)
	}
	if traffic := e.userTraffic(t, fixture.userID); traffic.used != 20_000 {
		t.Errorf("the user has used %d, want 20000 after two distinct batches", traffic.used)
	}
}

// Deltas the panel cannot attribute must be dropped and counted, never guessed at.
func TestUnattributableTrafficIsDropped(t *testing.T) {
	e := newEnv(t)
	fixture := e.trafficFixture(t, "unknown")

	future := time.Now().UTC().Add(6 * time.Hour).Truncate(time.Hour)
	hour := time.Now().UTC().Truncate(time.Hour)

	result, err := e.res.IngestTrafficBatch(context.Background(), fixture.nodeID, uuid.NewString(),
		[]service.TrafficDelta{
			{XrayEmail: fixture.email, Uplink: 500, Hour: hour},
			// A user deleted since the node was given its configuration.
			{XrayEmail: "zzzzzzzzzzzz", Uplink: 700, Hour: hour},
			// A node whose clock is hours ahead.
			{XrayEmail: fixture.email, Uplink: 900, Hour: future},
			// Traffic that would credit bytes back to a user.
			{XrayEmail: fixture.email, Uplink: -100, Downlink: -100, Hour: hour},
		})
	if err != nil {
		t.Fatalf("IngestTrafficBatch: %v", err)
	}

	if result.Applied != 1 || result.Unknown != 3 {
		t.Errorf("result is %+v, want one applied and three dropped", result)
	}
	if traffic := e.userTraffic(t, fixture.userID); traffic.used != 500 {
		t.Errorf("the user has used %d, want only the 500 bytes that could be attributed", traffic.used)
	}
}

// An invalid batch id is refused rather than stored: the id is what deduplication rests on.
func TestATrafficBatchNeedsAUsableID(t *testing.T) {
	e := newEnv(t)
	fixture := e.trafficFixture(t, "badid")

	_, err := e.res.IngestTrafficBatch(context.Background(), fixture.nodeID, "not-a-uuid",
		[]service.TrafficDelta{{XrayEmail: fixture.email, Uplink: 1, Hour: time.Now().UTC()}})
	if err == nil {
		t.Error("a batch with an unusable id was accepted")
	}
}

// Traffic reported for an earlier hour has to land in that hour's row and in that month's
// partition, which is what makes the hourly table prunable a month at a time.
func TestTrafficLandsInTheRightHourAndPartition(t *testing.T) {
	e := newEnv(t)
	fixture := e.trafficFixture(t, "hours")

	now := time.Now().UTC().Truncate(time.Hour)
	earlier := now.Add(-3 * time.Hour)

	_, err := e.res.IngestTrafficBatch(context.Background(), fixture.nodeID, uuid.NewString(),
		[]service.TrafficDelta{
			{XrayEmail: fixture.email, Uplink: 10, Downlink: 20, Hour: now},
			{XrayEmail: fixture.email, Uplink: 30, Downlink: 40, Hour: earlier},
			// The same hour again, in the same batch: a node folds its own readings, but
			// the panel must add rather than replace if it ever sees two.
			{XrayEmail: fixture.email, Uplink: 5, Downlink: 5, Hour: now},
		})
	if err != nil {
		t.Fatalf("IngestTrafficBatch: %v", err)
	}

	rows := e.trafficRows(t, fixture.userID)
	if len(rows) != 2 {
		t.Fatalf("stored %d hourly rows, want 2: %+v", len(rows), rows)
	}

	current := rows[now.Format(time.RFC3339)]
	if current.Uplink != 15 || current.Downlink != 25 {
		t.Errorf("the current hour holds %d/%d, want 15/25", current.Uplink, current.Downlink)
	}
	past := rows[earlier.Format(time.RFC3339)]
	if past.Uplink != 30 || past.Downlink != 40 {
		t.Errorf("the earlier hour holds %d/%d, want 30/40", past.Uplink, past.Downlink)
	}

	// Both must be in a real monthly partition rather than the default one, which exists
	// only so that traffic is never rejected for want of a partition.
	for hour, row := range rows {
		if row.Partition == "traffic_records_default" {
			t.Errorf("traffic for %s landed in the default partition; the monthly one is missing", hour)
		}
	}
}

// The rollup is what charts are drawn from, and it has to be safe to run twice: a day can
// still receive late batches from a node that was offline.
func TestRollupIsIdempotentAndPruneKeepsTheDailyHistory(t *testing.T) {
	e := newEnv(t)
	fixture := e.trafficFixture(t, "rollup")

	now := time.Now().UTC().Truncate(time.Hour)
	_, err := e.res.IngestTrafficBatch(context.Background(), fixture.nodeID, uuid.NewString(),
		[]service.TrafficDelta{
			{XrayEmail: fixture.email, Uplink: 100, Downlink: 200, Hour: now},
			{XrayEmail: fixture.email, Uplink: 300, Downlink: 400, Hour: now.Add(-time.Hour)},
		})
	if err != nil {
		t.Fatalf("IngestTrafficBatch: %v", err)
	}

	maintenance, err := worker.NewTraffic(e.pool, testLogger(t), worker.Config{
		Interval:        time.Hour,
		RecordRetention: 90 * 24 * time.Hour,
		BatchRetention:  48 * time.Hour,
		PartitionsAhead: 2,
	})
	if err != nil {
		t.Fatalf("worker.NewTraffic: %v", err)
	}

	ctx := context.Background()
	if err := maintenance.RollUp(ctx, now); err != nil {
		t.Fatalf("RollUp: %v", err)
	}
	if err := maintenance.RollUp(ctx, now); err != nil {
		t.Fatalf("RollUp (again): %v", err)
	}

	history, err := e.res.UserTrafficHistory(ctx, fixture.userID, now.AddDate(0, 0, -2), now)
	if err != nil {
		t.Fatalf("UserTrafficHistory: %v", err)
	}

	var uplink, downlink int64
	for _, day := range history {
		uplink += day.Uplink
		downlink += day.Downlink
	}
	// Two hours of traffic, rolled up twice: the totals must be the traffic, not double it.
	if uplink != 400 || downlink != 600 {
		t.Errorf("after two rollups the history holds %d/%d, want 400/600 — running it twice must "+
			"correct a day, not double it", uplink, downlink)
	}

	// Now prune with a retention window that excludes everything. The hourly rows go and
	// the daily history stays, which is the whole point of the rollup.
	pruning, err := worker.NewTraffic(e.pool, testLogger(t), worker.Config{
		RecordRetention: time.Nanosecond,
		BatchRetention:  time.Nanosecond,
		PartitionsAhead: 1,
	})
	if err != nil {
		t.Fatalf("worker.NewTraffic: %v", err)
	}
	if err := pruning.Prune(ctx, time.Now().UTC()); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	if rows := e.trafficRows(t, fixture.userID); len(rows) != 0 {
		t.Errorf("pruning left %d hourly rows, want none", len(rows))
	}

	history, err = e.res.UserTrafficHistory(ctx, fixture.userID, now.AddDate(0, 0, -2), now)
	if err != nil {
		t.Fatalf("UserTrafficHistory: %v", err)
	}
	if len(history) == 0 {
		t.Error("pruning the hourly rows also took the daily history, which is what charts read")
	}

	// And the batch ids are forgotten, which is safe only once no node could still be
	// holding one unacknowledged.
	var batches int
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM traffic_batches`).Scan(&batches); err != nil {
		t.Fatalf("count batches: %v", err)
	}
	if batches != 0 {
		t.Errorf("%d batch ids survived a retention window of one nanosecond", batches)
	}
}

// The history endpoints are how an operator checks a bill without a database client, so
// they have to report the same numbers the rollup stored.
func TestTrafficHistoryOverHTTP(t *testing.T) {
	e := newEnv(t)
	server := e.newServer()
	token := e.adminToken(server)

	fixture := e.trafficFixture(t, "http")

	now := time.Now().UTC().Truncate(time.Hour)
	_, err := e.res.IngestTrafficBatch(context.Background(), fixture.nodeID, uuid.NewString(),
		[]service.TrafficDelta{{XrayEmail: fixture.email, Uplink: 1_500, Downlink: 8_500, Hour: now}})
	if err != nil {
		t.Fatalf("IngestTrafficBatch: %v", err)
	}

	maintenance, err := worker.NewTraffic(e.pool, testLogger(t), worker.Config{PartitionsAhead: 1})
	if err != nil {
		t.Fatalf("worker.NewTraffic: %v", err)
	}
	if err := maintenance.RollUp(context.Background(), now); err != nil {
		t.Fatalf("RollUp: %v", err)
	}

	var body struct {
		From          string `json:"from"`
		To            string `json:"to"`
		TotalUplink   int64  `json:"total_uplink"`
		TotalDownlink int64  `json:"total_downlink"`
		Days          []struct {
			Day      string `json:"day"`
			Uplink   int64  `json:"uplink"`
			Downlink int64  `json:"downlink"`
		} `json:"days"`
	}

	for _, path := range []string{
		fmt.Sprintf("/api/v1/users/%d/traffic", fixture.userID),
		fmt.Sprintf("/api/v1/nodes/%d/traffic", fixture.nodeID),
	} {
		rec := e.do(server, apiCall{method: http.MethodGet, path: path, bearer: token})
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d: %s", path, rec.Code, rec.Body.String())
		}
		decodeInto(t, rec, &body)

		if body.TotalUplink != 1_500 || body.TotalDownlink != 8_500 {
			t.Errorf("GET %s reports %d/%d, want 1500/8500", path, body.TotalUplink, body.TotalDownlink)
		}
		if len(body.Days) != 1 || body.Days[0].Day != now.Format(time.DateOnly) {
			t.Errorf("GET %s returned days %+v, want just today", path, body.Days)
		}
	}

	// An unbounded window is an easy way to make the panel do unbounded work, so it is
	// refused rather than served slowly.
	rec := e.do(server, apiCall{
		method: http.MethodGet,
		path:   fmt.Sprintf("/api/v1/users/%d/traffic?from=2000-01-01", fixture.userID),
		bearer: token,
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a twenty-six year window returned %d, want 400", rec.Code)
	}

	rec = e.do(server, apiCall{
		method: http.MethodGet,
		path:   fmt.Sprintf("/api/v1/users/%d/traffic?from=yesterday", fixture.userID),
		bearer: token,
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an unparseable date returned %d, want 400", rec.Code)
	}
}

// Partitions have to exist before the traffic that belongs in them arrives.
func TestPartitionsAreCreatedAhead(t *testing.T) {
	e := newEnv(t)

	maintenance, err := worker.NewTraffic(e.pool, testLogger(t), worker.Config{PartitionsAhead: 4})
	if err != nil {
		t.Fatalf("worker.NewTraffic: %v", err)
	}

	// A year from now, where the migration's seeded partitions certainly do not reach.
	future := time.Now().UTC().AddDate(1, 0, 0)
	if err := maintenance.EnsurePartitions(context.Background(), future); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}

	for i := 0; i <= 4; i++ {
		month := time.Date(future.Year(), future.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, i, 0)
		name := "traffic_records_" + month.Format("2006_01")

		var exists bool
		err := e.pool.QueryRow(context.Background(),
			`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)`, name).Scan(&exists)
		if err != nil {
			t.Fatalf("check partition: %v", err)
		}
		if !exists {
			t.Errorf("partition %s was not created", name)
		}
	}

	// Running it again must not fail: two panels start at once, and a restart repeats the
	// pass.
	if err := maintenance.EnsurePartitions(context.Background(), future); err != nil {
		t.Errorf("EnsurePartitions is not repeatable: %v", err)
	}
}
