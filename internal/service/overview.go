package service

import (
	"context"
	"encoding/json"
	"time"

	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// AuditQuery narrows the audit log. Nil means no filter.
type AuditQuery struct {
	BeforeID   *int64
	EntityType *string
	EntityID   *string
	Action     *string
	ActorType  *string
	Limit      int
}

// AuditEntry is one row of the log as the API shows it.
type AuditEntry struct {
	ID         int64
	At         time.Time
	ActorType  string
	ActorID    *int64
	ActorLabel string
	Action     string
	EntityType string
	EntityID   *string
	IP         string
	Diff       json.RawMessage
}

// maxAuditPage bounds one page. The screen shows a few dozen; an export belongs somewhere
// else than a paged endpoint.
const maxAuditPage = 200

// SearchAudit reads the audit log newest first.
//
// Returns the entries and the id to pass as BeforeID for the next page, or nil when this
// was the last one.
func (s *Service) SearchAudit(ctx context.Context, q AuditQuery) ([]AuditEntry, *int64, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > maxAuditPage {
		limit = maxAuditPage
	}

	// One more than asked for, so the caller learns whether there is a next page without a
	// second query and without a total count — which on a log that only grows would be an
	// ever more expensive number nobody needs.
	rows, err := s.q.SearchAuditEntries(ctx, dbgen.SearchAuditEntriesParams{
		BeforeID:   q.BeforeID,
		EntityType: q.EntityType,
		EntityID:   q.EntityID,
		Action:     q.Action,
		ActorType:  q.ActorType,
		RowLimit:   int32(limit + 1),
	})
	if err != nil {
		return nil, nil, translate(err, "audit log")
	}

	var next *int64
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1].ID
		next = &last
	}

	entries := make([]AuditEntry, 0, len(rows))
	for _, row := range rows {
		entry := AuditEntry{
			ID:         row.ID,
			At:         row.At.UTC(),
			ActorType:  row.ActorType,
			ActorID:    row.ActorID,
			ActorLabel: row.ActorLabel,
			Action:     row.Action,
			EntityType: row.EntityType,
			EntityID:   row.EntityID,
			Diff:       row.Diff,
		}
		if row.Ip != nil {
			entry.IP = row.Ip.String()
		}
		entries = append(entries, entry)
	}
	return entries, next, nil
}

// Overview is the dashboard's headline figures.
type Overview struct {
	UsersByStatus map[string]int64
	NodesByStatus map[string]int64

	// OnlineUsers moved traffic within the last OnlineWindow.
	OnlineUsers  int64
	OnlineWindow time.Duration

	TrafficToday     TrafficTotals
	TrafficThisMonth TrafficTotals

	// Since values are the instants the totals are counted from, in UTC. They are returned
	// because "today" depends on the billing timezone, and a dashboard that did not say
	// where its day starts would be read in the viewer's own.
	TodaySince time.Time
	MonthSince time.Time
}

// TrafficTotals is traffic in both directions.
type TrafficTotals struct {
	Uplink   int64
	Downlink int64
}

// onlineWindow is what "online" means on the dashboard. A few poll intervals: shorter and a
// user whose connection is idle for a minute flickers off; longer and the number stops
// meaning "right now".
const onlineWindow = 5 * time.Minute

// Overview gathers the dashboard figures.
func (s *Service) Overview(ctx context.Context) (*Overview, error) {
	now := s.now()

	users, err := s.q.CountUsersByStatus(ctx)
	if err != nil {
		return nil, translate(err, "user counts")
	}
	nodes, err := s.q.CountNodesByStatus(ctx)
	if err != nil {
		return nil, translate(err, "node counts")
	}
	online, err := s.q.CountOnlineUsersSince(ctx, now.Add(-onlineWindow))
	if err != nil {
		return nil, translate(err, "online users")
	}

	// The same boundaries enforcement resets on, so the dashboard's "this month" and a
	// monthly user's allowance describe the same stretch of time.
	todaySince := PeriodStart(dbgen.ResetStrategyDaily, now, s.cfg.BillingLocation)
	monthSince := PeriodStart(dbgen.ResetStrategyMonthly, now, s.cfg.BillingLocation)

	today, err := s.q.SumTrafficSince(ctx, todaySince)
	if err != nil {
		return nil, translate(err, "traffic today")
	}
	month, err := s.q.SumTrafficSince(ctx, monthSince)
	if err != nil {
		return nil, translate(err, "traffic this month")
	}

	overview := &Overview{
		UsersByStatus:    map[string]int64{"active": 0, "limited": 0, "expired": 0, "disabled": 0},
		NodesByStatus:    map[string]int64{"connected": 0, "disconnected": 0, "error": 0, "disabled": 0},
		OnlineUsers:      online,
		OnlineWindow:     onlineWindow,
		TrafficToday:     TrafficTotals{Uplink: today.Uplink, Downlink: today.Downlink},
		TrafficThisMonth: TrafficTotals{Uplink: month.Uplink, Downlink: month.Downlink},
		TodaySince:       todaySince,
		MonthSince:       monthSince,
	}
	for _, row := range users {
		overview.UsersByStatus[row.Status] = row.Users
	}
	for _, row := range nodes {
		overview.NodesByStatus[row.Status] = row.Nodes
	}
	return overview, nil
}
