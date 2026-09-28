// Package listbuilder builds the filtered list queries sqlc cannot express well.
//
// sqlc is used for everything else. The problem it has with these is the pattern a
// generated query forces: `WHERE (col = $1 OR $1 IS NULL)` repeated per filter, which
// PostgreSQL cannot use an index for because the predicate is not known until runtime. On
// a list of users filtered by status and searched by name that turns an index scan into a
// sequential one.
//
// So these are assembled here. Every column that can appear in a WHERE or ORDER BY clause
// comes from a fixed allowlist in this file; user input only ever arrives as a bound
// parameter. String concatenation of a value into SQL never happens.
package listbuilder

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Querier is the subset of a pool or transaction this package needs.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Pagination limits.
const (
	DefaultLimit = 50
	MaxLimit     = 500
)

// userSortColumns is the allowlist for ORDER BY.
//
// A map rather than a check for dangerous characters: an allowlist cannot be defeated by
// an input nobody thought of, and the set of things worth sorting by is small and known.
var userSortColumns = map[string]string{
	"id":            "u.id",
	"username":      "u.username",
	"status":        "u.status",
	"traffic_used":  "u.traffic_used",
	"traffic_limit": "u.traffic_limit",
	"expires_at":    "u.expires_at",
	"created_at":    "u.created_at",
	"online_at":     "u.online_at",
}

// SortColumns returns the sortable field names, for the API to document and validate
// against.
func SortColumns() []string {
	out := make([]string, 0, len(userSortColumns))
	for name := range userSortColumns {
		out = append(out, name)
	}
	return out
}

// UserFilter describes which users to return.
type UserFilter struct {
	// Search matches the username or the note, case-insensitively.
	Search string

	// Statuses restricts to these statuses. Empty means all.
	Statuses []string

	// GroupID restricts to members of one group.
	GroupID *int64

	// ExpiringBefore restricts to subscriptions lapsing before an instant. Used for the
	// "expiring soon" view.
	ExpiringBefore *time.Time

	// OverQuota restricts to users whose usage has reached their limit. Users with no
	// limit are never over quota.
	OverQuota bool

	// HasTelegram restricts to users with or without a Telegram id.
	HasTelegram *bool

	Sort string
	Desc bool

	Limit  int
	Offset int
}

// UserRow is one row of the listing.
//
// It carries only what a list view shows. Credentials are deliberately absent: a list
// endpoint that returns every user's secrets turns one careless log line into a breach.
type UserRow struct {
	ID              int64
	Username        string
	Status          string
	TrafficLimit    int64
	TrafficUsed     int64
	TrafficLifetime int64
	ResetStrategy   string
	ExpiresAt       *time.Time
	Note            string
	TelegramID      *int64
	OnlineAt        *time.Time
	SubFetchedAt    *time.Time
	CreatedAt       time.Time
	GroupCount      int64
}

// UserPage is a page of results plus the total that matched.
type UserPage struct {
	Rows  []UserRow
	Total int64
}

// ListUsers runs the filtered listing.
//
// Offset pagination rather than keyset. At this panel's scale, a few thousand users, a
// deep offset costs nothing measurable, while keyset pagination over a caller-chosen sort
// column needs a composite cursor per column and careful handling of nullable ones. The
// unfiltered export path uses keyset on id instead, where it is both simple and correct.
func ListUsers(ctx context.Context, db Querier, filter UserFilter) (*UserPage, error) {
	where, args := buildUserWhere(filter)

	total, err := countUsers(ctx, db, where, args)
	if err != nil {
		return nil, err
	}

	orderBy, err := buildUserOrder(filter)
	if err != nil {
		return nil, err
	}

	limit := filter.Limit
	switch {
	case limit <= 0:
		limit = DefaultLimit
	case limit > MaxLimit:
		// Capped rather than rejected: a client asking for too much gets a full page and
		// a working request, instead of an error it has to learn to handle.
		limit = MaxLimit
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query := `
SELECT
    u.id, u.username, u.status, u.traffic_limit, u.traffic_used, u.traffic_lifetime,
    u.reset_strategy, u.expires_at, u.note, u.telegram_id, u.online_at,
    u.sub_fetched_at, u.created_at,
    (SELECT count(*) FROM user_groups ug2 WHERE ug2.user_id = u.id) AS group_count
FROM users u
` + where + `
ORDER BY ` + orderBy + `
LIMIT $` + strconv.Itoa(len(args)+1) + ` OFFSET $` + strconv.Itoa(len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listbuilder: list users: %w", err)
	}
	defer rows.Close()

	page := &UserPage{Total: total, Rows: make([]UserRow, 0, limit)}
	for rows.Next() {
		var row UserRow
		var status, resetStrategy string
		var expiresAt, onlineAt, subFetchedAt pgtype.Timestamptz

		if err := rows.Scan(
			&row.ID, &row.Username, &status, &row.TrafficLimit, &row.TrafficUsed,
			&row.TrafficLifetime, &resetStrategy, &expiresAt, &row.Note, &row.TelegramID,
			&onlineAt, &subFetchedAt, &row.CreatedAt, &row.GroupCount,
		); err != nil {
			return nil, fmt.Errorf("listbuilder: scan user: %w", err)
		}

		row.Status = status
		row.ResetStrategy = resetStrategy
		row.ExpiresAt = timestamptzPtr(expiresAt)
		row.OnlineAt = timestamptzPtr(onlineAt)
		row.SubFetchedAt = timestamptzPtr(subFetchedAt)

		page.Rows = append(page.Rows, row)
	}
	// rows.Err reports a failure that happened part way through, which would otherwise
	// look like a short page: the caller would see fewer users and no error at all.
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listbuilder: read users: %w", err)
	}

	return page, nil
}

// buildUserWhere assembles the predicate and its arguments.
func buildUserWhere(filter UserFilter) (string, []any) {
	var (
		conditions []string
		args       []any
	)

	placeholder := func(value any) string {
		args = append(args, value)
		return "$" + strconv.Itoa(len(args))
	}

	if search := strings.TrimSpace(filter.Search); search != "" {
		// ILIKE with a leading wildcard cannot use a btree index. At this scale the
		// sequential scan is cheaper than maintaining a trigram index, and the search box
		// is used by one administrator at a time.
		pattern := "%" + escapeLikePattern(search) + "%"
		p := placeholder(pattern)
		conditions = append(conditions, "(u.username ILIKE "+p+" OR u.note ILIKE "+p+")")
	}

	if len(filter.Statuses) > 0 {
		// Cast the bound array to the enum rather than interpolating the values.
		conditions = append(conditions, "u.status = ANY("+placeholder(filter.Statuses)+"::user_status[])")
	}

	if filter.GroupID != nil {
		conditions = append(conditions,
			"EXISTS (SELECT 1 FROM user_groups ug WHERE ug.user_id = u.id AND ug.group_id = "+
				placeholder(*filter.GroupID)+")")
	}

	if filter.ExpiringBefore != nil {
		conditions = append(conditions,
			"u.expires_at IS NOT NULL AND u.expires_at < "+placeholder(*filter.ExpiringBefore))
	}

	if filter.OverQuota {
		// A user with no limit is never over quota, which is why the limit check comes
		// first rather than relying on the comparison alone.
		conditions = append(conditions, "u.traffic_limit > 0 AND u.traffic_used >= u.traffic_limit")
	}

	if filter.HasTelegram != nil {
		if *filter.HasTelegram {
			conditions = append(conditions, "u.telegram_id IS NOT NULL")
		} else {
			conditions = append(conditions, "u.telegram_id IS NULL")
		}
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// buildUserOrder resolves the sort column through the allowlist.
func buildUserOrder(filter UserFilter) (string, error) {
	sortKey := strings.ToLower(strings.TrimSpace(filter.Sort))
	if sortKey == "" {
		sortKey = "id"
	}

	column, ok := userSortColumns[sortKey]
	if !ok {
		return "", fmt.Errorf("listbuilder: cannot sort by %q", filter.Sort)
	}

	direction := "ASC"
	if filter.Desc {
		direction = "DESC"
	}

	// NULLS LAST in both directions, so that users with no expiry never crowd the top of
	// an "expiring soon" listing, which is the opposite of what that view is for.
	const nulls = " NULLS LAST"

	// id is appended as a tiebreaker: without it, two users with the same sort value can
	// swap places between pages and one gets skipped while another appears twice.
	if column == "u.id" {
		return column + " " + direction, nil
	}
	return column + " " + direction + nulls + ", u.id " + direction, nil
}

func countUsers(ctx context.Context, db Querier, where string, args []any) (int64, error) {
	var total int64
	query := "SELECT count(*) FROM users u " + where
	if err := db.QueryRow(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("listbuilder: count users: %w", err)
	}
	return total, nil
}

// escapeLikePattern neutralises the wildcards inside a search term.
//
// Without this, searching for "100%" matches everything starting with "100", and an
// underscore in a username matches any character. Neither is wrong enough to notice, which
// is what makes it worth fixing.
func escapeLikePattern(s string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(s)
}

func timestamptzPtr(value pgtype.Timestamptz) *time.Time {
	if !value.Valid {
		return nil
	}
	t := value.Time
	return &t
}
