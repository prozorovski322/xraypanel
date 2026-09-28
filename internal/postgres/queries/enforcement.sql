-- Enforcement and scheduled resets. These queries drive the workers that switch users off
-- when they run out of traffic or time, and back on when a new period starts.
--
-- All of them take the current time as a parameter rather than calling now(). The panel has
-- one clock — the service's, which tests can move — and a query that reads the database's
-- clock instead would be the one place a test could not control, which for billing
-- boundaries is exactly the place that needs testing.

-- ListUsersOverLimit finds active users who have used their allowance.
--
-- Only active ones: a user already limited must not be limited again, or every pass would
-- re-announce the same event to every webhook endpoint.
-- name: ListUsersOverLimit :many
SELECT id, username, xray_email, traffic_used, traffic_limit
FROM users
WHERE status = 'active'
  AND traffic_limit > 0
  AND traffic_used >= traffic_limit
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- ListUsersPastExpiry finds active users whose subscription has ended.
-- name: ListUsersPastExpiry :many
SELECT id, username, xray_email, expires_at
FROM users
WHERE status = 'active'
  AND expires_at IS NOT NULL
  AND expires_at <= sqlc.arg(now)::timestamptz
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- ListUsersDueForReset finds users whose traffic counter belongs to a period that has ended.
--
-- One query with three cutoffs rather than three queries, because the cutoffs are computed
-- in the billing timezone by the panel and the database should not have to know about that.
-- A user who has never been reset is due if they were created before the current period
-- started; otherwise the account would have to wait a whole period for its first reset.
--
-- Disabled users are included on purpose: an operator switching an account back on should
-- not find a counter from three months ago. Expired ones are included for the same reason;
-- resetting traffic does not revive them, because the reset only clears the counter and
-- lifts a traffic limit.
-- name: ListUsersDueForReset :many
SELECT id, username, xray_email, status, reset_strategy, traffic_used, last_reset_at
FROM users
WHERE reset_strategy <> 'never'
  AND COALESCE(last_reset_at, created_at) < CASE reset_strategy
        WHEN 'daily'   THEN sqlc.arg(daily_cutoff)::timestamptz
        WHEN 'weekly'  THEN sqlc.arg(weekly_cutoff)::timestamptz
        WHEN 'monthly' THEN sqlc.arg(monthly_cutoff)::timestamptz
      END
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- LimitUser switches a user off for having used their allowance.
--
-- The status is re-checked in the statement, so two panel processes running the same pass
-- cannot both report the transition: only the one whose update matched a row sees it.
-- name: LimitUser :one
UPDATE users
SET status = 'limited', updated_at = now()
WHERE id = sqlc.arg(id) AND status = 'active'
RETURNING id, username, xray_email, traffic_used, traffic_limit, expires_at;

-- ExpireUser switches a user off for having run out of time.
-- name: ExpireUser :one
UPDATE users
SET status = 'expired', updated_at = now()
WHERE id = sqlc.arg(id) AND status = 'active'
RETURNING id, username, xray_email, traffic_used, traffic_limit, expires_at;

-- ResetUserTrafficForPeriod clears the counter and starts a new period.
--
-- A user who was limited comes back; one that an operator disabled stays off, and one whose
-- subscription expired stays expired. The guard on last_reset_at makes a second pass in the
-- same period a no-op, which matters because the workers are safe to run twice.
-- name: ResetUserTrafficForPeriod :one
UPDATE users
SET traffic_used  = 0,
    last_reset_at = sqlc.arg(now)::timestamptz,
    status        = CASE WHEN status = 'limited' THEN 'active'::user_status ELSE status END,
    updated_at    = now()
WHERE id = sqlc.arg(id)
  AND (last_reset_at IS NULL OR last_reset_at < sqlc.arg(cutoff)::timestamptz)
RETURNING id, username, xray_email, status, traffic_used;
