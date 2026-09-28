-- Traffic accounting. Every statement here runs inside the transaction that applies one
-- batch from one node, so that a batch is either accounted in full or not at all: a
-- half-applied batch would be a user's counters moved without the hourly rows that
-- explain them, and no way to tell afterwards which half landed.

-- RecordTrafficBatch claims a batch id for a node.
--
-- The primary key does the deduplication. A node resends a batch whenever it did not hear
-- the panel confirm the previous attempt — after a reconnect, a panel restart, a lost
-- message — and applying one twice would bill a user twice for the same bytes.
-- No row returned means this batch has already been applied and must be skipped.
-- name: RecordTrafficBatch :one
INSERT INTO traffic_batches (node_id, batch_id, received_at)
VALUES (sqlc.arg(node_id), sqlc.arg(batch_id), sqlc.arg(received_at)::timestamptz)
ON CONFLICT (node_id, batch_id) DO NOTHING
RETURNING received_at;

-- FindUsersByXrayEmail resolves the stats keys a node reported to user ids.
--
-- A node knows users only by xray_email (ADR-007), and a key that no longer resolves is a
-- user deleted since the node last had its configuration. That traffic is dropped rather
-- than guessed at.
-- name: FindUsersByXrayEmail :many
SELECT id, xray_email
FROM users
WHERE xray_email = ANY(sqlc.arg(xray_emails)::text[]);

-- AddTrafficRecord accumulates one user's traffic in one hour on one node.
--
-- Accumulated rather than inserted, because a node reports the same hour in several
-- batches: one per poll interval that elapsed while the panel was unreachable.
-- name: AddTrafficRecord :exec
INSERT INTO traffic_records (hour, user_id, node_id, uplink, downlink)
VALUES (
    sqlc.arg(hour)::timestamptz,
    sqlc.arg(user_id),
    sqlc.arg(node_id),
    sqlc.arg(uplink),
    sqlc.arg(downlink)
)
ON CONFLICT (hour, user_id, node_id) DO UPDATE
SET uplink   = traffic_records.uplink + excluded.uplink,
    downlink = traffic_records.downlink + excluded.downlink;

-- AddUserTraffic moves a user's counters and marks them as having been online.
--
-- traffic_used is what a limit is measured against and is reset on a schedule;
-- traffic_lifetime never goes down, so the two cannot be derived from one another.
-- online_at only moves forward: batches can arrive out of order after an outage, and a
-- late batch must not make a user look less recently active than they are.
-- name: AddUserTraffic :exec
UPDATE users
SET traffic_used     = traffic_used + sqlc.arg(bytes),
    traffic_lifetime = traffic_lifetime + sqlc.arg(bytes),
    online_at        = GREATEST(online_at, sqlc.arg(online_at)::timestamptz),
    updated_at       = now()
WHERE id = sqlc.arg(id);

-- AddNodeTraffic moves a node's own total, which is what the nodes list shows.
-- name: AddNodeTraffic :exec
UPDATE nodes
SET traffic_used = traffic_used + sqlc.arg(bytes),
    updated_at   = now()
WHERE id = sqlc.arg(id);

-- ListUserTrafficByDay is the per-user chart the admin UI draws.
-- name: ListUserTrafficByDay :many
SELECT day, sum(uplink)::bigint AS uplink, sum(downlink)::bigint AS downlink
FROM traffic_daily
WHERE user_id = sqlc.arg(user_id)
  AND day >= sqlc.arg(from_day)
  AND day <= sqlc.arg(to_day)
GROUP BY day
ORDER BY day;

-- ListNodeTrafficByDay is the same for a node.
-- name: ListNodeTrafficByDay :many
SELECT day, sum(uplink)::bigint AS uplink, sum(downlink)::bigint AS downlink
FROM traffic_daily
WHERE node_id = sqlc.arg(node_id)
  AND day >= sqlc.arg(from_day)
  AND day <= sqlc.arg(to_day)
GROUP BY day
ORDER BY day;

-- SumUserTrafficSince is the total a user moved in a window, across nodes.
-- name: SumUserTrafficSince :one
SELECT
    COALESCE(sum(uplink), 0)::bigint   AS uplink,
    COALESCE(sum(downlink), 0)::bigint AS downlink
FROM traffic_records
WHERE user_id = sqlc.arg(user_id)
  AND hour >= sqlc.arg(since)::timestamptz;

-- ============================================================ rollup and retention

-- RollUpTrafficDay collapses one day of hourly rows into traffic_daily.
--
-- Recomputed from the hourly rows rather than accumulated, so that running it twice for
-- the same day is harmless — which matters because it runs on a schedule that can overlap
-- a restart, and because a day can still receive late batches from a node that was
-- offline.
-- name: RollUpTrafficDay :execrows
INSERT INTO traffic_daily (day, user_id, node_id, uplink, downlink)
SELECT
    (hour AT TIME ZONE 'UTC')::date AS day,
    user_id,
    node_id,
    sum(uplink)::bigint,
    sum(downlink)::bigint
FROM traffic_records
WHERE hour >= sqlc.arg(day_start)::timestamptz
  AND hour <  sqlc.arg(day_end)::timestamptz
GROUP BY 1, 2, 3
ON CONFLICT (day, user_id, node_id) DO UPDATE
SET uplink   = excluded.uplink,
    downlink = excluded.downlink;

-- DeleteTrafficRecordsBefore drops hourly rows past the retention window. The daily
-- rollup keeps the history that charts are drawn from.
-- name: DeleteTrafficRecordsBefore :execrows
DELETE FROM traffic_records WHERE hour < sqlc.arg(cutoff)::timestamptz;

-- DeleteTrafficBatchesBefore forgets batch ids old enough that no node could still be
-- holding one unacknowledged. Until then they are what makes a resend safe.
-- name: DeleteTrafficBatchesBefore :execrows
DELETE FROM traffic_batches WHERE received_at < sqlc.arg(cutoff)::timestamptz;

-- Partitions are read and created straight through pgx rather than from here: the
-- catalogue tables sqlc would have to understand are not part of this schema, and
-- CREATE TABLE ... PARTITION OF cannot take the month as a parameter anyway. See
-- internal/worker.
--
-- Removing one user's hourly rows lives in users.sql next to the deletion it belongs to,
-- as DeleteUserTraffic.
