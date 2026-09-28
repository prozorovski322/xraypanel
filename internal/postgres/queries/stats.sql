-- Summary figures for the dashboard. Each is one aggregate over one table, so the whole
-- dashboard costs a handful of index or sequential scans on tables the size of the user
-- base — cheap enough to poll every few seconds without a cache in front of it.

-- CountUsersByStatus is the headline: who is on, and who is off for which reason.
-- name: CountUsersByStatus :many
SELECT status::text AS status, count(*)::bigint AS users
FROM users
GROUP BY status;

-- CountNodesByStatus is the same for nodes. Disabled nodes are reported as such rather
-- than as disconnected: one is a decision, the other is a problem.
-- name: CountNodesByStatus :many
SELECT
    CASE WHEN NOT is_enabled THEN 'disabled' ELSE status::text END AS status,
    count(*)::bigint AS nodes
FROM nodes
GROUP BY 1;

-- SumTrafficSince is everything accounted from an instant on, across all users and nodes.
-- Read from the hourly ledger rather than the daily rollup, so that today's figure is
-- current rather than as of the last maintenance pass.
-- name: SumTrafficSince :one
SELECT
    COALESCE(sum(uplink), 0)::bigint   AS uplink,
    COALESCE(sum(downlink), 0)::bigint AS downlink
FROM traffic_records
WHERE hour >= sqlc.arg(since)::timestamptz;

-- CountOnlineUsersSince counts users who moved traffic recently. "Online" is inferred from
-- traffic rather than asked of the nodes, which would be one call per node per refresh.
-- name: CountOnlineUsersSince :one
SELECT count(*)::bigint FROM users WHERE online_at >= sqlc.arg(since)::timestamptz;
