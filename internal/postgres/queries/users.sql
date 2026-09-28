-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1;

-- Lookup for the public subscription endpoint. It deliberately returns revoked and
-- expired users too: the handler decides what to disclose, and a query that filtered
-- them out could not tell "no such subscription" from "this one was revoked", which
-- is the difference between a 404 and a useful message.
-- name: GetUserBySubscriptionToken :one
SELECT * FROM users WHERE short_uuid = $1;

-- name: GetUserByStatsKey :one
SELECT * FROM users WHERE xray_email = $1;

-- name: CountUsers :one
SELECT count(*) FROM users;

-- name: CreateUser :one
INSERT INTO users (
    username, xray_email, vless_uuid, trojan_password, ss_password, short_uuid,
    status, traffic_limit, reset_strategy, expires_at, note, telegram_id
)
VALUES (
    sqlc.arg(username), sqlc.arg(xray_email), sqlc.arg(vless_uuid),
    sqlc.arg(trojan_password), sqlc.arg(ss_password), sqlc.arg(short_uuid),
    sqlc.arg(status), sqlc.arg(traffic_limit), sqlc.arg(reset_strategy),
    sqlc.narg(expires_at), sqlc.arg(note), sqlc.narg(telegram_id)
)
RETURNING *;

-- UpdateUser uses COALESCE so a caller can send only the fields it means to change.
-- That is acceptable here because every parameter is a scalar bound by the driver;
-- the pattern is only a problem when it lands in a WHERE clause, where it defeats
-- indexes.
-- name: UpdateUser :one
UPDATE users SET
    username       = COALESCE(sqlc.narg(username), username),
    status         = COALESCE(sqlc.narg(status), status),
    traffic_limit  = COALESCE(sqlc.narg(traffic_limit), traffic_limit),
    reset_strategy = COALESCE(sqlc.narg(reset_strategy), reset_strategy),
    note           = COALESCE(sqlc.narg(note), note),
    telegram_id    = COALESCE(sqlc.narg(telegram_id), telegram_id)
WHERE id = sqlc.arg(id)
RETURNING *;

-- SetUserExpiry is separate from UpdateUser because NULL is a meaningful value here:
-- it means "never expires". Folding it into a COALESCE update would make clearing an
-- expiry impossible to express.
-- name: SetUserExpiry :one
UPDATE users SET expires_at = sqlc.narg(expires_at)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: SetUserStatus :one
UPDATE users SET status = sqlc.arg(status) WHERE id = sqlc.arg(id) RETURNING *;

-- name: SetUserStatusBulk :execrows
UPDATE users SET status = sqlc.arg(status) WHERE id = ANY(sqlc.arg(ids)::bigint[]);

-- RotateUserCredentials issues new secrets. Used when a subscription leaks: the old
-- link stops working immediately.
-- name: RotateUserCredentials :one
UPDATE users SET
    vless_uuid      = sqlc.arg(vless_uuid),
    trojan_password = sqlc.arg(trojan_password),
    ss_password     = sqlc.arg(ss_password),
    short_uuid      = sqlc.arg(short_uuid),
    sub_revoked_at  = sqlc.arg(revoked_at)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: TouchSubscriptionFetch :exec
UPDATE users SET sub_fetched_at = sqlc.arg(fetched_at) WHERE id = sqlc.arg(id);

-- ResetUserTraffic zeroes the counter that enforcement reads while leaving the
-- lifetime total alone, and returns the account to active if it was limited. A reset
-- that left the user limited would be a reset in name only.
-- name: ResetUserTraffic :one
UPDATE users SET
    traffic_used  = 0,
    last_reset_at = sqlc.arg(reset_at),
    status        = CASE WHEN status = 'limited' THEN 'active'::user_status ELSE status END
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: DeleteUser :execrows
DELETE FROM users WHERE id = $1;

-- Traffic rows carry no foreign key to users on purpose (the table is partitioned),
-- so they are removed explicitly.
-- name: DeleteUserTraffic :execrows
DELETE FROM traffic_records WHERE user_id = $1;

-- name: ListUsersPage :many
SELECT * FROM users
WHERE id > sqlc.arg(after_id)
ORDER BY id
LIMIT sqlc.arg(row_limit);

-- Resolution for the subscription endpoint and for node configuration: every enabled
-- inbound a user can reach, through their groups, joined with how each host presents
-- it and which node serves it.
--
-- One query rather than several round trips, because the caller needs a consistent
-- picture: inbounds resolved from one read and hosts from another could disagree.
-- name: ListUserEndpoints :many
SELECT
    i.id            AS inbound_id,
    i.tag           AS inbound_tag,
    i.protocol,
    i.transport,
    i.security,
    i.listen_port,
    i.flow,
    i.ss_method,
    i.ss_server_key_enc,
    i.network_settings,
    i.tls_settings,
    rk.public_key   AS reality_public_key,
    rk.short_ids    AS reality_short_ids,
    rk.server_names AS reality_server_names,
    h.id            AS host_id,
    h.remark,
    h.address,
    h.port          AS host_port,
    h.sni,
    h.host_header,
    h.path,
    h.fingerprint,
    h.alpn,
    h.allow_insecure,
    h.sort_order,
    n.id            AS node_id,
    n.name          AS node_name,
    n.address       AS node_address,
    n.country_code
FROM users u
JOIN user_groups ug          ON ug.user_id = u.id
JOIN inbound_group_members m ON m.group_id = ug.group_id
JOIN inbounds i              ON i.id = m.inbound_id AND i.is_enabled
JOIN node_inbounds ni        ON ni.inbound_id = i.id
JOIN nodes n                 ON n.id = ni.node_id AND n.is_enabled
JOIN hosts h                 ON h.inbound_id = i.id AND h.is_enabled
LEFT JOIN reality_keys rk    ON rk.id = i.reality_key_id
WHERE u.id = sqlc.arg(user_id)
GROUP BY i.id, rk.id, h.id, n.id
ORDER BY h.sort_order, n.name, i.tag, h.id;
