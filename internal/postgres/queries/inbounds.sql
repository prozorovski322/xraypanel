-- name: GetInbound :one
SELECT * FROM inbounds WHERE id = $1;

-- name: GetInboundByTag :one
SELECT * FROM inbounds WHERE tag = $1;

-- name: ListInbounds :many
SELECT * FROM inbounds ORDER BY tag;

-- name: CreateInbound :one
INSERT INTO inbounds (
    tag, protocol, transport, security, listen_port, listen_address,
    ss_method, ss_server_key_enc, flow,
    network_settings, tls_settings, reality_key_id, sniffing, extra, is_enabled
)
VALUES (
    sqlc.arg(tag), sqlc.arg(protocol), sqlc.arg(transport), sqlc.arg(security),
    sqlc.arg(listen_port), sqlc.arg(listen_address),
    sqlc.narg(ss_method), sqlc.narg(ss_server_key_enc), sqlc.narg(flow),
    sqlc.arg(network_settings), sqlc.arg(tls_settings), sqlc.narg(reality_key_id),
    sqlc.arg(sniffing), sqlc.arg(extra), sqlc.arg(is_enabled)
)
RETURNING *;

-- name: UpdateInbound :one
UPDATE inbounds SET
    tag              = COALESCE(sqlc.narg(tag), tag),
    listen_port      = COALESCE(sqlc.narg(listen_port), listen_port),
    listen_address   = COALESCE(sqlc.narg(listen_address), listen_address),
    flow             = COALESCE(sqlc.narg(flow), flow),
    network_settings = COALESCE(sqlc.narg(network_settings), network_settings),
    tls_settings     = COALESCE(sqlc.narg(tls_settings), tls_settings),
    sniffing         = COALESCE(sqlc.narg(sniffing), sniffing),
    extra            = COALESCE(sqlc.narg(extra), extra),
    is_enabled       = COALESCE(sqlc.narg(is_enabled), is_enabled)
WHERE id = sqlc.arg(id)
RETURNING *;

-- ClearInboundFlow exists because NULL means "no flow" and a COALESCE update cannot
-- express clearing a value.
-- name: ClearInboundFlow :one
UPDATE inbounds SET flow = NULL WHERE id = $1 RETURNING *;

-- name: DeleteInbound :execrows
DELETE FROM inbounds WHERE id = $1;

-- ------------------------------------------------------------- node binding

-- name: AttachInboundToNode :exec
INSERT INTO node_inbounds (node_id, inbound_id)
VALUES (sqlc.arg(node_id), sqlc.arg(inbound_id))
ON CONFLICT DO NOTHING;

-- name: DetachInboundFromNode :execrows
DELETE FROM node_inbounds
WHERE node_id = sqlc.arg(node_id) AND inbound_id = sqlc.arg(inbound_id);

-- name: ListNodeInbounds :many
SELECT i.* FROM inbounds i
JOIN node_inbounds ni ON ni.inbound_id = i.id
WHERE ni.node_id = $1
ORDER BY i.tag;

-- name: ListInboundNodes :many
SELECT n.* FROM nodes n
JOIN node_inbounds ni ON ni.node_id = n.id
WHERE ni.inbound_id = $1
ORDER BY n.name;

-- PortConflictOnNode reports whether attaching an inbound would collide with one
-- already on that node.
--
-- Uniqueness of listen_port within a node is not expressible as a constraint without
-- denormalising the port into node_inbounds, so it is checked here and again in the
-- config generator. Two inbounds on one port mean Xray does not start at all, and from
-- the panel that looks like "the node broke" with no reason attached. See ADR-011.
-- name: PortConflictOnNode :many
SELECT i.id, i.tag, i.listen_port
FROM inbounds i
JOIN node_inbounds ni ON ni.inbound_id = i.id
WHERE ni.node_id = sqlc.arg(node_id)
  AND i.listen_port = sqlc.arg(listen_port)
  AND i.id <> sqlc.arg(excluding_inbound_id);

-- ConflictingPortsForInbound finds every node where changing this inbound's port would
-- collide. Used before an update, since a port change can break nodes the caller is
-- not looking at.
-- name: ConflictingPortsForInbound :many
SELECT n.id AS node_id, n.name AS node_name, other.tag AS other_tag
FROM node_inbounds mine
JOIN nodes n            ON n.id = mine.node_id
JOIN node_inbounds theirs ON theirs.node_id = mine.node_id
JOIN inbounds other     ON other.id = theirs.inbound_id
WHERE mine.inbound_id = sqlc.arg(inbound_id)
  AND other.id <> sqlc.arg(inbound_id)
  AND other.listen_port = sqlc.arg(listen_port)
ORDER BY n.name;

-- --------------------------------------------------------------- reality keys

-- name: GetRealityKey :one
SELECT * FROM reality_keys WHERE id = $1;

-- name: ListRealityKeys :many
SELECT * FROM reality_keys ORDER BY name;

-- name: CreateRealityKey :one
INSERT INTO reality_keys (name, private_enc, public_key, short_ids, dest, server_names)
VALUES (
    sqlc.arg(name), sqlc.arg(private_enc), sqlc.arg(public_key),
    sqlc.arg(short_ids), sqlc.arg(dest), sqlc.arg(server_names)
)
RETURNING *;

-- name: DeleteRealityKey :execrows
DELETE FROM reality_keys WHERE id = $1;

-- name: CountInboundsUsingRealityKey :one
SELECT count(*) FROM inbounds WHERE reality_key_id = $1;

-- ListInboundClients returns the users allowed on an inbound.
--
-- Only active users: a limited, expired or disabled account must not be written into a
-- node's configuration at all, since a user present in the config can connect regardless
-- of what the panel thinks. DISTINCT because a user reaching the same inbound through
-- two groups is still one client, and a duplicate stats key would merge two users'
-- traffic into one counter.
-- name: ListInboundClients :many
SELECT DISTINCT u.id, u.xray_email, u.vless_uuid, u.trojan_password, u.ss_password, u.username
FROM users u
JOIN user_groups ug          ON ug.user_id = u.id
JOIN inbound_group_members m ON m.group_id = ug.group_id
WHERE m.inbound_id = sqlc.arg(inbound_id)
  AND u.status = 'active'
ORDER BY u.id;
