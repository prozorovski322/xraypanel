-- name: GetNode :one
SELECT * FROM nodes WHERE id = $1;

-- name: GetNodeByName :one
SELECT * FROM nodes WHERE name = $1;

-- name: GetNodeByCertFingerprint :one
SELECT * FROM nodes WHERE cert_fingerprint = $1;

-- name: ListNodes :many
SELECT * FROM nodes ORDER BY name;

-- name: ListEnabledNodes :many
SELECT * FROM nodes WHERE is_enabled ORDER BY name;

-- name: CreateNode :one
INSERT INTO nodes (name, address, country_code, tag, config_patch, is_enabled)
VALUES (
    sqlc.arg(name), sqlc.arg(address), sqlc.narg(country_code),
    sqlc.arg(tag), sqlc.arg(config_patch), sqlc.arg(is_enabled)
)
RETURNING *;

-- name: UpdateNode :one
UPDATE nodes SET
    name         = COALESCE(sqlc.narg(name), name),
    address      = COALESCE(sqlc.narg(address), address),
    country_code = COALESCE(sqlc.narg(country_code), country_code),
    tag          = COALESCE(sqlc.narg(tag), tag),
    config_patch = COALESCE(sqlc.narg(config_patch), config_patch),
    is_enabled   = COALESCE(sqlc.narg(is_enabled), is_enabled)
WHERE id = sqlc.arg(id)
RETURNING *;

-- BumpNodeConfigVersion marks a node's desired configuration as changed.
--
-- It is called whenever anything that feeds a node's config changes: its own fields,
-- its inbound bindings, an inbound it carries, or a user on one of those inbounds. The
-- agent compares versions to decide whether to fetch, so forgetting to bump it means a
-- change that never reaches the node.
-- name: BumpNodeConfigVersion :one
UPDATE nodes SET config_version = config_version + 1
WHERE id = sqlc.arg(id)
RETURNING config_version;

-- name: BumpConfigVersionForInbound :execrows
UPDATE nodes SET config_version = config_version + 1
WHERE id IN (SELECT node_id FROM node_inbounds WHERE inbound_id = sqlc.arg(inbound_id));

-- BumpConfigVersionForUser touches every node that serves any inbound the user can
-- reach. Used when a user's credentials or access change.
-- name: BumpConfigVersionForUser :execrows
UPDATE nodes SET config_version = config_version + 1
WHERE id IN (
    SELECT ni.node_id
    FROM user_groups ug
    JOIN inbound_group_members m ON m.group_id = ug.group_id
    JOIN node_inbounds ni        ON ni.inbound_id = m.inbound_id
    WHERE ug.user_id = sqlc.arg(user_id)
);

-- name: BumpAllNodeConfigVersions :execrows
UPDATE nodes SET config_version = config_version + 1 WHERE is_enabled;

-- SetNodeCertificate records the identity a node was just issued.
--
-- The fingerprint is the identity, so writing a new one retires the previous
-- certificate on the spot: the panel resolves a connection by looking this value up,
-- and a certificate that is no longer anybody's fingerprint authenticates as nobody,
-- even though the CA still signed it. That is the revocation mechanism (ADR-052).
-- name: SetNodeCertificate :one
UPDATE nodes SET
    cert_fingerprint = sqlc.arg(cert_fingerprint),
    cert_serial      = sqlc.arg(cert_serial),
    cert_expires_at  = sqlc.arg(cert_expires_at)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: MarkNodeConnected :exec
UPDATE nodes SET
    status            = 'connected',
    agent_version     = sqlc.narg(agent_version),
    xray_version      = sqlc.narg(xray_version),
    applied_version   = sqlc.narg(applied_version),
    -- Cast so that the parameter is a plain time.Time in the generated code: a
    -- nullable one would let a caller silently erase the timestamp it is setting.
    last_connected_at = sqlc.arg(now)::timestamptz,
    last_heartbeat_at = sqlc.arg(now)::timestamptz,
    last_error        = ''
WHERE id = sqlc.arg(id);

-- MarkNodeDisconnected is called when a stream ends, for whatever reason.
--
-- It leaves a disabled node disabled: an administrator turning a node off is a
-- different state from the node dropping its connection, and the stream ending is the
-- expected consequence of the former rather than new information.
-- name: MarkNodeDisconnected :exec
UPDATE nodes SET
    -- Each branch is cast: a CASE over bare literals is typed as text, and assigning
    -- text to an enum column fails at execution time rather than at generation.
    status     = CASE WHEN status = 'disabled' THEN 'disabled'::node_status
                      WHEN sqlc.arg(had_error)::boolean THEN 'error'::node_status
                      ELSE 'disconnected'::node_status END,
    last_error = sqlc.arg(last_error)
WHERE id = sqlc.arg(id);

-- MarkAllNodesDisconnected runs once at startup.
--
-- Node status means "a stream is open to this panel process", and a freshly started
-- process holds none. Without this, a row left at 'connected' by a crash reports a
-- node as healthy until it happens to reconnect.
-- name: MarkAllNodesDisconnected :execrows
UPDATE nodes SET status = 'disconnected'
WHERE status IN ('connected', 'error');

-- TouchNodeHeartbeat records a heartbeat and repairs the node's status.
--
-- The repair matters: a heartbeat can only arrive on a stream that is open, so a node
-- that is heartbeating is connected by definition. Without this, a status left wrong by
-- a lost race — a replaced stream's teardown landing after its replacement's
-- registration, or a failed write when the stream opened — would persist until the node
-- next reconnected. With it, the panel is self-correcting within one interval.
-- name: TouchNodeHeartbeat :exec
UPDATE nodes SET
    last_heartbeat_at = sqlc.arg(now)::timestamptz,
    applied_version   = sqlc.narg(applied_version),
    xray_version      = sqlc.narg(xray_version),
    status            = CASE WHEN status = 'disabled' THEN 'disabled'::node_status
                             ELSE 'connected'::node_status END,
    -- An error recorded when an earlier stream died is stale once this one is talking.
    last_error        = CASE WHEN status = 'disabled' THEN last_error ELSE '' END
WHERE id = sqlc.arg(id);

-- SetNodeAppliedVersion records the outcome of a configuration push.
--
-- A failure passes NULL for the version, leaving the column at whatever the node is
-- really running. Advancing it on a failed apply would show a node as up to date while
-- it serves a stale configuration, which is the one thing this column exists to reveal.
-- name: SetNodeAppliedVersion :exec
UPDATE nodes SET
    applied_version = COALESCE(sqlc.narg(applied_version), applied_version),
    last_error      = sqlc.arg(last_error)
WHERE id = sqlc.arg(id);

-- name: SetNodeStatus :exec
UPDATE nodes SET
    status     = sqlc.arg(status),
    last_error = sqlc.arg(last_error)
WHERE id = sqlc.arg(id);

-- name: DeleteNode :execrows
DELETE FROM nodes WHERE id = $1;

-- name: CountNodeInbounds :one
SELECT count(*) FROM node_inbounds WHERE node_id = $1;
