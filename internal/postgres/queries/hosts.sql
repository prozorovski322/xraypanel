-- name: GetHost :one
SELECT * FROM hosts WHERE id = $1;

-- name: ListHosts :many
SELECT * FROM hosts ORDER BY inbound_id, sort_order, id;

-- name: ListHostsForInbound :many
SELECT * FROM hosts WHERE inbound_id = $1 ORDER BY sort_order, id;

-- name: CreateHost :one
INSERT INTO hosts (
    inbound_id, remark, address, port, sni, host_header, path,
    fingerprint, alpn, allow_insecure, sort_order, is_enabled
)
VALUES (
    sqlc.arg(inbound_id), sqlc.arg(remark), sqlc.arg(address), sqlc.narg(port),
    sqlc.narg(sni), sqlc.narg(host_header), sqlc.narg(path),
    sqlc.narg(fingerprint), sqlc.narg(alpn), sqlc.arg(allow_insecure),
    sqlc.arg(sort_order), sqlc.arg(is_enabled)
)
RETURNING *;

-- name: UpdateHost :one
UPDATE hosts SET
    remark         = COALESCE(sqlc.narg(remark), remark),
    address        = COALESCE(sqlc.narg(address), address),
    sni            = COALESCE(sqlc.narg(sni), sni),
    host_header    = COALESCE(sqlc.narg(host_header), host_header),
    path           = COALESCE(sqlc.narg(path), path),
    fingerprint    = COALESCE(sqlc.narg(fingerprint), fingerprint),
    alpn           = COALESCE(sqlc.narg(alpn), alpn),
    allow_insecure = COALESCE(sqlc.narg(allow_insecure), allow_insecure),
    sort_order     = COALESCE(sqlc.narg(sort_order), sort_order),
    is_enabled     = COALESCE(sqlc.narg(is_enabled), is_enabled)
WHERE id = sqlc.arg(id)
RETURNING *;

-- SetHostPort is separate because NULL means "inherit the inbound's listen port", and a
-- COALESCE update could not express going back to inheriting.
-- name: SetHostPort :one
UPDATE hosts SET port = sqlc.narg(port) WHERE id = sqlc.arg(id) RETURNING *;

-- name: DeleteHost :execrows
DELETE FROM hosts WHERE id = $1;

-- name: CountHostsForInbound :one
SELECT count(*) FROM hosts WHERE inbound_id = $1;
