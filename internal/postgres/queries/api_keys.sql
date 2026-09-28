-- name: CreateAPIKey :one
INSERT INTO api_keys (name, key_prefix, key_hash, scopes, created_by, expires_at)
VALUES (
    sqlc.arg(name),
    sqlc.arg(key_prefix),
    sqlc.arg(key_hash),
    sqlc.arg(scopes),
    sqlc.narg(created_by),
    sqlc.narg(expires_at)
)
RETURNING *;

-- Lookup is by hash, not by prefix: the prefix is only a display label, so
-- matching on it would authenticate a key by its public part.
-- name: GetAPIKeyByHash :one
SELECT * FROM api_keys WHERE key_hash = $1;

-- name: ListAPIKeys :many
SELECT * FROM api_keys ORDER BY created_at DESC;

-- name: TouchAPIKeyUsage :exec
UPDATE api_keys SET last_used_at = sqlc.arg(last_used_at) WHERE id = sqlc.arg(id);

-- name: RevokeAPIKey :execrows
UPDATE api_keys
SET revoked_at = sqlc.arg(revoked_at)
WHERE id = sqlc.arg(id) AND revoked_at IS NULL;
