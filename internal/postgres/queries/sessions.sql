-- CreateSession inserts a refresh-token row. A NULL chain_id means "start a new
-- chain", which the database fills in; rotation passes the parent's chain so the
-- whole lineage can be revoked at once.
-- name: CreateSession :one
INSERT INTO admin_sessions (admin_id, token_hash, parent_id, chain_id, user_agent, ip, expires_at)
VALUES (
    sqlc.arg(admin_id),
    sqlc.arg(token_hash),
    sqlc.narg(parent_id),
    COALESCE(sqlc.narg(chain_id)::uuid, gen_random_uuid()),
    sqlc.arg(user_agent),
    sqlc.narg(ip),
    sqlc.arg(expires_at)
)
RETURNING *;

-- GetSessionByTokenHash deliberately returns revoked and expired rows too. A
-- lookup that filtered them out could not tell "this token never existed" from
-- "this token was already used", and that difference is the signal that a stolen
-- refresh token is being replayed.
-- name: GetSessionByTokenHash :one
SELECT * FROM admin_sessions WHERE token_hash = $1;

-- LockSessionByTokenHash is the rotation path. FOR UPDATE serialises two requests
-- that arrive with the same refresh token, so the outcome is decided rather than
-- raced: one rotates, the other finds the row already revoked and is treated as a
-- replay. Without the lock both could read an unrevoked row and only the write
-- would disagree.
-- name: LockSessionByTokenHash :one
SELECT * FROM admin_sessions WHERE token_hash = $1 FOR UPDATE;

-- name: RevokeSession :execrows
UPDATE admin_sessions
SET revoked_at = sqlc.arg(revoked_at)
WHERE id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: RevokeSessionChain :execrows
UPDATE admin_sessions
SET revoked_at = sqlc.arg(revoked_at)
WHERE chain_id = sqlc.arg(chain_id) AND revoked_at IS NULL;

-- name: RevokeAllAdminSessions :execrows
UPDATE admin_sessions
SET revoked_at = sqlc.arg(revoked_at)
WHERE admin_id = sqlc.arg(admin_id) AND revoked_at IS NULL;

-- name: CountActiveAdminSessions :one
SELECT count(*) FROM admin_sessions
WHERE admin_id = sqlc.arg(admin_id)
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(now);

-- DeleteExpiredSessions keeps revoked rows for a grace period rather than
-- deleting them immediately: replay detection needs the row to still be there to
-- recognise a reused token.
-- name: DeleteExpiredSessions :execrows
DELETE FROM admin_sessions
WHERE expires_at < sqlc.arg(cutoff);
