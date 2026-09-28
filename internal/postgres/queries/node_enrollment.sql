-- name: CreateNodeEnrollmentToken :one
INSERT INTO node_enrollment_tokens (token_hash, node_id, created_by, expires_at)
VALUES (
    sqlc.arg(token_hash), sqlc.arg(node_id),
    sqlc.narg(created_by), sqlc.arg(expires_at)
)
RETURNING *;

-- ClaimNodeEnrollmentToken consumes a token in one statement.
--
-- The whole point is that the check and the consumption cannot be separated: two
-- agents replaying the same token concurrently must not both be issued a certificate,
-- and a SELECT followed by an UPDATE leaves exactly that window open. A zero-row
-- result means the token was unknown, already used, or expired; the caller classifies
-- it for the log with a separate read, and tells the applicant nothing either way.
-- name: ClaimNodeEnrollmentToken :one
UPDATE node_enrollment_tokens SET
    -- The cast is what makes the parameter non-nullable in the generated code; without
    -- it sqlc copies the nullability of the column being assigned.
    used_at      = sqlc.arg(now)::timestamptz,
    used_by_node = node_id
WHERE token_hash = sqlc.arg(token_hash)
  AND used_at IS NULL
  AND node_id IS NOT NULL
  AND expires_at > sqlc.arg(now)::timestamptz
RETURNING *;

-- name: GetNodeEnrollmentTokenByHash :one
SELECT * FROM node_enrollment_tokens WHERE token_hash = $1;

-- name: ListNodeEnrollmentTokens :many
SELECT * FROM node_enrollment_tokens
WHERE node_id = sqlc.arg(node_id)
ORDER BY created_at DESC;

-- DeleteUnusedNodeEnrollmentToken revokes a token that has not been redeemed.
--
-- A used token is deliberately not deletable: its used_at and used_by_node are the
-- record of which certificate came from where. The node id is part of the condition so
-- that a token cannot be revoked through the wrong node's URL.
-- name: DeleteUnusedNodeEnrollmentToken :execrows
DELETE FROM node_enrollment_tokens
WHERE id = sqlc.arg(id) AND node_id = sqlc.arg(node_id) AND used_at IS NULL;
