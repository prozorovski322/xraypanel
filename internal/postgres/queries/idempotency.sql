-- Idempotency is claim-then-complete rather than check-then-write.
--
-- ClaimIdempotencyKey inserts the key in one statement and reports whether it was this
-- caller that inserted it. Two concurrent retries of the same request then have a
-- decided outcome: exactly one proceeds, the other finds the row and waits for or reads
-- the stored response. A separate SELECT followed by an INSERT would let both pass.

-- name: ClaimIdempotencyKey :one
INSERT INTO idempotency_keys (key, scope, request_hash, created_at)
VALUES (sqlc.arg(key), sqlc.arg(scope), sqlc.arg(request_hash), sqlc.arg(created_at))
ON CONFLICT (key) DO NOTHING
RETURNING key;

-- name: GetIdempotencyKey :one
SELECT * FROM idempotency_keys WHERE key = $1;

-- name: CompleteIdempotencyKey :exec
UPDATE idempotency_keys SET
    response     = sqlc.arg(response),
    status_code  = sqlc.arg(status_code),
    completed_at = sqlc.arg(completed_at)
WHERE key = sqlc.arg(key);

-- ReleaseIdempotencyKey removes a claim whose operation failed, so a retry is allowed
-- to try again rather than being told it already happened.
-- name: ReleaseIdempotencyKey :execrows
DELETE FROM idempotency_keys WHERE key = $1 AND completed_at IS NULL;

-- name: DeleteOldIdempotencyKeys :execrows
DELETE FROM idempotency_keys WHERE created_at < sqlc.arg(cutoff);
