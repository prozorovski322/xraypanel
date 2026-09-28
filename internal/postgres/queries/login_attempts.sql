-- The timestamp comes from the application clock, the same one the lockout window is
-- measured with. Defaulting it to now() would measure the window between two clocks.
-- name: RecordLoginAttempt :exec
INSERT INTO login_attempts (username, ip, success, at)
VALUES (sqlc.arg(username), sqlc.arg(ip), sqlc.arg(success), sqlc.arg(at));

-- Two independent counters, because they stop two different attacks.
--
-- The per-username counter stops a guessing run against one account from many
-- addresses. The per-IP counter stops one address spraying a common password
-- across many accounts, which the username counter never notices because each
-- account only sees a failure or two.
--
-- Both return the most recent failure as well as the count, so the lockout can be
-- measured from the last attempt. Counting alone would let an attacker keep
-- hammering at exactly the window boundary.

-- name: LoginFailureStatsByUsername :one
-- max(at) is NULL when there are no failures, and the driver cannot scan NULL
-- into a time.Time, so it is collapsed to the epoch. Callers must check failures
-- before reading last_failure_at.
SELECT count(*) AS failures,
       COALESCE(max(at), to_timestamp(0))::timestamptz AS last_failure_at
FROM login_attempts
WHERE username = sqlc.arg(username)
  AND NOT success
  AND at > sqlc.arg(since);

-- name: LoginFailureStatsByIP :one
-- max(at) is NULL when there are no failures, and the driver cannot scan NULL
-- into a time.Time, so it is collapsed to the epoch. Callers must check failures
-- before reading last_failure_at.
SELECT count(*) AS failures,
       COALESCE(max(at), to_timestamp(0))::timestamptz AS last_failure_at
FROM login_attempts
WHERE ip = sqlc.arg(ip)
  AND NOT success
  AND at > sqlc.arg(since);

-- ClearLoginFailures runs after a successful login so earlier typos do not count
-- towards a lockout the administrator would hit on their next visit.
-- name: ClearLoginFailures :execrows
DELETE FROM login_attempts
WHERE username = $1 AND NOT success;

-- name: DeleteOldLoginAttempts :execrows
DELETE FROM login_attempts WHERE at < sqlc.arg(cutoff);
