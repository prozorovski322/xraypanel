-- name: GetAdminByUsername :one
SELECT * FROM admins WHERE username = $1;

-- name: GetAdminByID :one
SELECT * FROM admins WHERE id = $1;

-- name: CountAdmins :one
SELECT count(*) FROM admins;

-- name: ListAdmins :many
SELECT * FROM admins ORDER BY username;

-- Timestamps are supplied by the application rather than taken from now().
--
-- tokens_valid_from is compared against an access token's iat claim, which the panel
-- stamps from its own clock. Filling one side from the database clock and the other
-- from the application clock compares two independent clocks, and any skew between
-- them silently shifts token validity.
-- name: CreateAdmin :one
INSERT INTO admins (username, password_hash, role, tokens_valid_from)
VALUES (sqlc.arg(username), sqlc.arg(password_hash), sqlc.arg(role), sqlc.arg(tokens_valid_from))
RETURNING *;

-- SetAdminPassword also moves tokens_valid_from forward, so access tokens issued
-- before the change stop working immediately instead of lingering for their
-- remaining lifetime. Revoking refresh tokens alone would not do that.
-- name: SetAdminPassword :exec
UPDATE admins
SET password_hash = sqlc.arg(password_hash),
    tokens_valid_from = sqlc.arg(tokens_valid_from)
WHERE id = sqlc.arg(id);

-- SetAdminPasswordHashOnly upgrades a stored hash to stronger parameters without
-- touching tokens_valid_from. It runs during an ordinary login, and moving the
-- validity mark there would sign the administrator out of their other sessions as
-- a side effect of logging in.
-- name: SetAdminPasswordHashOnly :exec
UPDATE admins SET password_hash = $2 WHERE id = $1;

-- name: SetAdminActive :exec
UPDATE admins SET is_active = $2 WHERE id = $1;

-- name: TouchAdminLogin :exec
UPDATE admins SET last_login_at = sqlc.arg(last_login_at) WHERE id = sqlc.arg(id);

-- name: InvalidateAdminTokens :exec
UPDATE admins SET tokens_valid_from = sqlc.arg(tokens_valid_from) WHERE id = sqlc.arg(id);

-- StartTOTPEnrollment stores the secret without enabling 2FA. The admin must
-- prove they can generate a code before it is switched on; enabling first would
-- lock out anyone whose authenticator failed to scan the QR code.
-- name: StartTOTPEnrollment :exec
UPDATE admins
SET totp_secret = $2,
    totp_enabled = false,
    totp_last_step = NULL
WHERE id = $1;

-- name: ConfirmTOTPEnrollment :exec
UPDATE admins
SET totp_enabled = true,
    totp_last_step = sqlc.arg(totp_last_step),
    tokens_valid_from = sqlc.arg(tokens_valid_from)
WHERE id = sqlc.arg(id);

-- name: DisableTOTP :exec
UPDATE admins
SET totp_enabled = false,
    totp_secret = NULL,
    totp_last_step = NULL,
    tokens_valid_from = sqlc.arg(tokens_valid_from)
WHERE id = sqlc.arg(id);

-- ConsumeTOTPStep is the replay guard, and it has to be a single statement: a
-- read-then-write in the service would let two requests carrying the same code
-- both pass. It reports zero rows affected when the step was already used.
-- name: ConsumeTOTPStep :execrows
UPDATE admins
SET totp_last_step = sqlc.arg(step)
WHERE id = sqlc.arg(id)
  AND (totp_last_step IS NULL OR totp_last_step < sqlc.arg(step));
