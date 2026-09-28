-- Settings are the only queries in M1. They exist so the sqlc pipeline is wired
-- and verified from the first milestone rather than introduced later along with a
-- hundred queries at once.

-- name: GetSetting :one
SELECT key, value, updated_at
FROM settings
WHERE key = $1;

-- name: ListSettings :many
SELECT key, value, updated_at
FROM settings
ORDER BY key;

-- name: UpsertSetting :one
INSERT INTO settings (key, value)
VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE
    SET value = excluded.value
RETURNING key, value, updated_at;

-- name: DeleteSetting :execrows
DELETE FROM settings
WHERE key = $1;
