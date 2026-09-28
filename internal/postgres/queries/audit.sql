-- name: InsertAuditEntry :exec
INSERT INTO audit_log (at, actor_type, actor_id, actor_label, action, entity_type, entity_id, ip, diff)
VALUES (
    sqlc.arg(at),
    sqlc.arg(actor_type),
    sqlc.narg(actor_id),
    sqlc.arg(actor_label),
    sqlc.arg(action),
    sqlc.arg(entity_type),
    sqlc.narg(entity_id),
    sqlc.narg(ip),
    sqlc.narg(diff)
);

-- name: ListAuditEntries :many
SELECT * FROM audit_log
ORDER BY at DESC
LIMIT sqlc.arg(row_limit);

-- SearchAuditEntries is the audit screen: newest first, narrowed by what an operator asks
-- about, paged by id.
--
-- Keyset rather than offset paging, because the log only grows and is read from the top:
-- an offset page drifts by however many entries were written since the previous page, and
-- the operator sees the same entry twice or misses one — in the one screen whose job is
-- to be exact. The id is the key because it is strictly increasing; the timestamp is not
-- unique.
--
-- Each filter is optional and written as "narg IS NULL OR column = narg". That shape does
-- defeat an index in general, which is why the user list is built by hand instead (see
-- internal/postgres/listbuilder); here it is fine, because the primary key drives the scan
-- and the filters only thin it out.
-- name: SearchAuditEntries :many
SELECT * FROM audit_log
WHERE (sqlc.narg(before_id)::bigint IS NULL OR id < sqlc.narg(before_id)::bigint)
  AND (sqlc.narg(entity_type)::text IS NULL OR entity_type = sqlc.narg(entity_type)::text)
  AND (sqlc.narg(entity_id)::text IS NULL OR entity_id = sqlc.narg(entity_id)::text)
  AND (sqlc.narg(action)::text IS NULL OR action = sqlc.narg(action)::text)
  AND (sqlc.narg(actor_type)::text IS NULL OR actor_type = sqlc.narg(actor_type)::text)
ORDER BY id DESC
LIMIT sqlc.arg(row_limit);
