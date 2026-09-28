-- name: GetInboundGroup :one
SELECT * FROM inbound_groups WHERE id = $1;

-- name: GetInboundGroupByName :one
SELECT * FROM inbound_groups WHERE name = $1;

-- name: ListInboundGroups :many
SELECT * FROM inbound_groups ORDER BY name;

-- name: ListDefaultInboundGroups :many
SELECT * FROM inbound_groups WHERE is_default ORDER BY name;

-- name: CreateInboundGroup :one
INSERT INTO inbound_groups (name, description, is_default)
VALUES (sqlc.arg(name), sqlc.arg(description), sqlc.arg(is_default))
RETURNING *;

-- name: UpdateInboundGroup :one
UPDATE inbound_groups SET
    name        = COALESCE(sqlc.narg(name), name),
    description = COALESCE(sqlc.narg(description), description),
    is_default  = COALESCE(sqlc.narg(is_default), is_default)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: DeleteInboundGroup :execrows
DELETE FROM inbound_groups WHERE id = $1;

-- ---------------------------------------------------------------- membership

-- name: AddInboundToGroup :exec
INSERT INTO inbound_group_members (group_id, inbound_id)
VALUES (sqlc.arg(group_id), sqlc.arg(inbound_id))
ON CONFLICT DO NOTHING;

-- name: RemoveInboundFromGroup :execrows
DELETE FROM inbound_group_members
WHERE group_id = sqlc.arg(group_id) AND inbound_id = sqlc.arg(inbound_id);

-- ReplaceGroupInbounds is two statements the service runs inside one transaction, so
-- a group is never briefly empty from another reader's point of view.
-- name: ClearGroupInbounds :execrows
DELETE FROM inbound_group_members WHERE group_id = $1;

-- name: ListGroupInbounds :many
SELECT i.* FROM inbounds i
JOIN inbound_group_members m ON m.inbound_id = i.id
WHERE m.group_id = $1
ORDER BY i.tag;

-- name: CountGroupMembers :one
SELECT count(*) FROM inbound_group_members WHERE group_id = $1;

-- ------------------------------------------------------------ user to group

-- name: AddUserToGroup :exec
INSERT INTO user_groups (user_id, group_id)
VALUES (sqlc.arg(user_id), sqlc.arg(group_id))
ON CONFLICT DO NOTHING;

-- name: RemoveUserFromGroup :execrows
DELETE FROM user_groups
WHERE user_id = sqlc.arg(user_id) AND group_id = sqlc.arg(group_id);

-- name: ClearUserGroups :execrows
DELETE FROM user_groups WHERE user_id = $1;

-- name: ListUserGroups :many
SELECT g.* FROM inbound_groups g
JOIN user_groups ug ON ug.group_id = g.id
WHERE ug.user_id = $1
ORDER BY g.name;

-- name: ListGroupUserIDs :many
SELECT user_id FROM user_groups WHERE group_id = $1 ORDER BY user_id;

-- name: AddUsersToGroupBulk :execrows
INSERT INTO user_groups (user_id, group_id)
SELECT unnest(sqlc.arg(user_ids)::bigint[]), sqlc.arg(group_id)
ON CONFLICT DO NOTHING;
