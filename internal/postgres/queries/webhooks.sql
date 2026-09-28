-- Outgoing webhooks. The panel tells another system that something happened to a user —
-- a billing system, a bot, a spreadsheet — and does it durably: the event is written in the
-- same transaction as the change it describes, and delivered by a worker afterwards.
--
-- Writing the delivery row inside that transaction is what makes the two agree. Posting from
-- the request handler instead would mean an HTTP call inside a database transaction, and a
-- crash after the commit would lose the notification with nothing left to retry from.

-- name: CreateWebhookEndpoint :one
INSERT INTO webhook_endpoints (url, secret_enc, events, is_enabled)
VALUES (sqlc.arg(url), sqlc.arg(secret_enc), sqlc.arg(events)::text[], sqlc.arg(is_enabled))
RETURNING *;

-- name: GetWebhookEndpoint :one
SELECT * FROM webhook_endpoints WHERE id = $1;

-- name: ListWebhookEndpoints :many
SELECT * FROM webhook_endpoints ORDER BY id;

-- name: UpdateWebhookEndpoint :one
UPDATE webhook_endpoints
SET url        = COALESCE(sqlc.narg(url), url),
    events     = COALESCE(sqlc.narg(events)::text[], events),
    is_enabled = COALESCE(sqlc.narg(is_enabled), is_enabled)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: DeleteWebhookEndpoint :execrows
DELETE FROM webhook_endpoints WHERE id = $1;

-- EnqueueWebhookDelivery queues one event for every endpoint that subscribes to it.
--
-- One statement rather than a query and a loop, so that the enqueue is a single operation
-- inside the caller's transaction: half the endpoints notified is worse than none, because
-- nothing afterwards can tell which half.
-- name: EnqueueWebhookDelivery :execrows
INSERT INTO webhook_deliveries (endpoint_id, event, payload, next_try_at)
SELECT id, sqlc.arg(event), sqlc.arg(payload), sqlc.arg(now)::timestamptz
FROM webhook_endpoints
WHERE is_enabled
  AND sqlc.arg(event) = ANY(events);

-- ClaimWebhookDeliveries takes a batch of due deliveries and hands them to one worker.
--
-- FOR UPDATE SKIP LOCKED is what makes that safe with more than one panel process: a row
-- another worker is already holding is skipped rather than waited for. The attempt counter
-- is bumped here rather than after the POST, so a worker that dies mid-delivery cannot leave
-- a row that is retried for ever.
-- name: ClaimWebhookDeliveries :many
WITH due AS (
    SELECT w.id
    FROM webhook_deliveries w
    WHERE w.delivered_at IS NULL
      AND w.attempts < sqlc.arg(max_attempts)
      AND w.next_try_at <= sqlc.arg(now)::timestamptz
    ORDER BY w.next_try_at
    LIMIT sqlc.arg(max_rows)
    FOR UPDATE SKIP LOCKED
)
UPDATE webhook_deliveries d
SET attempts    = d.attempts + 1,
    next_try_at = sqlc.arg(retry_at)::timestamptz
FROM due
WHERE d.id = due.id
RETURNING d.id, d.endpoint_id, d.event, d.payload, d.attempts;

-- name: MarkWebhookDelivered :exec
UPDATE webhook_deliveries
SET delivered_at = sqlc.arg(now)::timestamptz,
    last_error   = ''
WHERE id = sqlc.arg(id);

-- MarkWebhookFailed records why an attempt failed and when to try again.
-- name: MarkWebhookFailed :exec
UPDATE webhook_deliveries
SET last_error  = sqlc.arg(last_error),
    next_try_at = sqlc.arg(next_try_at)::timestamptz
WHERE id = sqlc.arg(id);

-- CountWebhookDeliveriesPending is for diagnostics: a number that only grows means nobody is
-- listening at the other end.
-- name: CountWebhookDeliveriesPending :one
SELECT count(*) FROM webhook_deliveries WHERE delivered_at IS NULL;

-- DeleteWebhookDeliveriesBefore forgets delivered history. Failed ones past max_attempts are
-- kept: they are evidence, and the count above is what an operator watches.
-- name: DeleteWebhookDeliveriesBefore :execrows
DELETE FROM webhook_deliveries
WHERE delivered_at IS NOT NULL AND delivered_at < sqlc.arg(cutoff)::timestamptz;
