-- Store an idempotent response as opaque bytes rather than as jsonb.
--
-- jsonb normalises what it stores: it reformats whitespace, reorders object keys and drops
-- duplicates. A replayed response therefore came back semantically equal to the original
-- but not byte-equal, which defeats the point of the mechanism. "The same response" has to
-- mean the same response, not an equivalent one: a client comparing bytes, verifying a
-- signature over the body, or caching by hash would see two different answers to one
-- request.
--
-- It also removes an assumption that was never true: nothing requires a stored response to
-- be JSON at all.
--
-- The table is an ephemeral cache with a retention window measured in hours, so rewriting
-- it costs nothing.

-- +goose Up

ALTER TABLE idempotency_keys
    ALTER COLUMN response TYPE bytea
    USING convert_to(response::text, 'UTF8');

COMMENT ON COLUMN idempotency_keys.response IS
    'The response body exactly as it was first returned. Opaque bytes, because a replay must '
    'be byte-identical and nothing requires it to be JSON.';

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    RAISE EXCEPTION
        'migrations are forward-only; roll back by restoring a backup (see docs/migrations.md)';
END
$$;
-- +goose StatementEnd
