-- Shadowsocks-2022 server key.
--
-- A 2022-* inbound has two layers of key material: one server key on the inbound
-- and one per-user key on each client. Only the user key was modelled
-- (users.ss_password); without the server key the inbound cannot be generated at
-- all, and the ss:// link cannot be built either, since the URI carries both.
--
-- It is a column rather than a field inside inbounds.extra for the same reason flow
-- is (ADR-010): both the config generator and the subscription link generator need
-- to see it, and a value only one of them knows about produces a working server and
-- a broken client.

-- +goose Up

ALTER TABLE inbounds ADD COLUMN ss_server_key_enc bytea;

COMMENT ON COLUMN inbounds.ss_server_key_enc IS
    'AES-256-GCM envelope, purpose inbound.ss_server_key. The Shadowsocks-2022 server '
    'key, distinct from the per-user keys in users.ss_password.';

-- Enforced here rather than in the service so a hand-written INSERT cannot produce an
-- inbound that fails only when a node tries to start it.
ALTER TABLE inbounds ADD CONSTRAINT shadowsocks_requires_server_key
    CHECK (protocol <> 'shadowsocks' OR ss_server_key_enc IS NOT NULL);

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    RAISE EXCEPTION
        'migrations are forward-only; roll back by restoring a backup (see docs/migrations.md)';
END
$$;
-- +goose StatementEnd
