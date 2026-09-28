-- Initial schema.
--
-- Conventions used throughout:
--   * every timestamp is timestamptz and stored in UTC; reset schedules are
--     evaluated in BILLING_TIMEZONE at read time, never stored shifted;
--   * secrets are stored as bytea holding an AES-256-GCM envelope produced by
--     internal/crypto, never as plaintext;
--   * updated_at is maintained by a trigger rather than by each query, so a
--     forgotten SET in one hand-written UPDATE cannot silently stop it.
--
-- Migrations are forward-only; see docs/migrations.md and ADR-012.

-- +goose Up

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------- enum types

CREATE TYPE user_status    AS ENUM ('active', 'limited', 'expired', 'disabled');
CREATE TYPE reset_strategy AS ENUM ('never', 'daily', 'weekly', 'monthly');
CREATE TYPE node_status    AS ENUM ('connected', 'disconnected', 'disabled', 'error');
CREATE TYPE inbound_proto  AS ENUM ('vless', 'trojan', 'shadowsocks');
CREATE TYPE inbound_net    AS ENUM ('tcp', 'ws', 'grpc', 'httpupgrade', 'xhttp');
CREATE TYPE inbound_sec    AS ENUM ('none', 'tls', 'reality');

-- ------------------------------------------------------------ updated_at glue

-- +goose StatementBegin
CREATE FUNCTION set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION set_updated_at() IS
    'Maintains updated_at on UPDATE. Attached to every table that has the column.';

-- ------------------------------------------------------- admins and sessions

CREATE TABLE admins (
    id            bigserial PRIMARY KEY,
    username      text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role          text NOT NULL DEFAULT 'superadmin'
                      CHECK (role IN ('superadmin', 'admin', 'viewer')),
    totp_secret   bytea,
    totp_enabled  boolean NOT NULL DEFAULT false,
    is_active     boolean NOT NULL DEFAULT true,
    last_login_at timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),

    -- 2FA cannot be enabled without a secret to check codes against.
    CONSTRAINT totp_enabled_requires_secret
        CHECK (NOT totp_enabled OR totp_secret IS NOT NULL)
);

COMMENT ON COLUMN admins.password_hash IS 'argon2id in PHC string format';
COMMENT ON COLUMN admins.totp_secret IS 'AES-256-GCM envelope, purpose admin.totp_secret';

CREATE TRIGGER admins_set_updated_at BEFORE UPDATE ON admins
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE admin_sessions (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id   bigint NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    parent_id  uuid REFERENCES admin_sessions (id) ON DELETE SET NULL,
    chain_id   uuid NOT NULL,
    user_agent text NOT NULL DEFAULT '',
    ip         inet,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN admin_sessions.token_hash IS 'sha256 of the refresh token; the token itself is never stored';
COMMENT ON COLUMN admin_sessions.chain_id IS
    'Groups every rotation of one login. Replaying a revoked token revokes the whole chain (ADR-013).';

CREATE INDEX admin_sessions_active_idx ON admin_sessions (admin_id) WHERE revoked_at IS NULL;
CREATE INDEX admin_sessions_chain_idx ON admin_sessions (chain_id);
CREATE INDEX admin_sessions_expiry_idx ON admin_sessions (expires_at);

CREATE TABLE login_attempts (
    id       bigserial PRIMARY KEY,
    at       timestamptz NOT NULL DEFAULT now(),
    username text NOT NULL,
    ip       inet NOT NULL,
    success  boolean NOT NULL
);

COMMENT ON TABLE login_attempts IS
    'Backs login throttling and lockout. Redis is deliberately not a dependency in MVP (ADR-002).';

CREATE INDEX login_attempts_ip_idx ON login_attempts (ip, at DESC);
CREATE INDEX login_attempts_username_idx ON login_attempts (username, at DESC);

CREATE TABLE api_keys (
    id           bigserial PRIMARY KEY,
    name         text NOT NULL,
    key_prefix   text NOT NULL UNIQUE,
    key_hash     bytea NOT NULL UNIQUE,
    scopes       text[] NOT NULL DEFAULT '{}',
    created_by   bigint REFERENCES admins (id) ON DELETE SET NULL,
    expires_at   timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN api_keys.key_prefix IS 'Non-secret leading fragment, shown in the UI to identify a key';

-- --------------------------------------------------------------------- PKI

CREATE TABLE pki (
    id         text PRIMARY KEY,
    cert_pem   text NOT NULL,
    key_enc    bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE pki IS
    'Panel-owned certificate authority. Row id ''ca'' holds the CA that signs node client certificates.';
COMMENT ON COLUMN pki.key_enc IS 'AES-256-GCM envelope, purpose pki.ca_key';

-- ------------------------------------------------------------------- users

CREATE TABLE users (
    id               bigserial PRIMARY KEY,
    username         text NOT NULL UNIQUE,
    xray_email       text NOT NULL UNIQUE,
    vless_uuid       uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    trojan_password  text NOT NULL,
    ss_password      text NOT NULL,
    short_uuid       text NOT NULL UNIQUE,
    status           user_status NOT NULL DEFAULT 'active',
    traffic_limit    bigint NOT NULL DEFAULT 0 CHECK (traffic_limit >= 0),
    traffic_used     bigint NOT NULL DEFAULT 0 CHECK (traffic_used >= 0),
    traffic_lifetime bigint NOT NULL DEFAULT 0 CHECK (traffic_lifetime >= 0),
    reset_strategy   reset_strategy NOT NULL DEFAULT 'never',
    last_reset_at    timestamptz,
    expires_at       timestamptz,
    note             text NOT NULL DEFAULT '',
    telegram_id      bigint,
    online_at        timestamptz,
    sub_fetched_at   timestamptz,
    sub_revoked_at   timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN users.xray_email IS
    'Immutable random identifier used as the Xray stats key (user>>>{email}>>>traffic>>>*). '
    'Generated by the application before insert, so it does not depend on the bigserial id, '
    'and never changes, so renaming a user does not touch any node. See ADR-007.';
COMMENT ON COLUMN users.short_uuid IS
    'Bearer secret in the public /sub/{short_uuid} URL. Deliberately NOT reused as xray_email, '
    'which would leak it into the Xray logs of every node.';
COMMENT ON COLUMN users.traffic_limit IS '0 means unlimited';
COMMENT ON COLUMN users.traffic_used IS 'Bytes since the last scheduled reset; drives enforcement';
COMMENT ON COLUMN users.traffic_lifetime IS 'Bytes ever, never reset; reporting only';
COMMENT ON COLUMN users.expires_at IS 'NULL means the subscription never expires';

CREATE TRIGGER users_set_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX users_status_idx ON users (status);
CREATE INDEX users_expiry_idx ON users (expires_at)
    WHERE status = 'active' AND expires_at IS NOT NULL;
CREATE INDEX users_telegram_idx ON users (telegram_id) WHERE telegram_id IS NOT NULL;

-- Enforcement scans users whose quota is exhausted; a partial index keeps that
-- sweep proportional to the number of limited users, not to the whole table.
CREATE INDEX users_over_quota_idx ON users (id)
    WHERE status = 'active' AND traffic_limit > 0;

CREATE TABLE idempotency_keys (
    key          text PRIMARY KEY,
    scope        text NOT NULL,
    request_hash bytea NOT NULL,
    response     jsonb,
    status_code  int,
    created_at   timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

COMMENT ON TABLE idempotency_keys IS
    'Replay protection for user.create and user.renew. Present from day one because '
    'idempotency changes the endpoint contract and cannot be retrofitted (ADR-014).';
COMMENT ON COLUMN idempotency_keys.request_hash IS
    'Hash of the request body. The same key with a different body is a client bug (422), not a retry.';
COMMENT ON COLUMN idempotency_keys.response IS 'NULL while the operation is still in flight';

CREATE INDEX idempotency_keys_created_idx ON idempotency_keys (created_at);

-- ------------------------------------------------------------------- nodes

CREATE TABLE nodes (
    id                bigserial PRIMARY KEY,
    name              text NOT NULL UNIQUE,
    address           text NOT NULL,
    country_code      char(2),
    tag               text NOT NULL DEFAULT '',
    status            node_status NOT NULL DEFAULT 'disconnected',
    cert_fingerprint  bytea UNIQUE,
    cert_serial       text,
    cert_expires_at   timestamptz,
    xray_version      text,
    agent_version     text,
    config_patch      jsonb NOT NULL DEFAULT '{}',
    config_version    bigint NOT NULL DEFAULT 0,
    applied_version   bigint,
    last_connected_at timestamptz,
    last_heartbeat_at timestamptz,
    last_error        text NOT NULL DEFAULT '',
    traffic_used      bigint NOT NULL DEFAULT 0 CHECK (traffic_used >= 0),
    is_enabled        boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN nodes.address IS 'Default connection address offered to clients; hosts may override it';
COMMENT ON COLUMN nodes.cert_fingerprint IS
    'sha256 of the node client certificate DER. This is the node identity: the panel is the gRPC '
    'server and nodes dial in, so a node is whoever presents this certificate (ADR-001).';
COMMENT ON COLUMN nodes.config_patch IS
    'RFC 7386 JSON merge patch applied by the panel on top of the generated config. The only '
    'supported way to make one node differ; nodes hold no local config of their own (ADR-003).';
COMMENT ON COLUMN nodes.config_version IS 'Desired state version, owned by the panel';
COMMENT ON COLUMN nodes.applied_version IS 'Version the node last reported as applied';

CREATE TRIGGER nodes_set_updated_at BEFORE UPDATE ON nodes
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX nodes_status_idx ON nodes (status) WHERE is_enabled;

CREATE TABLE node_enrollment_tokens (
    id           bigserial PRIMARY KEY,
    token_hash   bytea NOT NULL UNIQUE,
    node_id      bigint REFERENCES nodes (id) ON DELETE CASCADE,
    created_by   bigint REFERENCES admins (id) ON DELETE SET NULL,
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz,
    used_by_node bigint REFERENCES nodes (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),

    -- Either both of used_at and used_by_node are set, or neither is.
    CONSTRAINT enrollment_use_is_consistent
        CHECK ((used_at IS NULL) = (used_by_node IS NULL))
);

COMMENT ON TABLE node_enrollment_tokens IS
    'Single-use tokens exchanged for a node client certificate. used_at makes reuse detectable.';

-- ------------------------------------------------- reality, inbounds, hosts

CREATE TABLE reality_keys (
    id           bigserial PRIMARY KEY,
    name         text NOT NULL UNIQUE,
    private_enc  bytea NOT NULL,
    public_key   text NOT NULL,
    short_ids    text[] NOT NULL CHECK (array_length(short_ids, 1) > 0),
    dest         text NOT NULL,
    server_names text[] NOT NULL CHECK (array_length(server_names, 1) > 0),
    created_at   timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN reality_keys.private_enc IS 'AES-256-GCM envelope, purpose reality.private_key';
COMMENT ON COLUMN reality_keys.public_key IS 'x25519 public key; this is what goes into client links';
COMMENT ON COLUMN reality_keys.dest IS 'Reality handshake target, host:port';

CREATE TABLE inbounds (
    id               bigserial PRIMARY KEY,
    tag              text NOT NULL UNIQUE,
    protocol         inbound_proto NOT NULL,
    transport        inbound_net NOT NULL,
    security         inbound_sec NOT NULL,
    listen_port      int NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    listen_address   text NOT NULL DEFAULT '0.0.0.0',
    ss_method        text,
    flow             text,
    network_settings jsonb NOT NULL DEFAULT '{}',
    tls_settings     jsonb NOT NULL DEFAULT '{}',
    reality_key_id   bigint REFERENCES reality_keys (id) ON DELETE RESTRICT,
    sniffing         jsonb NOT NULL DEFAULT '{}',
    extra            jsonb NOT NULL DEFAULT '{}',
    is_enabled       boolean NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT reality_requires_key
        CHECK (security <> 'reality' OR reality_key_id IS NOT NULL),

    CONSTRAINT shadowsocks_requires_method
        CHECK (protocol <> 'shadowsocks' OR ss_method IS NOT NULL),

    -- flow is only meaningful for VLESS over raw TCP with TLS or Reality. On any
    -- other transport Xray rejects or ignores it, and a link generator that
    -- emitted it anyway would produce a config that fails only on a live client.
    -- See ADR-010.
    CONSTRAINT flow_only_where_supported
        CHECK (
            flow IS NULL
            OR (protocol = 'vless' AND transport = 'tcp' AND security IN ('tls', 'reality'))
        )
);

COMMENT ON COLUMN inbounds.tag IS 'Inbound tag in the generated Xray config; also the routing handle';
COMMENT ON COLUMN inbounds.flow IS
    'XTLS flow, in practice xtls-rprx-vision. A first-class column rather than a JSON field so that '
    'both the config generator and the subscription link generator can see it (ADR-010).';
COMMENT ON COLUMN inbounds.extra IS
    'Escape hatch merged last into the generated inbound object. Use only for settings the schema '
    'does not model yet; anything used twice earns a column.';

CREATE TRIGGER inbounds_set_updated_at BEFORE UPDATE ON inbounds
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE node_inbounds (
    node_id    bigint NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    inbound_id bigint NOT NULL REFERENCES inbounds (id) ON DELETE CASCADE,
    PRIMARY KEY (node_id, inbound_id)
);

COMMENT ON TABLE node_inbounds IS
    'Which inbounds live on which nodes. Uniqueness of listen_port within one node is NOT enforced '
    'here: expressing it would mean denormalising the port into this table and risking two copies '
    'drifting apart. It is checked in the service on attach and again in the config generator, '
    'which refuses to emit a config with a port collision rather than letting Xray fail to '
    'start and look like a broken node. See ADR-011.';

CREATE INDEX node_inbounds_inbound_idx ON node_inbounds (inbound_id);

CREATE TABLE hosts (
    id             bigserial PRIMARY KEY,
    inbound_id     bigint NOT NULL REFERENCES inbounds (id) ON DELETE CASCADE,
    remark         text NOT NULL,
    address        text NOT NULL,
    port           int CHECK (port BETWEEN 1 AND 65535),
    sni            text,
    host_header    text,
    path           text,
    fingerprint    text,
    alpn           text,
    allow_insecure boolean NOT NULL DEFAULT false,
    sort_order     int NOT NULL DEFAULT 0,
    is_enabled     boolean NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE hosts IS
    'How an inbound is presented to a client. Separate from inbounds because the address a client '
    'connects to is often not the node address: CDN, fronting domain, or a vanity hostname.';
COMMENT ON COLUMN hosts.remark IS 'Display name template; supports {USERNAME}, {NODE}, {COUNTRY}';
COMMENT ON COLUMN hosts.address IS 'Connection address template, same placeholders as remark';
COMMENT ON COLUMN hosts.port IS 'NULL inherits inbounds.listen_port';
COMMENT ON COLUMN hosts.fingerprint IS 'uTLS fingerprint: chrome, firefox, safari, randomized, ...';

CREATE TRIGGER hosts_set_updated_at BEFORE UPDATE ON hosts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX hosts_inbound_idx ON hosts (inbound_id, sort_order) WHERE is_enabled;

-- ---------------------------------------------------------- access groups

CREATE TABLE inbound_groups (
    id          bigserial PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    is_default  boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE inbound_groups IS
    'The only way a user gets access to an inbound. There is no per-user override: a one-member '
    'group is cheaper than two-level resolution rules (ADR-004).';
COMMENT ON COLUMN inbound_groups.is_default IS 'Assigned automatically to newly created users';

CREATE TRIGGER inbound_groups_set_updated_at BEFORE UPDATE ON inbound_groups
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE inbound_group_members (
    group_id   bigint NOT NULL REFERENCES inbound_groups (id) ON DELETE CASCADE,
    inbound_id bigint NOT NULL REFERENCES inbounds (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, inbound_id)
);

CREATE INDEX inbound_group_members_inbound_idx ON inbound_group_members (inbound_id);

CREATE TABLE user_groups (
    user_id  bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    group_id bigint NOT NULL REFERENCES inbound_groups (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX user_groups_group_idx ON user_groups (group_id);

-- ------------------------------------------------------------------ traffic

CREATE TABLE traffic_records (
    hour     timestamptz NOT NULL,
    user_id  bigint NOT NULL,
    node_id  bigint NOT NULL,
    uplink   bigint NOT NULL DEFAULT 0 CHECK (uplink >= 0),
    downlink bigint NOT NULL DEFAULT 0 CHECK (downlink >= 0),
    PRIMARY KEY (hour, user_id, node_id)
) PARTITION BY RANGE (hour);

COMMENT ON TABLE traffic_records IS
    'Hourly traffic per (user, node), partitioned by month. Partitioned from the first migration '
    'because retrofitting partitioning onto a live billing table is painful. Foreign keys are '
    'deliberately omitted: a cascade from users would touch every partition, so deletion is an '
    'explicit DELETE in the service instead.';
COMMENT ON COLUMN traffic_records.hour IS 'date_trunc(''hour'', ...) in UTC';

CREATE INDEX traffic_records_user_idx ON traffic_records (user_id, hour DESC);
CREATE INDEX traffic_records_node_idx ON traffic_records (node_id, hour DESC);

-- A DEFAULT partition means a delta whose partition has not been pre-created is
-- still recorded rather than rejected: losing billing data to a missed
-- maintenance job is worse than the cost of moving rows later. The partition
-- worker keeps it empty and alerts if it is not.
CREATE TABLE traffic_records_default PARTITION OF traffic_records DEFAULT;

-- +goose StatementBegin
DO $$
DECLARE
    start_month date := (date_trunc('month', now() AT TIME ZONE 'UTC'))::date;
    month_offset int;
    from_date date;
    to_date date;
BEGIN
    -- Seed the current month plus three ahead. The partition worker extends this
    -- window; seeding here means a fresh install works before the worker runs.
    --
    -- Bounds are written with an explicit +00 offset. A bare date literal would be
    -- cast to timestamptz using the session TimeZone, so the same migration run
    -- with TimeZone=Europe/Moscow would silently shift every partition boundary
    -- three hours away from the UTC hour buckets the rows are keyed by.
    FOR month_offset IN 0..3 LOOP
        from_date := (start_month + (month_offset || ' month')::interval)::date;
        to_date := (start_month + ((month_offset + 1) || ' month')::interval)::date;
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF traffic_records FOR VALUES FROM (%L) TO (%L)',
            'traffic_records_' || to_char(from_date, 'YYYY_MM'),
            to_char(from_date, 'YYYY-MM-DD') || ' 00:00:00+00',
            to_char(to_date, 'YYYY-MM-DD') || ' 00:00:00+00'
        );
    END LOOP;
END
$$;
-- +goose StatementEnd

CREATE TABLE traffic_daily (
    day      date NOT NULL,
    user_id  bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    node_id  bigint NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    uplink   bigint NOT NULL DEFAULT 0 CHECK (uplink >= 0),
    downlink bigint NOT NULL DEFAULT 0 CHECK (downlink >= 0),
    PRIMARY KEY (day, user_id, node_id)
);

COMMENT ON TABLE traffic_daily IS
    'Daily rollup of traffic_records. Serves every chart longer than a few days, so retention can '
    'drop hourly rows without losing history.';

CREATE INDEX traffic_daily_user_idx ON traffic_daily (user_id, day DESC);
CREATE INDEX traffic_daily_node_idx ON traffic_daily (node_id, day DESC);

CREATE TABLE traffic_batches (
    node_id     bigint NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    batch_id    uuid NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, batch_id)
);

COMMENT ON TABLE traffic_batches IS
    'Deduplicates traffic submissions. A node retries a batch after a reconnect, and double '
    'counting a retry would bill a user for traffic they did not use.';

CREATE INDEX traffic_batches_received_idx ON traffic_batches (received_at);

-- ----------------------------------------------------------------- webhooks

CREATE TABLE webhook_endpoints (
    id         bigserial PRIMARY KEY,
    url        text NOT NULL,
    secret_enc bytea NOT NULL,
    events     text[] NOT NULL DEFAULT '{}',
    is_enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE webhook_endpoints IS
    'Outbound notifications. No Telegram bot and no payments in MVP, but the extension point is '
    'here because these are the integrations that will need it (ADR-014).';
COMMENT ON COLUMN webhook_endpoints.secret_enc IS 'AES-256-GCM envelope, purpose webhook.secret';
COMMENT ON COLUMN webhook_endpoints.events IS
    'Subscribed events: user.created, user.limited, user.expired, user.renewed';

CREATE TRIGGER webhook_endpoints_set_updated_at BEFORE UPDATE ON webhook_endpoints
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE webhook_deliveries (
    id           bigserial PRIMARY KEY,
    endpoint_id  bigint NOT NULL REFERENCES webhook_endpoints (id) ON DELETE CASCADE,
    event        text NOT NULL,
    payload      jsonb NOT NULL,
    attempts     int NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_try_at  timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    last_error   text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX webhook_deliveries_pending_idx ON webhook_deliveries (next_try_at)
    WHERE delivered_at IS NULL;

-- -------------------------------------------------------- audit and settings

CREATE TABLE audit_log (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    actor_type  text NOT NULL CHECK (actor_type IN ('admin', 'api_key', 'system', 'node')),
    actor_id    bigint,
    actor_label text NOT NULL DEFAULT '',
    action      text NOT NULL,
    entity_type text NOT NULL,
    entity_id   text,
    ip          inet,
    diff        jsonb
);

COMMENT ON COLUMN audit_log.actor_id IS
    'Intentionally not a foreign key: the trail must survive deletion of the admin or key that acted.';
COMMENT ON COLUMN audit_log.actor_label IS 'Actor name as it was at the time, for when actor_id no longer resolves';
COMMENT ON COLUMN audit_log.diff IS '{"before": {...}, "after": {...}} with secret fields removed';

CREATE INDEX audit_log_at_idx ON audit_log (at DESC);
CREATE INDEX audit_log_entity_idx ON audit_log (entity_type, entity_id, at DESC);
CREATE INDEX audit_log_actor_idx ON audit_log (actor_type, actor_id, at DESC);

CREATE TABLE settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER settings_set_updated_at BEFORE UPDATE ON settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose Down

-- Migrations are forward-only (ADR-012). Rolling back schema is done by
-- restoring a backup, following docs/migrations.md. Failing loudly here beats a
-- Down path that nobody ever exercises and that breaks on real data.
-- +goose StatementBegin
DO $$
BEGIN
    RAISE EXCEPTION
        'migrations are forward-only; roll back by restoring a backup (see docs/migrations.md)';
END
$$;
-- +goose StatementEnd
