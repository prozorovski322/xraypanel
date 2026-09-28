-- Authentication support.
--
-- Two columns that close holes the initial schema left open, plus scope
-- documentation for api_keys.

-- +goose Up

-- A TOTP code stays valid for its whole time step (30s by default, wider with
-- clock skew tolerance). Without remembering the last step an admin used, a code
-- observed over someone's shoulder or captured from a phishing page can be
-- replayed for the rest of that window. Storing the step makes each code
-- single-use.
ALTER TABLE admins ADD COLUMN totp_last_step bigint;

COMMENT ON COLUMN admins.totp_last_step IS
    'Last accepted TOTP time step. A code may be used once: replaying it within the '
    'same step is rejected.';

-- Revoking refresh tokens does not stop an access token that was already issued;
-- it stays valid until it expires. After a password change or a compromise, that
-- window is exactly when it matters. Access tokens carry their issue time and are
-- rejected if it predates this timestamp.
ALTER TABLE admins ADD COLUMN tokens_valid_from timestamptz NOT NULL DEFAULT now();

COMMENT ON COLUMN admins.tokens_valid_from IS
    'Access tokens issued before this instant are rejected. Moved forward on password '
    'change, on 2FA changes and on an explicit "sign out everywhere".';

COMMENT ON COLUMN api_keys.scopes IS
    'Required scopes, checked per endpoint. Format "resource:action", for example '
    'users:read, users:write, nodes:read. A key with no scopes can do nothing, which '
    'is the safe default for a half-finished creation request.';

-- Lockout counts failures in a window, so the sweep is always over recent rows.
-- The existing indexes lead on ip and username; this one lets retention delete old
-- attempts without a full scan.
CREATE INDEX login_attempts_at_idx ON login_attempts (at);

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    RAISE EXCEPTION
        'migrations are forward-only; roll back by restoring a backup (see docs/migrations.md)';
END
$$;
-- +goose StatementEnd
