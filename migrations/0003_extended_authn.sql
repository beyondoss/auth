SET search_path = auth, public;

-- app_config additions
ALTER TABLE auth.app_config
    ADD COLUMN oauth_providers_enc  bytea,        -- AES-256-GCM encrypted JSON (KEK)
    ADD COLUMN oauth_email_link     bool NOT NULL DEFAULT false;

-- TOTP second factor
CREATE TABLE auth.totp_factor (
    id           uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                             CHECK (auth.uuid_version(id) = 7),
    user_id      uuid        NOT NULL REFERENCES auth."user"(id) ON DELETE CASCADE,
    secret       bytea       NOT NULL,
    enrolled_at  timestamptz,
    last_used_at timestamptz,
    deleted_at   timestamptz
);

-- Covering partial index: all TOTP queries filter by user_id + deleted_at IS NULL and need
-- id/secret/enrolled_at/last_used_at without a heap fetch.
CREATE UNIQUE INDEX totp_factor_user_id_idx ON auth.totp_factor (user_id)
    INCLUDE (id, secret, enrolled_at, last_used_at)
    WHERE deleted_at IS NULL;

CREATE TABLE auth.totp_recovery_code (
    id        uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                          CHECK (auth.uuid_version(id) = 7),
    factor_id uuid        NOT NULL REFERENCES auth.totp_factor(id) ON DELETE CASCADE,
    code_hash bytea       NOT NULL,
    used_at   timestamptz
);

-- Covering partial index: recovery code lookup filters by factor_id + used_at IS NULL,
-- returns code_hash for constant-time comparison without a heap fetch.
CREATE INDEX totp_recovery_code_factor_id_idx ON auth.totp_recovery_code (factor_id)
    INCLUDE (id, code_hash)
    WHERE used_at IS NULL;

-- passkey passkey credentials (separate from identity: sign_count mutates on every auth)
CREATE TABLE auth.passkey_credential (
    id              uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                                CHECK (auth.uuid_version(id) = 7),
    user_id         uuid        NOT NULL REFERENCES auth."user"(id) ON DELETE CASCADE,
    credential_id   bytea       NOT NULL,
    credential_data jsonb       NOT NULL,   -- full serialized passkey-rs Passkey struct
    nickname        text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz,
    deleted_at      timestamptz
);

-- Auth path: look up credential by credential_id, return id + user_id to avoid heap fetch.
-- credential_data is large jsonb — fetched separately from heap only when needed.
CREATE UNIQUE INDEX passkey_credential_credential_id_idx
    ON auth.passkey_credential (credential_id)
    INCLUDE (id, user_id)
    WHERE deleted_at IS NULL;

-- List path: fetch all credentials for a user; covering avoids heap fetch for list view.
CREATE INDEX passkey_credential_user_id_idx
    ON auth.passkey_credential (user_id)
    INCLUDE (id, credential_id, nickname, created_at, last_used_at)
    WHERE deleted_at IS NULL;

-- Single table for all one-time token flows (magic link, password reset, email verify, email change).
-- kind mirrors the token wire-format prefix and is enforced by the CHECK constraint below.
-- Consumed via atomic DELETE...RETURNING — no used_at, no dead rows, no TOCTOU.
CREATE TABLE auth.one_time_token (
    id         uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                           CHECK (auth.uuid_version(id) = 7),
    user_id    uuid        NOT NULL REFERENCES auth."user"(id) ON DELETE CASCADE,
    kind       text        NOT NULL CHECK (kind IN ('ml', 'pwr', 'ev', 'ec')),
    secret     bytea       NOT NULL,
    expires_at timestamptz NOT NULL,
    context    jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Auth index mirrors token_auth_idx: validates id+secret, returns kind+user_id+context+expires_at
-- without a heap fetch for both the DELETE...RETURNING and the fallback SELECT.
CREATE INDEX one_time_token_auth_idx ON auth.one_time_token (id, secret)
    INCLUDE (kind, user_id, context, expires_at);

-- GC index: sweep expired tokens without a seq scan.
CREATE INDEX one_time_token_expires_at_idx ON auth.one_time_token (expires_at);
