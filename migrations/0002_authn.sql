SET search_path = auth, public;

-- Phase 1 fields on app_config

ALTER TABLE auth.app_config
    ADD COLUMN jwt_enabled  bool NOT NULL DEFAULT false,
    ADD COLUMN issuer_url   text;

-- Tenants: personal (1:1 with user, created atomically on signup) and team tenants (Phase 3+)

CREATE TABLE auth.tenant (
    id          uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                            CHECK (auth.uuid_version(id) = 7),
    user_id     uuid        NOT NULL,
    name        text        NOT NULL,
    slug        text        NOT NULL,
    metadata    jsonb       NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    deleted_at  timestamptz
);

CREATE UNIQUE INDEX tenant_slug_idx ON auth.tenant (slug) WHERE deleted_at IS NULL;

SELECT auth.enable_updated_at('auth.tenant');

-- Users

CREATE TABLE auth."user" (
    id                  uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                                    CHECK (auth.uuid_version(id) = 7),
    personal_tenant_id  uuid        NOT NULL REFERENCES auth.tenant(id),
    primary_email_id    uuid        NOT NULL,
    display_name        text,
    avatar_url          text,
    created_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    deleted_at          timestamptz
);

SELECT auth.enable_updated_at('auth."user"');

-- Email addresses (CITEXT handles case-insensitive comparison natively)

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE auth.email (
    id          uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                            CHECK (auth.uuid_version(id) = 7),
    user_id     uuid        NOT NULL REFERENCES auth."user"(id) ON DELETE CASCADE,
    email       citext      NOT NULL,
    verified_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Covering unique index: lookup by email returns id + user_id + verified_at without a heap fetch
CREATE UNIQUE INDEX email_email_idx ON auth.email (email) INCLUDE (id, user_id, verified_at, created_at);
CREATE INDEX email_user_id_idx ON auth.email USING HASH (user_id);

-- Auth method bindings. Phase 1: password only.
-- For password: subject = normalized email, secret = argon2id PHC string.
-- Phase 3 widens the provider CHECK constraint for OAuth.

CREATE TABLE auth.identity (
    id          uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                            CHECK (auth.uuid_version(id) = 7),
    user_id     uuid        NOT NULL REFERENCES auth."user"(id) ON DELETE CASCADE,
    provider    text        NOT NULL CHECK (provider IN ('password')),
    subject     text        NOT NULL,
    secret      text,
    created_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Covering unique index: lookup by (provider, subject) returns user_id without a heap fetch
CREATE UNIQUE INDEX identity_provider_subject_idx ON auth.identity (provider, subject) INCLUDE (user_id);
CREATE INDEX identity_user_id_idx ON auth.identity USING HASH (user_id);

-- Tokens: unified credential primitive (sessions and future API keys share this table)

CREATE TABLE auth.token (
    id           uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                             CHECK (auth.uuid_version(id) = 7),
    secret       text        NOT NULL,  -- SHA-256 of secret half, hex-encoded
    expires_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Covering auth index: validates id+secret and returns last_used_at+expires_at without a heap fetch
CREATE INDEX token_auth_idx ON auth.token (id, secret) INCLUDE (last_used_at, expires_at, created_at);
CREATE INDEX token_expires_at_idx ON auth.token (expires_at);

-- Sessions: links a token to a user

CREATE TABLE auth.session (
    id         uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                           CHECK (auth.uuid_version(id) = 7),
    user_id    uuid        NOT NULL REFERENCES auth."user"(id) ON DELETE RESTRICT,
    token_id   uuid        NOT NULL REFERENCES auth.token(id) ON DELETE CASCADE,
    ip_address inet,
    user_agent text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Unique: one token maps to exactly one session. INCLUDE user_id covers the bundled CTE join.
CREATE UNIQUE INDEX session_token_id_idx ON auth.session (token_id) INCLUDE (user_id);
CREATE INDEX session_user_id_idx ON auth.session USING HASH (user_id);
