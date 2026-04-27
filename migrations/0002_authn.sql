SET search_path = auth, public;

-- Phase 1 fields on app_config

ALTER TABLE auth.app_config
    ADD COLUMN jwt_enabled  bool NOT NULL DEFAULT false,
    ADD COLUMN issuer_url   text,
    ADD COLUMN jwt_audience text;

-- Orgs: personal (1:1 with user, created atomically on signup) and team orgs (Phase 3+)

CREATE TABLE auth.orgs (
    id          uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                            CHECK (auth.uuid_version(id) = 7),
    user_id     uuid        NOT NULL,
    name        text        NOT NULL,
    slug        text        NOT NULL,
    image_url   text,
    metadata    jsonb       NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz
);

CREATE UNIQUE INDEX orgs_slug_idx ON auth.orgs (slug) WHERE deleted_at IS NULL;

SELECT auth.enable_updated_at('auth.orgs');

-- Users

CREATE TABLE auth.users (
    id               uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                                 CHECK (auth.uuid_version(id) = 7),
    primary_org_id   uuid        NOT NULL REFERENCES auth.orgs(id),
    primary_email_id uuid        NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    deleted_at       timestamptz
);

SELECT auth.enable_updated_at('auth.users');

-- Circular FK: orgs references users and users references orgs.
-- Deferred so the signup transaction can insert both before commit checks.
ALTER TABLE auth.orgs
    ADD CONSTRAINT orgs_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES auth.users(id)
    DEFERRABLE INITIALLY DEFERRED;

-- Email addresses (CITEXT handles case-insensitive comparison natively)

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE auth.emails (
    id          uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                            CHECK (auth.uuid_version(id) = 7),
    user_id     uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    email       citext      NOT NULL,
    verified_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Covering unique index: lookup by email returns id + user_id + verified_at without a heap fetch
CREATE UNIQUE INDEX emails_email_idx ON auth.emails (email) INCLUDE (id, user_id, verified_at, created_at);
CREATE INDEX emails_user_id_idx ON auth.emails USING HASH (user_id);

ALTER TABLE auth.users
    ADD CONSTRAINT users_primary_email_fk
    FOREIGN KEY (primary_email_id) REFERENCES auth.emails(id)
    DEFERRABLE INITIALLY DEFERRED;

-- Auth method bindings. Phase 1: password only.
-- For password: subject = normalized email, secret = argon2id PHC string.
-- Phase 3 widens the provider CHECK constraint for OAuth.

CREATE TABLE auth.identities (
    id          uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                            CHECK (auth.uuid_version(id) = 7),
    user_id     uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    provider    text        NOT NULL CHECK (provider ~ '^(password|oauth_[a-z0-9_]+)$'),
    subject     text        NOT NULL,
    secret      bytea,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Covering unique index: lookup by (provider, subject) returns user_id without a heap fetch
CREATE UNIQUE INDEX identities_provider_subject_idx ON auth.identities (provider, subject) INCLUDE (user_id);
CREATE INDEX identities_user_id_idx ON auth.identities USING HASH (user_id);

-- Tokens: unified credential primitive (sessions and future API keys share this table)

CREATE TABLE auth.tokens (
    id           uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                             CHECK (auth.uuid_version(id) = 7),
    secret       bytea       NOT NULL,  -- SHA-256 of secret half, hex-encoded
    expires_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Covering auth index: validates id+secret and returns last_used_at+expires_at without a heap fetch
CREATE INDEX tokens_auth_idx ON auth.tokens (id, secret) INCLUDE (last_used_at, expires_at, created_at);
CREATE INDEX tokens_expires_at_idx ON auth.tokens USING BRIN (expires_at);

-- Sessions: links a token to a user

CREATE TABLE auth.sessions (
    id         uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                           CHECK (auth.uuid_version(id) = 7),
    user_id    uuid        NOT NULL REFERENCES auth.users(id) ON DELETE RESTRICT,
    token_id   uuid        NOT NULL REFERENCES auth.tokens(id) ON DELETE CASCADE,
    ip_address inet,
    user_agent text,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Unique: one token maps to exactly one session. INCLUDE user_id covers the bundled CTE join.
CREATE UNIQUE INDEX sessions_token_id_idx ON auth.sessions (token_id) INCLUDE (user_id);
CREATE INDEX sessions_user_id_idx ON auth.sessions USING HASH (user_id);
