CREATE SCHEMA IF NOT EXISTS auth;

SET search_path = auth, public;

-- uuid_version() extracts the version nibble; used in CHECK constraints to
-- reject non-v7 IDs at the DB level. uuidv7() (Postgres 17+) is the DEFAULT.
CREATE OR REPLACE FUNCTION auth.uuid_version(id uuid)
    RETURNS int
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT get_byte(uuid_send(id), 6) >> 4
$$;

CREATE OR REPLACE FUNCTION auth.set_updated_at()
    RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION auth.enable_updated_at(target regclass)
    RETURNS void
    LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format(
        'CREATE OR REPLACE TRIGGER updated_at_trigger
         BEFORE UPDATE ON %s
         FOR EACH ROW EXECUTE FUNCTION auth.set_updated_at()',
        target
    );
END;
$$;

-- App configuration (singleton row enforced by bool PRIMARY KEY)

CREATE TABLE auth.app_config (
    id                          bool        PRIMARY KEY DEFAULT true CHECK (id),
    -- JWT
    jwt_mode                    text        NOT NULL DEFAULT 'ed25519'
                                            CHECK (jwt_mode IN ('hs256', 'ed25519')),
    access_token_ttl_seconds    int         NOT NULL DEFAULT 900,
    refresh_token_ttl_seconds   int         NOT NULL DEFAULT 2592000,
    -- Sessions
    session_ttl_seconds         int         NOT NULL DEFAULT 2592000,
    -- Timestamps
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now()
);

SELECT auth.enable_updated_at('auth.app_config');

-- Signing keys (separate table for rotation support)

CREATE TABLE auth.signing_key (
    id              uuid        PRIMARY KEY DEFAULT uuidv7()
                                CHECK (auth.uuid_version(id) = 7),
    algorithm       text        NOT NULL DEFAULT 'ed25519'
                                CHECK (algorithm IN ('ed25519')),
    private_key_enc bytea       NOT NULL,
    status          text        NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active', 'rotating_out', 'retired')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    retired_at      timestamptz
);

-- Enforce at most one active key at a time
CREATE UNIQUE INDEX signing_key_one_active ON auth.signing_key (status)
    WHERE status = 'active';
