SET search_path = auth, public;

CREATE TABLE auth.refresh_tokens (
    id          uuid        PRIMARY KEY DEFAULT uuidv7()
                            CHECK (auth.uuid_version(id) = 7),
    session_id  uuid        NOT NULL REFERENCES auth.sessions(id) ON DELETE CASCADE,
    token_id    uuid        NOT NULL UNIQUE REFERENCES auth.tokens(id) ON DELETE CASCADE,
    family_id   uuid        NOT NULL,
    replaced_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX refresh_tokens_family_id_idx  ON auth.refresh_tokens (family_id);
CREATE INDEX refresh_tokens_session_id_idx ON auth.refresh_tokens (session_id);
