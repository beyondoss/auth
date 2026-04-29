SET search_path = auth, public;

CREATE TABLE auth.keys (
    id         uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                           CHECK (auth.uuid_version(id) = 7),
    user_id    uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token_id   uuid        NOT NULL REFERENCES auth.tokens(id) ON DELETE CASCADE,
    name       text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Fast lookup of all keys for a user
CREATE INDEX keys_user_id_idx ON auth.keys (user_id);
-- Unique: each token backs exactly one key; used by validate() to join token → key
CREATE UNIQUE INDEX keys_token_id_idx ON auth.keys (token_id);
