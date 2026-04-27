SET search_path = auth, public;

-- Dedicated partition for org membership tuples. Moving 'org' rows out of the
-- DEFAULT partition gives the planner a smaller segment to scan for membership
-- checks, which run on every authenticated request to org-scoped endpoints.
CREATE TABLE auth.relation_tuple_org
    PARTITION OF auth.relation_tuple
    FOR VALUES IN ('org');

-- Pending invitations. Token stored as SHA-256 hash (bytea), same as auth.token.
-- Deleted on accept (atomic DELETE...RETURNING) — no accepted_at, no dead rows.
-- No FKs — records must survive org/user deletes.
CREATE TABLE auth.org_invitation (
    id           uuid        NOT NULL PRIMARY KEY DEFAULT uuidv7()
                             CHECK (auth.uuid_version(id) = 7),
    org_id       uuid        NOT NULL,
    invited_by   uuid,                        -- user_id of inviter; NULL = system
    email        citext,                      -- NULL = shareable link (future)
    role         text        NOT NULL DEFAULT 'member'
                             CHECK (role ~ '^[a-z][a-z0-9_-]{0,63}$'),
    token_hash   bytea       NOT NULL,        -- SHA-256(plaintext_token)
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL DEFAULT now() + interval '7 days'
);

-- One pending invite per email per org (shareable links — NULL email — are many-allowed)
CREATE UNIQUE INDEX org_invitation_email_unique
    ON auth.org_invitation (org_id, email)
    WHERE email IS NOT NULL;

-- Lookup by org (list, revoke)
CREATE INDEX org_invitation_org_idx
    ON auth.org_invitation (org_id, created_at DESC);

-- Lookup by email (future: auto-accept on signup)
CREATE INDEX org_invitation_email_idx
    ON auth.org_invitation (email)
    WHERE email IS NOT NULL;
