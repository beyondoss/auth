SET search_path = auth, public;

-- Dedicated partition for org membership tuples. Moving 'org' rows out of the
-- DEFAULT partition gives the planner a smaller segment to scan for membership
-- checks, which run on every authenticated request to org-scoped endpoints.
CREATE TABLE auth.authz_relations_org
    PARTITION OF auth.authz_relations
    FOR VALUES IN ('org');

-- Pending invitations. Token stored as SHA-256 hash (bytea), same as auth.tokens.
-- Deleted on accept (atomic DELETE...RETURNING) — no accepted_at, no dead rows.
-- No FKs — records must survive org/user deletes.
CREATE TABLE auth.org_invitations (
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
CREATE UNIQUE INDEX org_invitations_email_unique
    ON auth.org_invitations (org_id, email)
    WHERE email IS NOT NULL;

-- Lookup by org (list, revoke)
CREATE INDEX org_invitations_org_idx
    ON auth.org_invitations (org_id, created_at DESC);

-- Lookup by email (future: auto-accept on signup)
CREATE INDEX org_invitations_email_idx
    ON auth.org_invitations (email)
    WHERE email IS NOT NULL;

-- Direct org membership: users assigned a role on an org. Subject-set members
-- (e.g. a team assigned to an org) are excluded — use authz_lookup_subjects for
-- full recursive expansion. Partition-pruned to authz_relations_org; composable
-- with WHERE, ORDER BY, LIMIT without materializing.
CREATE VIEW auth.org_members AS
SELECT r.object_id  AS org_id,
       r.relation   AS role,
       r.subject_id AS user_id,
       r.created_at AS created_at
  FROM auth.authz_relations r
 WHERE r.object_type      = 'org'
   AND r.subject_set_type IS NULL;
