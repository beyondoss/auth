SET search_path = auth, public;

-- Authz schema stored as JSON on the singleton app_config row.
-- NULL means authz is disabled; PUT /v1/authz/schema is the only way to enable it.

ALTER TABLE auth.app_config
    ADD COLUMN authz_schema jsonb;

-- authz_relations: the core storage for all authorization relationships.
-- Partitioned by object_type so hot types (e.g. 'document') can get dedicated
-- partitions without touching any other data. Start with a single DEFAULT
-- partition; add dedicated partitions via migrations/templates/add_object_type_partition.sql.template.
--
-- ID columns are text (not uuid/bigint) for maximum compatibility with
-- user-provided object identifiers: UUIDs, slugs, integers, arbitrary strings.

CREATE TABLE auth.authz_relations (
    id                   uuid        NOT NULL DEFAULT uuidv7()
                                     CHECK (auth.uuid_version(id) = 7),
    object_id            text        NOT NULL CHECK (object_id <> ''),
    object_type          text        NOT NULL,
    relation             text        NOT NULL,
    subject_id           text        NOT NULL CHECK (subject_id <> ''),
    -- subject_set_type and subject_set_relation are only set for subject-set relationships
    -- (e.g. "members of team X"). NULL means the subject is a direct user.
    subject_set_type     text,
    subject_set_relation text,
    created_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT authz_relations_pkey PRIMARY KEY (id, object_type)
) PARTITION BY LIST (object_type);

-- Unique constraint on the logical tuple identity.
-- NULLS NOT DISTINCT treats NULLs as equal so (obj, rel, subj, NULL, NULL) is one row.
CREATE UNIQUE INDEX authz_relations_key ON auth.authz_relations (
    object_type,
    object_id,
    relation,
    subject_set_type,
    subject_id,
    subject_set_relation ASC NULLS FIRST
) NULLS NOT DISTINCT;

-- Forward index: used by authz_lookup_resources() — find all objects a subject can access.
CREATE INDEX authz_relations_subject_lookup_idx ON auth.authz_relations (
    subject_id,
    object_type,
    relation
);

-- Partial index for recursive CTE traversal: find rows where this entity is
-- a subject set. Only rows with subject_set_type set participate in set expansion.
CREATE INDEX authz_relations_subject_set_idx ON auth.authz_relations (
    subject_set_type,
    subject_id,
    subject_set_relation
) WHERE subject_set_type IS NOT NULL;

-- ──────────────────────────────────────────────────────────────────────────────
-- authz_check: recursive CTE permission check. Two overloads:
--   1. single relation
--   2. array of relations (any match)
--
-- authz_check_path: multi-hop hierarchy traversal via (relation, object_type) path.
-- ──────────────────────────────────────────────────────────────────────────────

-- PL/pgSQL BFS implementation. Returns true as soon as p_subject_id is found,
-- without materializing the full reachable closure. Loses PARALLEL SAFE
-- (irrelevant for point checks; see build_batch_or_chain for the one call site
-- where it matters, acceptable at current batch sizes) in exchange for early
-- termination on deep graphs.
--
-- One query per BFS level expands the entire frontier via UNNEST join.
-- Visited nodes tracked as 'type\x01id\x01rel' keys (chr(1) separator;
-- assumes object_type/id/relation don't contain chr(1), which the schema
-- permits but real-world IDs won't violate).
-- Frontier deduplication via DISTINCT prevents re-expanding the same
-- subject-set node when multiple current-frontier nodes share a successor.
-- Visited-set construction uses a single array concat per level (O(k) not O(k²)).
CREATE OR REPLACE FUNCTION auth.authz_check(
    p_subject_id  text,
    p_relation    text,
    p_object_type text,
    p_object_id   text
) RETURNS boolean
    LANGUAGE plpgsql STABLE
AS $$
DECLARE
    v_ft    text[];
    v_fi    text[];
    v_fr    text[];
    v_seen  text[] := '{}';
    v_found bool;
    v_nft   text[];
    v_nfi   text[];
    v_nfr   text[];
BEGIN
    -- Anchor: direct leaf match exits immediately; subject-set rows seed the frontier.
    SELECT
        bool_or(subject_id = p_subject_id AND subject_set_type IS NULL),
        array_agg(subject_set_type)     FILTER (WHERE subject_set_type IS NOT NULL),
        array_agg(subject_id)           FILTER (WHERE subject_set_type IS NOT NULL),
        array_agg(subject_set_relation) FILTER (WHERE subject_set_type IS NOT NULL)
      INTO v_found, v_ft, v_fi, v_fr
      FROM auth.authz_relations
     WHERE object_type = p_object_type
       AND object_id   = p_object_id
       AND relation    = p_relation;

    IF v_found THEN RETURN true; END IF;

    WHILE v_ft IS NOT NULL LOOP
        v_seen := v_seen || ARRAY(
            SELECT ft || chr(1) || fi || chr(1) || fr
              FROM unnest(v_ft, v_fi, v_fr) AS f(ft, fi, fr)
        );

        WITH expanded AS (
            SELECT DISTINCT
                r.subject_set_type,
                r.subject_id,
                r.subject_set_relation,
                (r.subject_id = p_subject_id AND r.subject_set_type IS NULL) AS is_match
              FROM auth.authz_relations r
              JOIN unnest(v_ft, v_fi, v_fr) AS f(ot, oi, rel)
                ON r.object_type = f.ot
               AND r.object_id   = f.oi
               AND r.relation    = f.rel
             WHERE r.subject_set_type IS NULL
                OR NOT ((r.subject_set_type || chr(1) || r.subject_id || chr(1) || r.subject_set_relation) = ANY(v_seen))
        )
        SELECT
            bool_or(is_match),
            array_agg(subject_set_type) FILTER (WHERE subject_set_type IS NOT NULL),
            array_agg(subject_id)       FILTER (WHERE subject_set_type IS NOT NULL),
            array_agg(subject_set_relation) FILTER (WHERE subject_set_type IS NOT NULL)
          INTO v_found, v_nft, v_nfi, v_nfr
          FROM expanded;

        IF v_found THEN RETURN true; END IF;

        v_ft := v_nft;
        v_fi := v_nfi;
        v_fr := v_nfr;
    END LOOP;

    RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION auth.authz_check(
    p_subject_id  text,
    p_relation    text[],
    p_object_type text,
    p_object_id   text
) RETURNS boolean
    LANGUAGE plpgsql STABLE
AS $$
DECLARE
    v_ft    text[];
    v_fi    text[];
    v_fr    text[];
    v_seen  text[] := '{}';
    v_found bool;
    v_nft   text[];
    v_nfi   text[];
    v_nfr   text[];
BEGIN
    SELECT
        bool_or(subject_id = p_subject_id AND subject_set_type IS NULL),
        array_agg(subject_set_type)     FILTER (WHERE subject_set_type IS NOT NULL),
        array_agg(subject_id)           FILTER (WHERE subject_set_type IS NOT NULL),
        array_agg(subject_set_relation) FILTER (WHERE subject_set_type IS NOT NULL)
      INTO v_found, v_ft, v_fi, v_fr
      FROM auth.authz_relations
     WHERE object_type = p_object_type
       AND object_id   = p_object_id
       AND relation    = ANY(p_relation);

    IF v_found THEN RETURN true; END IF;

    WHILE v_ft IS NOT NULL LOOP
        v_seen := v_seen || ARRAY(
            SELECT ft || chr(1) || fi || chr(1) || fr
              FROM unnest(v_ft, v_fi, v_fr) AS f(ft, fi, fr)
        );

        WITH expanded AS (
            SELECT DISTINCT
                r.subject_set_type,
                r.subject_id,
                r.subject_set_relation,
                (r.subject_id = p_subject_id AND r.subject_set_type IS NULL) AS is_match
              FROM auth.authz_relations r
              JOIN unnest(v_ft, v_fi, v_fr) AS f(ot, oi, rel)
                ON r.object_type = f.ot
               AND r.object_id   = f.oi
               AND r.relation    = f.rel
             WHERE r.subject_set_type IS NULL
                OR NOT ((r.subject_set_type || chr(1) || r.subject_id || chr(1) || r.subject_set_relation) = ANY(v_seen))
        )
        SELECT
            bool_or(is_match),
            array_agg(subject_set_type) FILTER (WHERE subject_set_type IS NOT NULL),
            array_agg(subject_id)       FILTER (WHERE subject_set_type IS NOT NULL),
            array_agg(subject_set_relation) FILTER (WHERE subject_set_type IS NOT NULL)
          INTO v_found, v_nft, v_nfi, v_nfr
          FROM expanded;

        IF v_found THEN RETURN true; END IF;

        v_ft := v_nft;
        v_fi := v_nfi;
        v_fr := v_nfr;
    END LOOP;

    RETURN false;
END;
$$;

-- Path variant: walks a sequence of (relation, object_type) hops.
-- Used for multi-hop hierarchy checks, e.g. document→folder→owner.
-- Strictly direct-entity traversal: subject-set expansion is not performed.
-- If a hop lands on a subject-set row the path is not followed further.
CREATE OR REPLACE FUNCTION auth.authz_check_path(
    p_subject_id       text,
    p_relation_path    text[],
    p_object_type_path text[],
    p_object_id        text
) RETURNS boolean
    LANGUAGE sql PARALLEL SAFE STABLE
AS $$
    WITH RECURSIVE path_check AS (
        SELECT subject_id, subject_set_type, subject_set_relation, 1 AS depth
          FROM auth.authz_relations
         WHERE object_type      = p_object_type_path[1]
           AND object_id        = p_object_id
           AND relation         = p_relation_path[1]
           AND subject_set_type IS NULL
        UNION ALL
        SELECT rt.subject_id, rt.subject_set_type, rt.subject_set_relation, pc.depth + 1
          FROM auth.authz_relations rt
          JOIN path_check pc ON rt.object_id = pc.subject_id
         WHERE rt.object_type      = p_object_type_path[pc.depth + 1]
           AND rt.relation         = p_relation_path[pc.depth + 1]
           AND rt.subject_set_type IS NULL
           AND pc.depth < array_length(p_relation_path, 1)
    )
    CYCLE subject_id SET is_cycle USING cycle_path
    SELECT EXISTS (
        SELECT 1 FROM path_check
         WHERE subject_id = p_subject_id
           AND NOT is_cycle
    )
$$;

-- ──────────────────────────────────────────────────────────────────────────────
-- authz_lookup_subjects: given an object + relation, return all direct subjects
-- (resolves subject sets recursively). Used by the /v1/authz/expand endpoint
-- and internally by the why-check trace.
-- ──────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION auth.authz_lookup_subjects(
    p_relation    text,
    p_object_type text,
    p_object_id   text
) RETURNS TABLE (
    object_type text,
    object_id   text,
    relation    text,
    subject_id  text,
    tuple_id    uuid,
    created_at  timestamptz
)
    LANGUAGE sql PARALLEL SAFE STABLE
AS $$
    WITH RECURSIVE subject_expansion AS (
        SELECT object_type,
               object_id,
               relation,
               subject_id,
               subject_set_type,
               subject_set_relation,
               id,
               created_at
          FROM auth.authz_relations
         WHERE object_type = p_object_type
           AND object_id   = p_object_id
           AND relation    = p_relation
        UNION ALL
        SELECT se.object_type,
               se.object_id,
               se.relation,
               rt.subject_id,
               rt.subject_set_type,
               rt.subject_set_relation,
               rt.id,
               rt.created_at
          FROM auth.authz_relations rt
          JOIN subject_expansion se
            ON rt.object_type = se.subject_set_type
           AND rt.object_id   = se.subject_id
           AND rt.relation    = se.subject_set_relation
         WHERE se.subject_set_type     IS NOT NULL
           AND se.subject_set_relation IS NOT NULL
    )
    CYCLE subject_id SET is_cycle USING cycle_path
    SELECT object_type,
           object_id,
           relation,
           subject_id,
           id,
           created_at
      FROM subject_expansion
     WHERE subject_set_type     IS NULL
       AND subject_set_relation IS NULL
       AND NOT is_cycle
$$;

CREATE OR REPLACE FUNCTION auth.authz_lookup_subjects(
    p_relation    text[],
    p_object_type text,
    p_object_id   text
) RETURNS TABLE (
    object_type text,
    object_id   text,
    relation    text,
    subject_id  text,
    tuple_id    uuid,
    created_at  timestamptz
)
    LANGUAGE sql PARALLEL SAFE STABLE
AS $$
    WITH RECURSIVE subject_expansion AS (
        SELECT object_type,
               object_id,
               relation,
               subject_id,
               subject_set_type,
               subject_set_relation,
               id,
               created_at
          FROM auth.authz_relations
         WHERE object_type = p_object_type
           AND object_id   = p_object_id
           AND relation    = ANY(p_relation)
        UNION ALL
        SELECT se.object_type,
               se.object_id,
               se.relation,
               rt.subject_id,
               rt.subject_set_type,
               rt.subject_set_relation,
               rt.id,
               rt.created_at
          FROM auth.authz_relations rt
          JOIN subject_expansion se
            ON rt.object_type = se.subject_set_type
           AND rt.object_id   = se.subject_id
           AND rt.relation    = se.subject_set_relation
         WHERE se.subject_set_type     IS NOT NULL
           AND se.subject_set_relation IS NOT NULL
    )
    CYCLE subject_id SET is_cycle USING cycle_path
    SELECT object_type,
           object_id,
           relation,
           subject_id,
           id,
           created_at
      FROM subject_expansion
     WHERE subject_set_type     IS NULL
       AND subject_set_relation IS NULL
       AND NOT is_cycle
$$;

-- ──────────────────────────────────────────────────────────────────────────────
-- authz_lookup_resources: given a subject, return all objects of a given type that
-- the subject can access via the specified relation(s). Used by lookup-objects.
-- ──────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION auth.authz_lookup_resources(
    p_subject_id  text,
    p_relation    text,
    p_object_type text
) RETURNS TABLE (
    object_type text,
    object_id   text,
    relation    text,
    subject_id  text
)
    LANGUAGE sql PARALLEL SAFE STABLE
AS $$
    WITH RECURSIVE object_access AS (
        SELECT object_type, object_id, relation, subject_id
          FROM auth.authz_relations
         WHERE subject_id       = p_subject_id
           AND subject_set_type IS NULL
        UNION ALL
        SELECT rt.object_type, rt.object_id, rt.relation, oa.subject_id
          FROM auth.authz_relations rt
          JOIN object_access oa ON rt.subject_id           = oa.object_id
                                AND rt.subject_set_type     = oa.object_type
                                AND rt.subject_set_relation = oa.relation
    )
    CYCLE object_id, object_type, relation SET is_cycle USING cycle_path
    SELECT object_type, object_id, relation, subject_id
      FROM object_access
     WHERE object_type = p_object_type
       AND relation    = p_relation
       AND NOT is_cycle
$$;

CREATE OR REPLACE FUNCTION auth.authz_lookup_resources(
    p_subject_id  text,
    p_relation    text[],
    p_object_type text
) RETURNS TABLE (
    object_type text,
    object_id   text,
    relation    text,
    subject_id  text
)
    LANGUAGE sql PARALLEL SAFE STABLE
AS $$
    WITH RECURSIVE object_access AS (
        SELECT object_type, object_id, relation, subject_id
          FROM auth.authz_relations
         WHERE subject_id       = p_subject_id
           AND subject_set_type IS NULL
        UNION ALL
        SELECT rt.object_type, rt.object_id, rt.relation, oa.subject_id
          FROM auth.authz_relations rt
          JOIN object_access oa ON rt.subject_id           = oa.object_id
                                AND rt.subject_set_type     = oa.object_type
                                AND rt.subject_set_relation = oa.relation
    )
    CYCLE object_id, object_type, relation SET is_cycle USING cycle_path
    SELECT object_type, object_id, relation, subject_id
      FROM object_access
     WHERE object_type = p_object_type
       AND relation    = ANY(p_relation)
       AND NOT is_cycle
$$;

-- ──────────────────────────────────────────────────────────────────────────────
-- authz_schema CHECK constraint.
-- Guards against direct-DB writes that would corrupt the schema. Validates the
-- outer structure: version = 1, resources is a non-empty array, every resource
-- has name (string), roles (array), permissions (object). Identifier format and
-- cross-references are still enforced in the app layer.
-- ──────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION auth.authz_schema_valid(schema jsonb)
    RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT CASE
        WHEN NOT (schema ? 'version' AND schema ? 'resources')  THEN false
        WHEN jsonb_typeof(schema->'version')   <> 'number'      THEN false
        WHEN (schema->>'version')::int         <> 1             THEN false
        WHEN jsonb_typeof(schema->'resources') <> 'array'       THEN false
        WHEN jsonb_array_length(schema->'resources') < 1        THEN false
        ELSE NOT EXISTS (
            SELECT 1
              FROM jsonb_array_elements(schema->'resources') r
             WHERE jsonb_typeof(r->'name')        <> 'string'
                OR jsonb_typeof(r->'roles')        <> 'array'
                OR jsonb_typeof(r->'permissions')  <> 'object'
        )
    END
$$;

ALTER TABLE auth.app_config
    ADD CONSTRAINT authz_schema_valid
    CHECK (authz_schema IS NULL OR auth.authz_schema_valid(authz_schema));
