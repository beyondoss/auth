SET search_path = auth, public;

-- Authz schema stored as JSON on the singleton app_config row.
-- NULL means authz is disabled; PUT /v1/authz/schema is the only way to enable it.

ALTER TABLE auth.app_config
    ADD COLUMN authz_schema jsonb;

-- array_sort: needed by authz_check to produce stable cache keys for multi-relation
-- lookups regardless of caller-supplied relation ordering.

CREATE OR REPLACE FUNCTION auth.array_sort(anyarray)
    RETURNS anyarray
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT ARRAY(SELECT unnest($1) ORDER BY 1)
$$;

-- Relation tuples: the core storage for all authorization relationships.
-- Partitioned by object_type so hot types (e.g. 'document') can get dedicated
-- partitions without touching any other data. Start with a single DEFAULT
-- partition; add dedicated partitions via migrations/templates/add_object_type_partition.sql.template.
--
-- ID columns are text (not uuid/bigint) for maximum compatibility with
-- user-provided object identifiers: UUIDs, slugs, integers, arbitrary strings.

CREATE TABLE auth.relation_tuple (
    id               uuid        NOT NULL DEFAULT uuidv7()
                                 CHECK (auth.uuid_version(id) = 7),
    object_id        text        NOT NULL CHECK (object_id <> ''),
    object_type      text        NOT NULL,
    relation         text        NOT NULL,
    subject_id       text        NOT NULL CHECK (subject_id <> ''),
    -- subject_type and subject_relation are only set for subject-set relationships
    -- (e.g. "members of team X"). NULL means the subject is a direct user.
    subject_type     text        DEFAULT NULL,
    subject_relation text        DEFAULT NULL,
    created_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT relation_tuple_pkey PRIMARY KEY (id, object_type)
) PARTITION BY LIST (object_type);

-- Default partition catches all object types not yet given a dedicated partition.
CREATE TABLE auth.relation_tuple_default
    PARTITION OF auth.relation_tuple DEFAULT;

-- Unique constraint on the logical tuple identity.
-- NULLS NOT DISTINCT treats NULLs as equal so (obj, rel, subj, NULL, NULL) is one row.
CREATE UNIQUE INDEX relation_tuple_key ON auth.relation_tuple (
    object_type,
    object_id,
    relation,
    subject_type,
    subject_id,
    subject_relation ASC NULLS FIRST
) NULLS NOT DISTINCT;

-- Forward index: used by authz_enumerate() — find all objects a subject can access.
CREATE INDEX relation_tuple_subject_lookup_idx ON auth.relation_tuple (
    subject_id,
    object_type,
    relation
);

-- Partial index for recursive CTE traversal: find tuples where this entity is
-- a subject set. Only rows with subject_type set participate in set expansion.
CREATE INDEX relation_tuple_subject_set_idx ON auth.relation_tuple (
    subject_type,
    subject_id,
    subject_relation
) WHERE subject_type IS NOT NULL;

-- authz_check_cache: DB-side permission result cache, invalidated by trigger on
-- relation_tuple writes. HASH-partitioned for parallel cache eviction under load.

CREATE TABLE auth.authz_check_cache (
    cache_key   text        PRIMARY KEY,
    object_type text        NOT NULL,
    object_id   text        NOT NULL,
    relation    text        NOT NULL,
    subject_id  text        NOT NULL,
    is_allowed  boolean     NOT NULL,
    computed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at  timestamptz NOT NULL DEFAULT clock_timestamp() + interval '5 minutes'
) PARTITION BY HASH (cache_key);

CREATE TABLE auth.authz_check_cache_0 PARTITION OF auth.authz_check_cache FOR VALUES WITH (MODULUS 8, REMAINDER 0);
CREATE TABLE auth.authz_check_cache_1 PARTITION OF auth.authz_check_cache FOR VALUES WITH (MODULUS 8, REMAINDER 1);
CREATE TABLE auth.authz_check_cache_2 PARTITION OF auth.authz_check_cache FOR VALUES WITH (MODULUS 8, REMAINDER 2);
CREATE TABLE auth.authz_check_cache_3 PARTITION OF auth.authz_check_cache FOR VALUES WITH (MODULUS 8, REMAINDER 3);
CREATE TABLE auth.authz_check_cache_4 PARTITION OF auth.authz_check_cache FOR VALUES WITH (MODULUS 8, REMAINDER 4);
CREATE TABLE auth.authz_check_cache_5 PARTITION OF auth.authz_check_cache FOR VALUES WITH (MODULUS 8, REMAINDER 5);
CREATE TABLE auth.authz_check_cache_6 PARTITION OF auth.authz_check_cache FOR VALUES WITH (MODULUS 8, REMAINDER 6);
CREATE TABLE auth.authz_check_cache_7 PARTITION OF auth.authz_check_cache FOR VALUES WITH (MODULUS 8, REMAINDER 7);

-- BRIN is tiny and sufficient here: cache rows are append-mostly and cleanup
-- queries scan by expires_at range.
CREATE INDEX authz_check_cache_expires_at_idx  ON auth.authz_check_cache USING BRIN (expires_at);
CREATE INDEX authz_check_cache_object_idx      ON auth.authz_check_cache (object_type, object_id);
CREATE INDEX authz_check_cache_subject_idx     ON auth.authz_check_cache USING HASH (subject_id);

-- ──────────────────────────────────────────────────────────────────────────────
-- authz_check_direct: recursive CTE permission check (no cache). Three overloads:
--   1. single relation
--   2. array of relations (any match)
--   3. relation path (multi-hop hierarchy traversal)
-- ──────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION auth.authz_check_direct(
    p_subject_id  text,
    p_relation    text,
    p_object_type text,
    p_object_id   text
) RETURNS boolean
    LANGUAGE sql PARALLEL SAFE STABLE
AS $$
    WITH RECURSIVE permission_check AS (
        SELECT subject_id, subject_type, subject_relation, 0 AS depth
        FROM auth.relation_tuple
        WHERE object_type = p_object_type
          AND object_id   = p_object_id
          AND relation    = p_relation
        UNION ALL
        SELECT rt.subject_id, rt.subject_type, rt.subject_relation, pc.depth + 1
        FROM auth.relation_tuple rt
        JOIN permission_check pc
          ON rt.object_type = pc.subject_type
         AND rt.object_id   = pc.subject_id
         AND rt.relation    = pc.subject_relation
        WHERE pc.subject_type     IS NOT NULL
          AND pc.subject_relation IS NOT NULL
          AND pc.depth < 10
    )
    SELECT EXISTS (
        SELECT 1 FROM permission_check
        WHERE subject_id = p_subject_id
          AND (subject_type IS NULL OR subject_relation IS NULL)
    )
$$;

CREATE OR REPLACE FUNCTION auth.authz_check_direct(
    p_subject_id  text,
    p_relation    text[],
    p_object_type text,
    p_object_id   text
) RETURNS boolean
    LANGUAGE sql PARALLEL SAFE STABLE
AS $$
    WITH RECURSIVE permission_check AS (
        SELECT subject_id, subject_type, subject_relation, 0 AS depth
        FROM auth.relation_tuple
        WHERE object_type = p_object_type
          AND object_id   = p_object_id
          AND relation    = ANY(p_relation)
        UNION ALL
        SELECT rt.subject_id, rt.subject_type, rt.subject_relation, pc.depth + 1
        FROM auth.relation_tuple rt
        JOIN permission_check pc
          ON rt.object_type = pc.subject_type
         AND rt.object_id   = pc.subject_id
         AND rt.relation    = pc.subject_relation
        WHERE pc.subject_type     IS NOT NULL
          AND pc.subject_relation IS NOT NULL
          AND pc.depth < 10
    )
    SELECT EXISTS (
        SELECT 1 FROM permission_check
        WHERE subject_id = p_subject_id
          AND (subject_type IS NULL OR subject_relation IS NULL)
    )
$$;

-- Path variant: walks a sequence of (relation, object_type) hops.
-- Used for multi-hop hierarchy checks, e.g. document→folder→owner.
CREATE OR REPLACE FUNCTION auth.authz_check_direct(
    p_subject_id       text,
    p_relation_path    text[],
    p_object_type_path text[],
    p_object_id        text
) RETURNS boolean
    LANGUAGE sql PARALLEL SAFE STABLE
AS $$
    WITH RECURSIVE path_check AS (
        SELECT subject_id, subject_type, subject_relation, 1 AS depth
        FROM auth.relation_tuple
        WHERE object_type = p_object_type_path[1]
          AND object_id   = p_object_id
          AND relation    = p_relation_path[1]
        UNION ALL
        SELECT rt.subject_id, rt.subject_type, rt.subject_relation, pc.depth + 1
        FROM auth.relation_tuple rt
        JOIN path_check pc ON rt.object_id = pc.subject_id
        WHERE rt.object_type = p_object_type_path[pc.depth + 1]
          AND rt.relation    = p_relation_path[pc.depth + 1]
          AND pc.depth < array_length(p_relation_path, 1)
    )
    SELECT EXISTS (
        SELECT 1 FROM path_check
        WHERE subject_id = p_subject_id
          AND (subject_type IS NULL OR subject_relation IS NULL)
    )
$$;

-- ──────────────────────────────────────────────────────────────────────────────
-- authz_check: cached wrapper around authz_check_direct. Three overloads matching
-- authz_check_direct. Results are cached for 5 minutes; the trigger below
-- invalidates relevant cache entries on any relation_tuple mutation.
-- ──────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION auth.authz_check(
    p_subject_id  text,
    p_relation    text,
    p_object_type text,
    p_object_id   text
) RETURNS boolean
    LANGUAGE plpgsql
AS $$
DECLARE
    v_cache_key  text;
    v_is_allowed boolean;
    v_expires_at timestamptz;
BEGIN
    v_cache_key := p_subject_id || ':' || p_relation || ':' || p_object_type || ':' || p_object_id;
    SELECT is_allowed, expires_at
      INTO v_is_allowed, v_expires_at
      FROM auth.authz_check_cache
     WHERE cache_key = v_cache_key
       AND expires_at > clock_timestamp();
    IF FOUND THEN
        RETURN v_is_allowed;
    END IF;
    v_is_allowed := auth.authz_check_direct(p_subject_id, p_relation, p_object_type, p_object_id);
    INSERT INTO auth.authz_check_cache (cache_key, object_type, object_id, relation, subject_id, is_allowed)
         VALUES (v_cache_key, p_object_type, p_object_id, p_relation, p_subject_id, v_is_allowed)
    ON CONFLICT (cache_key) DO UPDATE
        SET is_allowed  = EXCLUDED.is_allowed,
            computed_at = clock_timestamp(),
            expires_at  = clock_timestamp() + interval '5 minutes';
    RETURN v_is_allowed;
END;
$$;

CREATE OR REPLACE FUNCTION auth.authz_check(
    p_subject_id  text,
    p_relation    text[],
    p_object_type text,
    p_object_id   text
) RETURNS boolean
    LANGUAGE plpgsql
AS $$
DECLARE
    v_cache_key  text;
    v_is_allowed boolean;
    v_expires_at timestamptz;
BEGIN
    v_cache_key := p_subject_id || ':' || array_to_string(auth.array_sort(p_relation), ',') || ':' || p_object_type || ':' || p_object_id;
    SELECT is_allowed, expires_at
      INTO v_is_allowed, v_expires_at
      FROM auth.authz_check_cache
     WHERE cache_key = v_cache_key
       AND expires_at > clock_timestamp();
    IF FOUND THEN
        RETURN v_is_allowed;
    END IF;
    v_is_allowed := auth.authz_check_direct(p_subject_id, p_relation, p_object_type, p_object_id);
    INSERT INTO auth.authz_check_cache (cache_key, object_type, object_id, relation, subject_id, is_allowed)
         VALUES (v_cache_key, p_object_type, p_object_id, array_to_string(auth.array_sort(p_relation), ','), p_subject_id, v_is_allowed)
    ON CONFLICT (cache_key) DO UPDATE
        SET is_allowed  = EXCLUDED.is_allowed,
            computed_at = clock_timestamp(),
            expires_at  = clock_timestamp() + interval '5 minutes';
    RETURN v_is_allowed;
END;
$$;

-- Path variant has no cache: the cache key would need to encode the full path
-- arrays and the benefit is marginal for debug/hierarchy traversal paths.
CREATE OR REPLACE FUNCTION auth.authz_check(
    p_subject_id       text,
    p_relation_path    text[],
    p_object_type_path text[],
    p_object_id        text
) RETURNS boolean
    LANGUAGE plpgsql
AS $$
BEGIN
    RETURN auth.authz_check_direct(p_subject_id, p_relation_path, p_object_type_path, p_object_id);
END;
$$;

-- ──────────────────────────────────────────────────────────────────────────────
-- authz_expand: given an object + relation, return all direct subjects
-- (resolves subject sets recursively). Used by the /v1/authz/expand endpoint
-- and internally by the why-check trace.
-- ──────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION auth.authz_expand(
    p_relation    text,
    p_object_type text,
    p_object_id   text
) RETURNS TABLE (
    r_object_type text,
    r_object_id   text,
    r_relation    text,
    r_subject_id  text,
    r_tuple_id    uuid,
    r_created_at  timestamptz
)
    LANGUAGE sql PARALLEL SAFE STABLE
AS $$
    WITH RECURSIVE subject_expansion AS (
        SELECT object_type,
               object_id,
               relation,
               subject_id,
               subject_type,
               subject_relation,
               id,
               created_at,
               0              AS depth,
               ARRAY[subject_id] AS seen_subjects
          FROM auth.relation_tuple
         WHERE object_type = p_object_type
           AND object_id   = p_object_id
           AND relation    = p_relation
        UNION ALL
        SELECT se.object_type,
               se.object_id,
               se.relation,
               rt.subject_id,
               rt.subject_type,
               rt.subject_relation,
               rt.id,
               rt.created_at,
               se.depth + 1,
               se.seen_subjects || rt.subject_id
          FROM auth.relation_tuple rt
          JOIN subject_expansion se
            ON rt.object_type = se.subject_type
           AND rt.object_id   = se.subject_id
           AND rt.relation    = se.subject_relation
         WHERE se.subject_type     IS NOT NULL
           AND se.subject_relation IS NOT NULL
           AND se.depth < 10
           AND NOT (rt.subject_id = ANY(se.seen_subjects))
    )
    SELECT object_type,
           object_id,
           relation,
           subject_id,
           id,
           created_at
      FROM subject_expansion
     WHERE subject_type     IS NULL
       AND subject_relation IS NULL
$$;

CREATE OR REPLACE FUNCTION auth.authz_expand(
    p_relation    text[],
    p_object_type text,
    p_object_id   text
) RETURNS TABLE (
    r_object_type text,
    r_object_id   text,
    r_relation    text,
    r_subject_id  text,
    r_tuple_id    uuid,
    r_created_at  timestamptz
)
    LANGUAGE sql PARALLEL SAFE STABLE
AS $$
    WITH RECURSIVE subject_expansion AS (
        SELECT object_type,
               object_id,
               relation,
               subject_id,
               subject_type,
               subject_relation,
               id,
               created_at,
               0              AS depth,
               ARRAY[subject_id] AS seen_subjects
          FROM auth.relation_tuple
         WHERE object_type = p_object_type
           AND object_id   = p_object_id
           AND relation    = ANY(p_relation)
        UNION ALL
        SELECT se.object_type,
               se.object_id,
               se.relation,
               rt.subject_id,
               rt.subject_type,
               rt.subject_relation,
               rt.id,
               rt.created_at,
               se.depth + 1,
               se.seen_subjects || rt.subject_id
          FROM auth.relation_tuple rt
          JOIN subject_expansion se
            ON rt.object_type = se.subject_type
           AND rt.object_id   = se.subject_id
           AND rt.relation    = se.subject_relation
         WHERE se.subject_type     IS NOT NULL
           AND se.subject_relation IS NOT NULL
           AND se.depth < 10
           AND NOT (rt.subject_id = ANY(se.seen_subjects))
    )
    SELECT object_type,
           object_id,
           relation,
           subject_id,
           id,
           created_at
      FROM subject_expansion
     WHERE subject_type     IS NULL
       AND subject_relation IS NULL
$$;

-- ──────────────────────────────────────────────────────────────────────────────
-- authz_enumerate: given a subject, return all objects of a given type that the
-- subject can access via the specified relation(s). Used by lookup-objects.
-- ──────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION auth.authz_enumerate(
    p_subject_id  text,
    p_relation    text,
    p_object_type text
) RETURNS TABLE (
    r_object_type text,
    r_object_id   text,
    r_relation    text,
    r_subject_id  text
)
    LANGUAGE sql PARALLEL SAFE STABLE
AS $$
    WITH RECURSIVE object_access AS (
        SELECT object_type,
               object_id,
               relation,
               subject_id,
               0              AS depth,
               ARRAY[object_id || '#' || relation] AS seen_rels
          FROM auth.relation_tuple
         WHERE subject_id = p_subject_id
        UNION ALL
        SELECT rt.object_type,
               rt.object_id,
               rt.relation,
               oa.subject_id,
               oa.depth + 1,
               oa.seen_rels || (rt.object_id || '#' || rt.relation)
          FROM auth.relation_tuple rt
          JOIN object_access oa ON rt.subject_id = oa.object_id
         WHERE oa.depth < 10
           AND NOT (rt.object_id || '#' || rt.relation = ANY(oa.seen_rels))
    )
    SELECT object_type, object_id, relation, subject_id
      FROM object_access
     WHERE object_type = p_object_type
       AND relation    = p_relation
$$;

CREATE OR REPLACE FUNCTION auth.authz_enumerate(
    p_subject_id  text,
    p_relation    text[],
    p_object_type text
) RETURNS TABLE (
    r_object_type text,
    r_object_id   text,
    r_relation    text,
    r_subject_id  text
)
    LANGUAGE sql PARALLEL SAFE STABLE
AS $$
    WITH RECURSIVE object_access AS (
        SELECT object_type,
               object_id,
               relation,
               subject_id,
               0              AS depth,
               ARRAY[object_id || '#' || relation] AS seen_rels
          FROM auth.relation_tuple
         WHERE subject_id = p_subject_id
        UNION ALL
        SELECT rt.object_type,
               rt.object_id,
               rt.relation,
               oa.subject_id,
               oa.depth + 1,
               oa.seen_rels || (rt.object_id || '#' || rt.relation)
          FROM auth.relation_tuple rt
          JOIN object_access oa ON rt.subject_id = oa.object_id
         WHERE oa.depth < 10
           AND NOT (rt.object_id || '#' || rt.relation = ANY(oa.seen_rels))
    )
    SELECT object_type, object_id, relation, subject_id
      FROM object_access
     WHERE object_type = p_object_type
       AND relation    = ANY(p_relation)
$$;

-- ──────────────────────────────────────────────────────────────────────────────
-- Cache invalidation: any write to relation_tuple clears cached check results
-- for the affected object and subject. Handles inherited permission changes.
-- ──────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION auth.authz_invalidate_cache()
    RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD IS NOT DISTINCT FROM NEW THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'DELETE' THEN
        DELETE FROM auth.authz_check_cache
         WHERE object_type = OLD.object_type AND object_id = OLD.object_id;
        DELETE FROM auth.authz_check_cache
         WHERE subject_id = OLD.subject_id;
    ELSE
        DELETE FROM auth.authz_check_cache
         WHERE object_type = NEW.object_type AND object_id = NEW.object_id;
        DELETE FROM auth.authz_check_cache
         WHERE subject_id = NEW.subject_id;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER trigger_invalidate_cache
    AFTER INSERT OR UPDATE OR DELETE ON auth.relation_tuple
    FOR EACH ROW EXECUTE FUNCTION auth.authz_invalidate_cache();
