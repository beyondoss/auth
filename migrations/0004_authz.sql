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

CREATE FUNCTION auth.authz_check(
    subject_id  text,
    relation    text,
    object_type text,
    object_id   text
) RETURNS boolean
    LANGUAGE c STABLE STRICT
    AS 'beyond_auth', 'authz_check_single_wrapper';

COMMENT ON FUNCTION auth.authz_check(text, text, text, text) IS
'Ask: does subject_id hold relation on (object_type, object_id)?

Returns true if the answer is yes — directly or through any depth of group/set
membership (e.g. user → team → org that holds the relation). Cycles are safe.

Use authz_check_parallel_batch when checking many tuples at once.';

CREATE FUNCTION auth.authz_check(
    subject_id  text,
    relations   text[],
    object_type text,
    object_id   text
) RETURNS boolean
    LANGUAGE c STABLE STRICT
    AS 'beyond_auth', 'authz_check_array_wrapper';

COMMENT ON FUNCTION auth.authz_check(text, text[], text, text) IS
'Ask: does subject_id hold any of the given relations on (object_type, object_id)?

Same as authz_check(text, text, text, text) but accepts an array of relations
and returns true if the subject holds at least one of them.';

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

COMMENT ON FUNCTION auth.authz_check_path(text, text[], text[], text) IS
'Multi-hop hierarchy check along a fixed (relation, object_type) path.

Walks outward from (p_object_type_path[1], p_object_id) hop by hop and returns
true if p_subject_id appears as a direct subject at any hop.

Note: subject-set expansion (group membership) is NOT performed at any hop —
only direct subjects are matched. Use authz_check if you need group expansion.

Example: check if user U owns folder F that document D links to —
  authz_check_path(U, ARRAY[''folder'', ''owner''], ARRAY[''document'', ''folder''], D)';

CREATE FUNCTION auth.authz_check_path(
    p_subject_id         text,
    p_relation_prefix    text[],
    p_object_type_path   text[],
    p_terminal_relations text[],
    p_object_id          text
) RETURNS boolean
    LANGUAGE sql PARALLEL SAFE STABLE
AS $$
    WITH RECURSIVE path_check AS (
        SELECT subject_id, subject_set_type, subject_set_relation, 1 AS depth
          FROM auth.authz_relations
         WHERE object_type      = p_object_type_path[1]
           AND object_id        = p_object_id
           AND relation         = p_relation_prefix[1]
           AND subject_set_type IS NULL
        UNION ALL
        SELECT rt.subject_id, rt.subject_set_type, rt.subject_set_relation, pc.depth + 1
          FROM auth.authz_relations rt
          JOIN path_check pc ON rt.object_id = pc.subject_id
         WHERE rt.object_type      = p_object_type_path[pc.depth + 1]
           AND rt.subject_set_type IS NULL
           AND pc.depth <= array_length(p_relation_prefix, 1)
           AND CASE
               WHEN pc.depth < array_length(p_relation_prefix, 1)
               THEN rt.relation = p_relation_prefix[pc.depth + 1]
               ELSE rt.relation = ANY(p_terminal_relations)
               END
    )
    CYCLE subject_id SET is_cycle USING cycle_path
    SELECT EXISTS (
        SELECT 1 FROM path_check
         WHERE subject_id = p_subject_id
           AND depth      = array_length(p_relation_prefix, 1) + 1
           AND NOT is_cycle
    )
$$;

COMMENT ON FUNCTION auth.authz_check_path(text, text[], text[], text[], text) IS
'Multi-hop hierarchy check — any-of-terminal-relations variant.

Same traversal as authz_check_path(text, text[], text[], text) but accepts an
array of accepted relations at the final hop instead of embedding one relation
per call. Use this when checking a permission that maps to multiple roles
(e.g. read = [viewer, editor, owner]) to collapse N calls into 1.

Example: check if user U holds any of owner/editor/viewer on the folder that
document D links to —
  authz_check_path(U, ARRAY[''folder''], ARRAY[''document'',''folder''],
                   ARRAY[''owner'',''editor'',''viewer''], D)';

CREATE FUNCTION auth.authz_check_path_batch(
    subject_ids          text[],
    relation_prefix      text[],
    object_type_path     text[],
    terminal_relations   text[],
    object_ids           text[]
) RETURNS boolean[]
    LANGUAGE c STABLE STRICT
    AS 'beyond_auth', 'authz_check_path_batch_wrapper';

COMMENT ON FUNCTION auth.authz_check_path_batch(text[], text[], text[], text[], text[]) IS
'Parallel hierarchy batch check.

Accepts N parallel (subject_ids, object_ids) pairs, all sharing the same path
structure (relation_prefix, object_type_path, terminal_relations), and returns a
boolean[] in the same order.

All N checks are evaluated simultaneously — one SQL query per path hop — so
total queries = hops + 1 regardless of N.

Used by: POST /v1/authz/checks for MultiHop (hierarchy) permission checks.';

CREATE FUNCTION auth.authz_check_multi(
    subject_id         text,
    direct_relations   text[],
    relation_prefix    text[],
    object_type_path   text[],
    terminal_relations text[],
    object_id          text
) RETURNS boolean
    LANGUAGE c STABLE STRICT
    AS 'beyond_auth', 'authz_check_multi_wrapper';

COMMENT ON FUNCTION auth.authz_check_multi(text, text[], text[], text[], text[], text) IS
'Ask: does subject_id hold any of direct_relations on (object_type_path[1], object_id),
or hold any of terminal_relations on an ancestor reached by following relation_prefix?

Returns true if the subject has direct access to the object OR has access via any
level of the parent hierarchy. Subject-set expansion (group membership) is performed
for the direct check; hierarchy hops use direct subjects only.

Example: check if user U can read document D, where read is granted by
owner/editor/viewer directly on the document or inherited from its parent folder —
  authz_check_multi(U,
    ARRAY[''owner'',''editor'',''viewer''],
    ARRAY[''folder''],
    ARRAY[''document'',''folder''],
    ARRAY[''owner'',''editor'',''viewer''],
    D
  )';

CREATE FUNCTION auth.authz_check_batch(
    subject_ids  text[],
    relations    text[],
    object_types text[],
    object_ids   text[]
) RETURNS boolean[]
    LANGUAGE c STABLE STRICT
    AS 'beyond_auth', 'authz_check_batch_wrapper';

COMMENT ON FUNCTION auth.authz_check_batch(text[], text[], text[], text[]) IS
'Bulk permission check — sequential. Accepts N parallel arrays (subject_ids,
relations, object_types, object_ids) and returns a boolean[] in the same order.

For large batches, prefer authz_check_parallel_batch — it is significantly
faster because it processes all checks at each graph depth in a single query.';

CREATE FUNCTION auth.authz_check_parallel_batch(
    subject_ids  text[],
    relations    text[],
    object_types text[],
    object_ids   text[]
) RETURNS boolean[]
    LANGUAGE c STABLE STRICT
    AS 'beyond_auth', 'authz_check_parallel_batch_wrapper';

COMMENT ON FUNCTION auth.authz_check_parallel_batch(text[], text[], text[], text[]) IS
'Bulk permission check — parallel. The preferred function for checking many
tuples at once. Accepts N parallel arrays (subject_ids, relations, object_types,
object_ids) and returns a boolean[] in the same order.

All checks are evaluated simultaneously at each graph depth level, making this
significantly faster than authz_check_batch for any meaningful batch size.

Used by: POST /v1/authz/checks.';

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

COMMENT ON FUNCTION auth.authz_lookup_subjects(text, text, text) IS
'Return all leaf subjects reachable from (p_object_type, p_object_id) via p_relation.

Recursively expands subject-set rows (e.g. a group relation) until only direct
user IDs remain. Handles cycles. Each returned row carries the original
(object_type, object_id, relation) anchor plus the resolved subject_id and
the tuple''s created_at timestamp.

Used by: GET /v1/authz/subjects (expand endpoint) and the explain/trace path.';

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

COMMENT ON FUNCTION auth.authz_lookup_subjects(text[], text, text) IS
'Return all leaf subjects reachable from (p_object_type, p_object_id) via any relation in p_relation.

Array-of-relations overload of authz_lookup_subjects(text, text, text).
Returns the union of subjects across all listed relations in one query.';

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

COMMENT ON FUNCTION auth.authz_lookup_resources(text, text, text) IS
'Return all objects of p_object_type that p_subject_id can access via p_relation.

Walks the relation graph from the subject outward, following subject-set
memberships in reverse (i.e. if subject S is a member of group G, and G holds
a relation on object O, then O is reachable from S). Handles cycles.

Used by: GET /v1/authz/objects (lookup-objects endpoint).';

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

COMMENT ON FUNCTION auth.authz_lookup_resources(text, text[], text) IS
'Return all objects of p_object_type that p_subject_id can access via any relation in p_relation.

Array-of-relations overload of authz_lookup_resources(text, text, text).
Returns the union of accessible objects across all listed relations in one query.';

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

COMMENT ON FUNCTION auth.authz_schema_valid(jsonb) IS
'Structural validator for the authz schema JSON stored in app_config.authz_schema.

Checks: version = 1, resources is a non-empty array, every resource has a
string name, an array roles, and an object permissions. Identifier format and
cross-reference correctness are enforced in the application layer before the
row is written; this function is the last-resort DB-level guard.

Called exclusively by the authz_schema_valid CHECK constraint on app_config.';

ALTER TABLE auth.app_config
    ADD CONSTRAINT authz_schema_valid
    CHECK (authz_schema IS NULL OR auth.authz_schema_valid(authz_schema));
