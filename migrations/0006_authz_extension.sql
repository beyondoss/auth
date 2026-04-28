SET search_path = auth, public;

-- Replace PL/pgSQL authz_check overloads with the Rust/pgrx implementation when
-- the shared library is present. If authz_extension.so is absent from pg_config
-- --pkglibdir, the LOAD probe raises an exception and this block returns early,
-- leaving the PL/pgSQL functions from 0004 unchanged.
--
-- This lets xtask (sqlx prepare) and bench baseline runs proceed without the
-- library present. Production deployments place the .so in $libdir before
-- applying this migration.
--
-- authz_check_path, authz_lookup_subjects, and authz_lookup_resources are pure
-- LANGUAGE sql PARALLEL SAFE recursive CTEs and are not affected here.

DO $$
BEGIN
    BEGIN
        LOAD 'authz_extension';
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'authz_extension library not found; keeping PL/pgSQL authz_check';
        RETURN;
    END;

    DROP FUNCTION IF EXISTS auth.authz_check(text, text, text, text);
    DROP FUNCTION IF EXISTS auth.authz_check(text, text[], text, text);
    DROP FUNCTION IF EXISTS auth.authz_check_v2(text, text, text, text);

    CREATE FUNCTION auth.authz_check(
        subject_id  text,
        relation    text,
        object_type text,
        object_id   text
    ) RETURNS boolean
        LANGUAGE c
        STABLE
        AS 'authz_extension', 'authz_check_single_wrapper';

    CREATE FUNCTION auth.authz_check(
        subject_id  text,
        relations   text[],
        object_type text,
        object_id   text
    ) RETURNS boolean
        LANGUAGE c
        STABLE
        AS 'authz_extension', 'authz_check_array_wrapper';

    RAISE NOTICE 'authz_extension: replaced authz_check with Rust/pgrx BFS implementation';
END $$;
