use std::collections::HashSet;

use chrono::{DateTime, Utc};
use quick_cache::sync::Cache;
use sqlx::PgPool;
use tracing;
use uuid::Uuid;

use crate::{authz::schema::ValidIdent, error::AuthError};

// ── Write / delete relations ──────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn write_relation(
    pool: &PgPool,
    partition_cache: &Cache<String, ()>,
    object_type: &ValidIdent,
    object_id: &str,
    relation: &str,
    subject_id: &str,
    subject_set_type: Option<&str>,
    subject_set_relation: Option<&str>,
) -> Result<(), AuthError> {
    ensure_partition(pool, object_type, partition_cache).await?;
    sqlx::query!(
        r#"
        INSERT INTO auth.authz_relations
            (object_type, object_id, relation, subject_id, subject_set_type, subject_set_relation)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT DO NOTHING
        "#,
        object_type.as_str(),
        object_id,
        relation,
        subject_id,
        subject_set_type,
        subject_set_relation,
    )
    .execute(pool)
    .await
    .map_err(AuthError::from)?;
    Ok(())
}

pub async fn delete_relation(
    pool: &PgPool,
    object_type: &str,
    object_id: &str,
    relation: &str,
    subject_id: &str,
    subject_set_type: Option<&str>,
    subject_set_relation: Option<&str>,
) -> Result<bool, AuthError> {
    let result = sqlx::query!(
        r#"
        DELETE FROM auth.authz_relations
        WHERE object_type            = $1
          AND object_id              = $2
          AND relation               = $3
          AND subject_id             = $4
          AND subject_set_type     IS NOT DISTINCT FROM $5
          AND subject_set_relation IS NOT DISTINCT FROM $6
        "#,
        object_type,
        object_id,
        relation,
        subject_id,
        subject_set_type,
        subject_set_relation,
    )
    .execute(pool)
    .await
    .map_err(AuthError::from)?;
    Ok(result.rows_affected() > 0)
}

pub struct BatchOp {
    pub object_type: ValidIdent,
    pub object_id: String,
    pub relation: String,
    pub subject_id: String,
    pub subject_set_type: Option<String>,
    pub subject_set_relation: Option<String>,
}

pub struct BatchResult {
    pub written: u64,
    pub deleted: u64,
}

pub async fn batch_relations(
    pool: &PgPool,
    partition_cache: &Cache<String, ()>,
    writes: Vec<BatchOp>,
    deletes: Vec<BatchOp>,
) -> Result<BatchResult, AuthError> {
    // Ensure partitions for every distinct write object_type before opening the tx.
    // DDL inside a tx would conflict with auto-commit semantics; we want the partition
    // table to exist independently of the write succeeding.
    let mut seen: HashSet<&str> = HashSet::new();
    for op in &writes {
        if seen.insert(op.object_type.as_str()) {
            ensure_partition(pool, &op.object_type, partition_cache).await?;
        }
    }

    let mut tx = pool.begin().await.map_err(AuthError::from)?;
    let mut written = 0u64;
    let mut deleted = 0u64;

    // Non-macro batch INSERT/DELETE: execute-only, no row data accessed.
    if !writes.is_empty() {
        let w_object_type: Vec<&str> = writes.iter().map(|o| o.object_type.as_str()).collect();
        let w_object_id: Vec<&str> = writes.iter().map(|o| o.object_id.as_str()).collect();
        let w_relation: Vec<&str> = writes.iter().map(|o| o.relation.as_str()).collect();
        let w_subject_id: Vec<&str> = writes.iter().map(|o| o.subject_id.as_str()).collect();
        let w_subj_set_type: Vec<Option<&str>> = writes
            .iter()
            .map(|o| o.subject_set_type.as_deref())
            .collect();
        let w_subj_set_rel: Vec<Option<&str>> = writes
            .iter()
            .map(|o| o.subject_set_relation.as_deref())
            .collect();
        let r = sqlx::query(
            "INSERT INTO auth.authz_relations
                (object_type, object_id, relation, subject_id, subject_set_type, subject_set_relation)
             SELECT * FROM UNNEST(
                $1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[]
             )
             ON CONFLICT DO NOTHING",
        )
        .bind(&w_object_type)
        .bind(&w_object_id)
        .bind(&w_relation)
        .bind(&w_subject_id)
        .bind(&w_subj_set_type)
        .bind(&w_subj_set_rel)
        .execute(tx.as_mut())
        .await
        .map_err(AuthError::from)?;
        written = r.rows_affected();
    }

    if !deletes.is_empty() {
        let d_object_type: Vec<&str> = deletes.iter().map(|o| o.object_type.as_str()).collect();
        let d_object_id: Vec<&str> = deletes.iter().map(|o| o.object_id.as_str()).collect();
        let d_relation: Vec<&str> = deletes.iter().map(|o| o.relation.as_str()).collect();
        let d_subject_id: Vec<&str> = deletes.iter().map(|o| o.subject_id.as_str()).collect();
        let d_subj_set_type: Vec<Option<&str>> = deletes
            .iter()
            .map(|o| o.subject_set_type.as_deref())
            .collect();
        let d_subj_set_rel: Vec<Option<&str>> = deletes
            .iter()
            .map(|o| o.subject_set_relation.as_deref())
            .collect();
        let r = sqlx::query(
            "DELETE FROM auth.authz_relations
             USING UNNEST(
                $1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[]
             ) AS d(object_type, object_id, relation, subject_id, subject_set_type, subject_set_relation)
             WHERE auth.authz_relations.object_type            = d.object_type
               AND auth.authz_relations.object_id              = d.object_id
               AND auth.authz_relations.relation               = d.relation
               AND auth.authz_relations.subject_id             = d.subject_id
               AND auth.authz_relations.subject_set_type     IS NOT DISTINCT FROM d.subject_set_type
               AND auth.authz_relations.subject_set_relation IS NOT DISTINCT FROM d.subject_set_relation",
        )
        .bind(&d_object_type)
        .bind(&d_object_id)
        .bind(&d_relation)
        .bind(&d_subject_id)
        .bind(&d_subj_set_type)
        .bind(&d_subj_set_rel)
        .execute(tx.as_mut())
        .await
        .map_err(AuthError::from)?;
        deleted = r.rows_affected();
    }

    tx.commit().await.map_err(AuthError::from)?;
    Ok(BatchResult { written, deleted })
}

// ── Check ─────────────────────────────────────────────────────────────────────

/// Bundled CTE: validate session + authz check in one DB round-trip.
///
/// Returns `None` if the token is invalid or expired; `Some((subject_id, allowed))` otherwise.
/// `or_chain` is the SQL fragment produced by `CompiledSchema::build_or_chain`.
///
/// Uses the non-macro `sqlx::query_as` because the query shape is dynamic
/// (the OR-chain length varies by permission/schema). This is the one justified
/// exception to the type-safe macro rule.
pub async fn check_with_session(
    pool: &PgPool,
    token_id: Uuid,
    secret_hash: &[u8],
    object_id: &str,
    or_chain: &str,
    idle_timeout_seconds: Option<i32>,
) -> Result<Option<(String, bool)>, AuthError> {
    let sql = format!(
        r#"
        WITH valid_token AS (
            SELECT tokens.id AS token_id
            FROM auth.tokens
            WHERE tokens.id      = $1
              AND tokens.secret  = $2
              AND tokens.expires_at > now()
              AND (
                  $4::int4 IS NULL
                  OR tokens.last_used_at IS NULL
                  OR tokens.last_used_at > now() - make_interval(secs => $4::float8)
              )
            LIMIT 1
        ),
        update_attempt AS (
            UPDATE auth.tokens SET last_used_at = now()
            FROM valid_token
            WHERE auth.tokens.id = valid_token.token_id
              AND (auth.tokens.last_used_at IS NULL
                   OR auth.tokens.last_used_at < now() - interval '1 minute')
        ),
        subject AS (
            SELECT u.id::text AS subject_id
            FROM valid_token v
            INNER JOIN auth.sessions s ON s.token_id  = v.token_id
            INNER JOIN auth.users  u ON u.id = s.user_id AND u.deleted_at IS NULL
        )
        SELECT subject_id, (
            {or_chain}
        )
        FROM subject
        "#
    );

    sqlx::query_as::<_, (String, bool)>(&sql)
        .bind(token_id)
        .bind(secret_hash)
        .bind(object_id)
        .bind(idle_timeout_seconds)
        .fetch_optional(pool)
        .await
        .map_err(AuthError::from)
}

/// Validate a bearer token and return the subject user_id as a string for authz checks.
/// Returns `None` if the token is invalid or expired.
pub async fn resolve_session(
    pool: &PgPool,
    token_id: Uuid,
    secret_hash: &[u8],
    idle_timeout_seconds: Option<i32>,
) -> Result<Option<String>, AuthError> {
    let sql = r#"
        WITH valid_token AS (
            SELECT tokens.id AS token_id
            FROM auth.tokens
            WHERE tokens.id      = $1
              AND tokens.secret  = $2
              AND tokens.expires_at > now()
              AND (
                  $3::int4 IS NULL
                  OR tokens.last_used_at IS NULL
                  OR tokens.last_used_at > now() - make_interval(secs => $3::float8)
              )
            LIMIT 1
        ),
        update_attempt AS (
            UPDATE auth.tokens SET last_used_at = now()
            FROM valid_token
            WHERE auth.tokens.id = valid_token.token_id
              AND (auth.tokens.last_used_at IS NULL
                   OR auth.tokens.last_used_at < now() - interval '1 minute')
        )
        SELECT u.id::text
        FROM valid_token v
        INNER JOIN auth.sessions s ON s.token_id  = v.token_id
        INNER JOIN auth.users  u ON u.id = s.user_id AND u.deleted_at IS NULL
    "#;

    sqlx::query_scalar::<_, String>(sql)
        .bind(token_id)
        .bind(secret_hash)
        .bind(idle_timeout_seconds)
        .fetch_optional(pool)
        .await
        .map_err(AuthError::from)
}

/// Batch check multiple object IDs against a single subject in one round-trip.
/// `or_chain` must be built with `CompiledSchema::build_batch_or_chain` (uses `$1` for
/// subject_id and `t.object_id` from the UNNEST). Returns one bool per input object_id,
/// in the same order.
pub async fn batch_check_standalone(
    pool: &PgPool,
    subject_id: &str,
    object_ids: &[String],
    or_chain: &str,
) -> Result<Vec<bool>, AuthError> {
    let sql = format!("SELECT ({or_chain})\nFROM UNNEST($2::text[]) AS t(object_id)");

    sqlx::query_scalar::<_, bool>(&sql)
        .bind(subject_id)
        .bind(object_ids)
        .fetch_all(pool)
        .await
        .map_err(AuthError::from)
}

/// Standalone check for an explicit subject (no session CTE). Two round-trips
/// total when used after require_auth, but fine for admin/impersonation paths.
pub async fn check_standalone(
    pool: &PgPool,
    subject_id: &str,
    object_id: &str,
    or_chain: &str,
) -> Result<bool, AuthError> {
    let sql = format!("SELECT ({or_chain})");

    sqlx::query_scalar::<_, bool>(&sql)
        .bind(subject_id)
        .bind(object_id)
        .fetch_one(pool)
        .await
        .map_err(AuthError::from)
}

/// Probe whether auth.authz_check_parallel_batch exists (migration 0006 + extension loaded).
pub async fn probe_parallel_batch(pool: &PgPool) -> bool {
    match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_proc p \
         JOIN pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = 'auth' AND p.proname = 'authz_check_parallel_batch')",
    )
    .fetch_one(pool)
    .await
    {
        Ok(true) => true,
        Ok(false) => {
            tracing::info!(
                "authz_check_parallel_batch not found; using serial authz fallback \
                 (install the pgrx extension and run migration 0006 to enable parallel mode)"
            );
            false
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "probe_parallel_batch query failed; falling back to serial authz checks for \
                 the lifetime of this process"
            );
            false
        }
    }
}

/// Call authz_check_parallel_batch with fully-expanded atomic checks.
/// Returns one bool per input row in the same order.
/// Non-macro sqlx: function is a pgrx extension not known at compile time.
pub async fn parallel_batch_check(
    pool: &PgPool,
    rows: &[(String, String, String, String)], // (subject_id, relation, object_type, object_id)
) -> Result<Vec<bool>, AuthError> {
    if rows.is_empty() {
        return Ok(vec![]);
    }
    let mut subject_ids = Vec::with_capacity(rows.len());
    let mut relations = Vec::with_capacity(rows.len());
    let mut object_types = Vec::with_capacity(rows.len());
    let mut object_ids = Vec::with_capacity(rows.len());
    for (s, r, t, o) in rows {
        subject_ids.push(s.clone());
        relations.push(r.clone());
        object_types.push(t.clone());
        object_ids.push(o.clone());
    }
    let (bools,): (Vec<bool>,) = sqlx::query_as(
        "SELECT auth.authz_check_parallel_batch($1::text[], $2::text[], $3::text[], $4::text[])",
    )
    .bind(&subject_ids)
    .bind(&relations)
    .bind(&object_types)
    .bind(&object_ids)
    .fetch_one(pool)
    .await
    .map_err(AuthError::from)?;
    Ok(bools)
}

/// Call authz_check_path_batch for N hierarchy checks sharing the same path structure.
/// Returns one bool per input row in the same order.
/// Non-macro sqlx: function is a pgrx extension not known at compile time.
pub async fn path_batch_check(
    pool: &PgPool,
    subject_ids: &[String],
    relation_prefix: &[String],
    object_type_path: &[String],
    terminal_relations: &[String],
    object_ids: &[String],
) -> Result<Vec<bool>, AuthError> {
    if subject_ids.is_empty() {
        return Ok(vec![]);
    }
    let (bools,): (Vec<bool>,) = sqlx::query_as(
        "SELECT auth.authz_check_path_batch($1::text[], $2::text[], $3::text[], $4::text[], $5::text[])",
    )
    .bind(subject_ids)
    .bind(relation_prefix)
    .bind(object_type_path)
    .bind(terminal_relations)
    .bind(object_ids)
    .fetch_one(pool)
    .await
    .map_err(AuthError::from)?;
    Ok(bools)
}

// ── Expand ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
#[allow(dead_code)]
pub struct ExpandRow {
    pub object_type: String,
    pub object_id: String,
    pub relation: String,
    pub subject_id: String,
    pub tuple_id: Uuid,
    pub created_at: DateTime<Utc>,
}

pub async fn expand(
    pool: &PgPool,
    object_type: &str,
    object_id: &str,
    relations: &[String],
) -> Result<Vec<ExpandRow>, AuthError> {
    let rows = sqlx::query_as!(
        ExpandRow,
        r#"
        SELECT
            object_type AS "object_type!",
            object_id   AS "object_id!",
            relation    AS "relation!",
            subject_id  AS "subject_id!",
            tuple_id    AS "tuple_id!: Uuid",
            created_at  AS "created_at!: DateTime<Utc>"
        FROM auth.authz_lookup_subjects($1::text[], $2, $3)
        "#,
        relations as &[String],
        object_type,
        object_id,
    )
    .fetch_all(pool)
    .await
    .map_err(AuthError::from)?;
    Ok(rows)
}

// ── Lookup Resources ──────────────────────────────────────────────────────────

/// Look up resource IDs accessible to `subject_id` via the given relations.
/// Returns up to `limit` IDs with cursor applied at the DB level. The caller is
/// responsible for pagination (pass `limit + 1` to detect has-more).
pub async fn enumerate_ids(
    pool: &PgPool,
    subject_id: &str,
    relations: &[String],
    object_type: &str,
    limit: i64,
    cursor: Option<&str>,
) -> Result<Vec<String>, AuthError> {
    sqlx::query_scalar!(
        r#"
        SELECT object_id AS "object_id!"
        FROM auth.authz_lookup_resources($1, $2::text[], $3)
        WHERE ($4::text IS NULL OR object_id > $4)
        ORDER BY object_id
        LIMIT $5
        "#,
        subject_id,
        relations as &[String],
        object_type,
        cursor,
        limit,
    )
    .fetch_all(pool)
    .await
    .map_err(AuthError::from)
}

/// Look up resources of `child_type` accessible to `subject_id` via a parent
/// hierarchy: find parents of `parent_type` the subject can access via
/// `parent_roles`, then return child objects linked to those parents via
/// `parent_link_relation`. Returns up to `limit` IDs with cursor applied.
#[allow(clippy::too_many_arguments)]
pub async fn enumerate_via_parent(
    pool: &PgPool,
    subject_id: &str,
    child_type: &str,
    parent_link_relation: &str,
    parent_roles: &[String],
    parent_type: &str,
    limit: i64,
    cursor: Option<&str>,
) -> Result<Vec<String>, AuthError> {
    sqlx::query_scalar!(
        r#"
        SELECT DISTINCT rt_child.object_id AS "object_id!"
        FROM auth.authz_relations rt_child
        WHERE rt_child.object_type = $1
          AND rt_child.relation    = $2
          AND ($3::text IS NULL OR rt_child.object_id > $3)
          AND rt_child.subject_id IN (
              SELECT object_id
              FROM auth.authz_lookup_resources($4, $5::text[], $6)
          )
        ORDER BY rt_child.object_id
        LIMIT $7
        "#,
        child_type,
        parent_link_relation,
        cursor,
        subject_id,
        parent_roles as &[String],
        parent_type,
        limit,
    )
    .fetch_all(pool)
    .await
    .map_err(AuthError::from)
}

// ── Partition management ──────────────────────────────────────────────────────

/// Ensure a dedicated LIST partition exists for `object_type`.
///
/// Called JIT from the write path: first write of a type pays the DDL cost
/// (one CREATE TABLE IF NOT EXISTS), all subsequent writes hit the in-memory
/// `HashSet` cache and skip the round-trip entirely. `object_type` is a
/// `ValidIdent` so the format-string interpolation is a structural guarantee,
/// not a call-site invariant.
pub async fn ensure_partition(
    pool: &PgPool,
    object_type: &ValidIdent,
    cache: &Cache<String, ()>,
) -> Result<(), AuthError> {
    if cache.get(object_type.as_str()).is_some() {
        return Ok(());
    }
    let sql = format!(
        "CREATE TABLE IF NOT EXISTS auth.authz_relations_{object_type} \
         PARTITION OF auth.authz_relations FOR VALUES IN ('{object_type}')"
    );
    match sqlx::query(&sql).execute(pool).await {
        Ok(_) => {}
        // IF NOT EXISTS is not atomic for partition DDL: two concurrent connections
        // can both pass the existence check and race to create the table. The loser
        // gets 42P07 (duplicate_table) — treat it as success.
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("42P07") => {}
        Err(e) => return Err(AuthError::from(e)),
    }
    cache.insert(object_type.as_str().to_owned(), ());
    Ok(())
}
