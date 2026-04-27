use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AuthError;

// ── Write / delete relations ──────────────────────────────────────────────────

pub async fn write_relation(
    pool: &PgPool,
    object_type: &str,
    object_id: &str,
    relation: &str,
    subject_id: &str,
    subject_set_type: Option<&str>,
    subject_set_relation: Option<&str>,
) -> Result<(), AuthError> {
    sqlx::query!(
        r#"
        INSERT INTO auth.authz_relations
            (object_type, object_id, relation, subject_id, subject_set_type, subject_set_relation)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT DO NOTHING
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
    pub object_type: String,
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
    writes: Vec<BatchOp>,
    deletes: Vec<BatchOp>,
) -> Result<BatchResult, AuthError> {
    let mut tx = pool.begin().await.map_err(AuthError::from)?;
    let mut written = 0u64;
    let mut deleted = 0u64;

    for op in writes {
        let r = sqlx::query!(
            r#"
            INSERT INTO auth.authz_relations
                (object_type, object_id, relation, subject_id, subject_set_type, subject_set_relation)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT DO NOTHING
            "#,
            op.object_type,
            op.object_id,
            op.relation,
            op.subject_id,
            op.subject_set_type,
            op.subject_set_relation,
        )
        .execute(tx.as_mut())
        .await
        .map_err(AuthError::from)?;
        written += r.rows_affected();
    }

    for op in deletes {
        let r = sqlx::query!(
            r#"
            DELETE FROM auth.authz_relations
            WHERE object_type            = $1
              AND object_id              = $2
              AND relation               = $3
              AND subject_id             = $4
              AND subject_set_type     IS NOT DISTINCT FROM $5
              AND subject_set_relation IS NOT DISTINCT FROM $6
            "#,
            op.object_type,
            op.object_id,
            op.relation,
            op.subject_id,
            op.subject_set_type,
            op.subject_set_relation,
        )
        .execute(tx.as_mut())
        .await
        .map_err(AuthError::from)?;
        deleted += r.rows_affected();
    }

    tx.commit().await.map_err(AuthError::from)?;
    Ok(BatchResult { written, deleted })
}

// ── Check ─────────────────────────────────────────────────────────────────────

/// Bundled CTE: validate session + authz check in one DB round-trip.
///
/// Returns `None` if the token is invalid or expired; `Some(allowed)` otherwise.
/// `or_chain` is the SQL fragment produced by `CompiledSchema::build_or_chain`.
///
/// Uses the non-macro `sqlx::query_scalar` because the query shape is dynamic
/// (the OR-chain length varies by permission/schema). This is the one justified
/// exception to the type-safe macro rule.
pub async fn check_with_session(
    pool: &PgPool,
    token_id: Uuid,
    secret_hash: &[u8],
    object_id: &str,
    or_chain: &str,
) -> Result<Option<bool>, AuthError> {
    let sql = format!(
        r#"
        WITH valid_token AS (
            SELECT token.id AS token_id
            FROM auth.tokens
            WHERE token.id      = $1
              AND token.secret  = $2
              AND token.expires_at > now()
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
        SELECT (
            {or_chain}
        )
        FROM subject
        "#
    );

    sqlx::query_scalar::<_, bool>(&sql)
        .bind(token_id)
        .bind(secret_hash)
        .bind(object_id)
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
) -> Result<Option<String>, AuthError> {
    let sql = r#"
        WITH valid_token AS (
            SELECT token.id AS token_id
            FROM auth.tokens
            WHERE token.id      = $1
              AND token.secret  = $2
              AND token.expires_at > now()
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

/// Ensure a dedicated partition exists for each resource type in the schema.
/// Called after schema PUT — DDL is auto-committed so this runs outside the
/// config UPDATE's implicit transaction. IF NOT EXISTS makes it idempotent.
pub async fn ensure_partitions(pool: &PgPool, resource_names: &[&str]) -> Result<(), AuthError> {
    for name in resource_names {
        let sql = format!(
            "CREATE TABLE IF NOT EXISTS auth.authz_relations_{name} \
             PARTITION OF auth.authz_relations FOR VALUES IN ('{name}')"
        );
        sqlx::query(&sql)
            .execute(pool)
            .await
            .map_err(AuthError::from)?;
    }
    Ok(())
}
