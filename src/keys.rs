use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

// Re-exported so callers that use `crate::keys::LoadedKey` still resolve.
pub use crate::signing_keys::LoadedKey;

use crate::{
    emails::Email,
    error::AuthError,
    orgs::Org,
    sessions::{AuthContext, AuthSource},
    tokens::Token,
    users::User,
};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Key {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

/// Validate an API key token and return the caller's context in one round-trip.
///
/// Same CTE shape as `sessions::validate` but joins `auth.keys` instead of
/// `auth.sessions`. No idle timeout — keys are programmatic credentials.
pub async fn validate(
    pool: &PgPool,
    token_id: Uuid,
    secret_hash: &[u8],
) -> Result<Option<AuthContext>, AuthError> {
    let row = sqlx::query!(
        r#"
        WITH valid_token AS (
            SELECT tokens.id AS token_id
            FROM auth.tokens
            WHERE tokens.id         = $1
              AND tokens.secret     = $2
              AND tokens.expires_at > now()
            LIMIT 1
        ),
        update_attempt AS (
            UPDATE auth.tokens SET last_used_at = now()
            FROM valid_token
            WHERE auth.tokens.id = valid_token.token_id
              AND (auth.tokens.last_used_at IS NULL
                   OR auth.tokens.last_used_at < now() - interval '1 minute')
        )
        SELECT
            k.id                AS "key_id!: Uuid",
            u.id                AS "user_id!: Uuid",
            u.primary_org_id    AS "primary_org_id!: Uuid",
            u.primary_email_id  AS "primary_email_id!: Uuid",
            u.created_at        AS "user_created_at!: DateTime<Utc>",
            t.id                AS "org_id!: Uuid",
            t.user_id           AS "org_user_id!: Uuid",
            t.name              AS "org_name!",
            t.slug              AS "org_slug!",
            t.image_url         AS "org_image_url",
            t.metadata          AS "org_metadata: serde_json::Value",
            t.created_at        AS "org_created_at!: DateTime<Utc>",
            t.updated_at        AS "org_updated_at!: DateTime<Utc>",
            t.deleted_at        AS "org_deleted_at",
            e.id                AS "email_id!: Uuid",
            e.email::text       AS "email!",
            e.verified_at,
            v.token_id          AS "token_id!: Uuid"
        FROM valid_token v
        INNER JOIN auth.keys     k ON k.token_id  = v.token_id
        INNER JOIN auth.users    u ON u.id = k.user_id AND u.deleted_at IS NULL
        INNER JOIN auth.orgs     t ON t.id = u.primary_org_id AND t.deleted_at IS NULL
        LEFT  JOIN auth.emails   e ON e.id = u.primary_email_id
        "#,
        token_id,
        secret_hash,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?;

    Ok(row.map(|r| AuthContext {
        source: AuthSource::Key,
        token_id: r.token_id,
        is_impersonated: false,
        user: User {
            id: r.user_id,
            primary_org_id: r.primary_org_id,
            primary_email_id: r.primary_email_id,
            created_at: r.user_created_at,
        },
        org: Org {
            id: r.org_id,
            user_id: r.org_user_id,
            name: r.org_name,
            slug: r.org_slug,
            image_url: r.org_image_url,
            metadata: r.org_metadata,
            created_at: r.org_created_at,
            updated_at: r.org_updated_at,
            deleted_at: r.org_deleted_at,
        },
        email: Email {
            id: r.email_id,
            user_id: r.user_id,
            email: r.email,
            verified_at: r.verified_at,
        },
    }))
}

/// Create a token + key atomically. Returns `(key_id, expires_at)`.
/// Deletion = `DELETE FROM auth.tokens WHERE id = token.id` (cascades to auth.keys).
pub async fn create(
    pool: &PgPool,
    user_id: Uuid,
    name: &str,
    token: &Token,
    expires_at: DateTime<Utc>,
) -> Result<(Uuid, DateTime<Utc>), AuthError> {
    let mut tx = pool.begin().await.map_err(AuthError::from)?;

    let stored_expires_at = sqlx::query_scalar!(
        "INSERT INTO auth.tokens (id, secret, expires_at)
         VALUES ($1, $2, $3)
         RETURNING expires_at",
        token.id,
        &token.secret_hash() as &[u8],
        expires_at,
    )
    .fetch_one(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    let key_id = sqlx::query_scalar!(
        "INSERT INTO auth.keys (user_id, token_id, name)
         VALUES ($1, $2, $3)
         RETURNING id",
        user_id,
        token.id,
        name,
    )
    .fetch_one(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    tx.commit().await.map_err(AuthError::from)?;

    Ok((key_id, stored_expires_at))
}

pub async fn list(pool: &PgPool, user_id: Uuid) -> Result<Vec<Key>, AuthError> {
    sqlx::query_as!(
        Key,
        r#"
        SELECT
            k.id,
            k.name,
            k.created_at,
            tok.last_used_at,
            tok.expires_at
        FROM auth.keys k
        INNER JOIN auth.tokens tok ON tok.id = k.token_id
        WHERE k.user_id = $1
          AND tok.expires_at > now()
        ORDER BY k.created_at DESC
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await
    .map_err(AuthError::from)
}

pub async fn get(pool: &PgPool, user_id: Uuid, key_id: Uuid) -> Result<Option<Key>, AuthError> {
    sqlx::query_as!(
        Key,
        r#"
        SELECT
            k.id,
            k.name,
            k.created_at,
            tok.last_used_at,
            tok.expires_at
        FROM auth.keys k
        INNER JOIN auth.tokens tok ON tok.id = k.token_id
        WHERE k.id      = $1
          AND k.user_id = $2
        "#,
        key_id,
        user_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)
}

/// Delete a key by deleting its backing token (cascades to auth.keys).
/// Idempotent: returns Ok(()) whether or not the key existed.
pub async fn delete(pool: &PgPool, user_id: Uuid, key_id: Uuid) -> Result<(), AuthError> {
    // Non-macro: execute-only, no row data accessed.
    sqlx::query(
        "WITH target AS (
            SELECT k.token_id
            FROM auth.keys k
            WHERE k.id = $1 AND k.user_id = $2
        )
        DELETE FROM auth.tokens WHERE id = (SELECT token_id FROM target)",
    )
    .bind(key_id)
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(AuthError::from)?;
    Ok(())
}
