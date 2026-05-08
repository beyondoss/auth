use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AuthError;

#[allow(dead_code)]
#[derive(Debug)]
pub struct Identity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub subject: String,
    pub created_at: DateTime<Utc>,
}

pub async fn create(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    provider: &str,
    subject: &str,
    secret: &[u8],
) -> Result<Identity, AuthError> {
    sqlx::query_as!(
        Identity,
        "INSERT INTO auth.identities (user_id, provider, subject, secret)
         VALUES ($1, $2, $3, $4)
         RETURNING id, user_id, provider, subject, created_at",
        user_id,
        provider,
        subject,
        secret,
    )
    .fetch_one(tx.as_mut())
    .await
    .map_err(AuthError::from)
}

pub async fn list(pool: &PgPool, user_id: Uuid) -> Result<Vec<Identity>, AuthError> {
    sqlx::query_as!(
        Identity,
        "SELECT id, user_id, provider, subject, created_at
         FROM auth.identities
         WHERE user_id = $1
         ORDER BY created_at ASC",
        user_id,
    )
    .fetch_all(pool)
    .await
    .map_err(AuthError::from)
}

pub async fn count(pool: &PgPool, user_id: Uuid) -> Result<i64, AuthError> {
    let row = sqlx::query!(
        "SELECT COUNT(*) as count FROM auth.identities WHERE user_id = $1",
        user_id,
    )
    .fetch_one(pool)
    .await
    .map_err(AuthError::from)?;
    Ok(row.count.unwrap_or(0))
}

pub async fn delete(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<bool, AuthError> {
    let result = sqlx::query!(
        "DELETE FROM auth.identities WHERE id = $1 AND user_id = $2",
        id,
        user_id,
    )
    .execute(pool)
    .await
    .map_err(AuthError::from)?;
    Ok(result.rows_affected() > 0)
}

pub async fn find_password_secret_by_user(
    pool: &PgPool,
    id: Uuid,
    user_id: Uuid,
) -> Result<Option<(String, String)>, AuthError> {
    let row = sqlx::query!(
        "SELECT subject, secret
         FROM auth.identities
         WHERE id = $1 AND user_id = $2 AND provider = 'password'
         LIMIT 1",
        id,
        user_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?;

    match row {
        None => Ok(None),
        Some(r) => match r.secret {
            None => Ok(None),
            Some(s) => {
                let hash = String::from_utf8(s).map_err(|_| {
                    tracing::error!(%user_id, "password hash is not valid utf-8");
                    AuthError::internal("corrupted password hash")
                })?;
                Ok(Some((r.subject, hash)))
            }
        },
    }
}

pub async fn has_password(pool: &PgPool, user_id: Uuid) -> Result<bool, AuthError> {
    let row = sqlx::query!(
        "SELECT id FROM auth.identities WHERE user_id = $1 AND provider = 'password' LIMIT 1",
        user_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?;
    Ok(row.is_some())
}

/// Look up a password identity's user_id and PHC hash string.
pub async fn find_password_secret(
    pool: &PgPool,
    subject: &str,
) -> Result<Option<(Uuid, String)>, AuthError> {
    let row = sqlx::query!(
        "SELECT i.user_id, i.secret
         FROM auth.identities i
         JOIN auth.users u ON u.id = i.user_id
         WHERE i.provider = 'password' AND i.subject = $1 AND u.deleted_at IS NULL
         LIMIT 1",
        subject,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?;

    match row {
        None => Ok(None),
        Some(r) => match r.secret {
            None => Ok(None),
            Some(s) => {
                let hash = String::from_utf8(s).map_err(|_| {
                    tracing::error!(user_id = %r.user_id, "password hash is not valid utf-8");
                    AuthError::internal("corrupted password hash")
                })?;
                Ok(Some((r.user_id, hash)))
            }
        },
    }
}
