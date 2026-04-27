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
        "INSERT INTO auth.identity (user_id, provider, subject, secret)
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

/// Look up a password identity's user_id and PHC hash string.
pub async fn find_password_secret(
    pool: &PgPool,
    subject: &str,
) -> Result<Option<(Uuid, String)>, AuthError> {
    let row = sqlx::query!(
        "SELECT user_id, secret
         FROM auth.identity
         WHERE provider = 'password' AND subject = $1
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
                let hash = String::from_utf8(s)
                    .map_err(|_| AuthError::internal("corrupted password hash"))?;
                Ok(Some((r.user_id, hash)))
            }
        },
    }
}
