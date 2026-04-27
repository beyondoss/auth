use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::error::AuthError;

#[derive(Debug, Clone, Serialize)]
pub struct Email {
    pub id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub verified_at: Option<DateTime<Utc>>,
}

pub async fn create(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    user_id: Uuid,
    email: &str,
) -> Result<Email, AuthError> {
    sqlx::query_as!(
        Email,
        "INSERT INTO auth.emails (id, user_id, email)
         VALUES ($1, $2, $3::text)
         RETURNING id, user_id, email::text AS \"email!\", verified_at",
        id,
        user_id,
        email,
    )
    .fetch_one(tx.as_mut())
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(ref db) = e
            && db.constraint() == Some("emails_email_idx")
        {
            return AuthError::EmailAlreadyExists;
        }
        AuthError::from(e)
    })
}
