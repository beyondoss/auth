use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AuthError;

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: Uuid,
    pub primary_org_id: Uuid,
    pub primary_email_id: Uuid,
    pub created_at: DateTime<Utc>,
}

pub async fn create(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    primary_org_id: Uuid,
    primary_email_id: Uuid,
) -> Result<User, AuthError> {
    sqlx::query_as!(
        User,
        r#"INSERT INTO auth.users (id, primary_org_id, primary_email_id)
           VALUES ($1, $2, $3)
           RETURNING id, primary_org_id, primary_email_id, created_at"#,
        id,
        primary_org_id,
        primary_email_id,
    )
    .fetch_one(tx.as_mut())
    .await
    .map_err(AuthError::from)
}

#[allow(dead_code)]
pub async fn get(pool: &PgPool, user_id: Uuid) -> Result<Option<User>, AuthError> {
    sqlx::query_as!(
        User,
        r#"SELECT id, primary_org_id, primary_email_id, created_at
           FROM auth.users
           WHERE id = $1 AND deleted_at IS NULL"#,
        user_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)
}
