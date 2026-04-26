use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AuthError;

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: Uuid,
    pub personal_tenant_id: Uuid,
    pub primary_email_id: Uuid,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUser {
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

pub async fn create(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    personal_tenant_id: Uuid,
    primary_email_id: Uuid,
    display_name: Option<&str>,
) -> Result<User, AuthError> {
    sqlx::query_as!(
        User,
        "INSERT INTO auth.\"user\" (id, personal_tenant_id, primary_email_id, display_name)
         VALUES ($1, $2, $3, $4)
         RETURNING id, personal_tenant_id, primary_email_id, display_name, avatar_url, created_at",
        id,
        personal_tenant_id,
        primary_email_id,
        display_name,
    )
    .fetch_one(tx.as_mut())
    .await
    .map_err(AuthError::from)
}

pub async fn update(
    pool: &PgPool,
    user_id: Uuid,
    patch: &UpdateUser,
) -> Result<User, AuthError> {
    sqlx::query_as!(
        User,
        "UPDATE auth.\"user\"
         SET display_name = COALESCE($2, display_name),
             avatar_url   = COALESCE($3, avatar_url)
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING id, personal_tenant_id, primary_email_id, display_name, avatar_url, created_at",
        user_id,
        patch.display_name,
        patch.avatar_url,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?
    .ok_or(AuthError::NotFound)
}
