use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::error::AuthError;

#[derive(Debug, Clone, Serialize)]
pub struct Tenant {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
}

pub async fn create(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    user_id: Uuid,
    name: &str,
    slug: &str,
) -> Result<Tenant, AuthError> {
    sqlx::query_as!(
        Tenant,
        "INSERT INTO auth.tenant (id, user_id, name, slug)
         VALUES ($1, $2, $3, $4)
         RETURNING id, user_id, name, slug, created_at",
        id,
        user_id,
        name,
        slug,
    )
    .fetch_one(tx.as_mut())
    .await
    .map_err(AuthError::from)
}
