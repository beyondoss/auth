use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::AuthError, http::AppState};

/// Full user record returned to admin callers.
#[derive(Serialize, utoipa::ToSchema)]
pub struct AdminUserResponse {
    pub id: Uuid,
    pub primary_org_id: Uuid,
    pub primary_email_id: Uuid,
    pub email: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// Set when the user has been soft-deleted; null for active accounts.
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct SearchQuery {
    /// Look up by primary email address (case-insensitive).
    pub email: Option<String>,
}

/// Look up a user by primary email address. Returns 400 if the `email` query parameter
/// is omitted.
#[utoipa::path(
    get,
    path = "/v1/admin/users",
    operation_id = "admin_search_users",
    tag = "admin",
    params(SearchQuery),
    responses(
        (status = 200, body = AdminUserResponse),
        (status = 400, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn search(
    State(state): State<AppState>,
    Query(q): Query<SearchQuery>,
) -> Result<Json<AdminUserResponse>, AuthError> {
    let email = q
        .email
        .ok_or_else(|| AuthError::bad_request("email query parameter is required"))?;

    let row = sqlx::query!(
        r#"
        SELECT
            u.id                AS "id!: Uuid",
            u.primary_org_id    AS "primary_org_id!: Uuid",
            u.primary_email_id  AS "primary_email_id!: Uuid",
            u.created_at        AS "created_at!: DateTime<Utc>",
            u.deleted_at,
            e.email::text       AS email,
            e.verified_at       AS email_verified_at
        FROM auth.users u
        LEFT JOIN auth.emails e ON e.id = u.primary_email_id
        WHERE lower(e.email::text) = lower($1)
        LIMIT 1
        "#,
        email,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(AuthError::from)?
    .ok_or(AuthError::NotFound)?;

    Ok(Json(AdminUserResponse {
        id: row.id,
        primary_org_id: row.primary_org_id,
        primary_email_id: row.primary_email_id,
        email: row.email,
        email_verified_at: row.email_verified_at,
        created_at: row.created_at,
        deleted_at: row.deleted_at,
    }))
}

/// Revoke all active sessions for a user. Idempotent — safe to call when the user
/// has no sessions.
#[utoipa::path(
    delete,
    path = "/v1/admin/users/{id}/sessions",
    operation_id = "admin_delete_user_sessions",
    tag = "admin",
    params(("id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 204, description = "All sessions revoked"),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn delete_sessions(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, AuthError> {
    let exists = sqlx::query_scalar!(
        r#"SELECT EXISTS(SELECT 1 FROM auth.users WHERE id = $1) AS "exists!: bool""#,
        user_id,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(AuthError::from)?;

    if !exists {
        return Err(AuthError::NotFound);
    }

    let token_ids: Vec<Uuid> = sqlx::query_scalar!(
        r#"
        WITH deleted AS (
            DELETE FROM auth.tokens
            WHERE id IN (
                SELECT token_id FROM auth.sessions WHERE user_id = $1
            )
            RETURNING id
        )
        SELECT id AS "id: Uuid" FROM deleted
        "#,
        user_id,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(AuthError::from)?;

    for token_id in token_ids {
        state.authz_cache.invalidate_session(token_id);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Look up a user by ID.
#[utoipa::path(
    get,
    path = "/v1/admin/users/{id}",
    operation_id = "admin_get_user",
    tag = "admin",
    params(("id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, body = AdminUserResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn get_by_id(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<AdminUserResponse>, AuthError> {
    let row = sqlx::query!(
        r#"
        SELECT
            u.id                AS "id!: Uuid",
            u.primary_org_id    AS "primary_org_id!: Uuid",
            u.primary_email_id  AS "primary_email_id!: Uuid",
            u.created_at        AS "created_at!: DateTime<Utc>",
            u.deleted_at,
            e.email::text       AS email,
            e.verified_at       AS email_verified_at
        FROM auth.users u
        LEFT JOIN auth.emails e ON e.id = u.primary_email_id
        WHERE u.id = $1
        "#,
        user_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(AuthError::from)?
    .ok_or(AuthError::NotFound)?;

    Ok(Json(AdminUserResponse {
        id: row.id,
        primary_org_id: row.primary_org_id,
        primary_email_id: row.primary_email_id,
        email: row.email,
        email_verified_at: row.email_verified_at,
        created_at: row.created_at,
        deleted_at: row.deleted_at,
    }))
}
