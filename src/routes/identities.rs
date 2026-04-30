use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::AuthError, http::AppState, identities, passwords, sessions::AuthContext};

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
pub struct IdentityItem {
    pub id: Uuid,
    pub provider: String,
    /// Human-readable label: email address for password identities, provider slug for OAuth.
    pub display: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct IdentitiesResponse {
    pub identities: Vec<IdentityItem>,
}

// ── Request types ─────────────────────────────────────────────────────────────

/// Request to add a password identity to an account that currently has none
/// (e.g. a user who signed up via OAuth and wants to add password login).
#[derive(Deserialize, utoipa::ToSchema)]
pub struct AddPasswordRequest {
    pub password: String,
}

/// Request to change the password for an existing password identity.
/// Requires the current password as proof of possession.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateIdentityRequest {
    /// The existing password — must be correct or the request is rejected with 401.
    pub current_password: String,
    pub new_password: String,
}

// ── GET /v1/identities ────────────────────────────────────────────────────────

/// List all authentication methods (identities) attached to the authenticated user.
/// Each identity represents one way the user can log in: a password, or a linked OAuth provider.
#[utoipa::path(
    get,
    operation_id = "list_identities",
    path = "/v1/identities",
    tag = "identities",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, body = IdentitiesResponse),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<IdentitiesResponse>, AuthError> {
    let rows = identities::list(&state.pool, ctx.user.id).await?;
    let items = rows
        .into_iter()
        .map(|i| {
            let display = if i.provider == "password" {
                i.subject.clone()
            } else {
                i.provider
                    .strip_prefix("oauth_")
                    .unwrap_or(&i.provider)
                    .to_string()
            };
            IdentityItem {
                id: i.id,
                provider: i.provider,
                display,
                created_at: i.created_at,
            }
        })
        .collect();
    Ok(Json(IdentitiesResponse { identities: items }))
}

// ── POST /v1/identities ───────────────────────────────────────────────────────

/// Add a password identity to an account that has none. Useful when a user signed up via
/// OAuth and wants to enable password login. Returns 409 if a password identity already exists.
#[utoipa::path(
    post,
    path = "/v1/identities",
    tag = "identities",
    security(("BearerAuth" = [])),
    request_body = AddPasswordRequest,
    responses(
        (status = 201, body = IdentityItem),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 409, description = "Password identity already exists", body = crate::error::ErrorResponse),
        (status = 422, description = "Password validation failed", body = crate::error::ErrorResponse),
    )
)]
pub async fn add_password(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<AddPasswordRequest>,
) -> Result<(StatusCode, Json<IdentityItem>), AuthError> {
    if identities::has_password(&state.pool, ctx.user.id).await? {
        return Err(AuthError::Conflict);
    }

    let hash = passwords::hash(&req.password)?;
    let subject = ctx.email.email.clone();
    let normalized = crate::email::normalize(&subject);

    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;
    let identity = identities::create(
        &mut tx,
        ctx.user.id,
        "password",
        &normalized,
        hash.as_bytes(),
    )
    .await?;
    tx.commit().await.map_err(AuthError::from)?;

    Ok((
        StatusCode::CREATED,
        Json(IdentityItem {
            id: identity.id,
            provider: identity.provider,
            display: subject,
            created_at: identity.created_at,
        }),
    ))
}

// ── PATCH /v1/identities/{id} ─────────────────────────────────────────────────

/// Change the password for a password identity. Requires the current password. On success,
/// all sessions except the current one are revoked.
#[utoipa::path(
    patch,
    path = "/v1/identities/{id}",
    tag = "identities",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Identity ID")),
    request_body = UpdateIdentityRequest,
    responses(
        (status = 204),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
        (status = 422, description = "Password validation failed", body = crate::error::ErrorResponse),
    )
)]
pub async fn update(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateIdentityRequest>,
) -> Result<StatusCode, AuthError> {
    let Some((_subject, current_hash)) =
        identities::find_password_secret_by_user(&state.pool, id, ctx.user.id).await?
    else {
        return Err(AuthError::NotFound);
    };

    if !passwords::verify(&req.current_password, &current_hash)? {
        return Err(AuthError::InvalidCredentials);
    }
    let new_hash = passwords::hash(&req.new_password)?;

    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;

    sqlx::query!(
        "UPDATE auth.identities SET secret = $1 WHERE id = $2 AND user_id = $3",
        new_hash.as_bytes() as &[u8],
        id,
        ctx.user.id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    // Revoke all sessions except the current one.
    sqlx::query!(
        "DELETE FROM auth.tokens
         WHERE id IN (SELECT token_id FROM auth.sessions WHERE user_id = $1)
           AND id != $2",
        ctx.user.id,
        ctx.token_id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    tx.commit().await.map_err(AuthError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── DELETE /v1/identities/{id} ────────────────────────────────────────────────

/// Unlink an authentication method. Returns 409 if this is the last identity — at least
/// one must remain so the user can still log in.
#[utoipa::path(
    delete,
    path = "/v1/identities/{id}",
    tag = "identities",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Identity ID")),
    responses(
        (status = 204),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
        (status = 409, description = "Cannot remove last auth method", body = crate::error::ErrorResponse),
    )
)]
pub async fn unlink(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AuthError> {
    if identities::count(&state.pool, ctx.user.id).await? <= 1 {
        return Err(AuthError::LastIdentity);
    }

    let deleted = identities::delete(&state.pool, id, ctx.user.id).await?;
    if !deleted {
        return Err(AuthError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}
