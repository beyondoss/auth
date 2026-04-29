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

#[derive(Deserialize, utoipa::ToSchema)]
pub struct AddPasswordRequest {
    pub password: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateIdentityRequest {
    pub current_password: String,
    pub new_password: String,
}

// ── GET /v1/identities ────────────────────────────────────────────────────────

#[utoipa::path(
    get,
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
