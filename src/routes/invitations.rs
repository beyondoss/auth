use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::AuthError, http::AppState, invitations, orgs, sessions::AuthContext, tokens};

// ── Response types ───────────────────────────────────────────────────────────

/// Public view of an invitation, shown to the invitee before they accept or decline.
#[derive(Serialize, utoipa::ToSchema)]
pub struct InvitationViewResponse {
    pub id: Uuid,
    pub org_id: Uuid,
    pub org_name: String,
    /// The role the invitee will receive on acceptance.
    pub role: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

// ── Query params ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TokenQuery {
    pub token: String,
}

// ── GET /v1/invitations/{id}?token=… (unauthenticated) ──────────────────────

/// Look up an invitation by ID and token. Unauthenticated — intended for pre-acceptance
/// display (show the org name and role before asking the user to log in). Returns 404 if
/// the invitation doesn't exist, is expired, or the token is wrong.
#[utoipa::path(
    get,
    path = "/v1/invitations/{id}",
    tag = "invitations",
    params(
        ("id" = Uuid, Path, description = "Invitation ID"),
        ("token" = String, Query, description = "Plaintext invitation token"),
    ),
    responses(
        (status = 200, body = InvitationViewResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn view_invitation(
    State(state): State<AppState>,
    Path(inv_id): Path<Uuid>,
    Query(q): Query<TokenQuery>,
) -> Result<Json<InvitationViewResponse>, AuthError> {
    let parsed = tokens::parse(&q.token).ok_or(AuthError::InvitationNotFound)?;
    let view = invitations::get_by_token(&state.pool, inv_id, &parsed.secret_hash).await?;

    Ok(Json(InvitationViewResponse {
        id: view.id,
        org_id: view.org_id,
        org_name: view.org_name,
        role: view.role,
        expires_at: view.expires_at,
    }))
}

// ── POST /v1/invitations/{id}/acceptances (authenticated) ───────────────────

/// Accept an invitation. The authenticated user is added to the org with the invitation's
/// role. The invitation token is consumed and cannot be reused. Returns 409 if already a member.
#[utoipa::path(
    post,
    path = "/v1/invitations/{id}/acceptances",
    tag = "invitations",
    security(("BearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Invitation ID"),
        ("token" = String, Query, description = "Plaintext invitation token"),
    ),
    responses(
        (status = 204),
        (status = 404, description = "Invitation not found or expired", body = crate::error::ErrorResponse),
        (status = 409, description = "Already a member", body = crate::error::ErrorResponse),
    )
)]
pub async fn accept_invitation(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(inv_id): Path<Uuid>,
    Query(q): Query<TokenQuery>,
) -> Result<StatusCode, AuthError> {
    let parsed = tokens::parse(&q.token).ok_or(AuthError::InvitationNotFound)?;

    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;

    let inv = invitations::consume(&mut tx, inv_id, &parsed.secret_hash).await?;
    orgs::add_member(&mut tx, inv.org_id, ctx.user.id, &inv.role).await?;

    tx.commit().await.map_err(AuthError::from)?;

    Ok(StatusCode::NO_CONTENT)
}

// ── POST /v1/invitations/{id}/declinations (token-only, unauthenticated) ────

/// Decline an invitation. The token is consumed and the invitation is removed.
/// Unauthenticated — the token in the query string is sufficient.
#[utoipa::path(
    post,
    path = "/v1/invitations/{id}/declinations",
    tag = "invitations",
    params(
        ("id" = Uuid, Path, description = "Invitation ID"),
        ("token" = String, Query, description = "Plaintext invitation token"),
    ),
    responses(
        (status = 204),
        (status = 404, description = "Invitation not found or expired", body = crate::error::ErrorResponse),
    )
)]
pub async fn decline_invitation(
    State(state): State<AppState>,
    Path(inv_id): Path<Uuid>,
    Query(q): Query<TokenQuery>,
) -> Result<StatusCode, AuthError> {
    let parsed = tokens::parse(&q.token).ok_or(AuthError::InvitationNotFound)?;

    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;
    invitations::consume(&mut tx, inv_id, &parsed.secret_hash).await?;
    tx.commit().await.map_err(AuthError::from)?;

    Ok(StatusCode::NO_CONTENT)
}
