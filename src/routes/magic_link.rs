use axum::{Json, extract::State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{email, error::AuthError, http::AppState, one_time_token, tokens::TokenPrefix};

const TTL_SECONDS: i32 = 900; // 15 minutes

/// Request to issue a magic-link login token for a user.
#[derive(Deserialize, utoipa::ToSchema)]
#[schema(as = MagicLinkRequest)]
pub struct CreateRequest {
    /// The user's primary email address.
    pub email: String,
}

/// Magic-link token response. Pass `token` to `POST /v1/sessions` with
/// `grant_type=magic_link` to authenticate.
#[derive(Serialize, utoipa::ToSchema)]
#[schema(as = MagicLinkResponse)]
pub struct CreateResponse {
    /// One-time token to exchange via `POST /v1/sessions` with `grant_type=magic_link`.
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

// ── POST /v1/magic-links ──────────────────────────────────────────────────────

/// Issue a passwordless magic-link token for the given email address. The caller is
/// responsible for delivering the token to the user (e.g. via email). The token is
/// exchanged for a session via `POST /v1/sessions` with `grant_type=magic_link`.
/// Expires in 15 minutes. Returns 404 if no account exists for the address.
#[utoipa::path(
    post,
    path = "/v1/magic-links",
    operation_id = "create_magic_link",
    tag = "magic-links",
    request_body = CreateRequest,
    responses(
        (status = 200, body = CreateResponse),
        (status = 404, description = "No account with that email", body = crate::error::ErrorResponse),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    Json(req): Json<CreateRequest>,
) -> Result<Json<CreateResponse>, AuthError> {
    let normalized = email::normalize(&req.email);

    let user_id = sqlx::query_scalar!(
        "SELECT u.id FROM auth.users u
         INNER JOIN auth.emails e ON e.id = u.primary_email_id
         WHERE e.email = $1::text AND u.deleted_at IS NULL",
        normalized,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(AuthError::from)?
    .ok_or(AuthError::NotFound)?;

    let created = one_time_token::create(
        &state.pool,
        TokenPrefix::MagicLink,
        user_id,
        TTL_SECONDS,
        None,
    )
    .await?;

    Ok(Json(CreateResponse {
        token: created.token.to_string(),
        expires_at: created.expires_at,
    }))
}
