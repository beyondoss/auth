use axum::{Json, extract::State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{email, error::AuthError, http::AppState, one_time_token, tokens::TokenPrefix};

const TTL_SECONDS: i32 = 3600; // 1 hour

/// Request to issue a password-reset token for a user.
#[derive(Deserialize, utoipa::ToSchema)]
#[schema(as = PasswordResetRequest)]
pub struct CreateRequest {
    /// The user's primary email address.
    pub email: String,
}

/// Password-reset token response. Pass `token` to `POST /v1/sessions` with
/// `grant_type=password_reset` along with the new password to complete the reset.
#[derive(Serialize, utoipa::ToSchema)]
#[schema(as = PasswordResetResponse)]
pub struct CreateResponse {
    /// One-time token to exchange via `POST /v1/sessions` with `grant_type=password_reset`.
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

// ── POST /v1/password-resets ──────────────────────────────────────────────────

/// Issue a password-reset token for the given email address. The caller is responsible
/// for delivering the token to the user. The token is exchanged — along with a new password
/// — via `POST /v1/sessions` with `grant_type=password_reset`, which also invalidates all
/// existing sessions. Expires in 1 hour. Returns 404 if no account exists or the account
/// has no password identity.
#[utoipa::path(
    post,
    path = "/v1/password-resets",
    operation_id = "create_password_reset",
    tag = "password-resets",
    request_body = CreateRequest,
    responses(
        (status = 200, body = CreateResponse),
        (status = 404, description = "No account with that email or no password identity", body = crate::error::ErrorResponse),
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

    // Only users with a password identity can reset their password.
    let has_password = sqlx::query_scalar!(
        "SELECT 1 FROM auth.identities WHERE user_id = $1 AND provider = 'password'",
        user_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(AuthError::from)?;

    if has_password.is_none() {
        return Err(AuthError::NotFound);
    }

    let created = one_time_token::create(
        &state.pool,
        TokenPrefix::PasswordReset,
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
