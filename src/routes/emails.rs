use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    email, error::AuthError, http::AppState, one_time_token, sessions::SessionContext,
    tokens::TokenPrefix,
};

const VERIFICATION_TTL_SECONDS: i32 = 86400; // 24 hours
const CHANGE_TTL_SECONDS: i32 = 86400; // 24 hours

// ── GET /v1/emails ────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
pub struct EmailRecord {
    pub id: Uuid,
    pub email: String,
    pub verified_at: Option<DateTime<Utc>>,
    pub is_primary: bool,
}

#[utoipa::path(
    get,
    path = "/v1/emails",
    operation_id = "list_emails",
    tag = "emails",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, body = Vec<EmailRecord>),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<Json<Vec<EmailRecord>>, AuthError> {
    let rows = sqlx::query!(
        r#"
        SELECT e.id, e.email::text AS "email!", e.verified_at,
               (e.id = u.primary_email_id) AS "is_primary!"
        FROM auth.email e
        INNER JOIN auth."user" u ON u.id = e.user_id
        WHERE e.user_id = $1
        ORDER BY e.created_at ASC
        "#,
        ctx.user.id,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(AuthError::from)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| EmailRecord {
                id: r.id,
                email: r.email,
                verified_at: r.verified_at,
                is_primary: r.is_primary,
            })
            .collect(),
    ))
}

// ── POST /v1/emails ───────────────────────────────────────────────────────────
// Authenticated — initiates a primary email change. Confirmation is done via
// POST /v1/sessions with grant_type=email_change.

#[derive(Deserialize, utoipa::ToSchema)]
pub struct AddRequest {
    pub email: String,
}

#[derive(Serialize, utoipa::ToSchema)]
#[schema(as = OttTokenResponse)]
pub struct TokenResponse {
    /// One-time token to use in the corresponding session grant.
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[utoipa::path(
    post,
    path = "/v1/emails",
    tag = "emails",
    security(("BearerAuth" = [])),
    request_body = AddRequest,
    responses(
        (status = 200, body = TokenResponse),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 409, description = "Email already registered", body = crate::error::ErrorResponse),
    )
)]
pub async fn add(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Json(req): Json<AddRequest>,
) -> Result<Json<TokenResponse>, AuthError> {
    let normalized = email::normalize(&req.email);

    let taken = sqlx::query_scalar!(
        "SELECT 1 FROM auth.email WHERE email = $1::citext",
        normalized,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(AuthError::from)?;

    if taken.is_some() {
        return Err(AuthError::EmailAlreadyExists);
    }

    let context = serde_json::json!({ "new_email": normalized });
    let created = one_time_token::create(
        &state.pool,
        TokenPrefix::EmailChange,
        ctx.user.id,
        CHANGE_TTL_SECONDS,
        Some(context),
    )
    .await?;

    Ok(Json(TokenResponse {
        token: created.token.to_string(),
        expires_at: created.expires_at,
    }))
}

// ── DELETE /v1/emails/{id} ────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/emails/{id}",
    tag = "emails",
    security(("BearerAuth" = [])),
    params(("id" = uuid::Uuid, Path, description = "Email ID")),
    responses(
        (status = 204, description = "Email removed"),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
        (status = 409, description = "Cannot remove primary email", body = crate::error::ErrorResponse),
    )
)]
pub async fn remove(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AuthError> {
    // Cannot delete the primary email.
    if id == ctx.user.primary_email_id {
        return Err(AuthError::Conflict);
    }

    let result = sqlx::query!(
        "DELETE FROM auth.email WHERE id = $1 AND user_id = $2",
        id,
        ctx.user.id,
    )
    .execute(&state.pool)
    .await
    .map_err(AuthError::from)?;

    if result.rows_affected() == 0 {
        return Err(AuthError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── PUT /v1/emails/{id} ───────────────────────────────────────────────────────
// Promote a verified email to primary.

#[utoipa::path(
    put,
    path = "/v1/emails/{id}",
    tag = "emails",
    security(("BearerAuth" = [])),
    params(("id" = uuid::Uuid, Path, description = "Email ID")),
    responses(
        (status = 204, description = "Email set as primary"),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 404, description = "Email not found or not verified", body = crate::error::ErrorResponse),
    )
)]
pub async fn make_primary(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AuthError> {
    let result = sqlx::query!(
        r#"UPDATE auth."user" SET primary_email_id = $1
         WHERE id = $2
           AND EXISTS (
               SELECT 1 FROM auth.email
               WHERE id = $1 AND user_id = $2 AND verified_at IS NOT NULL
           )"#,
        id,
        ctx.user.id,
    )
    .execute(&state.pool)
    .await
    .map_err(AuthError::from)?;

    if result.rows_affected() == 0 {
        return Err(AuthError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── POST /v1/emails/{id}/verifications ────────────────────────────────────────
// Authenticated — issues a verification token for a specific email address.

#[utoipa::path(
    post,
    path = "/v1/emails/{id}/verifications",
    tag = "emails",
    security(("BearerAuth" = [])),
    params(("id" = uuid::Uuid, Path, description = "Email ID")),
    responses(
        (status = 200, body = TokenResponse),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 404, description = "Email not found or already verified", body = crate::error::ErrorResponse),
    )
)]
pub async fn create_verification(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<TokenResponse>, AuthError> {
    // Confirm the email belongs to this user and isn't already verified.
    let exists = sqlx::query_scalar!(
        "SELECT 1 FROM auth.email
         WHERE id = $1 AND user_id = $2 AND verified_at IS NULL",
        id,
        ctx.user.id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(AuthError::from)?;

    if exists.is_none() {
        return Err(AuthError::NotFound);
    }

    let context = serde_json::json!({ "email_id": id });
    let created = one_time_token::create(
        &state.pool,
        TokenPrefix::EmailVerification,
        ctx.user.id,
        VERIFICATION_TTL_SECONDS,
        Some(context),
    )
    .await?;

    Ok(Json(TokenResponse {
        token: created.token.to_string(),
        expires_at: created.expires_at,
    }))
}

// ── POST /v1/emails/verifications ─────────────────────────────────────────────
// Unauthenticated — confirms email ownership via the verification token.

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ConfirmVerificationRequest {
    pub token: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct ConfirmVerificationResponse {
    pub verified_at: DateTime<Utc>,
}

#[utoipa::path(
    post,
    path = "/v1/emails/verifications",
    tag = "emails",
    request_body = ConfirmVerificationRequest,
    responses(
        (status = 200, body = ConfirmVerificationResponse),
        (status = 401, description = "Invalid or expired token", body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn confirm_verification(
    State(state): State<AppState>,
    Json(req): Json<ConfirmVerificationRequest>,
) -> Result<Json<ConfirmVerificationResponse>, AuthError> {
    let (user_id, context) = one_time_token::consume(&state.pool, &req.token).await?;

    let email_id: Uuid = context
        .as_ref()
        .and_then(|v| v.get("email_id"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AuthError::internal("email_id missing from token context"))?;

    let verified_at = sqlx::query_scalar!(
        "UPDATE auth.email SET verified_at = clock_timestamp()
         WHERE id = $1 AND user_id = $2
         RETURNING verified_at",
        email_id,
        user_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(AuthError::from)?
    .flatten()
    .ok_or(AuthError::NotFound)?;

    Ok(Json(ConfirmVerificationResponse { verified_at }))
}
