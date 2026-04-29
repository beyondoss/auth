use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde::Serialize;
use uuid::Uuid;

use crate::{error::AuthError, http::AppState, mfa::totp, sessions::AuthContext};

#[derive(Serialize, utoipa::ToSchema)]
pub struct EnrollmentResponse {
    pub factor_id: Uuid,
    pub secret_b32: String,
    pub provisioning_uri: String,
    pub qr_data_url: String,
    pub recovery_codes: Vec<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ConfirmRequest {
    pub code: String,
}

#[utoipa::path(
    post,
    path = "/v1/totp",
    tag = "totp",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, body = EnrollmentResponse),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn begin_enrollment(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<EnrollmentResponse>, AuthError> {
    let r = totp::enroll(&state.pool, ctx.user.id, &ctx.email.email, "Beyond Auth").await?;
    Ok(Json(EnrollmentResponse {
        factor_id: r.factor_id,
        secret_b32: r.secret_b32,
        provisioning_uri: r.provisioning_uri,
        qr_data_url: r.qr_data_url,
        recovery_codes: r.recovery_codes,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/totp/confirmations",
    tag = "totp",
    security(("BearerAuth" = [])),
    request_body = ConfirmRequest,
    responses(
        (status = 204, description = "TOTP enrollment confirmed"),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn confirm_enrollment(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<ConfirmRequest>,
) -> Result<StatusCode, AuthError> {
    totp::confirm(&state.pool, ctx.user.id, &req.code).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/v1/totp",
    tag = "totp",
    security(("BearerAuth" = [])),
    responses(
        (status = 204, description = "TOTP disabled"),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn disable(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<StatusCode, AuthError> {
    totp::disable(&state.pool, ctx.user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── POST /v1/totp/recovery-codes ─────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
pub struct RecoveryCodesResponse {
    pub recovery_codes: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/v1/totp/recovery-codes",
    tag = "totp",
    security(("BearerAuth" = [])),
    request_body = ConfirmRequest,
    responses(
        (status = 200, body = RecoveryCodesResponse),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 404, description = "No enrolled TOTP factor", body = crate::error::ErrorResponse),
    )
)]
pub async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<ConfirmRequest>,
) -> Result<Json<RecoveryCodesResponse>, AuthError> {
    let codes = totp::regenerate_recovery_codes(&state.pool, ctx.user.id, &req.code).await?;
    Ok(Json(RecoveryCodesResponse {
        recovery_codes: codes,
    }))
}
