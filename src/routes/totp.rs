use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde::Serialize;
use uuid::Uuid;

use crate::{error::AuthError, http::AppState, mfa::totp, sessions::AuthContext};

/// TOTP enrollment data returned when starting enrollment. Pass `provisioning_uri` or
/// `qr_data_url` to an authenticator app, then confirm enrollment with a live TOTP code.
#[derive(Serialize, utoipa::ToSchema)]
pub struct EnrollmentResponse {
    /// Opaque factor identifier.
    pub factor_id: Uuid,
    /// Raw TOTP secret in base32 — for manual entry into an authenticator app.
    pub secret_b32: String,
    /// `otpauth://` URI for QR code generation or direct authenticator import.
    pub provisioning_uri: String,
    /// Data URL (`data:image/png;base64,…`) of the provisioning QR code.
    pub qr_data_url: String,
    /// Single-use recovery codes. Store these securely — they are shown only once.
    pub recovery_codes: Vec<String>,
}

/// Request body for TOTP confirmation and recovery-code regeneration.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct ConfirmRequest {
    /// Current 6-digit TOTP code from the authenticator app.
    pub code: String,
}

/// Begin TOTP enrollment. Returns the secret and a QR code data URL. Enrollment is not
/// active until confirmed via `POST /v1/totp/confirmations`. Calling this again before
/// confirming replaces the pending enrollment.
#[utoipa::path(
    post,
    path = "/v1/totp",
    operation_id = "begin_totp_enrollment",
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
    let r = totp::enroll(
        &state.pool,
        ctx.user.id,
        &ctx.email.email,
        "Beyond Auth",
        state.encryptor.as_ref(),
    )
    .await?;
    Ok(Json(EnrollmentResponse {
        factor_id: r.factor_id,
        secret_b32: r.secret_b32,
        provisioning_uri: r.provisioning_uri,
        qr_data_url: r.qr_data_url,
        recovery_codes: r.recovery_codes,
    }))
}

/// Confirm TOTP enrollment by verifying a live code from the authenticator app. After this
/// call, TOTP is active and future logins will require a step-up challenge.
#[utoipa::path(
    post,
    path = "/v1/totp/confirmations",
    operation_id = "confirm_totp_enrollment",
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
    totp::confirm(
        &state.pool,
        ctx.user.id,
        &req.code,
        state.encryptor.as_ref(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Disable TOTP for the authenticated user. Future logins will no longer require a step-up
/// challenge. All recovery codes are also invalidated.
#[utoipa::path(
    delete,
    path = "/v1/totp",
    operation_id = "disable_totp",
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

/// Freshly generated TOTP recovery codes.
#[derive(Serialize, utoipa::ToSchema)]
pub struct RecoveryCodesResponse {
    /// New single-use recovery codes. All previous codes are immediately invalidated.
    pub recovery_codes: Vec<String>,
}

/// Regenerate TOTP recovery codes. Requires a valid TOTP code to prove the authenticator
/// app is still accessible. All existing recovery codes are invalidated and replaced.
#[utoipa::path(
    post,
    path = "/v1/totp/recovery-codes",
    operation_id = "regenerate_totp_recovery_codes",
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
    let codes = totp::regenerate_recovery_codes(
        &state.pool,
        ctx.user.id,
        &req.code,
        state.encryptor.as_ref(),
    )
    .await?;
    Ok(Json(RecoveryCodesResponse {
        recovery_codes: codes,
    }))
}
