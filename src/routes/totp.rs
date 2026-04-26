use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::AuthError, http::AppState, mfa::totp, sessions::SessionContext};

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
    Extension(ctx): Extension<SessionContext>,
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
    put,
    path = "/v1/totp",
    tag = "totp",
    security(("BearerAuth" = [])),
    request_body = ConfirmRequest,
    responses(
        (status = 200, description = "TOTP enrollment confirmed"),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn confirm_enrollment(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Json(req): Json<ConfirmRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    totp::confirm(&state.pool, ctx.user.id, &req.code).await?;
    Ok(Json(serde_json::json!({})))
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
    Extension(ctx): Extension<SessionContext>,
) -> Result<StatusCode, AuthError> {
    totp::disable(&state.pool, ctx.user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}
