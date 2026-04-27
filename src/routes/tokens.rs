use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
};
use serde::Serialize;

use crate::{error::AuthError, http::AppState, jwt, sessions::SessionContext};

#[derive(Serialize, utoipa::ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    #[schema(value_type = String)]
    pub token_type: &'static str,
    /// Lifetime in seconds.
    pub expires_in: i32,
}

/// POST /v1/tokens — issue a short-lived JWT access token.
/// Requires `jwt_enabled = true` in app_config; returns 400 otherwise.
#[utoipa::path(
    post,
    path = "/v1/tokens",
    tag = "tokens",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, body = TokenResponse),
        (status = 400, description = "JWT not enabled", body = crate::error::ErrorResponse),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn issue(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<(StatusCode, Json<TokenResponse>), AuthError> {
    let cfg = state.app_config.read().await;

    if !cfg.jwt_enabled {
        return Err(AuthError::JwtDisabled);
    }

    let default_url = "https://auth.beyond.internal";
    let issuer_url = cfg.issuer_url.as_deref().unwrap_or(default_url);
    let audience = cfg
        .jwt_audience
        .as_deref()
        .or(cfg.issuer_url.as_deref())
        .unwrap_or(default_url);
    let ttl = cfg.access_token_ttl_seconds;
    let kid = state.signing_key.id;
    let signing_key = &state.signing_key.signing_key;

    let access_token = jwt::issue_access_token(
        ctx.user.id,
        issuer_url,
        audience,
        ttl,
        kid,
        signing_key,
        ctx.is_impersonated,
    )?;

    Ok((
        StatusCode::OK,
        Json(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: ttl,
        }),
    ))
}
