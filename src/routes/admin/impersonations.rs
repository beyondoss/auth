use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    error::AuthError,
    http::AppState,
    sessions::{self, RequestContext},
    tokens::{Token, TokenPrefix},
};

use super::super::users::{AuthResponse, make_auth_response};

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ImpersonateRequest {
    /// The ID of the user to impersonate.
    pub user_id: Uuid,
}

/// Create an impersonation session for any user. Returns a session token that behaves like
/// a normal session but carries an `impersonated` flag in issued JWTs. Use this for admin
/// support workflows — not for production automation.
#[utoipa::path(
    post,
    operation_id = "create_impersonation",
    path = "/v1/admin/impersonations",
    tag = "admin",
    request_body = ImpersonateRequest,
    responses(
        (status = 201, description = "Impersonation session created", body = AuthResponse),
        (status = 404, description = "User not found", body = crate::error::ErrorResponse),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    Json(req): Json<ImpersonateRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), AuthError> {
    let cfg = state.app_config.read().await;
    let ttl = cfg.session_ttl_seconds;
    drop(cfg);

    let (user, org, email) = sessions::load_user_context(&state.pool, req.user_id).await?;
    let token = Token::new(TokenPrefix::Impersonation);
    let req_ctx = RequestContext {
        ip_address: None,
        user_agent: None,
    };
    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;
    let (session_id, expires_at) =
        sessions::create(&mut tx, &token, req.user_id, ttl, &req_ctx).await?;
    tx.commit().await.map_err(AuthError::from)?;

    Ok((
        StatusCode::CREATED,
        Json(make_auth_response(
            user, email, org, session_id, &token, expires_at,
        )),
    ))
}
