use axum::{
    extract::State,
    http::{Request, header},
    middleware::Next,
    response::Response,
};

use crate::{error::AuthError, http::AppState, sessions, tokens};

/// Require a valid `Authorization: Bearer session_X_Y` token.
/// On success, inserts a `SessionContext` into request extensions.
/// On failure, returns 401.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AuthError> {
    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AuthError::Unauthorized)?;

    let parsed = tokens::parse(bearer).ok_or(AuthError::Unauthorized)?;
    let is_impersonated = parsed.prefix == "impersonate";

    let mut ctx = sessions::validate(&state.pool, parsed.id, &parsed.secret_hash)
        .await?
        .ok_or(AuthError::Unauthorized)?;
    ctx.is_impersonated = is_impersonated;

    req.extensions_mut().insert(ctx);
    Ok(next.run(req).await)
}
