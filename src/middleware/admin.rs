use axum::{extract::State, http::Request, middleware::Next, response::Response};
use subtle::ConstantTimeEq;

use crate::{error::AuthError, http::AppState};

pub async fn require_admin(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AuthError> {
    let token = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    if !bool::from(state.admin_secret.as_bytes().ct_eq(token.as_bytes())) {
        return Err(AuthError::AdminRequired);
    }

    Ok(next.run(req).await)
}
