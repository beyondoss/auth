use axum::{
    extract::State,
    http::{Request, header},
    middleware::Next,
    response::Response,
};

use crate::{error::AuthError, http::AppState, keys, sessions, tokens};

/// Require a valid bearer token — either a session token or an API key.
///
/// Extraction order:
///   1. `x-api-key: key_<id>_<secret>`
///   2. `Authorization: Bearer <token>`
///
/// Dispatches on the parsed prefix:
///   - `"key"`        → API key validation (`auth.keys`)
///   - `"session"` / `"impersonate"` → session validation (`auth.sessions`)
///
/// On success, inserts an `AuthContext` into request extensions.
/// On failure, returns 401.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AuthError> {
    let raw = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .or_else(|| {
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(|s| s.to_owned())
        })
        .ok_or(AuthError::Unauthorized)?;

    let parsed = tokens::parse(&raw).ok_or(AuthError::Unauthorized)?;

    let ctx = match parsed.prefix.as_str() {
        "key" => keys::validate(&state.pool, parsed.id, &parsed.secret_hash)
            .await?
            .ok_or(AuthError::Unauthorized)?,

        "session" | "impersonate" => {
            let idle_timeout = state.app_config.read().await.session_idle_timeout_seconds;
            let start = std::time::Instant::now();
            let result =
                sessions::validate(&state.pool, parsed.id, &parsed.secret_hash, idle_timeout).await;
            state
                .metrics
                .session_validation_duration_seconds
                .observe(start.elapsed().as_secs_f64());
            let mut ctx = result?.ok_or(AuthError::Unauthorized)?;
            ctx.is_impersonated = parsed.prefix == "impersonate";
            ctx
        }

        _ => return Err(AuthError::Unauthorized),
    };

    req.extensions_mut().insert(ctx);
    Ok(next.run(req).await)
}
