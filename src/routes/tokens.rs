use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AuthError,
    http::AppState,
    jwt, keys, refresh_tokens,
    sessions::{self, AuthSource},
    tokens::{self, TokenPrefix},
};

#[derive(Deserialize, utoipa::ToSchema)]
pub struct IssueRequest {
    /// Arbitrary JSON object merged into the JWT payload.
    /// Reserved keys (`sub`, `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`,
    /// `impersonated`) are always overwritten by the service and cannot be
    /// supplied here.
    #[serde(default)]
    pub claims: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    #[schema(value_type = String)]
    pub token_type: &'static str,
    /// Access token lifetime in seconds.
    pub expires_in: i32,
    /// Rotate-on-use refresh token. Present when authenticated via a session or
    /// a prior refresh token; absent for API-key auth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// POST /v1/tokens — issue a short-lived JWT access token.
///
/// Accepts any valid bearer credential in `Authorization`:
/// - **Session token** (`session_…`) — issues JWT + a fresh refresh token.
/// - **Refresh token** (`rt_…`) — rotates the refresh token and issues a new JWT.
/// - **API key** (`key_…`) — issues JWT only (no refresh token).
///
/// Requires `jwt_enabled = true` in app_config; returns 400 otherwise.
/// An optional JSON body may carry `claims` — a flat object of key/value pairs
/// merged into the JWT payload after all reserved claims are set.
#[utoipa::path(
    post,
    path = "/v1/tokens",
    tag = "tokens",
    security(("BearerAuth" = [])),
    request_body(content = IssueRequest),
    responses(
        (status = 200, body = TokenResponse),
        (status = 400, description = "JWT not enabled", body = crate::error::ErrorResponse),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<IssueRequest>>,
) -> Result<(StatusCode, Json<TokenResponse>), AuthError> {
    // Extract bearer token directly — this route handles its own auth so that
    // refresh tokens (`rt_…`) are only usable here and not as general session
    // credentials via the shared require_auth middleware.
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
        .ok_or(AuthError::Unauthorized)?
        .to_owned();

    let parsed = tokens::parse(&raw).ok_or(AuthError::Unauthorized)?;

    let cfg = state.app_config.read().await;
    if !cfg.jwt_enabled {
        return Err(AuthError::JwtDisabled);
    }

    let default_url = "https://auth.beyond.internal";
    let issuer_url = cfg.issuer_url.as_deref().unwrap_or(default_url).to_owned();
    let audience = cfg
        .jwt_audience
        .as_deref()
        .or(cfg.issuer_url.as_deref())
        .unwrap_or(default_url)
        .to_owned();
    let access_ttl = cfg.access_token_ttl_seconds;
    let refresh_ttl = cfg.refresh_token_ttl_seconds;
    let idle_timeout = cfg.session_idle_timeout_seconds;
    drop(cfg);

    let kid = state.signing_key.id;
    let signing_key = &state.signing_key.signing_key;
    let extra_claims = body.and_then(|b| b.0.claims);

    match parsed.prefix.as_str() {
        "rt" => {
            let validated = refresh_tokens::validate(&state.pool, parsed.id, &parsed.secret_hash)
                .await?
                .ok_or(AuthError::Unauthorized)?;

            let access_token = jwt::issue_access_token(
                validated.user_id,
                &issuer_url,
                &audience,
                access_ttl,
                kid,
                signing_key,
                validated.is_impersonated,
                extra_claims.as_ref(),
            )?;

            let new_rt = tokens::Token::new(TokenPrefix::Refresh);
            let new_rt_str = new_rt.to_string();
            let mut tx = state.pool.begin().await.map_err(AuthError::from)?;
            refresh_tokens::rotate(
                &state.pool,
                &mut tx,
                validated.token_id,
                &new_rt,
                validated.session_id,
                validated.family_id,
                refresh_ttl,
            )
            .await?;
            tx.commit().await.map_err(AuthError::from)?;

            Ok((
                StatusCode::OK,
                Json(TokenResponse {
                    access_token,
                    token_type: "Bearer",
                    expires_in: access_ttl,
                    refresh_token: Some(new_rt_str),
                }),
            ))
        }

        "session" | "impersonate" => {
            let mut ctx =
                sessions::validate(&state.pool, parsed.id, &parsed.secret_hash, idle_timeout)
                    .await?
                    .ok_or(AuthError::Unauthorized)?;
            ctx.is_impersonated = parsed.prefix == "impersonate";

            let access_token = jwt::issue_access_token(
                ctx.user.id,
                &issuer_url,
                &audience,
                access_ttl,
                kid,
                signing_key,
                ctx.is_impersonated,
                extra_claims.as_ref(),
            )?;

            let refresh_token = if let AuthSource::Session(session_id) = ctx.source {
                let rt = tokens::Token::new(TokenPrefix::Refresh);
                let rt_str = rt.to_string();
                let family_id = Uuid::now_v7();
                let mut tx = state.pool.begin().await.map_err(AuthError::from)?;
                refresh_tokens::create(&mut tx, &rt, session_id, family_id, refresh_ttl).await?;
                tx.commit().await.map_err(AuthError::from)?;
                Some(rt_str)
            } else {
                None
            };

            Ok((
                StatusCode::OK,
                Json(TokenResponse {
                    access_token,
                    token_type: "Bearer",
                    expires_in: access_ttl,
                    refresh_token,
                }),
            ))
        }

        "key" => {
            let ctx = keys::validate(&state.pool, parsed.id, &parsed.secret_hash)
                .await?
                .ok_or(AuthError::Unauthorized)?;

            let access_token = jwt::issue_access_token(
                ctx.user.id,
                &issuer_url,
                &audience,
                access_ttl,
                kid,
                signing_key,
                ctx.is_impersonated,
                extra_claims.as_ref(),
            )?;

            Ok((
                StatusCode::OK,
                Json(TokenResponse {
                    access_token,
                    token_type: "Bearer",
                    expires_in: access_ttl,
                    refresh_token: None,
                }),
            ))
        }

        _ => Err(AuthError::Unauthorized),
    }
}
