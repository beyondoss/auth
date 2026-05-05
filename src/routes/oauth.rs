use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AuthError,
    http::AppState,
    mfa,
    oauth::{self, pkce::PkceVerifier},
    sessions,
    tokens::{Token, TokenPrefix},
};

// ── Shared helpers ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuthorizeParams {
    pub redirect_url: String,
}

#[derive(Deserialize)]
pub struct CallbackParams {
    pub code: String,
    pub state: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct AppleCallbackForm {
    pub code: String,
    pub state: String,
    pub user: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AuthorizeResponse {
    /// Full OAuth authorization URL — navigate the browser here to start the flow.
    pub url: String,
}

/// Session token returned after a successful OAuth login callback.
#[derive(Serialize, utoipa::ToSchema)]
pub struct CallbackResponse {
    /// Opaque session bearer token. Use as `Authorization: Bearer <token>`.
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Returned when an OAuth callback links a provider identity to an existing account
/// rather than creating a new session.
#[derive(Serialize, utoipa::ToSchema)]
pub struct LinkCallbackResponse {
    pub linked: bool,
}

fn callback_uri(headers: &HeaderMap, provider: &str, public_url: Option<&str>) -> String {
    if let Some(base) = public_url {
        return format!(
            "{}/v1/oauth/{provider}/callback",
            base.trim_end_matches('/')
        );
    }
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    format!("{proto}://{host}/v1/oauth/{provider}/callback")
}

fn validate_redirect_url(url: &str, allowlist: &[String]) -> Result<(), AuthError> {
    if allowlist.is_empty() {
        return Ok(());
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| AuthError::OAuthRedirectNotAllowed)?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(AuthError::OAuthRedirectNotAllowed),
    }
    let origin = parsed.origin().ascii_serialization();
    if allowlist.iter().any(|o| o == &origin) {
        Ok(())
    } else {
        Err(AuthError::OAuthRedirectNotAllowed)
    }
}

/// Extract a user_id from an optional `Authorization: Bearer` session token.
/// Returns `None` if no token is present or the token is invalid/expired —
/// never returns an error, so unauthenticated callers fall through to the normal login flow.
async fn try_session_user_id(state: &AppState, headers: &HeaderMap) -> Option<Uuid> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))?;

    let parsed = crate::tokens::parse(bearer)?;
    let idle_timeout = state.app_config.read().await.session_idle_timeout_seconds;
    let ctx = sessions::validate(&state.pool, parsed.id, &parsed.secret_hash, idle_timeout)
        .await
        .ok()??;
    Some(ctx.user.id)
}

// ── GET /v1/oauth/{provider} ──────────────────────────────────────────────────

/// Start an OAuth authorization flow. Returns the provider's authorization URL.
/// If the caller includes a valid session Bearer token, the resulting identity will be
/// linked to that account instead of creating a new session.
#[utoipa::path(
    get,
    path = "/v1/oauth/{provider}",
    operation_id = "oauth_authorize",
    tag = "oauth",
    params(
        ("provider" = String, Path, description = "OAuth provider slug, e.g. `github`, `google`"),
        ("redirect_url" = String, Query, description = "URL to redirect to after authentication"),
    ),
    responses(
        (status = 200, body = AuthorizeResponse),
        (status = 400, description = "Provider not configured", body = crate::error::ErrorResponse),
    )
)]
pub async fn authorize(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(params): Query<AuthorizeParams>,
    headers: HeaderMap,
) -> Result<Json<AuthorizeResponse>, AuthError> {
    let client = {
        let providers = state.oauth.read().await;
        providers
            .get(&provider)
            .ok_or(AuthError::OAuthProviderNotConfigured)?
            .clone()
    };

    validate_redirect_url(&params.redirect_url, &state.oauth_redirect_allowlist)?;

    let link_user_id = try_session_user_id(&state, &headers).await;

    let verifier = PkceVerifier::new();
    let challenge = verifier.challenge();
    let redirect_uri = callback_uri(&headers, &provider, state.public_url.as_deref());

    let state_jwt = oauth::state::issue(
        verifier.as_str(),
        &params.redirect_url,
        link_user_id,
        &state.signing_key,
    );
    let auth_url = client.auth_url(&state_jwt, challenge.as_str(), &redirect_uri);

    Ok(Json(AuthorizeResponse { url: auth_url }))
}

// ── GET /v1/oauth/{provider}/callback ─────────────────────────────────────────

/// OAuth authorization callback. Exchanges the provider code for a profile, then either
/// creates a new session (login) or links the identity to the authenticated user (link flow).
/// When TOTP is enrolled, returns a step-up challenge instead of a session token.
/// Returns 409 if the OAuth identity is already claimed by a different user.
#[utoipa::path(
    get,
    path = "/v1/oauth/{provider}/callback",
    operation_id = "oauth_callback",
    tag = "oauth",
    params(
        ("provider" = String, Path, description = "OAuth provider slug"),
        ("code" = String, Query, description = "Authorization code from provider"),
        ("state" = String, Query, description = "PKCE state JWT"),
    ),
    responses(
        (status = 200, body = CallbackResponse, description = "Login — returns session token"),
        (status = 200, body = LinkCallbackResponse, description = "Link — identity added to existing account"),
        (status = 400, description = "Invalid state or provider error", body = crate::error::ErrorResponse),
        (status = 409, description = "OAuth identity already claimed by another user", body = crate::error::ErrorResponse),
    )
)]
pub async fn callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(params): Query<CallbackParams>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AuthError> {
    let claims = oauth::state::verify(&params.state, &state.signing_key)?;

    let client = {
        let providers = state.oauth.read().await;
        providers
            .get(&provider)
            .ok_or(AuthError::OAuthProviderNotConfigured)?
            .clone()
    };

    let redirect_uri = callback_uri(&headers, &provider, state.public_url.as_deref());

    let profile = client
        .exchange_and_profile(&params.code, &claims.pkce_verifier, &redirect_uri)
        .await?;

    if let Some(link_user_id) = claims.link_user_id {
        oauth::link_identity(
            &state.pool,
            link_user_id,
            client.provider_slug(),
            &profile.external_id,
        )
        .await?;
        return Ok(Json(serde_json::json!({ "linked": true })));
    }

    let email_link_enabled = {
        let cfg = state.app_config.read().await;
        cfg.oauth_email_link
    };

    let user_id = oauth::find_or_create_oauth_user(
        &state.pool,
        &profile,
        client.provider_slug(),
        email_link_enabled,
    )
    .await?;

    if mfa::totp::is_enrolled(&state.pool, user_id).await? {
        let step_up_token = mfa::step_up::issue(user_id, "totp", &state.signing_key);
        return Ok(Json(serde_json::json!({
            "step_up_required": "totp",
            "step_up_token": step_up_token,
        })));
    }

    let (token, expires_at) = create_session(&state, &headers, user_id).await?;
    Ok(Json(serde_json::json!({
        "token": token.to_string(),
        "expires_at": expires_at.to_rfc3339(),
    })))
}

// ── POST /v1/oauth/apple/callback ─────────────────────────────────────────────

/// Apple Sign-In callback. Apple uses a POST form submission instead of a GET redirect,
/// so this is a separate endpoint. Behavior is identical to `GET /v1/oauth/{provider}/callback`.
#[utoipa::path(
    post,
    path = "/v1/oauth/apple/callback",
    operation_id = "apple_oauth_callback",
    tag = "oauth",
    responses(
        (status = 200, body = CallbackResponse, description = "Login — returns session token"),
        (status = 200, body = LinkCallbackResponse, description = "Link — identity added to existing account"),
        (status = 400, description = "Invalid state or Apple error", body = crate::error::ErrorResponse),
    )
)]
pub async fn apple_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Form(params): axum::extract::Form<AppleCallbackForm>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let claims = oauth::state::verify(&params.state, &state.signing_key)?;

    let client = {
        let providers = state.oauth.read().await;
        providers
            .get("apple")
            .ok_or(AuthError::OAuthProviderNotConfigured)?
            .clone()
    };

    let redirect_uri = callback_uri(&headers, "apple", state.public_url.as_deref());

    let mut profile = client
        .exchange_and_profile(&params.code, "", &redirect_uri)
        .await?;

    if profile.display_name.is_none()
        && let Some(user_json) = params.user.as_deref()
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(user_json)
    {
        let first = v
            .get("name")
            .and_then(|n| n.get("firstName"))
            .and_then(|s| s.as_str());
        let last = v
            .get("name")
            .and_then(|n| n.get("lastName"))
            .and_then(|s| s.as_str());
        let combined = match (first, last) {
            (Some(f), Some(l)) => Some(format!("{f} {l}")),
            (Some(f), None) => Some(f.to_string()),
            (None, Some(l)) => Some(l.to_string()),
            (None, None) => None,
        };
        if combined.is_some() {
            profile.display_name = combined;
        }
    }

    if let Some(link_user_id) = claims.link_user_id {
        oauth::link_identity(
            &state.pool,
            link_user_id,
            client.provider_slug(),
            &profile.external_id,
        )
        .await?;
        return Ok(Json(serde_json::json!({ "linked": true })));
    }

    let email_link_enabled = {
        let cfg = state.app_config.read().await;
        cfg.oauth_email_link
    };

    let user_id = oauth::find_or_create_oauth_user(
        &state.pool,
        &profile,
        client.provider_slug(),
        email_link_enabled,
    )
    .await?;

    if mfa::totp::is_enrolled(&state.pool, user_id).await? {
        let step_up_token = mfa::step_up::issue(user_id, "totp", &state.signing_key);
        return Ok(Json(serde_json::json!({
            "step_up_required": "totp",
            "step_up_token": step_up_token,
        })));
    }

    let (token, expires_at) = create_session(&state, &headers, user_id).await?;
    Ok(Json(serde_json::json!({
        "token": token.to_string(),
        "expires_at": expires_at.to_rfc3339(),
    })))
}

async fn create_session(
    state: &AppState,
    headers: &HeaderMap,
    user_id: Uuid,
) -> Result<(Token, chrono::DateTime<chrono::Utc>), AuthError> {
    let ttl = {
        let cfg = state.app_config.read().await;
        cfg.session_ttl_seconds
    };

    let session_token = Token::new(TokenPrefix::Session);
    let ctx = sessions::request_context(headers);

    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;
    let (_session_id, expires_at) =
        sessions::create(&mut tx, &session_token, user_id, ttl, &ctx).await?;
    tx.commit().await.map_err(AuthError::from)?;

    Ok((session_token, expires_at))
}
