use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    error::AuthError,
    http::AppState,
    oauth::{self, pkce::PkceVerifier},
    sessions::{self, RequestContext},
    tokens::{Token, TokenPrefix},
};

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

fn validate_redirect_url(url: &str, allowlist: &[String]) -> Result<(), crate::error::AuthError> {
    if allowlist.is_empty() {
        return Ok(());
    }
    let parsed =
        reqwest::Url::parse(url).map_err(|_| crate::error::AuthError::OAuthRedirectNotAllowed)?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(crate::error::AuthError::OAuthRedirectNotAllowed),
    }
    let origin = parsed.origin().ascii_serialization();
    if allowlist.iter().any(|o| o == &origin) {
        Ok(())
    } else {
        Err(crate::error::AuthError::OAuthRedirectNotAllowed)
    }
}

fn request_context<'a>(headers: &'a HeaderMap) -> RequestContext<'a> {
    let ip_address = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(str::trim)
        });
    RequestContext {
        ip_address,
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok()),
    }
}

async fn complete_oauth_login(
    state: &AppState,
    headers: &HeaderMap,
    user_id: Uuid,
    redirect_url: &str,
) -> Result<Response, AuthError> {
    let ttl = {
        let cfg = state.app_config.read().await;
        cfg.session_ttl_seconds
    };

    let session_token = Token::new(TokenPrefix::Session);
    let ctx = request_context(headers);

    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;
    let (_session_id, expires_at) =
        sessions::create(&mut tx, &session_token, user_id, ttl, &ctx).await?;
    tx.commit().await.map_err(AuthError::from)?;

    let final_url = format!(
        "{}?token={}&expires_at={}",
        redirect_url,
        session_token,
        expires_at.to_rfc3339(),
    );

    Ok(Redirect::temporary(&final_url).into_response())
}

#[utoipa::path(
    get,
    path = "/v1/oauth/{provider}",
    tag = "oauth",
    params(
        ("provider" = String, Path, description = "OAuth provider slug, e.g. `github`, `google`"),
        ("redirect_url" = String, Query, description = "URL to redirect to after authentication"),
    ),
    responses(
        (status = 302, description = "Redirect to OAuth provider"),
        (status = 400, description = "Provider not configured", body = crate::error::ErrorResponse),
    )
)]
pub async fn authorize(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(params): Query<AuthorizeParams>,
    headers: HeaderMap,
) -> Result<Response, AuthError> {
    let client = {
        let providers = state.oauth.read().await;
        providers
            .get(&provider)
            .ok_or(AuthError::OAuthProviderNotConfigured)?
            .clone()
    };

    validate_redirect_url(&params.redirect_url, &state.oauth_redirect_allowlist)?;

    let verifier = PkceVerifier::new();
    let challenge = verifier.challenge();
    let redirect_uri = callback_uri(&headers, &provider, state.public_url.as_deref());

    let state_jwt =
        oauth::state::issue(verifier.as_str(), &params.redirect_url, &state.signing_key);
    let auth_url = client.auth_url(&state_jwt, challenge.as_str(), &redirect_uri);

    Ok(Redirect::temporary(&auth_url).into_response())
}

#[utoipa::path(
    get,
    path = "/v1/oauth/{provider}/callback",
    tag = "oauth",
    params(
        ("provider" = String, Path, description = "OAuth provider slug"),
        ("code" = String, Query, description = "Authorization code from provider"),
        ("state" = String, Query, description = "PKCE state JWT"),
    ),
    responses(
        (status = 302, description = "Redirect to redirect_url with token and expires_at query params"),
        (status = 400, description = "Invalid state or provider error", body = crate::error::ErrorResponse),
    )
)]
pub async fn callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(params): Query<CallbackParams>,
    headers: HeaderMap,
) -> Result<Response, AuthError> {
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

    complete_oauth_login(&state, &headers, user_id, &claims.redirect_url).await
}

#[utoipa::path(
    post,
    path = "/v1/oauth/apple/callback",
    tag = "oauth",
    responses(
        (status = 302, description = "Redirect to redirect_url with token and expires_at query params"),
        (status = 400, description = "Invalid state or Apple error", body = crate::error::ErrorResponse),
    )
)]
pub async fn apple_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Form(params): axum::extract::Form<AppleCallbackForm>,
) -> Result<Response, AuthError> {
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

    complete_oauth_login(&state, &headers, user_id, &claims.redirect_url).await
}
