use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::{
    error::AuthError,
    http::AppState,
    oauth::{
        OAuthProviders, OAuthProvidersConfig, apple::AppleConfig, github::GithubConfig,
        google::GoogleConfig, microsoft::MicrosoftConfig, oidc::OidcConfig,
    },
};

#[derive(Deserialize, utoipa::ToSchema)]
pub struct AdminOAuthRequest {
    #[schema(value_type = Object, nullable)]
    pub github: Option<GithubConfig>,
    #[schema(value_type = Object, nullable)]
    pub google: Option<GoogleConfig>,
    #[schema(value_type = Object, nullable)]
    pub apple: Option<AppleConfig>,
    #[schema(value_type = Object, nullable)]
    pub microsoft: Option<MicrosoftConfig>,
    #[schema(value_type = Vec<Object>, nullable)]
    pub oidc: Option<Vec<OidcConfig>>,
    /// When true, OAuth identities are linked to existing accounts with the same email.
    #[schema(nullable)]
    pub email_link: Option<bool>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AdminOAuthResponse {
    #[schema(nullable)]
    pub github: Option<GithubRedacted>,
    #[schema(nullable)]
    pub google: Option<GoogleRedacted>,
    #[schema(nullable)]
    pub apple: Option<AppleRedacted>,
    #[schema(nullable)]
    pub microsoft: Option<MicrosoftRedacted>,
    #[schema(nullable)]
    pub oidc: Option<Vec<OidcRedacted>>,
    pub email_link: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct GithubRedacted {
    pub client_id: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct GoogleRedacted {
    pub client_id: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AppleRedacted {
    pub client_id: String,
    pub team_id: String,
    pub key_id: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct MicrosoftRedacted {
    pub client_id: String,
    pub org: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct OidcRedacted {
    pub id: String,
    pub discovery_url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
}

fn redact(cfg: &OAuthProvidersConfig, email_link: bool) -> AdminOAuthResponse {
    AdminOAuthResponse {
        github: cfg.github.as_ref().map(|g| GithubRedacted {
            client_id: g.client_id.clone(),
        }),
        google: cfg.google.as_ref().map(|g| GoogleRedacted {
            client_id: g.client_id.clone(),
        }),
        apple: cfg.apple.as_ref().map(|a| AppleRedacted {
            client_id: a.client_id.clone(),
            team_id: a.team_id.clone(),
            key_id: a.key_id.clone(),
        }),
        microsoft: cfg.microsoft.as_ref().map(|m| MicrosoftRedacted {
            client_id: m.client_id.clone(),
            org: m.org.clone(),
        }),
        oidc: cfg.oidc.as_ref().map(|list| {
            list.iter()
                .map(|o| OidcRedacted {
                    id: o.id.clone(),
                    discovery_url: o.discovery_url.clone(),
                    client_id: o.client_id.clone(),
                    scopes: o.scopes.clone(),
                })
                .collect()
        }),
        email_link,
    }
}

/// Replace the OAuth provider configuration. Secrets are encrypted at rest and never
/// returned in GET responses — only redacted metadata (client_id, etc.) is shown.
#[utoipa::path(
    put,
    path = "/v1/admin/oauth-providers",
    operation_id = "admin_set_oauth_providers",
    tag = "admin",
    request_body = AdminOAuthRequest,
    responses(
        (status = 200, body = AdminOAuthResponse),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn put(
    State(state): State<AppState>,
    Json(req): Json<AdminOAuthRequest>,
) -> Result<Json<AdminOAuthResponse>, AuthError> {
    let email_link = req.email_link.unwrap_or(false);

    let cfg = OAuthProvidersConfig {
        github: req.github,
        google: req.google,
        apple: req.apple,
        microsoft: req.microsoft,
        oidc: req.oidc,
    };

    let enc_bytes = OAuthProviders::encrypt_config(&cfg, state.encryptor.as_ref())
        .map_err(|e| AuthError::internal(format!("encrypt oauth config: {e}")))?;

    sqlx::query!(
        "UPDATE auth.app_config SET oauth_providers_enc = $1, oauth_email_link = $2 WHERE id = true",
        &enc_bytes as &[u8],
        email_link,
    )
    .execute(&state.pool)
    .await
    .map_err(AuthError::from)?;

    let new_providers = OAuthProviders::load(
        Some(&enc_bytes),
        state.encryptor.as_ref(),
        &state.http_client,
    )
    .await
    .map_err(|e| AuthError::internal(format!("reload oauth providers: {e}")))?;
    *state.oauth.write().await = new_providers;

    {
        let mut app_cfg = state.app_config.write().await;
        app_cfg.oauth_providers_enc = Some(enc_bytes);
        app_cfg.oauth_email_link = email_link;
    }

    Ok(Json(redact(&cfg, email_link)))
}

/// Get the current OAuth provider configuration. Secrets are redacted — only public
/// metadata (client_id, discovery URL, etc.) is returned.
#[utoipa::path(
    get,
    path = "/v1/admin/oauth-providers",
    operation_id = "admin_get_oauth_providers",
    tag = "admin",
    responses(
        (status = 200, body = AdminOAuthResponse),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn get(State(state): State<AppState>) -> Result<Json<AdminOAuthResponse>, AuthError> {
    let (enc_bytes, email_link) = {
        let cfg = state.app_config.read().await;
        (cfg.oauth_providers_enc.clone(), cfg.oauth_email_link)
    };

    let Some(enc_bytes) = enc_bytes.filter(|b| !b.is_empty()) else {
        return Ok(Json(AdminOAuthResponse {
            github: None,
            google: None,
            apple: None,
            microsoft: None,
            oidc: None,
            email_link,
        }));
    };

    let cfg = OAuthProviders::decrypt_config(&enc_bytes, state.encryptor.as_ref())
        .map_err(|e| AuthError::internal(format!("decrypt oauth config: {e}")))?;

    Ok(Json(redact(&cfg, email_link)))
}
