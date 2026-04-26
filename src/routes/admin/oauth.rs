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

#[derive(Deserialize)]
pub struct AdminOAuthRequest {
    pub github: Option<GithubConfig>,
    pub google: Option<GoogleConfig>,
    pub apple: Option<AppleConfig>,
    pub microsoft: Option<MicrosoftConfig>,
    pub oidc: Option<Vec<OidcConfig>>,
    pub email_link: Option<bool>,
}

#[derive(Serialize)]
pub struct AdminOAuthResponse {
    pub github: Option<GithubRedacted>,
    pub google: Option<GoogleRedacted>,
    pub apple: Option<AppleRedacted>,
    pub microsoft: Option<MicrosoftRedacted>,
    pub oidc: Option<Vec<OidcRedacted>>,
    pub email_link: bool,
}

#[derive(Serialize)]
pub struct GithubRedacted {
    pub client_id: String,
}

#[derive(Serialize)]
pub struct GoogleRedacted {
    pub client_id: String,
}

#[derive(Serialize)]
pub struct AppleRedacted {
    pub client_id: String,
    pub team_id: String,
    pub key_id: String,
}

#[derive(Serialize)]
pub struct MicrosoftRedacted {
    pub client_id: String,
    pub tenant: String,
}

#[derive(Serialize)]
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
            tenant: m.tenant.clone(),
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
