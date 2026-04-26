use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AuthError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcConfig {
    pub id: String,
    pub discovery_url: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Clone)]
pub struct OidcClient {
    http: reqwest::Client,
    slug: String,
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
    auth_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
}

#[derive(Deserialize)]
struct DiscoveryDoc {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    id_token: Option<String>,
}

impl OidcClient {
    pub async fn new(http: reqwest::Client, cfg: OidcConfig) -> anyhow::Result<Self> {
        let discovery: DiscoveryDoc = http
            .get(&cfg.discovery_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(Self {
            http,
            slug: format!("oauth_oidc_{}", cfg.id),
            client_id: cfg.client_id,
            client_secret: cfg.client_secret,
            scopes: cfg.scopes,
            auth_endpoint: discovery.authorization_endpoint,
            token_endpoint: discovery.token_endpoint,
            userinfo_endpoint: discovery.userinfo_endpoint,
        })
    }

    pub fn auth_url(&self, state: &str, pkce_challenge: &str) -> String {
        let mut all_scopes = vec!["openid".to_string()];
        all_scopes.extend(self.scopes.iter().cloned());
        let scope = all_scopes.join(" ");

        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            self.auth_endpoint,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(""),
            urlencoding::encode(&scope),
            urlencoding::encode(state),
            urlencoding::encode(pkce_challenge),
        )
    }

    pub async fn exchange_and_profile(
        &self,
        code: &str,
        pkce_verifier: &str,
        redirect_uri: &str,
    ) -> Result<super::OAuthProfile, AuthError> {
        let token_resp = self
            .http
            .post(&self.token_endpoint)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
                ("code_verifier", pkce_verifier),
            ])
            .send()
            .await
            .map_err(|e| AuthError::OAuthError {
                message: e.to_string(),
            })?;

        if !token_resp.status().is_success() {
            return Err(AuthError::OAuthError {
                message: format!("oidc returned {}", token_resp.status()),
            });
        }

        let token: TokenResponse = token_resp.json().await.map_err(|e| AuthError::OAuthError {
            message: e.to_string(),
        })?;

        let id_token_sub: Option<String> = if let Some(id_token) = token.id_token.as_deref() {
            let parts: Vec<&str> = id_token.split('.').collect();
            if parts.len() != 3 {
                return Err(AuthError::OAuthError {
                    message: "oidc returned malformed id_token".to_string(),
                });
            }
            let payload_bytes =
                URL_SAFE_NO_PAD
                    .decode(parts[1])
                    .map_err(|e| AuthError::OAuthError {
                        message: format!("failed to decode id_token payload: {e}"),
                    })?;
            let claims: Value =
                serde_json::from_slice(&payload_bytes).map_err(|e| AuthError::OAuthError {
                    message: format!("failed to parse id_token claims: {e}"),
                })?;
            claims.get("sub").and_then(|v| v.as_str()).map(String::from)
        } else {
            None
        };

        let userinfo_resp = self
            .http
            .get(&self.userinfo_endpoint)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", token.access_token),
            )
            .send()
            .await
            .map_err(|e| AuthError::OAuthError {
                message: e.to_string(),
            })?;

        if !userinfo_resp.status().is_success() {
            return Err(AuthError::OAuthError {
                message: format!("oidc userinfo returned {}", userinfo_resp.status()),
            });
        }

        let userinfo: Value = userinfo_resp
            .json()
            .await
            .map_err(|e| AuthError::OAuthError {
                message: e.to_string(),
            })?;

        let sub = id_token_sub
            .or_else(|| {
                userinfo
                    .get("sub")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .ok_or_else(|| AuthError::OAuthError {
                message: "oidc missing sub".to_string(),
            })?;

        let email = userinfo
            .get("email")
            .and_then(|v| v.as_str())
            .map(String::from);
        let email_verified = userinfo.get("email_verified").and_then(|v| v.as_bool());
        let display_name = userinfo
            .get("name")
            .and_then(|v| v.as_str())
            .map(String::from);
        let avatar_url = userinfo
            .get("picture")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(super::OAuthProfile {
            external_id: sub,
            email,
            email_verified,
            display_name,
            avatar_url,
        })
    }

    pub fn provider_slug(&self) -> &str {
        &self.slug
    }
}
