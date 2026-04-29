use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::error::AuthError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GoogleConfig {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Clone)]
pub struct GoogleClient {
    http: reqwest::Client,
    client_id: String,
    client_secret: String,
    auth_endpoint: String,
    token_endpoint: String,
}

#[derive(Deserialize)]
struct DiscoveryDoc {
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

impl GoogleClient {
    pub async fn new(http: reqwest::Client, cfg: GoogleConfig) -> anyhow::Result<Self> {
        let discovery: DiscoveryDoc = http
            .get("https://accounts.google.com/.well-known/openid-configuration")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(Self {
            http,
            client_id: cfg.client_id,
            client_secret: cfg.client_secret,
            auth_endpoint: discovery.authorization_endpoint,
            token_endpoint: discovery.token_endpoint,
        })
    }

    pub fn auth_url(&self, state: &str, pkce_challenge: &str) -> String {
        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            self.auth_endpoint,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(""),
            urlencoding::encode("openid email profile"),
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
            .map_err(|e| AuthError::OAuth {
                message: e.to_string(),
            })?;

        if !token_resp.status().is_success() {
            return Err(AuthError::OAuth {
                message: format!("google returned {}", token_resp.status()),
            });
        }

        let token: TokenResponse = token_resp.json().await.map_err(|e| AuthError::OAuth {
            message: e.to_string(),
        })?;

        let parts: Vec<&str> = token.id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::OAuth {
                message: "google returned malformed id_token".to_string(),
            });
        }

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| AuthError::OAuth {
                message: format!("failed to decode id_token payload: {e}"),
            })?;

        let claims: serde_json::Value =
            serde_json::from_slice(&payload_bytes).map_err(|e| AuthError::OAuth {
                message: format!("failed to parse id_token claims: {e}"),
            })?;

        let sub = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::OAuth {
                message: "id_token missing sub claim".to_string(),
            })?
            .to_string();

        let email = claims
            .get("email")
            .and_then(|v| v.as_str())
            .map(String::from);
        let email_verified = claims.get("email_verified").and_then(|v| v.as_bool());
        let display_name = claims
            .get("name")
            .and_then(|v| v.as_str())
            .map(String::from);
        let image_url = claims
            .get("picture")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(super::OAuthProfile {
            external_id: sub,
            email,
            email_verified,
            display_name,
            image_url,
        })
    }

    pub fn provider_slug(&self) -> &'static str {
        "oauth_google"
    }
}
