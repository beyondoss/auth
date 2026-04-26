use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::AuthError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppleConfig {
    pub client_id: String,
    pub team_id: String,
    pub key_id: String,
    pub private_key_pem: String,
}

#[derive(Clone)]
pub struct AppleClient {
    http: reqwest::Client,
    client_id: String,
    team_id: String,
    key_id: String,
    signing_key: SigningKey,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

impl AppleClient {
    pub fn new(http: reqwest::Client, cfg: AppleConfig) -> anyhow::Result<Self> {
        let signing_key = SigningKey::from_pkcs8_pem(&cfg.private_key_pem)
            .map_err(|e| anyhow::anyhow!("invalid Apple private key: {e}"))?;

        Ok(Self {
            http,
            client_id: cfg.client_id,
            team_id: cfg.team_id,
            key_id: cfg.key_id,
            signing_key,
        })
    }

    pub fn auth_url(&self, state: &str, redirect_uri: &str) -> String {
        format!(
            "https://appleid.apple.com/auth/authorize?client_id={}&redirect_uri={}&response_mode=form_post&response_type=code&scope={}&state={}",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode("name email"),
            urlencoding::encode(state),
        )
    }

    fn client_secret(&self) -> String {
        let now = Utc::now().timestamp();
        let exp = now + 15_552_000;

        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(&json!({
                "alg": "ES256",
                "kid": self.key_id,
                "typ": "JWT",
            }))
            .expect("apple client_secret header serialization is infallible"),
        );

        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(&json!({
                "iss": self.team_id,
                "sub": self.client_id,
                "aud": "https://appleid.apple.com",
                "iat": now,
                "exp": exp,
            }))
            .expect("apple client_secret claims serialization is infallible"),
        );

        let signing_input = format!("{header}.{claims}");
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_encoded = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        format!("{signing_input}.{sig_encoded}")
    }

    pub async fn exchange_and_profile(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<super::OAuthProfile, AuthError> {
        let secret = self.client_secret();
        let token_resp = self
            .http
            .post("https://appleid.apple.com/auth/token")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", secret.as_str()),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| AuthError::OAuthError {
                message: e.to_string(),
            })?;

        if !token_resp.status().is_success() {
            return Err(AuthError::OAuthError {
                message: format!("apple returned {}", token_resp.status()),
            });
        }

        let token: TokenResponse = token_resp.json().await.map_err(|e| AuthError::OAuthError {
            message: e.to_string(),
        })?;

        let parts: Vec<&str> = token.id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::OAuthError {
                message: "apple returned malformed id_token".to_string(),
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

        let sub = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::OAuthError {
                message: "id_token missing sub claim".to_string(),
            })?
            .to_string();

        let email = claims
            .get("email")
            .and_then(|v| v.as_str())
            .map(String::from);

        let email_verified = claims.get("email_verified").and_then(|v| match v {
            Value::Bool(b) => Some(*b),
            Value::String(s) => match s.as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            _ => None,
        });

        Ok(super::OAuthProfile {
            external_id: sub,
            email,
            email_verified,
            display_name: None,
            avatar_url: None,
        })
    }

    pub fn provider_slug(&self) -> &'static str {
        "oauth_apple"
    }
}
