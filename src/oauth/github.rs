use serde::{Deserialize, Serialize};

use crate::error::AuthError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GithubConfig {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Clone)]
pub struct GithubClient {
    http: reqwest::Client,
    client_id: String,
    client_secret: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GithubUser {
    id: i64,
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

impl GithubClient {
    pub fn new(http: reqwest::Client, cfg: GithubConfig) -> Self {
        Self {
            http,
            client_id: cfg.client_id,
            client_secret: cfg.client_secret,
        }
    }

    pub fn auth_url(&self, state: &str) -> String {
        format!(
            "https://github.com/login/oauth/authorize?client_id={}&scope={}&state={}",
            urlencoding::encode(&self.client_id),
            urlencoding::encode("read:user,user:email"),
            urlencoding::encode(state),
        )
    }

    pub async fn exchange_and_profile(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<super::OAuthProfile, AuthError> {
        let token_resp = self
            .http
            .post("https://github.com/login/oauth/access_token")
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await
            .map_err(|e| AuthError::OAuth {
                message: e.to_string(),
            })?;

        if !token_resp.status().is_success() {
            return Err(AuthError::OAuth {
                message: format!("github returned {}", token_resp.status()),
            });
        }

        let token: TokenResponse = token_resp.json().await.map_err(|e| AuthError::OAuth {
            message: e.to_string(),
        })?;

        let user_resp = self
            .http
            .get("https://api.github.com/user")
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", token.access_token),
            )
            .header(reqwest::header::USER_AGENT, "beyond-auth")
            .send()
            .await
            .map_err(|e| AuthError::OAuth {
                message: e.to_string(),
            })?;

        if !user_resp.status().is_success() {
            return Err(AuthError::OAuth {
                message: format!("github returned {}", user_resp.status()),
            });
        }

        let user: GithubUser = user_resp.json().await.map_err(|e| AuthError::OAuth {
            message: e.to_string(),
        })?;

        let emails_resp = self
            .http
            .get("https://api.github.com/user/emails")
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", token.access_token),
            )
            .header(reqwest::header::USER_AGENT, "beyond-auth")
            .send()
            .await
            .map_err(|e| AuthError::OAuth {
                message: e.to_string(),
            })?;

        if !emails_resp.status().is_success() {
            return Err(AuthError::OAuth {
                message: format!("github returned {}", emails_resp.status()),
            });
        }

        let emails: Vec<GithubEmail> = emails_resp.json().await.map_err(|e| AuthError::OAuth {
            message: e.to_string(),
        })?;

        let primary_email = emails.into_iter().find(|e| e.primary && e.verified);

        Ok(super::OAuthProfile {
            external_id: user.id.to_string(),
            email: primary_email.map(|e| e.email),
            email_verified: Some(true),
            display_name: user.name,
            image_url: user.avatar_url,
        })
    }

    pub fn provider_slug(&self) -> &'static str {
        "oauth_github"
    }
}
