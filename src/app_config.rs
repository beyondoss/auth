use sqlx::PgPool;

use crate::error::AuthError;

#[derive(Debug, Clone)]
pub struct AppConfig {
    #[allow(dead_code)]
    pub jwt_mode: String,
    pub access_token_ttl_seconds: i32,
    pub session_ttl_seconds: i32,
    pub jwt_enabled: bool,
    pub issuer_url: Option<String>,
}

pub async fn load(pool: &PgPool) -> Result<AppConfig, AuthError> {
    sqlx::query_as!(
        AppConfig,
        "SELECT jwt_mode, access_token_ttl_seconds, session_ttl_seconds, jwt_enabled, issuer_url
         FROM auth.app_config
         WHERE id = true"
    )
    .fetch_one(pool)
    .await
    .map_err(AuthError::from)
}
