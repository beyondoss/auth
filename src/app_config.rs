use sqlx::PgPool;

use crate::{
    authz::schema::{AuthzSchema, CompiledSchema, SchemaError, compile},
    error::AuthError,
};

#[derive(Debug, Clone)]
pub struct AppConfig {
    #[allow(dead_code)]
    pub jwt_mode: String,
    pub access_token_ttl_seconds: i32,
    pub refresh_token_ttl_seconds: i32,
    pub session_ttl_seconds: i32,
    pub jwt_enabled: bool,
    pub issuer_url: Option<String>,
    pub jwt_audience: Option<String>,
    pub oauth_providers_enc: Option<Vec<u8>>,
    pub oauth_email_link: bool,
    pub authz_schema: Option<serde_json::Value>,
    pub session_idle_timeout_seconds: Option<i32>,
}

pub async fn load(pool: &PgPool) -> Result<AppConfig, AuthError> {
    sqlx::query_as!(
        AppConfig,
        r#"
        SELECT jwt_mode,
               access_token_ttl_seconds,
               refresh_token_ttl_seconds,
               session_ttl_seconds,
               jwt_enabled,
               issuer_url,
               jwt_audience,
               oauth_providers_enc,
               oauth_email_link,
               authz_schema AS "authz_schema: serde_json::Value",
               session_idle_timeout_seconds
        FROM auth.app_config
        WHERE id = true
        "#
    )
    .fetch_one(pool)
    .await
    .map_err(AuthError::from)
}

/// Compile the stored authz schema JSON into a `CompiledSchema`, if present.
pub fn compile_authz_schema(cfg: &AppConfig) -> Result<Option<CompiledSchema>, SchemaError> {
    cfg.authz_schema
        .as_ref()
        .map(|v| {
            serde_json::from_value::<AuthzSchema>(v.clone())
                .map_err(|e| SchemaError::ParseError(e.to_string()))
                .and_then(|s| compile(&s))
        })
        .transpose()
}

/// Extract resource names from the stored authz schema, for partition management.
#[allow(dead_code)]
pub fn authz_resource_names(cfg: &AppConfig) -> Vec<String> {
    cfg.authz_schema
        .as_ref()
        .and_then(|v| serde_json::from_value::<AuthzSchema>(v.clone()).ok())
        .map(|s| s.resources.into_iter().map(|r| r.name).collect())
        .unwrap_or_default()
}
