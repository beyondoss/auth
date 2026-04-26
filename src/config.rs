use clap::Args;

#[derive(Debug, Args)]
pub struct ServeConfig {
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: String,

    #[arg(long, env = "ADDRESS", default_value = "0.0.0.0:8080")]
    pub address: String,

    #[arg(long, env = "LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    #[arg(long, env = "OTLP_ENABLED", default_value_t = false)]
    pub otlp_enabled: bool,

    #[arg(long, env = "OTLP_ENDPOINT", default_value = "http://localhost:4317")]
    pub otlp_endpoint: String,

    /// Base64url-encoded 32-byte key used to AES-256-GCM encrypt signing key material at rest.
    #[arg(long, env = "SIGNING_KEY_ENCRYPTION_KEY")]
    pub signing_key_encryption_key: String,

    /// Comma-separated old keys for zero-downtime KEK rotation. When set,
    /// decryption falls back to these keys in order if the current key fails.
    /// On successful fallback, the data is immediately re-encrypted with the
    /// current key. Remove old keys once all data has been rotated.
    #[arg(long, env = "SIGNING_KEY_ENCRYPTION_KEY_OLD")]
    pub signing_key_encryption_key_old: Option<String>,

    /// Secret token required for admin endpoints (e.g. PUT /v1/admin/oauth-providers).
    #[arg(long, env = "ADMIN_SECRET")]
    pub admin_secret: String,

    /// WebAuthn relying party ID (e.g. "example.com").
    #[arg(long, env = "WEBAUTHN_RP_ID")]
    pub webauthn_rp_id: String,

    /// WebAuthn relying party origin (e.g. "https://example.com").
    #[arg(long, env = "WEBAUTHN_RP_ORIGIN")]
    pub webauthn_rp_origin: String,

    /// Public base URL of this service (e.g. "https://auth.example.com").
    /// Used to construct OAuth callback URIs. If unset, derived from the
    /// incoming request Host header (less reliable behind some proxies).
    #[arg(long, env = "PUBLIC_URL")]
    pub public_url: Option<String>,

    /// Comma-separated list of origins allowed as OAuth post-login redirect targets.
    /// Example: "https://app.example.com,https://app.example.com:3000"
    /// If unset, redirect URL validation is skipped — configure this in production.
    #[arg(long, env = "OAUTH_ALLOWED_REDIRECT_ORIGINS")]
    pub oauth_allowed_redirect_origins: Option<String>,
}

#[derive(Debug, Args)]
pub struct MigrateConfig {
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: String,
}
