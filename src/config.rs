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
}

#[derive(Debug, Args)]
pub struct MigrateConfig {
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: String,
}
