use std::path::PathBuf;

use clap::Args;

#[derive(Args)]
pub struct ServeConfig {
    /// If set, secrets (DATABASE_URL, SIGNING_KEY_ENCRYPTION_KEY, ADMIN_SECRET)
    /// are fetched from the Firecracker Metadata Service at this endpoint
    /// (e.g. `http://169.254.169.254`) instead of environment variables.
    /// Env vars act as per-key fallbacks when a key is absent from MMDS.
    #[arg(long, env = "MMDS_ENDPOINT")]
    pub mmds_endpoint: Option<String>,

    #[arg(long, env = "DATABASE_URL")]
    pub database_url: Option<String>,

    #[arg(long, env = "ADDRESS", default_value = "0.0.0.0:8080")]
    pub address: String,

    #[arg(long, env = "LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    #[arg(long, env = "OTLP_ENABLED", default_value_t = false)]
    pub otlp_enabled: bool,

    #[arg(long, env = "OTLP_ENDPOINT", default_value = "http://localhost:4317")]
    pub otlp_endpoint: String,

    /// OTLP trace sample rate (0.0 = never, 1.0 = always, 0.1 = 10%).
    /// Only effective when OTLP_ENABLED=true.
    #[arg(long, env = "OTLP_SAMPLE_RATE", default_value_t = 0.1)]
    pub otlp_sample_rate: f64,

    /// Base64url-encoded 32-byte key used to AES-256-GCM encrypt signing key material at rest.
    #[arg(long, env = "SIGNING_KEY_ENCRYPTION_KEY")]
    pub signing_key_encryption_key: Option<String>,

    /// Comma-separated old keys for zero-downtime KEK rotation. When set,
    /// decryption falls back to these keys in order if the current key fails.
    /// On successful fallback, the data is immediately re-encrypted with the
    /// current key. Remove old keys once all data has been rotated.
    #[arg(long, env = "SIGNING_KEY_ENCRYPTION_KEY_OLD")]
    pub signing_key_encryption_key_old: Option<String>,

    /// Secret token required for admin endpoints (e.g. PUT /v1/admin/oauth-providers).
    #[arg(long, env = "ADMIN_SECRET")]
    pub admin_secret: Option<String>,

    /// WebAuthn relying party ID (e.g. "example.com"). Required only when passkeys are used.
    #[arg(long, env = "WEBAUTHN_RP_ID")]
    pub webauthn_rp_id: Option<String>,

    /// WebAuthn relying party origin (e.g. "https://example.com"). Required only when passkeys are used.
    #[arg(long, env = "WEBAUTHN_RP_ORIGIN")]
    pub webauthn_rp_origin: Option<String>,

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

    /// Maximum number of connections in the Postgres connection pool.
    #[arg(long, env = "DATABASE_POOL_SIZE", default_value_t = 16)]
    pub database_pool_size: u32,

    /// Maximum number of (subject, resource, permission) entries in the in-process authz check cache.
    #[arg(long, env = "AUTHZ_CACHE_SIZE", default_value_t = 100_000)]
    pub authz_cache_size: usize,

    /// TTL in seconds for authz check cache entries. Version-tag invalidation handles most
    /// write-side correctness; TTL is a safety net for deep-chain transitive changes.
    #[arg(long, env = "AUTHZ_CACHE_TTL_SECS", default_value_t = 1800)]
    pub authz_cache_ttl_secs: u64,

    /// Path to the PEM-encoded TLS certificate for this service.
    /// When all three BEYOND_TLS_* vars are set, the server switches to mTLS.
    #[arg(long, env = "BEYOND_TLS_CERT")]
    pub tls_cert: Option<String>,

    /// Path to the PEM-encoded TLS private key for this service.
    #[arg(long, env = "BEYOND_TLS_KEY")]
    pub tls_key: Option<String>,

    /// Path to the PEM-encoded CA certificate used to verify client certificates.
    #[arg(long, env = "BEYOND_TLS_CA")]
    pub tls_ca: Option<String>,

    /// Directory for handoff coordination state — the data-dir flock
    /// (`.handoff.lock`) and the handoff control socket (`.handoff.sock`).
    /// Created at startup if missing. Required even when running without
    /// `handoff-supervisor`, since `ColdStart` still acquires the flock.
    #[arg(long, env = "BEYOND_DATA_DIR", default_value = "/var/lib/beyond-auth")]
    pub data_dir: PathBuf,
}

impl std::fmt::Debug for ServeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeConfig")
            .field("mmds_endpoint", &self.mmds_endpoint)
            .field("database_url", &"[redacted]")
            .field("address", &self.address)
            .field("log_level", &self.log_level)
            .field("otlp_enabled", &self.otlp_enabled)
            .field("otlp_endpoint", &self.otlp_endpoint)
            .field("otlp_sample_rate", &self.otlp_sample_rate)
            .field("signing_key_encryption_key", &"[redacted]")
            .field(
                "signing_key_encryption_key_old",
                &self
                    .signing_key_encryption_key_old
                    .as_ref()
                    .map(|_| "[redacted]"),
            )
            .field("admin_secret", &"[redacted]")
            .field("webauthn_rp_id", &self.webauthn_rp_id)
            .field("webauthn_rp_origin", &self.webauthn_rp_origin)
            .field("public_url", &self.public_url)
            .field(
                "oauth_allowed_redirect_origins",
                &self.oauth_allowed_redirect_origins,
            )
            .field("database_pool_size", &self.database_pool_size)
            .field("authz_cache_size", &self.authz_cache_size)
            .field("authz_cache_ttl_secs", &self.authz_cache_ttl_secs)
            .field("tls_cert", &self.tls_cert)
            .field("tls_key", &self.tls_key)
            .field("tls_ca", &self.tls_ca)
            .field("data_dir", &self.data_dir)
            .finish()
    }
}

#[derive(Args)]
pub struct MigrateConfig {
    /// If set, DATABASE_URL is fetched from MMDS at this endpoint instead of
    /// the environment variable.
    #[arg(long, env = "MMDS_ENDPOINT")]
    pub mmds_endpoint: Option<String>,

    #[arg(long, env = "DATABASE_URL")]
    pub database_url: Option<String>,
}

impl std::fmt::Debug for MigrateConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrateConfig")
            .field("mmds_endpoint", &self.mmds_endpoint)
            .field("database_url", &"[redacted]")
            .finish()
    }
}
