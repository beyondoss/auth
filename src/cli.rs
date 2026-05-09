#![allow(dead_code)]

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;

use crate::{
    app_config,
    config::{MigrateConfig, ServeConfig},
    crypto::LocalKeyEncryptor,
    db, http, mmds, routes, signing_keys, telemetry, token_gc,
};

#[derive(Parser)]
#[command(
    name = "beyond-auth",
    about = "Beyond authentication and authorization service",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the HTTP server
    Serve(Box<ServeConfig>),
    /// Run database migrations only (without starting the server)
    Migrate(MigrateConfig),
    /// Write openapi/v1.json from the compiled route annotations
    GenerateOpenapi,
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve(cfg) => serve(*cfg).await,
        Command::Migrate(cfg) => migrate(cfg).await,
        Command::GenerateOpenapi => generate_openapi(),
    }
}

/// Resolved secret values — sourced from MMDS (primary) or env vars (fallback).
struct Secrets {
    database_url: String,
    signing_key_encryption_key: String,
    signing_key_encryption_key_old: Option<String>,
    admin_secret: String,
}

/// Fetch secrets from MMDS if `mmds_endpoint` is configured, otherwise require
/// them from environment variables. MMDS values take priority; per-key fallback
/// to the env var value allows gradual migration.
async fn resolve_secrets(
    mmds_endpoint: Option<&str>,
    database_url: Option<String>,
    signing_key_encryption_key: Option<String>,
    signing_key_encryption_key_old: Option<String>,
    admin_secret: Option<String>,
) -> Result<Secrets> {
    if let Some(endpoint) = mmds_endpoint {
        let env = mmds::fetch(endpoint)
            .await
            .context("failed to fetch secrets from MMDS")?;
        Ok(Secrets {
            database_url: env
                .get("DATABASE_URL")
                .map(str::to_owned)
                .or(database_url)
                .context("DATABASE_URL not found in MMDS or environment")?,
            signing_key_encryption_key: env
                .get("SIGNING_KEY_ENCRYPTION_KEY")
                .map(str::to_owned)
                .or(signing_key_encryption_key)
                .context("SIGNING_KEY_ENCRYPTION_KEY not found in MMDS or environment")?,
            signing_key_encryption_key_old: env
                .get("SIGNING_KEY_ENCRYPTION_KEY_OLD")
                .map(str::to_owned)
                .or(signing_key_encryption_key_old),
            admin_secret: env
                .get("ADMIN_SECRET")
                .map(str::to_owned)
                .or(admin_secret)
                .context("ADMIN_SECRET not found in MMDS or environment")?,
        })
    } else {
        Ok(Secrets {
            database_url: database_url
                .context("DATABASE_URL is required (set env var or configure MMDS_ENDPOINT)")?,
            signing_key_encryption_key: signing_key_encryption_key
                .context("SIGNING_KEY_ENCRYPTION_KEY is required")?,
            signing_key_encryption_key_old,
            admin_secret: admin_secret.context("ADMIN_SECRET is required")?,
        })
    }
}

async fn serve(cfg: ServeConfig) -> Result<()> {
    let secrets = resolve_secrets(
        cfg.mmds_endpoint.as_deref(),
        cfg.database_url,
        cfg.signing_key_encryption_key,
        cfg.signing_key_encryption_key_old,
        cfg.admin_secret,
    )
    .await?;

    if secrets.admin_secret.is_empty() {
        anyhow::bail!("ADMIN_SECRET must not be empty");
    }

    let oauth_redirect_allowlist: Vec<String> = cfg
        .oauth_allowed_redirect_origins
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            reqwest::Url::parse(s)
                .ok()
                .map(|u| u.origin().ascii_serialization())
        })
        .collect();

    if oauth_redirect_allowlist.is_empty() {
        tracing::warn!(
            "OAUTH_ALLOWED_REDIRECT_ORIGINS is not configured — OAuth redirect URLs are not \
             validated. Set this to a comma-separated list of allowed origins in production."
        );
    }

    let otel_config = telemetry::OtelConfig {
        enabled: cfg.otlp_enabled,
        otlp_endpoint: cfg.otlp_endpoint.clone(),
        service_name: "beyond-auth".into(),
        sample_rate: cfg.otlp_sample_rate,
    };

    // Hold the guard for the lifetime of serve() — dropped on shutdown.
    let _otel_guard = telemetry::init(&otel_config, vec![], &cfg.log_level)?;

    db::migrate(&secrets.database_url).await?;
    let pool = db::connect(&secrets.database_url, cfg.database_pool_size).await?;

    let old_key_strs: Vec<&str> = secrets
        .signing_key_encryption_key_old
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let enc_key =
        LocalKeyEncryptor::from_base64(&secrets.signing_key_encryption_key, &old_key_strs)?;

    signing_keys::ensure_app_config(&pool).await?;
    let metrics = Arc::new(crate::metrics::Metrics::new());
    let loaded_key = signing_keys::load_or_create_active_key(&pool, &enc_key, &metrics).await?;
    let all_keys = signing_keys::load_all_keys_for_jwks(&pool, &enc_key).await?;
    let jwks = signing_keys::render_jwks(&all_keys);
    let app_config = app_config::load(&pool)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load app_config: {e}"))?;

    let compiled_authz = app_config::compile_authz_schema(&app_config)
        .map_err(|e| anyhow::anyhow!("failed to compile authz schema: {e}"))?;

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")?;

    let oauth = crate::oauth::OAuthProviders::load(
        app_config.oauth_providers_enc.as_deref(),
        &enc_key,
        &http_client,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to load oauth providers: {e}"))?;

    let encryptor: std::sync::Arc<dyn crate::crypto::KeyEncryptor> = std::sync::Arc::new(enc_key);

    let webauthn = match (&cfg.webauthn_rp_id, &cfg.webauthn_rp_origin) {
        (Some(rp_id), Some(rp_origin)) => {
            let wn_origin = reqwest::Url::parse(rp_origin).context("invalid WEBAUTHN_RP_ORIGIN")?;
            let wn = webauthn_rs::WebauthnBuilder::new(rp_id, &wn_origin)
                .map_err(|e| anyhow::anyhow!("WebauthnBuilder::new failed: {e}"))?
                .build()
                .map_err(|e| anyhow::anyhow!("Webauthn::build failed: {e}"))?;
            Some(Arc::new(wn))
        }
        _ => {
            tracing::warn!(
                "WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGIN are not set — passkey endpoints will return an error"
            );
            None
        }
    };

    let authz_cache = Arc::new(crate::authz::cache::AuthzCache::new(
        cfg.authz_cache_size,
        cfg.authz_cache_size / 2,
        std::time::Duration::from_secs(cfg.authz_cache_ttl_secs),
    ));

    let parallel_batch_available = crate::authz::engine::probe_parallel_batch(&pool).await;

    let state = http::AppState {
        pool,
        jwks: Arc::new(bytes::Bytes::from(jwks)),
        signing_key: Arc::new(loaded_key),
        app_config: Arc::new(RwLock::new(app_config)),
        authz_schema: Arc::new(RwLock::new(compiled_authz)),
        metrics,
        admin_secret: http::AdminSecret::new(secrets.admin_secret),
        http_client,
        oauth: Arc::new(RwLock::new(oauth)),
        webauthn,
        encryptor,
        oauth_redirect_allowlist,
        public_url: cfg.public_url.clone(),
        authz_cache,
        partition_cache: Arc::new(quick_cache::sync::Cache::new(1024)),
        parallel_batch_available,
        cache_sync: Arc::new(http::CacheSyncState::new()),
    };

    let gc_handle = tokio::spawn(token_gc::run(state.pool.clone(), state.metrics.clone()));
    let sessions_handle = tokio::spawn(http::active_sessions_gauge(
        state.pool.clone(),
        state.metrics.clone(),
    ));

    let result = http::serve(&cfg.address, state).await;
    gc_handle.abort();
    sessions_handle.abort();
    let _ = gc_handle.await; // JoinError here means cancelled (expected) or panicked (already exiting)
    let _ = sessions_handle.await;
    result
}

async fn migrate(cfg: MigrateConfig) -> Result<()> {
    telemetry::init_simple("info");

    let database_url = if let Some(endpoint) = cfg.mmds_endpoint.as_deref() {
        let env = mmds::fetch(endpoint)
            .await
            .context("failed to fetch secrets from MMDS")?;
        env.get("DATABASE_URL")
            .map(str::to_owned)
            .or(cfg.database_url)
            .context("DATABASE_URL not found in MMDS or environment")?
    } else {
        cfg.database_url
            .context("DATABASE_URL is required (set env var or configure MMDS_ENDPOINT)")?
    };

    db::migrate(&database_url).await?;
    tracing::info!("migrations applied successfully");
    Ok(())
}

fn generate_openapi() -> Result<()> {
    use utoipa::OpenApi as _;
    telemetry::init_simple("info");
    let doc = routes::ApiDoc::openapi();
    let json = serde_json::to_string_pretty(&doc)?;
    std::fs::create_dir_all("openapi")?;
    std::fs::write("openapi/v1.json", json)?;
    tracing::info!("wrote openapi/v1.json");
    Ok(())
}
