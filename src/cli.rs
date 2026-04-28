use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;

use crate::{
    app_config,
    config::{MigrateConfig, ServeConfig},
    crypto::LocalKeyEncryptor,
    db, http, keys, routes, telemetry, token_gc,
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
    Serve(ServeConfig),
    /// Run database migrations only (without starting the server)
    Migrate(MigrateConfig),
    /// Write openapi/v1.json from the compiled route annotations
    GenerateOpenapi,
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve(cfg) => serve(cfg).await,
        Command::Migrate(cfg) => migrate(cfg).await,
        Command::GenerateOpenapi => generate_openapi(),
    }
}

async fn serve(cfg: ServeConfig) -> Result<()> {
    if cfg.admin_secret.is_empty() {
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
        sample_rate: 1.0,
    };

    // Hold the guard for the lifetime of serve() — dropped on shutdown.
    let _otel_guard = telemetry::init(&otel_config, vec![], &cfg.log_level)?;

    db::migrate(&cfg.database_url).await?;
    let pool = db::connect(&cfg.database_url).await?;

    let old_key_strs: Vec<&str> = cfg
        .signing_key_encryption_key_old
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let enc_key = LocalKeyEncryptor::from_base64(&cfg.signing_key_encryption_key, &old_key_strs)?;

    keys::ensure_app_config(&pool).await?;
    let loaded_key = keys::load_or_create_active_key(&pool, &enc_key).await?;
    let jwks = keys::render_jwks(&loaded_key);
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

    let wn_origin =
        reqwest::Url::parse(&cfg.webauthn_rp_origin).context("invalid WEBAUTHN_RP_ORIGIN")?;
    let webauthn = webauthn_rs::WebauthnBuilder::new(&cfg.webauthn_rp_id, &wn_origin)
        .map_err(|e| anyhow::anyhow!("WebauthnBuilder::new failed: {e}"))?
        .build()
        .map_err(|e| anyhow::anyhow!("Webauthn::build failed: {e}"))?;

    let gc_handle = tokio::spawn(token_gc::run(pool.clone()));

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
        metrics: crate::metrics::Metrics::new(),
        admin_secret: cfg.admin_secret.clone(),
        http_client,
        oauth: Arc::new(RwLock::new(oauth)),
        webauthn: Arc::new(webauthn),
        encryptor,
        oauth_redirect_allowlist,
        public_url: cfg.public_url.clone(),
        authz_cache,
        partition_cache: Arc::new(RwLock::new(std::collections::HashSet::new())),
        parallel_batch_available,
    };

    let result = http::serve(&cfg.address, state).await;
    gc_handle.abort();
    let _ = gc_handle.await; // JoinError here means cancelled (expected) or panicked (already exiting)
    result
}

async fn migrate(cfg: MigrateConfig) -> Result<()> {
    telemetry::init_simple("info");
    db::migrate(&cfg.database_url).await?;
    tracing::info!("migrations applied successfully");
    Ok(())
}

fn generate_openapi() -> Result<()> {
    use utoipa::OpenApi as _;
    let doc = routes::ApiDoc::openapi();
    let json = serde_json::to_string_pretty(&doc)?;
    std::fs::create_dir_all("openapi")?;
    std::fs::write("openapi/v1.json", json)?;
    println!("wrote openapi/v1.json");
    Ok(())
}
