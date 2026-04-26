use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;

use crate::{
    app_config,
    config::{MigrateConfig, ServeConfig},
    crypto::LocalKeyEncryptor,
    db, http, keys, telemetry,
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
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve(cfg) => serve(cfg).await,
        Command::Migrate(cfg) => migrate(cfg).await,
    }
}

async fn serve(cfg: ServeConfig) -> Result<()> {
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

    let state = http::AppState {
        pool,
        jwks: Arc::new(bytes::Bytes::from(jwks)),
        signing_key: Arc::new(loaded_key),
        app_config: Arc::new(RwLock::new(app_config)),
        metrics: crate::metrics::Metrics::new(),
    };

    http::serve(&cfg.address, state).await
}

async fn migrate(cfg: MigrateConfig) -> Result<()> {
    telemetry::init_simple("info");
    db::migrate(&cfg.database_url).await?;
    tracing::info!("migrations applied successfully");
    Ok(())
}
