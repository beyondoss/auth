#![allow(dead_code)]

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use sqlx::{PgPool, postgres::PgPoolOptions};

/// How long we keep retrying the initial database connection before giving up.
const CONNECT_RETRY_BUDGET: Duration = Duration::from_secs(60);
/// First backoff after a failed connect; doubles up to [`CONNECT_BACKOFF_MAX`].
const CONNECT_BACKOFF_START: Duration = Duration::from_millis(250);
const CONNECT_BACKOFF_MAX: Duration = Duration::from_secs(3);

/// Retry an async connect with capped exponential backoff.
///
/// On a fresh deploy, postgres comes up in parallel with us and its `.internal`
/// name may not resolve for the first few seconds. Rather than exit and rely on a
/// process restart (which wastes the whole startup and re-races the same window),
/// we wait for the dependency to become reachable. Connect failures (DNS,
/// connection refused, pool acquire timeout) are transient and retried; we only
/// give up after [`CONNECT_RETRY_BUDGET`].
async fn connect_with_retry<F, Fut>(what: &str, mut attempt: F) -> Result<PgPool>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = sqlx::Result<PgPool>>,
{
    let deadline = Instant::now() + CONNECT_RETRY_BUDGET;
    let mut backoff = CONNECT_BACKOFF_START;
    loop {
        match attempt().await {
            Ok(pool) => return Ok(pool),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(anyhow::anyhow!(
                        "{what}: database unreachable after retrying: {e}"
                    ));
                }
                tracing::warn!(
                    error = %e,
                    what,
                    backoff_ms = backoff.as_millis() as u64,
                    "database not ready; retrying"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(CONNECT_BACKOFF_MAX);
            }
        }
    }
}

/// App connection pool — every connection gets search_path = auth, public.
pub async fn connect(database_url: &str, max_connections: u32) -> Result<PgPool> {
    connect_with_retry("connect to database", || {
        PgPoolOptions::new()
            .max_connections(max_connections)
            .after_connect(|conn, _| {
                Box::pin(async move {
                    // Literal constant, no user input, no row access — intentionally untyped.
                    sqlx::query("SET search_path = auth, public")
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(database_url)
    })
    .await
}

/// Run migrations against a plain connection with the default (public) search_path
/// so sqlx's internal _sqlx_migrations table stays in public, separate from our
/// auth schema tables.
pub async fn migrate(database_url: &str) -> Result<()> {
    let pool = connect_with_retry("connect for migrations", || PgPool::connect(database_url)).await?;

    sqlx::migrate!()
        .run(&pool)
        .await
        .context("failed to run migrations")?;

    pool.close().await;
    Ok(())
}
