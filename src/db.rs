#![allow(dead_code)]

use anyhow::{Context, Result};
use sqlx::{PgPool, postgres::PgPoolOptions};

/// App connection pool — every connection gets search_path = auth, public.
pub async fn connect(database_url: &str, max_connections: u32) -> Result<PgPool> {
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
        .await
        .context("failed to connect to database")
}

/// Run migrations against a plain connection with the default (public) search_path
/// so sqlx's internal _sqlx_migrations table stays in public, separate from our
/// auth schema tables.
pub async fn migrate(database_url: &str) -> Result<()> {
    let pool = PgPool::connect(database_url)
        .await
        .context("failed to connect for migrations")?;

    sqlx::migrate!()
        .run(&pool)
        .await
        .context("failed to run migrations")?;

    pool.close().await;
    Ok(())
}
