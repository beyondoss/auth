use std::process::Command;

use anyhow::{Context, bail};
use testcontainers::ImageExt;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let container = Postgres::default()
        .with_tag("18-alpine")
        .start()
        .await
        .context("failed to start postgres container")?;

    let port = container.get_host_port_ipv4(5432).await?;
    // search_path must include auth (citext lives there) and public (pg builtins).
    let url = format!(
        "postgres://postgres:postgres@127.0.0.1:{port}/postgres?options=-csearch_path%3Dauth%2Cpublic"
    );

    let pool = sqlx::PgPool::connect(&url)
        .await
        .context("failed to connect to postgres")?;

    sqlx::migrate!("../migrations")
        .run(&pool)
        .await
        .context("failed to run migrations")?;

    pool.close().await;

    let status = Command::new("cargo")
        .args(["sqlx", "prepare", "--workspace"])
        .env("DATABASE_URL", &url)
        .status()
        .context("failed to run cargo sqlx prepare")?;

    if !status.success() {
        bail!("cargo sqlx prepare exited with status {status}");
    }

    Ok(())
}
