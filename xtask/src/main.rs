use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use testcontainers::CopyTargetOptions;
use testcontainers::ImageExt;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

// pkglibdir inside postgres:18 (`pg_config --pkglibdir`)
const CONTAINER_LIBDIR: &str = "/usr/lib/postgresql/18/lib";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let so_path = find_extension_so();
    if let Some(ref p) = so_path {
        eprintln!("[xtask] found extension library: {}", p.display());
    } else {
        eprintln!(
            "[xtask] no pre-built Linux authz_extension .so found; \
             migration 0006 will fall back to PL/pgSQL. \
             Run `mise run extension:build:linux` to build it."
        );
    }

    let pg = Postgres::default().with_tag("18");
    let pg = match so_path.as_deref() {
        Some(p) => pg.with_copy_to(
            CopyTargetOptions::new(format!("{CONTAINER_LIBDIR}/authz_extension.so"))
                .with_mode(0o755),
            Path::new(p),
        ),
        None => pg,
    };

    let container = pg
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
        .args(["sqlx", "prepare", "--workspace", "--", "--tests"])
        .env("DATABASE_URL", &url)
        .status()
        .context("failed to run cargo sqlx prepare")?;

    if !status.success() {
        bail!("cargo sqlx prepare exited with status {status}");
    }

    Ok(())
}

/// Find a pre-built Linux `.so` for the authz_extension across common cross-compilation targets.
/// Returns the first path that exists, or None if none are present.
fn find_extension_so() -> Option<PathBuf> {
    let candidates: &[&str] = &[
        // ARM64 Linux GNU (M-series Mac → postgres:18 on ARM)
        "target/aarch64-unknown-linux-gnu/release/libauthz_extension.so",
        // x86_64 Linux GNU (Intel Mac → postgres:18 on x86)
        "target/x86_64-unknown-linux-gnu/release/libauthz_extension.so",
    ];
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}
