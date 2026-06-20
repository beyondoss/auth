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
    let so_path = find_extension_so()
        .unwrap_or_else(|| build_extension_so().expect("failed to build beyond-auth-extension"));
    eprintln!("[xtask] using extension library: {}", so_path.display());

    let pg = Postgres::default().with_tag("18");
    let pg = pg.with_copy_to(
        CopyTargetOptions::new(format!("{CONTAINER_LIBDIR}/beyond_auth.so")).with_mode(0o755),
        Path::new(&so_path),
    );

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
        .args([
            "sqlx",
            "prepare",
            "--workspace",
            "--",
            "--tests",
            "--features",
            "test-server",
        ])
        .env("DATABASE_URL", &url)
        .status()
        .context("failed to run cargo sqlx prepare")?;

    if !status.success() {
        bail!("cargo sqlx prepare exited with status {status}");
    }

    Ok(())
}

fn find_extension_so() -> Option<PathBuf> {
    let candidates: &[&str] = &[
        "target/aarch64-unknown-linux-gnu/release/libbeyond_auth.so",
        "target/x86_64-unknown-linux-gnu/release/libbeyond_auth.so",
    ];
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

/// Build the Linux extension .so via Docker (the same command as `mise run extension:build:linux:*`).
/// Returns the path to the built .so on success.
fn build_extension_so() -> anyhow::Result<PathBuf> {
    let task = if cfg!(target_arch = "aarch64") {
        "extension:build:linux:arm64"
    } else {
        "extension:build:linux:amd64"
    };
    eprintln!("[xtask] beyond-auth-extension .so not found — building via `mise run {task}`...");
    let status = Command::new("mise")
        .args(["run", task])
        .status()
        .context("failed to invoke mise")?;
    if !status.success() {
        anyhow::bail!("`mise run {task}` failed — is Docker running?");
    }
    find_extension_so().context("build succeeded but .so still not found")
}
