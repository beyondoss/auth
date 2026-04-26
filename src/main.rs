use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod app_config;
mod cli;
mod config;
mod crypto;
mod db;
mod email;
mod emails;
mod error;
mod http;
mod identities;
mod jwt;
mod keys;
mod metrics;
mod middleware;
mod passwords;
mod routes;
mod sessions;
mod telemetry;
mod tenants;
mod tokens;
mod users;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::run().await
}
