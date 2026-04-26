use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod cli;
mod config;
mod crypto;
mod db;
mod error;
mod http;
mod keys;
mod metrics;
mod routes;
mod telemetry;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::run().await
}
