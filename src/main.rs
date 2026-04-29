use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod app_config;
mod authz;
mod cli;
mod config;
mod crypto;
mod db;
mod email;
mod emails;
mod error;
mod http;
mod identities;
mod invitations;
mod jwt;
mod keys;
mod metrics;
mod mfa;
mod middleware;
mod mmds;
mod oauth;
mod one_time_token;
mod orgs;
mod pages;
mod passwords;
mod refresh_tokens;
mod routes;
mod sessions;
mod signing_keys;
mod telemetry;
mod token_gc;
mod tokens;
mod users;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::run().await
}
