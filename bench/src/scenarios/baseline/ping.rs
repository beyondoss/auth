use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx};

pub struct Ping;

#[async_trait]
impl Scenario for Ping {
    fn name(&self) -> &str {
        "baseline::ping"
    }

    fn question(&self) -> &str {
        "Raw connection round-trip cost: SELECT 1. Use this to normalize other results — if this is slow, the environment was loaded."
    }

    async fn setup(&self, _pool: &PgPool) -> Result<()> {
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let _: (i32,) = sqlx::query_as("SELECT 1").fetch_one(ctx.pool).await?;
        Ok(())
    }
}
