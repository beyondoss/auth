use anyhow::Result;
use async_trait::async_trait;
use rand::rngs::SmallRng;
use sqlx::PgPool;

use super::metrics::Metric;

pub struct WorkerCtx<'a> {
    pub pool: &'a PgPool,
    pub worker_id: usize,
    pub rng: SmallRng,
}

#[async_trait]
pub trait Scenario: Send + Sync {
    fn name(&self) -> &str;

    /// One-line summary of the question this scenario answers. Rendered in reports.
    fn question(&self) -> &str {
        ""
    }

    /// Idempotent. Called once on a fresh DB before any workers start.
    async fn setup(&self, pool: &PgPool) -> Result<()>;

    /// One unit of work. Called concurrently by N workers in a hot loop.
    /// The harness times each call and records latency. Errors abort the worker.
    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()>;

    /// Custom server-side metrics on top of the default pg_stat_* snapshot.
    /// Captured once after each concurrency level finishes.
    async fn extra_metrics(&self, _pool: &PgPool) -> Result<Vec<Metric>> {
        Ok(vec![])
    }
}
