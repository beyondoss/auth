use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx, ZipfSampler};

/// Pure depth-N chains, one chain per (user, head_object) pair. Each check
/// must traverse exactly N recursive steps on cache miss. Run as multiple
/// scenarios with different `depth` values (1, 3, 5, 10) so depth-vs-latency
/// is read directly off the report.
pub struct DepthSweep {
    pub depth: usize,
    pub n_chains: usize,
    sampler: ZipfSampler,
}

impl DepthSweep {
    pub fn new(depth: usize) -> Self {
        let n_chains = 5_000;
        Self {
            depth,
            n_chains,
            sampler: ZipfSampler::new(n_chains, 1.0),
        }
    }

    fn name_owned(&self) -> String {
        format!("authz::depth_sweep::depth_{}", self.depth)
    }
}

#[async_trait]
impl Scenario for DepthSweep {
    fn name(&self) -> &str {
        // Box::leak the name string to give a 'static reference. One leak per
        // scenario for the program's lifetime is acceptable.
        Box::leak(self.name_owned().into_boxed_str())
    }

    fn question(&self) -> &str {
        "How does cache-miss latency scale with hierarchy depth?"
    }

    async fn setup(&self, _pool: &PgPool) -> Result<()> {
        // Corpus is seeded once globally by `seed_all` in main.
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let i = self.sampler.sample(&mut ctx.rng);
        let depth = self.depth;
        let row: (bool,) = sqlx::query_as(
            "SELECT auth.authz_check($1, ARRAY[$2]::text[], 'head', $3)",
        )
        .bind(format!("u{depth}_{i}"))
        .bind("link")
        .bind(format!("h{depth}_{i}"))
        .fetch_one(ctx.pool)
        .await?;
        let _ = row.0;
        Ok(())
    }
}
