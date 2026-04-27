use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx, ZipfSampler};

/// Cold-cache variant of `depth_sweep`: calls `auth.authz_check_direct`,
/// which bypasses `authz_check_cache` entirely. Every call pays the full
/// recursive CTE cost, so latency reflects true depth-N traversal cost
/// rather than cache-hit cost.
///
/// The hot variant (`depth_sweep`) measures end-to-end behavior in a
/// real workload (cache fronts the CTE). This variant isolates the
/// CTE-on-miss path so we can answer "is the CTE expensive at depth N?"
/// independent of cache hit ratio.
pub struct DepthSweepCold {
    pub depth: usize,
    pub n_chains: usize,
    sampler: ZipfSampler,
}

impl DepthSweepCold {
    pub fn new(depth: usize) -> Self {
        let n_chains = 50_000;
        Self {
            depth,
            n_chains,
            sampler: ZipfSampler::new(n_chains, 1.0),
        }
    }
}

#[async_trait]
impl Scenario for DepthSweepCold {
    fn name(&self) -> &str {
        Box::leak(format!("authz::depth_sweep_cold::depth_{}", self.depth).into_boxed_str())
    }

    fn question(&self) -> &str {
        "How does pure recursive-CTE latency scale with hierarchy depth (no cache fronting)?"
    }

    async fn setup(&self, _pool: &PgPool) -> Result<()> {
        // Corpus is seeded once globally by `seed_all` in main.
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let i = self.sampler.sample(&mut ctx.rng);
        let depth = self.depth;
        let row: (bool,) =
            sqlx::query_as("SELECT auth.authz_check_direct($1, ARRAY[$2]::text[], 'head', $3)")
                .bind(format!("u{depth}_{i}"))
                .bind("link")
                .bind(format!("h{depth}_{i}"))
                .fetch_one(ctx.pool)
                .await?;
        let _ = row.0;
        Ok(())
    }
}
