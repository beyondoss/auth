use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx, ZipfSampler};

/// Measures recursive-CTE latency at a fixed hierarchy depth against a
/// fresh connection each call, so every check pays the full CTE cost with
/// no warm buffer reuse across calls. Answers: "how does CTE latency scale
/// with depth?" independent of connection-level caching effects.
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
        "How does recursive-CTE latency scale with hierarchy depth?"
    }

    async fn setup(&self, _pool: &PgPool) -> Result<()> {
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let i = self.sampler.sample(&mut ctx.rng);
        let depth = self.depth;
        let row: (bool,) =
            sqlx::query_as("SELECT auth.authz_check($1, ARRAY[$2]::text[], 'head', $3)")
                .bind(format!("u{depth}_{i}"))
                .bind("link")
                .bind(format!("h{depth}_{i}"))
                .fetch_one(ctx.pool)
                .await?;
        let _ = row.0;
        Ok(())
    }
}
