use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx, ZipfSampler};

/// Measures the early-termination gap in authz_check.
///
/// Each head object has two paths to the query subject:
///   1. A direct grant (depth 1) — always the shortest path.
///   2. A noise subject-set chain of `noise_depth` hops — also valid, but long.
///
/// The recursive-CTE implementation materializes both branches before EXISTS
/// evaluates. A PL/pgSQL BFS finds the direct grant first and returns without
/// touching the noise chain. The delta between the two implementations on this
/// scenario is the early-termination benefit. Deeper noise = wider gap.
pub struct EarlyExit {
    pub noise_depth: usize,
    pub n_chains: usize,
    sampler: ZipfSampler,
}

impl EarlyExit {
    pub fn new(noise_depth: usize) -> Self {
        let n_chains = 50_000;
        Self {
            noise_depth,
            n_chains,
            sampler: ZipfSampler::new(n_chains, 1.0),
        }
    }
}

#[async_trait]
impl Scenario for EarlyExit {
    fn name(&self) -> &str {
        Box::leak(
            format!("authz::early_exit::noise_{}", self.noise_depth).into_boxed_str(),
        )
    }

    fn question(&self) -> &str {
        "How much does early termination help when a direct path exists alongside a deep noise chain?"
    }

    async fn setup(&self, _pool: &PgPool) -> Result<()> {
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let i = self.sampler.sample(&mut ctx.rng);
        let d = self.noise_depth;
        let row: (bool,) =
            sqlx::query_as("SELECT auth.authz_check($1, ARRAY[$2]::text[], $3, $4)")
                .bind(format!("ume{d}_{i}"))
                .bind("link")
                .bind(format!("me{d}_head"))
                .bind(format!("me{d}_{i}"))
                .fetch_one(ctx.pool)
                .await?;
        let _ = row.0;
        Ok(())
    }
}
