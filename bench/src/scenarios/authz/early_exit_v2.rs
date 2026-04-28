use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx, ZipfSampler};

/// Same corpus as EarlyExit but calls authz_check_v2 (split-anchor variant).
/// authz_check_v2 is dropped by migration 0006 and only exists in older deployments.
pub struct EarlyExitV2 {
    pub noise_depth: usize,
    pub n_chains: usize,
    sampler: ZipfSampler,
}

impl EarlyExitV2 {
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
impl Scenario for EarlyExitV2 {
    fn name(&self) -> &str {
        Box::leak(format!("authz::early_exit_v2::noise_{}", self.noise_depth).into_boxed_str())
    }

    fn question(&self) -> &str {
        "Comparison baseline for authz_check_v2 (split-anchor variant, dropped in migration 0006)."
    }

    async fn setup(&self, _pool: &PgPool) -> Result<()> {
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let i = self.sampler.sample(&mut ctx.rng);
        let d = self.noise_depth;
        let row: (bool,) = sqlx::query_as("SELECT auth.authz_check_v2($1, $2, $3, $4)")
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
