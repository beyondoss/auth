use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx};

use super::corpus::{ChainCorpus, seed_chain};

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
}

impl DepthSweepCold {
    pub fn new(depth: usize) -> Self {
        Self {
            depth,
            n_chains: 5_000,
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

    async fn setup(&self, pool: &PgPool) -> Result<()> {
        seed_chain(
            pool,
            &ChainCorpus {
                n_chains: self.n_chains,
                depth: self.depth,
                seed: 0xC0_FFEE + self.depth as u64,
            },
        )
        .await?;
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let i = ctx.rng.gen_range(0..self.n_chains);
        let row: (bool,) = sqlx::query_as(
            "SELECT auth.authz_check_direct($1, ARRAY[$2]::text[], 'head', $3)",
        )
        .bind(format!("u_{i}"))
        .bind("link")
        .bind(format!("h_{i}"))
        .fetch_one(ctx.pool)
        .await?;
        let _ = row.0;
        Ok(())
    }
}
