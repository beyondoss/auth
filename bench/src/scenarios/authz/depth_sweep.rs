use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx};

use super::corpus::{ChainCorpus, seed_chain};

/// Pure depth-N chains, one chain per (user, head_object) pair. Each check
/// must traverse exactly N recursive steps on cache miss. Run as multiple
/// scenarios with different `depth` values (1, 3, 5, 10) so depth-vs-latency
/// is read directly off the report.
pub struct DepthSweep {
    pub depth: usize,
    pub n_chains: usize,
}

impl DepthSweep {
    pub fn new(depth: usize) -> Self {
        Self {
            depth,
            n_chains: 5_000,
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
            "SELECT auth.authz_check($1, ARRAY[$2]::text[], 'head', $3)",
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
