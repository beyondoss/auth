use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx};

use super::corpus::{FlatCorpus, seed_flat};

/// Simulates a UI page or API caller issuing M sequential checks per "request".
/// One unit of work = M serial round-trips. Measures the cost of N+1 in real
/// workloads (UI gating multiple buttons, per-row list filtering done client-side).
pub struct MultiDecisionSerial {
    corpus: FlatCorpus,
    decisions_per_request: usize,
}

impl MultiDecisionSerial {
    pub fn new() -> Self {
        Self {
            corpus: FlatCorpus::default(),
            decisions_per_request: 25,
        }
    }
}

#[async_trait]
impl Scenario for MultiDecisionSerial {
    fn name(&self) -> &str {
        "authz::multi_decision_serial"
    }

    fn question(&self) -> &str {
        "When a caller issues M sequential checks per request (UI gating pattern), where does it saturate?"
    }

    async fn setup(&self, pool: &PgPool) -> Result<()> {
        seed_flat(pool, &self.corpus).await?;
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let user = ctx.rng.gen_range(0..self.corpus.n_users);
        for _ in 0..self.decisions_per_request {
            let doc = ctx.rng.gen_range(0..self.corpus.n_documents);
            let rel = match ctx.rng.gen_range(0..3) {
                0 => "viewer",
                1 => "editor",
                _ => "owner",
            };
            let row: (bool,) = sqlx::query_as(
                "SELECT auth.authz_check($1, ARRAY[$2]::text[], 'document', $3)",
            )
            .bind(format!("u_{user}"))
            .bind(rel)
            .bind(format!("d_{doc}"))
            .fetch_one(ctx.pool)
            .await?;
            let _ = row.0;
        }
        Ok(())
    }
}
