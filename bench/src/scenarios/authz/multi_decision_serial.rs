use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx, ZipfSampler};

use super::corpus::FlatCorpus;

/// Simulates a UI page or API caller issuing M sequential checks per "request".
/// One unit of work = M serial round-trips. Measures the cost of N+1 in real
/// workloads (UI gating multiple buttons, per-row list filtering done client-side).
pub struct MultiDecisionSerial {
    corpus: FlatCorpus,
    decisions_per_request: usize,
    doc_sampler: ZipfSampler,
}

impl MultiDecisionSerial {
    pub fn new() -> Self {
        let corpus = FlatCorpus::default();
        let doc_sampler = ZipfSampler::new(corpus.n_documents, 1.0);
        Self {
            corpus,
            decisions_per_request: 25,
            doc_sampler,
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

    async fn setup(&self, _pool: &PgPool) -> Result<()> {
        // Corpus is seeded once globally by `seed_all` in main.
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let user = ctx.rng.gen_range(0..self.corpus.n_users);
        for _ in 0..self.decisions_per_request {
            let doc = self.doc_sampler.sample(&mut ctx.rng);
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
