use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx, ZipfSampler};

use super::corpus::FlatCorpus;

pub struct SingleCheck {
    corpus: FlatCorpus,
    doc_sampler: ZipfSampler,
}

impl SingleCheck {
    pub fn new() -> Self {
        let corpus = FlatCorpus::default();
        let doc_sampler = ZipfSampler::new(corpus.n_documents, 1.0);
        Self {
            corpus,
            doc_sampler,
        }
    }
}

impl Default for SingleCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scenario for SingleCheck {
    fn name(&self) -> &str {
        "authz::single_check"
    }

    fn question(&self) -> &str {
        "What is the QPS ceiling for `auth.authz_check` against a steady-state corpus, and where does p99 break?"
    }

    async fn setup(&self, _pool: &PgPool) -> Result<()> {
        // Corpus is seeded once globally by `seed_all` in main.
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        // Zipf-distributed doc selection mimics realistic skewed access:
        // a hot head accounts for most traffic, the tail is cold.
        let user = ctx.rng.gen_range(0..self.corpus.n_users);
        let doc = self.doc_sampler.sample(&mut ctx.rng);
        let rel = match ctx.rng.gen_range(0..3) {
            0 => "viewer",
            1 => "editor",
            _ => "owner",
        };
        let row: (bool,) =
            sqlx::query_as("SELECT auth.authz_check($1, ARRAY[$2]::text[], 'document', $3)")
                .bind(format!("u_{user}"))
                .bind(rel)
                .bind(format!("d_{doc}"))
                .fetch_one(ctx.pool)
                .await?;
        let _ = row.0;
        Ok(())
    }
}
