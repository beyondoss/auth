use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx};

use super::corpus::{FlatCorpus, seed_flat};

pub struct SingleCheck {
    corpus: FlatCorpus,
}

impl SingleCheck {
    pub fn new() -> Self {
        Self {
            corpus: FlatCorpus::default(),
        }
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

    async fn setup(&self, pool: &PgPool) -> Result<()> {
        seed_flat(pool, &self.corpus).await?;
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        // Mix of likely-cached and likely-uncached lookups. The first ~10% of
        // unique query keys will become cache hits after warmup; the rest miss.
        let user = ctx.rng.gen_range(0..self.corpus.n_users);
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
        Ok(())
    }
}
