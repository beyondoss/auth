use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx, ZipfSampler};

use super::corpus::FlatCorpus;

/// Calls `authz_check_direct` (pure SQL recursive CTE, no cache) with the same
/// Zipf corpus as `single_check`. Every call is a cache miss by definition.
///
/// Comparing this to `single_check` isolates the plpgsql wrapper overhead:
///   - If direct_check >> single_check: the wrapper + cache machinery dominate hot-path cost.
///   - If direct_check ~= single_check: the CTE itself is the cost; the cache is earning its keep.
///   - If direct_check < single_check: the cache is helping (hot entries served cheaper).
pub struct DirectCheck {
    corpus: FlatCorpus,
    doc_sampler: ZipfSampler,
}

impl DirectCheck {
    pub fn new() -> Self {
        let corpus = FlatCorpus::default();
        let doc_sampler = ZipfSampler::new(corpus.n_documents, 1.0);
        Self {
            corpus,
            doc_sampler,
        }
    }
}

#[async_trait]
impl Scenario for DirectCheck {
    fn name(&self) -> &str {
        "authz::direct_check"
    }

    fn question(&self) -> &str {
        "What does `authz_check_direct` (pure CTE, no cache) cost vs the cached wrapper? Isolates plpgsql overhead."
    }

    async fn setup(&self, _pool: &PgPool) -> Result<()> {
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let user = ctx.rng.gen_range(0..self.corpus.n_users);
        let doc = self.doc_sampler.sample(&mut ctx.rng);
        let rel = match ctx.rng.gen_range(0..3) {
            0 => "viewer",
            1 => "editor",
            _ => "owner",
        };
        let row: (bool,) =
            sqlx::query_as("SELECT auth.authz_check_direct($1, ARRAY[$2]::text[], 'document', $3)")
                .bind(format!("u_{user}"))
                .bind(rel)
                .bind(format!("d_{doc}"))
                .fetch_one(ctx.pool)
                .await?;
        let _ = row.0;
        Ok(())
    }
}
