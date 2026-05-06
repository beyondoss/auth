use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx, ZipfSampler};

use super::corpus::FlatCorpus;

/// Concurrent read/write mix: 80% authz_check reads, 20% relation_tuple
/// inserts, all workers running the same loop. Tests whether the invalidation
/// trigger causes read latency to spike under write pressure.
///
/// This is the scenario that validates (or invalidates) the cache design under
/// production-like conditions. If p99 stays flat → design holds. If p99 spikes
/// under write pressure → invalidation trigger contention is the bottleneck.
pub struct ReadWriteMix {
    corpus: FlatCorpus,
    doc_sampler: ZipfSampler,
}

impl ReadWriteMix {
    pub fn new() -> Self {
        let corpus = FlatCorpus::default();
        let doc_sampler = ZipfSampler::new(corpus.n_documents, 1.0);
        Self {
            corpus,
            doc_sampler,
        }
    }
}

impl Default for ReadWriteMix {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scenario for ReadWriteMix {
    fn name(&self) -> &str {
        "authz::read_write_mix"
    }

    fn question(&self) -> &str {
        "Does p99 read latency spike under concurrent write pressure? Validates the invalidation trigger under production-like conditions."
    }

    async fn setup(&self, pool: &PgPool) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS auth.authz_relations_rwm_doc \
             PARTITION OF auth.authz_relations FOR VALUES IN ('rwm_doc')",
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        if ctx.rng.gen_bool(0.20) {
            // Write: insert one new tuple. Unique ID per call ensures no
            // ON CONFLICT no-ops blunting the trigger.
            let n: u64 = ctx.rng.r#gen();
            sqlx::query(
                "INSERT INTO auth.authz_relations
                    (object_type, object_id, relation, subject_id, subject_set_type, subject_set_relation)
                 VALUES ('rwm_doc', $1, 'viewer', $2, NULL, NULL)
                 ON CONFLICT DO NOTHING",
            )
            .bind(format!("d_{n}"))
            .bind(format!("u_{}", n & 0xFFFF))
            .execute(ctx.pool)
            .await?;
        } else {
            // Read: authz_check against the shared flat corpus with Zipf access.
            let d = self.doc_sampler.sample(&mut ctx.rng);
            let u = ctx.rng.gen_range(0..self.corpus.n_users);
            let rel = match ctx.rng.gen_range(0..3) {
                0 => "viewer",
                1 => "editor",
                _ => "owner",
            };
            let _: (bool,) =
                sqlx::query_as("SELECT auth.authz_check($1, ARRAY[$2]::text[], 'document', $3)")
                    .bind(format!("u_{u}"))
                    .bind(rel)
                    .bind(format!("d_{d}"))
                    .fetch_one(ctx.pool)
                    .await?;
        }
        Ok(())
    }
}
