//! Batch-check scenario: issue N permission checks in a single SQL call via
//! UNNEST'd parallel arrays. Compared against `multi_decision_serial` (N
//! round-trips), this measures the round-trip tax vs the per-call query cost.

use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx, ZipfSampler};

use super::corpus::FlatCorpus;

pub struct BatchCheck {
    batch_size: usize,
    name: String,
    corpus: FlatCorpus,
    doc_sampler: ZipfSampler,
}

impl BatchCheck {
    pub fn new(batch_size: usize) -> Self {
        let corpus = FlatCorpus::default();
        let doc_sampler = ZipfSampler::new(corpus.n_documents, 1.0);
        Self {
            batch_size,
            name: format!("authz::batch_check::{batch_size}"),
            corpus,
            doc_sampler,
        }
    }
}

#[async_trait]
impl Scenario for BatchCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn question(&self) -> &str {
        "Check N permissions in one SQL call vs N round trips. Measures round-trip tax vs query cost."
    }

    async fn setup(&self, _pool: &PgPool) -> Result<()> {
        // Flat corpus is seeded globally by `seed_all` in main.
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let n = self.batch_size;
        let mut subject_id = Vec::with_capacity(n);
        let mut relation = Vec::with_capacity(n);
        let mut object_type = Vec::with_capacity(n);
        let mut object_id = Vec::with_capacity(n);
        for _ in 0..n {
            let u = ctx.rng.gen_range(0..self.corpus.n_users);
            let rel = match ctx.rng.gen_range(0..3) {
                0 => "viewer",
                1 => "editor",
                _ => "owner",
            };
            let d = self.doc_sampler.sample(&mut ctx.rng);
            subject_id.push(format!("u_{u}"));
            relation.push(rel.to_string());
            object_type.push("document".to_string());
            object_id.push(format!("d_{d}"));
        }
        // Drain the result set; we don't care about per-row values, just that
        // every check executed server-side.
        let rows: Vec<(bool,)> = sqlx::query_as(
            r#"
            SELECT auth.authz_check(t.subject_id, ARRAY[t.relation]::text[], t.object_type, t.object_id)
            FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[])
                AS t(subject_id, relation, object_type, object_id)
            "#,
        )
        .bind(&subject_id)
        .bind(&relation)
        .bind(&object_type)
        .bind(&object_id)
        .fetch_all(ctx.pool)
        .await?;
        let _ = rows.len();
        Ok(())
    }
}
