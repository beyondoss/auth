use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx, ZipfSampler};

use super::corpus::FlatCorpus;

/// Calls auth.authz_check_batch / authz_check_parallel_batch — the pgrx batch
/// functions that open a single SPI context for N checks.
pub struct NativeBatchCheck {
    batch_size: usize,
    parallel: bool,
    name: String,
    corpus: FlatCorpus,
    doc_sampler: ZipfSampler,
}

impl NativeBatchCheck {
    pub fn new(batch_size: usize, parallel: bool) -> Self {
        let corpus = FlatCorpus::default();
        let doc_sampler = ZipfSampler::new(corpus.n_documents, 1.0);
        let variant = if parallel { "parallel" } else { "sequential" };
        Self {
            batch_size,
            parallel,
            name: format!("authz::native_batch_{variant}::{batch_size}"),
            corpus,
            doc_sampler,
        }
    }
}

#[async_trait]
impl Scenario for NativeBatchCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn question(&self) -> &str {
        if self.parallel {
            "Parallel BFS batch: one SQL query per level covers all N checks simultaneously."
        } else {
            "Sequential batch: N BFS traversals in one SPI connect, amortising connect cost."
        }
    }

    async fn setup(&self, _pool: &PgPool) -> Result<()> {
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let n = self.batch_size;
        let mut subject_ids: Vec<String> = Vec::with_capacity(n);
        let mut relations: Vec<String> = Vec::with_capacity(n);
        let mut object_types: Vec<String> = Vec::with_capacity(n);
        let mut object_ids: Vec<String> = Vec::with_capacity(n);

        for _ in 0..n {
            let u = ctx.rng.gen_range(0..self.corpus.n_users);
            let rel = match ctx.rng.gen_range(0..3) {
                0 => "viewer",
                1 => "editor",
                _ => "owner",
            };
            let d = self.doc_sampler.sample(&mut ctx.rng);
            subject_ids.push(format!("u_{u}"));
            relations.push(rel.to_string());
            object_types.push("document".to_string());
            object_ids.push(format!("d_{d}"));
        }

        let fn_name = if self.parallel {
            "auth.authz_check_parallel_batch"
        } else {
            "auth.authz_check_batch"
        };

        let rows: Vec<(Vec<bool>,)> = sqlx::query_as(&format!(
            "SELECT {fn_name}($1::text[], $2::text[], $3::text[], $4::text[])"
        ))
        .bind(&subject_ids)
        .bind(&relations)
        .bind(&object_types)
        .bind(&object_ids)
        .fetch_all(ctx.pool)
        .await?;
        let _ = rows.len();
        Ok(())
    }
}
