//! Corpus-scale sweep: same authz_check workload over progressively larger
//! direct-grant corpora. Answers "does throughput degrade as the relation_tuple
//! table grows?". Each instance owns a unique `object_type` prefix so multiple
//! sizes can coexist in the database without trampling each other.

use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx, ZipfSampler};

pub struct ScaleSweep {
    n_tuples: usize,
    object_type: String,
    name: String,
    sampler: ZipfSampler,
}

impl ScaleSweep {
    pub fn new(n_tuples: usize) -> Self {
        let label = label_for(n_tuples);
        Self {
            n_tuples,
            object_type: format!("ss_doc_{label}"),
            name: format!("authz::scale_sweep::{label}"),
            sampler: ZipfSampler::new(n_tuples, 1.0),
        }
    }
}

fn label_for(n: usize) -> String {
    if n >= 1_000_000 && n % 1_000_000 == 0 {
        format!("{}M", n / 1_000_000)
    } else if n >= 1_000 && n % 1_000 == 0 {
        format!("{}k", n / 1_000)
    } else {
        n.to_string()
    }
}

#[async_trait]
impl Scenario for ScaleSweep {
    fn name(&self) -> &str {
        &self.name
    }

    fn question(&self) -> &str {
        "Does authz_check throughput degrade with corpus size? Finds the recursive-CTE scale ceiling."
    }

    async fn setup(&self, pool: &PgPool) -> Result<()> {
        // Idempotent: if at least n_tuples rows for this prefix already exist,
        // skip seeding entirely. Otherwise seed fresh (after wiping any partial
        // prior state for this prefix only — no global truncate).
        let existing: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM auth.authz_relations WHERE object_type = $1",
        )
        .bind(&self.object_type)
        .fetch_one(pool)
        .await?;
        if existing.0 as usize >= self.n_tuples {
            return Ok(());
        }
        sqlx::query("DELETE FROM auth.authz_relations WHERE object_type = $1")
            .bind(&self.object_type)
            .execute(pool)
            .await?;

        let mut rng = SmallRng::seed_from_u64(0x5CA1E_u64.wrapping_add(self.n_tuples as u64));
        // Direct grants only: one row per logical document. Cheap to seed at
        // 1M scale, and what we want to measure is the read path against a
        // large flat tuple table, not corpus shape.
        const BATCH: usize = 10_000;
        let mut object_id: Vec<String> = Vec::with_capacity(BATCH);
        let mut subject_id: Vec<String> = Vec::with_capacity(BATCH);
        let mut relation: Vec<String> = Vec::with_capacity(BATCH);
        let mut subject_set_type: Vec<Option<String>> = Vec::with_capacity(BATCH);
        let mut subject_set_relation: Vec<Option<String>> = Vec::with_capacity(BATCH);
        let mut object_type_v: Vec<String> = Vec::with_capacity(BATCH);

        // user pool sized as sqrt(n_tuples), bounded — keeps Zipf head meaningful
        let n_users = ((self.n_tuples as f64).sqrt() as usize).clamp(1_000, 100_000);

        let mut written = 0usize;
        while written < self.n_tuples {
            object_id.clear();
            subject_id.clear();
            relation.clear();
            subject_set_type.clear();
            subject_set_relation.clear();
            object_type_v.clear();
            let take = BATCH.min(self.n_tuples - written);
            for k in 0..take {
                let i = written + k;
                let u = rng.gen_range(0..n_users);
                let rel = match rng.gen_range(0..3) {
                    0 => "viewer",
                    1 => "editor",
                    _ => "owner",
                };
                object_type_v.push(self.object_type.clone());
                object_id.push(format!("d_{i}"));
                relation.push(rel.to_string());
                subject_id.push(format!("u_{u}"));
                subject_set_type.push(None);
                subject_set_relation.push(None);
            }
            sqlx::query(
                r#"
                INSERT INTO auth.authz_relations
                    (object_type, object_id, relation, subject_id, subject_set_type, subject_set_relation)
                SELECT * FROM UNNEST(
                    $1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[]
                )
                ON CONFLICT DO NOTHING
                "#,
            )
            .bind(&object_type_v)
            .bind(&object_id)
            .bind(&relation)
            .bind(&subject_id)
            .bind(&subject_set_type)
            .bind(&subject_set_relation)
            .execute(pool)
            .await?;
            written += take;
        }
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let i = self.sampler.sample(&mut ctx.rng);
        let rel = match ctx.rng.gen_range(0..3) {
            0 => "viewer",
            1 => "editor",
            _ => "owner",
        };
        // Subject pool same heuristic as setup; uniform user pick.
        let n_users = ((self.n_tuples as f64).sqrt() as usize).clamp(1_000, 100_000);
        let u = ctx.rng.gen_range(0..n_users);
        let row: (bool,) = sqlx::query_as("SELECT auth.authz_check($1, ARRAY[$2]::text[], $3, $4)")
            .bind(format!("u_{u}"))
            .bind(rel)
            .bind(&self.object_type)
            .bind(format!("d_{i}"))
            .fetch_one(ctx.pool)
            .await?;
        let _ = row.0;
        Ok(())
    }
}
