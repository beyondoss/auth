use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx};

/// Inserts batches of `batch_size` relation_tuple rows per unit of work.
/// Run with multiple `batch_size` instances to measure how the statement-level
/// invalidation trigger scales with bulk size.
pub struct BulkWrite {
    pub batch_size: usize,
}

impl BulkWrite {
    pub fn new(batch_size: usize) -> Self {
        Self { batch_size }
    }
}

#[async_trait]
impl Scenario for BulkWrite {
    fn name(&self) -> &str {
        Box::leak(format!("authz::bulk_write::batch_{}", self.batch_size).into_boxed_str())
    }

    fn question(&self) -> &str {
        "What is sustained tuple-write throughput at this batch size?"
    }

    async fn setup(&self, pool: &PgPool) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS auth.authz_relations_bw_doc \
             PARTITION OF auth.authz_relations FOR VALUES IN ('bw_doc')",
        )
        .execute(pool)
        .await?;
        sqlx::query("DELETE FROM auth.authz_relations WHERE object_type = 'bw_doc'")
            .execute(pool)
            .await?;
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let mut object_type = Vec::with_capacity(self.batch_size);
        let mut object_id = Vec::with_capacity(self.batch_size);
        let mut relation = Vec::with_capacity(self.batch_size);
        let mut subject_id = Vec::with_capacity(self.batch_size);
        let mut subject_set_type: Vec<Option<String>> = Vec::with_capacity(self.batch_size);
        let mut subject_set_relation: Vec<Option<String>> = Vec::with_capacity(self.batch_size);

        // Use unique IDs per call to avoid ON CONFLICT no-op blunting the measurement.
        // Worker-id + monotonic counter via rng yields enough uniqueness for the run.
        for _ in 0..self.batch_size {
            let n: u64 = ctx.rng.r#gen();
            object_type.push("bw_doc".to_string());
            object_id.push(format!("w{}_{}", ctx.worker_id, n));
            relation.push("viewer".to_string());
            subject_id.push(format!("u_{}", n & 0xFFFF));
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
        .bind(&object_type)
        .bind(&object_id)
        .bind(&relation)
        .bind(&subject_id)
        .bind(&subject_set_type)
        .bind(&subject_set_relation)
        .execute(ctx.pool)
        .await?;
        Ok(())
    }
}
