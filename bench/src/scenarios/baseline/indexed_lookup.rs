use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx};

const N: i64 = 10_000;

pub struct IndexedLookup;

#[async_trait]
impl Scenario for IndexedLookup {
    fn name(&self) -> &str {
        "baseline::indexed_lookup"
    }

    fn question(&self) -> &str {
        "Point read on a btree-indexed bigint column with N=10k rows. Isolates PG index scan cost from any authz logic."
    }

    async fn setup(&self, pool: &PgPool) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS bench_baseline_kv (
                id bigint PRIMARY KEY,
                val text NOT NULL
            )",
        )
        .execute(pool)
        .await?;

        // Idempotent seed: only insert if empty.
        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM bench_baseline_kv")
            .fetch_one(pool)
            .await?;
        if count.0 == 0 {
            for i in 0..N {
                sqlx::query("INSERT INTO bench_baseline_kv (id, val) VALUES ($1, $2)")
                    .bind(i)
                    .bind(format!("v{i}"))
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let id: i64 = ctx.rng.gen_range(0..N);
        let _: (i64, String) =
            sqlx::query_as("SELECT id, val FROM bench_baseline_kv WHERE id = $1")
                .bind(id)
                .fetch_one(ctx.pool)
                .await?;
        Ok(())
    }
}
