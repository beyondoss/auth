use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use sqlx::PgPool;
use tokio::time::sleep;

use crate::harness::{Metric, Scenario, WorkerCtx};

use super::corpus::{FlatCorpus, reset_cache_only};

/// Steady-state read workload with a periodic mass-invalidation pulse fired
/// from a background task. The test measures whether p99 latency on reads
/// stays bounded across the storm window.
///
/// Pulse pattern: every ~3 seconds, delete then reinsert every team-membership
/// tuple for a single team — touches every cache entry for that team's members.
pub struct InvalidationStorm {
    corpus: FlatCorpus,
    pulse_started: AtomicBool,
}

impl InvalidationStorm {
    pub fn new() -> Self {
        Self {
            corpus: FlatCorpus::default(),
            pulse_started: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl Scenario for InvalidationStorm {
    fn name(&self) -> &str {
        "authz::invalidation_storm"
    }

    fn question(&self) -> &str {
        "After mass cache invalidation, how long until p99 recovers?"
    }

    async fn setup(&self, pool: &PgPool) -> Result<()> {
        // Flat corpus is seeded globally in main; we only need to start from
        // a cold cache so the storm's first pulse has something to invalidate.
        reset_cache_only(pool).await?;
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        // First worker spawns the pulse task. Other workers just do reads.
        if ctx.worker_id == 0
            && self
                .pulse_started
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            let pool = ctx.pool.clone();
            let n_teams = self.corpus.n_teams;
            tokio::spawn(async move {
                let mut team = 0usize;
                loop {
                    sleep(Duration::from_secs(3)).await;
                    let team_id = format!("t_{team}");
                    // DELETE + reinsert is the cheapest way to fire INSERT triggers
                    // without changing the steady-state corpus shape.
                    let _ = sqlx::query(
                        "DELETE FROM auth.relation_tuple WHERE object_type = 'team' AND object_id = $1",
                    )
                    .bind(&team_id)
                    .execute(&pool)
                    .await;
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO auth.relation_tuple
                            (object_type, object_id, relation, subject_id, subject_type, subject_relation)
                        SELECT 'team', $1, 'member', 'u_' || g::text, NULL, NULL
                        FROM generate_series(0, 19) g
                        ON CONFLICT DO NOTHING
                        "#,
                    )
                    .bind(&team_id)
                    .execute(&pool)
                    .await;
                    team = (team + 1) % n_teams;
                }
            });
        }

        let user = ctx.rng.gen_range(0..self.corpus.n_users);
        let doc = ctx.rng.gen_range(0..self.corpus.n_documents);
        let rel = if ctx.rng.gen_bool(0.5) {
            "viewer"
        } else {
            "editor"
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

    async fn extra_metrics(&self, pool: &PgPool) -> Result<Vec<Metric>> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM auth.authz_check_cache")
            .fetch_one(pool)
            .await?;
        Ok(vec![Metric::new("cache_rows", row.0 as f64, "rows")])
    }
}

// Holding Arc<dyn Scenario> means we share via clone; the AtomicBool inside
// must therefore be safe to share across clones — which it is since it lives
// behind the Arc.
unsafe impl Send for InvalidationStorm {}
unsafe impl Sync for InvalidationStorm {}
