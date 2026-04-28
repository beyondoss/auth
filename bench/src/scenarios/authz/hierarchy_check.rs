use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use sqlx::PgPool;

use crate::harness::{Scenario, WorkerCtx, ZipfSampler};

const N_DOCS: usize = 5_000;
const N_FOLDERS: usize = 1_000;
const N_USERS: usize = 2_000;

async fn seed_hierarchy(pool: &PgPool) -> Result<()> {
    // Idempotent: skip if already seeded
    let existing: (i64,) =
        sqlx::query_as("SELECT COUNT(*)::bigint FROM auth.authz_relations WHERE object_type = 'hier_doc'")
            .fetch_one(pool)
            .await?;
    if existing.0 as usize >= N_DOCS {
        return Ok(());
    }

    // Ensure partitions exist
    for ot in &["hier_doc", "hier_folder"] {
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS auth.authz_relations_{ot} \
             PARTITION OF auth.authz_relations FOR VALUES IN ('{ot}')"
        ))
        .execute(pool)
        .await?;
    }

    let mut rng = SmallRng::seed_from_u64(0xBEEF_CAFE);
    let mut ots: Vec<String> = Vec::new();
    let mut ois: Vec<String> = Vec::new();
    let mut rels: Vec<String> = Vec::new();
    let mut sids: Vec<String> = Vec::new();
    let mut ssts: Vec<Option<String>> = Vec::new();
    let mut ssrs: Vec<Option<String>> = Vec::new();

    // Folder → user direct grants
    for f in 0..N_FOLDERS {
        let u = rng.gen_range(0..N_USERS);
        let role = match rng.gen_range(0u8..3) {
            0 => "owner",
            1 => "editor",
            _ => "viewer",
        };
        ots.push("hier_folder".into());
        ois.push(format!("hf_{f}"));
        rels.push(role.into());
        sids.push(format!("hu_{u}"));
        ssts.push(None);
        ssrs.push(None);
    }

    // Document → folder parent link
    for d in 0..N_DOCS {
        let f = rng.gen_range(0..N_FOLDERS);
        ots.push("hier_doc".into());
        ois.push(format!("hd_{d}"));
        rels.push("folder".into());
        sids.push(format!("hf_{f}"));
        ssts.push(None);
        ssrs.push(None);
    }

    sqlx::query(
        "INSERT INTO auth.authz_relations
             (object_type, object_id, relation, subject_id, subject_set_type, subject_set_relation)
         SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[])
         ON CONFLICT DO NOTHING",
    )
    .bind(&ots)
    .bind(&ois)
    .bind(&rels)
    .bind(&sids)
    .bind(&ssts)
    .bind(&ssrs)
    .execute(pool)
    .await?;

    Ok(())
}

/// Old OR-chain pattern: 1 authz_check + 3 authz_check_path (one per role).
/// This is what the schema compiler used to generate for a 3-role permission with hierarchy.
pub struct HierarchyOrChainOld {
    doc_sampler: ZipfSampler,
}

impl HierarchyOrChainOld {
    pub fn new() -> Self {
        Self { doc_sampler: ZipfSampler::new(N_DOCS, 1.0) }
    }
}

#[async_trait]
impl Scenario for HierarchyOrChainOld {
    fn name(&self) -> &str { "authz::hierarchy_or_chain_old" }

    fn question(&self) -> &str {
        "Old OR-chain (1 authz_check + 3 authz_check_path, one per role): what is the baseline QPS?"
    }

    async fn setup(&self, pool: &PgPool) -> Result<()> {
        seed_hierarchy(pool).await
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let u = ctx.rng.gen_range(0..N_USERS);
        let d = self.doc_sampler.sample(&mut ctx.rng);
        // Mimics the old 4-call OR-chain for "read" on hier_doc (3 roles + 1 hierarchy level)
        let row: (bool,) = sqlx::query_as(
            "SELECT
                auth.authz_check($1, ARRAY['owner','editor','viewer']::text[], 'hier_doc', $2)
             OR auth.authz_check_path($1, ARRAY['folder','owner']::text[],  ARRAY['hier_doc','hier_folder']::text[], $2)
             OR auth.authz_check_path($1, ARRAY['folder','editor']::text[], ARRAY['hier_doc','hier_folder']::text[], $2)
             OR auth.authz_check_path($1, ARRAY['folder','viewer']::text[], ARRAY['hier_doc','hier_folder']::text[], $2)",
        )
        .bind(format!("hu_{u}"))
        .bind(format!("hd_{d}"))
        .fetch_one(ctx.pool)
        .await?;
        let _ = row.0;
        Ok(())
    }
}

/// New OR-chain pattern: 1 authz_check + 1 authz_check_path with terminal array.
/// This is what the schema compiler now generates — N_levels calls instead of N_roles × N_levels.
pub struct HierarchyOrChainNew {
    doc_sampler: ZipfSampler,
}

impl HierarchyOrChainNew {
    pub fn new() -> Self {
        Self { doc_sampler: ZipfSampler::new(N_DOCS, 1.0) }
    }
}

#[async_trait]
impl Scenario for HierarchyOrChainNew {
    fn name(&self) -> &str { "authz::hierarchy_or_chain_new" }

    fn question(&self) -> &str {
        "New OR-chain (1 authz_check + 1 authz_check_path with terminal array): QPS improvement?"
    }

    async fn setup(&self, pool: &PgPool) -> Result<()> {
        seed_hierarchy(pool).await
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let u = ctx.rng.gen_range(0..N_USERS);
        let d = self.doc_sampler.sample(&mut ctx.rng);
        // New 2-call OR-chain
        let row: (bool,) = sqlx::query_as(
            "SELECT
                auth.authz_check($1, ARRAY['owner','editor','viewer']::text[], 'hier_doc', $2)
             OR auth.authz_check_path($1, ARRAY['folder']::text[], ARRAY['hier_doc','hier_folder']::text[], ARRAY['owner','editor','viewer']::text[], $2)",
        )
        .bind(format!("hu_{u}"))
        .bind(format!("hd_{d}"))
        .fetch_one(ctx.pool)
        .await?;
        let _ = row.0;
        Ok(())
    }
}
