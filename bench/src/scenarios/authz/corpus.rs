//! Synthetic relation_tuple corpus generators.
//!
//! - `seed_flat`: realistic mixed-depth corpus for general read benches
//!   (mostly direct grants + some team-mediated grants). Most checks should
//!   resolve at the recursive CTE base case; some require one expansion.
//!
//! - `seed_chain`: pure depth-N chains for measuring how cache-miss latency
//!   scales with hierarchy depth. Each chain links a unique terminal user to
//!   a unique head object via N intermediate subject-set hops.

use anyhow::Result;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct FlatCorpus {
    pub n_users: usize,
    pub n_documents: usize,
    pub n_teams: usize,
    pub team_fanout: usize,
    pub seed: u64,
}

impl Default for FlatCorpus {
    fn default() -> Self {
        Self {
            n_users: 5_000,
            n_documents: 5_000,
            n_teams: 500,
            team_fanout: 20,
            seed: 0xF1A7,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChainCorpus {
    pub n_chains: usize,
    pub depth: usize,
    pub seed: u64,
}

/// Truncate relation tuples. Use only when a scenario genuinely needs a clean
/// slate (scale_sweep resets its own prefixed object_type rows directly).
pub async fn reset(pool: &PgPool) -> Result<()> {
    sqlx::query("TRUNCATE auth.authz_relations")
        .execute(pool)
        .await?;
    Ok(())
}

/// Idempotent: if a flat corpus is already present (>= n_documents document
/// rows), this is a no-op. Otherwise seeds the full corpus. Coexists with
/// chain corpora since chain rows use object_type `head`/`link_N`.
pub async fn seed_flat(pool: &PgPool, c: &FlatCorpus) -> Result<()> {
    let existing: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM auth.authz_relations WHERE object_type = 'document'",
    )
    .fetch_one(pool)
    .await?;
    if existing.0 as usize >= c.n_documents {
        return Ok(());
    }
    let mut rng = SmallRng::seed_from_u64(c.seed);
    let mut rows = TupleBuf::new();

    // Direct grants: each document gets 0-2 direct user owners/editors.
    for d in 0..c.n_documents {
        let n_direct = rng.gen_range(0..=2);
        for _ in 0..n_direct {
            let u = rng.gen_range(0..c.n_users);
            let rel = if rng.gen_bool(0.5) { "owner" } else { "editor" };
            rows.push(
                "document",
                &format!("d_{d}"),
                rel,
                &format!("u_{u}"),
                None,
                None,
            );
        }
    }

    // Team membership: random users per team.
    for t in 0..c.n_teams {
        for _ in 0..c.team_fanout {
            let u = rng.gen_range(0..c.n_users);
            rows.push(
                "team",
                &format!("t_{t}"),
                "member",
                &format!("u_{u}"),
                None,
                None,
            );
        }
    }

    // Team-mediated viewer grants: each document gets 1 team#member as viewer.
    for d in 0..c.n_documents {
        let t = rng.gen_range(0..c.n_teams);
        rows.push(
            "document",
            &format!("d_{d}"),
            "viewer",
            &format!("t_{t}"),
            Some("team"),
            Some("member"),
        );
    }

    rows.flush(pool).await?;
    Ok(())
}

/// Seeds `n_chains` independent chains of depth N. Each chain's terminal subject
/// is a unique user; the head object is queried at relation `link`.
///
/// For depth=1, this is identical to a direct grant.
/// For depth=N>1, the chain is `head → c1 → c2 → ... → c_{N-1} → user`, where
/// each link is a subject-set tuple (object#relation = next type#link).
/// Idempotent: if `n_chains` head rows already exist for the given depth's
/// chain set, this is a no-op. Coexists with other chain depths because each
/// chain head uses the canonical type `head` but a unique id `h_{chain_id}`,
/// and intermediate links are typed `link_{i}` where i runs 1..depth.
///
/// To avoid collisions across depths we partition the head id space by depth:
/// `h_{depth}_{chain_id}` rather than `h_{chain_id}`. Existing depth_sweep
/// scenarios use the new naming.
pub async fn seed_chain(pool: &PgPool, c: &ChainCorpus) -> Result<()> {
    assert!(c.depth >= 1, "depth must be >= 1");
    let prefix = format!("h{}_", c.depth);
    let existing: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM auth.authz_relations WHERE object_type = 'head' AND object_id LIKE $1",
    )
    .bind(format!("{prefix}%"))
    .fetch_one(pool)
    .await?;
    if existing.0 as usize >= c.n_chains {
        return Ok(());
    }
    let mut rows = TupleBuf::new();

    for chain_id in 0..c.n_chains {
        // Partition users, heads, and link ids by depth so multiple chain
        // depths can coexist in one corpus without colliding.
        let user = format!("u{}_{}", c.depth, chain_id);
        let head_type = "head".to_string();
        let head_id = format!("h{}_{}", c.depth, chain_id);

        if c.depth == 1 {
            // Direct: (head, h_X, link, u_X, NULL, NULL)
            rows.push(&head_type, &head_id, "link", &user, None, None);
        } else {
            // Build chain: head → link_1 → link_2 → ... → link_{N-1} → user
            // Layers are typed `link_{i}` for i in 1..N (so depth=2 has one intermediate).
            let mut prev_obj_type = head_type.clone();
            let mut prev_obj_id = head_id.clone();
            for i in 1..c.depth {
                let next_type = format!("link_{i}");
                let next_id = format!("l{}_{}_{}", c.depth, i, chain_id);
                // (prev_obj_type, prev_obj_id, link, next_id, next_type, link)
                rows.push(
                    &prev_obj_type,
                    &prev_obj_id,
                    "link",
                    &next_id,
                    Some(&next_type),
                    Some("link"),
                );
                prev_obj_type = next_type;
                prev_obj_id = next_id;
            }
            // Terminal: (last_type, last_id, link, user, NULL, NULL)
            rows.push(&prev_obj_type, &prev_obj_id, "link", &user, None, None);
        }
    }

    rows.flush(pool).await?;
    Ok(())
}

/// Seed flat corpus and all requested chain depths in one pass. Called once
/// from the harness before any scenarios run, so individual scenario `setup()`
/// methods are no-ops and the testcontainer is shared across the full run.
pub async fn seed_all(
    pool: &PgPool,
    flat: &FlatCorpus,
    chain_depths: &[(usize, usize)],
) -> Result<()> {
    seed_flat(pool, flat).await?;
    for &(depth, n_chains) in chain_depths {
        seed_chain(
            pool,
            &ChainCorpus {
                n_chains,
                depth,
                seed: 0xC0_FFEE + depth as u64,
            },
        )
        .await?;
    }
    Ok(())
}

/// Buffered tuple inserter using UNNEST'd parallel arrays. Flushes in batches
/// of `BATCH_SIZE` to keep parameter count bounded and avoid one giant
/// transaction.
struct TupleBuf {
    object_type: Vec<String>,
    object_id: Vec<String>,
    relation: Vec<String>,
    subject_id: Vec<String>,
    subject_set_type: Vec<Option<String>>,
    subject_set_relation: Vec<Option<String>>,
}

const BATCH_SIZE: usize = 5_000;

impl TupleBuf {
    fn new() -> Self {
        Self {
            object_type: Vec::new(),
            object_id: Vec::new(),
            relation: Vec::new(),
            subject_id: Vec::new(),
            subject_set_type: Vec::new(),
            subject_set_relation: Vec::new(),
        }
    }

    fn push(
        &mut self,
        object_type: &str,
        object_id: &str,
        relation: &str,
        subject_id: &str,
        subject_set_type: Option<&str>,
        subject_set_relation: Option<&str>,
    ) {
        self.object_type.push(object_type.to_string());
        self.object_id.push(object_id.to_string());
        self.relation.push(relation.to_string());
        self.subject_id.push(subject_id.to_string());
        self.subject_set_type
            .push(subject_set_type.map(str::to_string));
        self.subject_set_relation
            .push(subject_set_relation.map(str::to_string));
    }

    async fn flush(self, pool: &PgPool) -> Result<()> {
        let total = self.object_type.len();
        let mut start = 0;
        while start < total {
            let end = (start + BATCH_SIZE).min(total);
            let ot = &self.object_type[start..end];
            let oi = &self.object_id[start..end];
            let r = &self.relation[start..end];
            let si = &self.subject_id[start..end];
            // For nullable arrays, sqlx requires Vec<Option<String>>; convert slice.
            let st: Vec<Option<String>> = self.subject_set_type[start..end].to_vec();
            let sr: Vec<Option<String>> = self.subject_set_relation[start..end].to_vec();

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
            .bind(ot)
            .bind(oi)
            .bind(r)
            .bind(si)
            .bind(&st)
            .bind(&sr)
            .execute(pool)
            .await?;

            start = end;
        }
        Ok(())
    }
}
