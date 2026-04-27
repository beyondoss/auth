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

pub async fn reset(pool: &PgPool) -> Result<()> {
    sqlx::query("TRUNCATE auth.relation_tuple")
        .execute(pool)
        .await?;
    sqlx::query("TRUNCATE auth.authz_check_cache")
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn seed_flat(pool: &PgPool, c: &FlatCorpus) -> Result<()> {
    reset(pool).await?;
    let mut rng = SmallRng::seed_from_u64(c.seed);
    let mut rows = TupleBuf::new();

    // Direct grants: each document gets 0-2 direct user owners/editors.
    for d in 0..c.n_documents {
        let n_direct = rng.gen_range(0..=2);
        for _ in 0..n_direct {
            let u = rng.gen_range(0..c.n_users);
            let rel = if rng.gen_bool(0.5) { "owner" } else { "editor" };
            rows.push("document", &format!("d_{d}"), rel, &format!("u_{u}"), None, None);
        }
    }

    // Team membership: random users per team.
    for t in 0..c.n_teams {
        for _ in 0..c.team_fanout {
            let u = rng.gen_range(0..c.n_users);
            rows.push("team", &format!("t_{t}"), "member", &format!("u_{u}"), None, None);
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
pub async fn seed_chain(pool: &PgPool, c: &ChainCorpus) -> Result<()> {
    reset(pool).await?;
    assert!(c.depth >= 1, "depth must be >= 1");
    let mut rows = TupleBuf::new();

    for chain_id in 0..c.n_chains {
        let user = format!("u_{chain_id}");
        let head_type = "head".to_string();
        let head_id = format!("h_{chain_id}");

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
                let next_id = format!("l{i}_{chain_id}");
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

/// Buffered tuple inserter using UNNEST'd parallel arrays. Flushes in batches
/// of `BATCH_SIZE` to keep parameter count bounded and avoid one giant
/// transaction.
struct TupleBuf {
    object_type: Vec<String>,
    object_id: Vec<String>,
    relation: Vec<String>,
    subject_id: Vec<String>,
    subject_type: Vec<Option<String>>,
    subject_relation: Vec<Option<String>>,
}

const BATCH_SIZE: usize = 5_000;

impl TupleBuf {
    fn new() -> Self {
        Self {
            object_type: Vec::new(),
            object_id: Vec::new(),
            relation: Vec::new(),
            subject_id: Vec::new(),
            subject_type: Vec::new(),
            subject_relation: Vec::new(),
        }
    }

    fn push(
        &mut self,
        object_type: &str,
        object_id: &str,
        relation: &str,
        subject_id: &str,
        subject_type: Option<&str>,
        subject_relation: Option<&str>,
    ) {
        self.object_type.push(object_type.to_string());
        self.object_id.push(object_id.to_string());
        self.relation.push(relation.to_string());
        self.subject_id.push(subject_id.to_string());
        self.subject_type.push(subject_type.map(str::to_string));
        self.subject_relation.push(subject_relation.map(str::to_string));
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
            let st: Vec<Option<String>> = self.subject_type[start..end].to_vec();
            let sr: Vec<Option<String>> = self.subject_relation[start..end].to_vec();

            sqlx::query(
                r#"
                INSERT INTO auth.relation_tuple
                    (object_type, object_id, relation, subject_id, subject_type, subject_relation)
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
