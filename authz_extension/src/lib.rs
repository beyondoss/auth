use std::collections::HashSet;

use pgrx::prelude::*;
use pgrx::spi;

pgrx::pg_module_magic!();

// A BFS frontier node: (object_type, object_id, relation) that identifies a
// subject-set to expand — i.e. "find all rows in authz_relations where
// object_type=t, object_id=i, relation=r, then recurse into their subjects."
type Node = (String, String, String);

/// Core BFS implementation shared by both `authz_check` overloads.
///
/// Replaces the PL/pgSQL version's `= ANY(v_seen)` O(n) visited check with
/// a `HashSet` O(1) lookup, and eliminates PL/pgSQL interpreter overhead
/// between BFS levels. The SQL query structure (one round-trip per level via
/// UNNEST join) is identical to the PL/pgSQL version.
fn bfs(
    subject_id: &str,
    relations: Vec<Option<String>>,
    object_type: &str,
    object_id: &str,
) -> Result<bool, spi::Error> {
    Spi::connect(|client| {
        // --- Anchor ---
        // Check for a direct leaf match and seed the frontier with subject-set
        // rows. Collecting into an owned Vec before the while loop so the
        // SpiTupleTable lifetime doesn't conflict with subsequent client.select
        // calls inside the loop.
        let anchor_rows: Vec<(Option<String>, Option<String>, Option<String>)> = client
            .select(
                "SELECT subject_id, subject_set_type, subject_set_relation \
                 FROM auth.authz_relations \
                 WHERE object_type = $1 \
                   AND object_id   = $2 \
                   AND relation    = ANY($3::text[])",
                None,
                &[object_type.into(), object_id.into(), relations.into()],
            )?
            .into_iter()
            .map(|row| -> Result<_, spi::Error> {
                Ok((
                    row.get::<String>(1)?,
                    row.get::<String>(2)?,
                    row.get::<String>(3)?,
                ))
            })
            .collect::<Result<_, _>>()?;

        let mut frontier: Vec<Node> = Vec::new();
        let mut visited: HashSet<Node> = HashSet::new();

        for (si, sst, ssr) in anchor_rows {
            if sst.is_none() && si.as_deref() == Some(subject_id) {
                return Ok(true);
            }
            if let (Some(t), Some(i), Some(r)) = (sst, si, ssr) {
                let node = (t, i, r);
                if visited.insert(node.clone()) {
                    frontier.push(node);
                }
            }
        }

        // --- BFS loop ---
        // One SQL query per level expands the entire frontier via UNNEST join,
        // matching the PL/pgSQL approach. The visited-set filter that PL/pgSQL
        // did with `= ANY(v_seen)` (O(n) per row per level) is replaced here
        // with `HashSet::insert` (O(1) amortized). Rows for already-visited
        // nodes are discarded in Rust rather than filtered in SQL.
        while !frontier.is_empty() {
            let ft: Vec<Option<String>> =
                frontier.iter().map(|(t, _, _)| Some(t.clone())).collect();
            let fi: Vec<Option<String>> =
                frontier.iter().map(|(_, i, _)| Some(i.clone())).collect();
            let fr: Vec<Option<String>> =
                frontier.iter().map(|(_, _, r)| Some(r.clone())).collect();

            let level_rows: Vec<(Option<String>, Option<String>, Option<String>, Option<bool>)> =
                client
                    .select(
                        "SELECT DISTINCT \
                             r.subject_set_type, \
                             r.subject_id, \
                             r.subject_set_relation, \
                             (r.subject_id = $1 AND r.subject_set_type IS NULL) AS is_match \
                         FROM auth.authz_relations r \
                         JOIN unnest($2::text[], $3::text[], $4::text[]) AS f(ot, oi, rel) \
                           ON r.object_type = f.ot \
                          AND r.object_id   = f.oi \
                          AND r.relation    = f.rel",
                        None,
                        &[subject_id.into(), ft.into(), fi.into(), fr.into()],
                    )?
                    .into_iter()
                    .map(|row| -> Result<_, spi::Error> {
                        Ok((
                            row.get::<String>(1)?,
                            row.get::<String>(2)?,
                            row.get::<String>(3)?,
                            row.get::<bool>(4)?,
                        ))
                    })
                    .collect::<Result<_, _>>()?;

            let mut next_frontier: Vec<Node> = Vec::new();

            for (sst, si, ssr, is_match) in level_rows {
                if is_match.unwrap_or(false) {
                    return Ok(true);
                }
                if let (Some(t), Some(i), Some(r)) = (sst, si, ssr) {
                    let node = (t, i, r);
                    if visited.insert(node.clone()) {
                        next_frontier.push(node);
                    }
                }
            }

            frontier = next_frontier;
        }

        Ok(false)
    })
}

/// authz_check(subject_id text, relation text, object_type text, object_id text) → bool
#[pg_extern(name = "authz_check", schema = "auth", stable)]
fn authz_check_single(
    subject_id: &str,
    relation: &str,
    object_type: &str,
    object_id: &str,
) -> bool {
    let relations = vec![Some(relation.to_string())];
    match bfs(subject_id, relations, object_type, object_id) {
        Ok(r) => r,
        Err(e) => pgrx::error!("authz_check: {e}"),
    }
}

/// authz_check(subject_id text, relations text[], object_type text, object_id text) → bool
#[pg_extern(name = "authz_check", schema = "auth", stable)]
fn authz_check_array(
    subject_id: &str,
    relations: pgrx::Array<&str>,
    object_type: &str,
    object_id: &str,
) -> bool {
    let relations: Vec<Option<String>> = relations.iter().map(|r| r.map(str::to_string)).collect();
    match bfs(subject_id, relations, object_type, object_id) {
        Ok(r) => r,
        Err(e) => pgrx::error!("authz_check: {e}"),
    }
}
