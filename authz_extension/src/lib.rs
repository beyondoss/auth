use std::collections::HashSet;

use pgrx::prelude::*;
use pgrx::spi;

pgrx::pg_module_magic!();

// A BFS frontier node: (object_type, object_id, relation).
type Node = (String, String, String);

// ── BFS kernel ────────────────────────────────────────────────────────────────

/// Run one BFS traversal using a borrowed SpiClient (no extra Spi::connect).
/// Called by both the single-check wrappers and the batch functions.
fn bfs_with_client(
    client: &spi::SpiClient<'_>,
    subject_id: &str,
    relations: Vec<Option<String>>,
    object_type: &str,
    object_id: &str,
) -> Result<bool, spi::Error> {
    // --- Theory 3: direct-grant fast path ---
    // Check for a direct leaf match with a point-lookup before fetching frontier
    // rows.  Saves iterating over subject-set rows on the common cache-hot case.
    let direct: bool = client
        .select(
            "SELECT EXISTS ( \
                 SELECT 1 FROM auth.authz_relations \
                 WHERE object_type      = $1 \
                   AND object_id        = $2 \
                   AND relation         = ANY($3::text[]) \
                   AND subject_id       = $4 \
                   AND subject_set_type IS NULL \
             )",
            None,
            &[
                object_type.into(),
                object_id.into(),
                relations.clone().into(),
                subject_id.into(),
            ],
        )?
        .first()
        .get::<bool>(1)?
        .unwrap_or(false);

    if direct {
        return Ok(true);
    }

    // --- Anchor: seed frontier with subject-set rows ---
    let anchor_rows: Vec<(Option<String>, Option<String>, Option<String>)> = client
        .select(
            "SELECT subject_id, subject_set_type, subject_set_relation \
             FROM auth.authz_relations \
             WHERE object_type      = $1 \
               AND object_id        = $2 \
               AND relation         = ANY($3::text[]) \
               AND subject_set_type IS NOT NULL",
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
        if let (Some(t), Some(i), Some(r)) = (sst, si, ssr) {
            let node = (t, i, r);
            if visited.insert(node.clone()) {
                frontier.push(node);
            }
        }
    }

    // --- BFS loop ---
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
}

fn bfs(
    subject_id: &str,
    relations: Vec<Option<String>>,
    object_type: &str,
    object_id: &str,
) -> Result<bool, spi::Error> {
    Spi::connect(|client| bfs_with_client(&client, subject_id, relations, object_type, object_id))
}

// ── Single-check exports ──────────────────────────────────────────────────────

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

// ── Theory 2A: sequential batch (one SPI connect, N BFS calls) ───────────────

/// authz_check_batch(subject_ids, relations, object_types, object_ids) → bool[]
///
/// Runs N permission checks inside a single SpiClient, amortising the
/// Spi::connect cost across all checks.  Equivalent correctness to calling
/// authz_check N times; faster when N > 1.
#[pg_extern(name = "authz_check_batch", schema = "auth", stable)]
fn authz_check_batch(
    subject_ids: pgrx::Array<&str>,
    relations: pgrx::Array<&str>,
    object_types: pgrx::Array<&str>,
    object_ids: pgrx::Array<&str>,
) -> Vec<Option<bool>> {
    // Collect input arrays into owned Strings before entering Spi::connect so
    // the pgrx Array borrows don't conflict with the SPI memory context.
    let inputs: Vec<(String, String, String, String)> = subject_ids
        .iter()
        .zip(relations.iter())
        .zip(object_types.iter())
        .zip(object_ids.iter())
        .map(|(((s, r), t), o)| {
            (
                s.unwrap_or("").to_string(),
                r.unwrap_or("").to_string(),
                t.unwrap_or("").to_string(),
                o.unwrap_or("").to_string(),
            )
        })
        .collect();

    match Spi::connect(|client| {
        let mut results = Vec::with_capacity(inputs.len());
        for (subject_id, relation, object_type, object_id) in &inputs {
            let rels = vec![Some(relation.clone())];
            let r = bfs_with_client(&client, subject_id, rels, object_type, object_id)?;
            results.push(Some(r));
        }
        Ok::<_, spi::Error>(results)
    }) {
        Ok(r) => r,
        Err(e) => pgrx::error!("authz_check_batch: {e}"),
    }
}

// ── Theory 2B: parallel BFS (one SQL query per level across all N checks) ────

struct CheckState {
    subject_id: String,
    frontier: Vec<Node>,
    visited: HashSet<Node>,
}

/// authz_check_parallel_batch(subject_ids, relations, object_types, object_ids) → bool[]
///
/// Runs N permission checks with a shared BFS expansion: one SQL query per
/// level covers all N active frontiers simultaneously.  For N checks at depth D,
/// this issues D+1 SQL queries total vs N×(D+1) for the sequential batch.
#[pg_extern(name = "authz_check_parallel_batch", schema = "auth", stable)]
fn authz_check_parallel_batch(
    subject_ids: pgrx::Array<&str>,
    relations: pgrx::Array<&str>,
    object_types: pgrx::Array<&str>,
    object_ids: pgrx::Array<&str>,
) -> Vec<Option<bool>> {
    let inputs: Vec<(String, String, String, String)> = subject_ids
        .iter()
        .zip(relations.iter())
        .zip(object_types.iter())
        .zip(object_ids.iter())
        .map(|(((s, r), t), o)| {
            (
                s.unwrap_or("").to_string(),
                r.unwrap_or("").to_string(),
                t.unwrap_or("").to_string(),
                o.unwrap_or("").to_string(),
            )
        })
        .collect();

    let n = inputs.len();
    let mut results: Vec<Option<bool>> = vec![None; n];

    match Spi::connect(|client| {
        // --- Direct-grant fast path for all N checks in one query ---
        // Returns one bool per check_idx (1-based in the UNNEST).
        let ci: Vec<Option<i64>> = (0..n as i64).map(|i| Some(i + 1)).collect();
        let sids: Vec<Option<String>> =
            inputs.iter().map(|(s, _, _, _)| Some(s.clone())).collect();
        let rels: Vec<Option<String>> =
            inputs.iter().map(|(_, r, _, _)| Some(r.clone())).collect();
        let ots: Vec<Option<String>> =
            inputs.iter().map(|(_, _, t, _)| Some(t.clone())).collect();
        let ois: Vec<Option<String>> =
            inputs.iter().map(|(_, _, _, o)| Some(o.clone())).collect();

        let direct_rows: Vec<(Option<i64>, Option<bool>)> = client
            .select(
                "SELECT f.check_idx, \
                        EXISTS ( \
                            SELECT 1 FROM auth.authz_relations \
                            WHERE object_type      = f.object_type \
                              AND object_id        = f.object_id \
                              AND relation         = f.relation \
                              AND subject_id       = f.subject_id \
                              AND subject_set_type IS NULL \
                        ) AS direct_match \
                 FROM unnest($1::bigint[], $2::text[], $3::text[], $4::text[], $5::text[]) \
                      AS f(check_idx, subject_id, object_type, object_id, relation)",
                None,
                &[ci.into(), sids.into(), ots.into(), ois.into(), rels.into()],
            )?
            .into_iter()
            .map(|row| -> Result<_, spi::Error> {
                Ok((row.get::<i64>(1)?, row.get::<bool>(2)?))
            })
            .collect::<Result<_, _>>()?;

        let mut states: Vec<Option<CheckState>> = (0..n).map(|_| None).collect();

        for (check_idx, direct_match) in direct_rows {
            let idx = (check_idx.unwrap_or(1) - 1) as usize;
            if direct_match.unwrap_or(false) {
                results[idx] = Some(true);
            } else {
                states[idx] = Some(CheckState {
                    subject_id: inputs[idx].0.clone(),
                    frontier: Vec::new(),
                    visited: HashSet::new(),
                });
            }
        }

        // --- Anchor: seed frontiers for non-direct checks ---
        // Build one UNNEST query covering all undone checks.
        let undone: Vec<usize> = (0..n).filter(|&i| results[i].is_none()).collect();
        if !undone.is_empty() {
            let a_ci: Vec<Option<i64>> =
                undone.iter().map(|&i| Some(i as i64 + 1)).collect();
            let a_ots: Vec<Option<String>> =
                undone.iter().map(|&i| Some(inputs[i].2.clone())).collect();
            let a_ois: Vec<Option<String>> =
                undone.iter().map(|&i| Some(inputs[i].3.clone())).collect();
            let a_rels: Vec<Option<String>> =
                undone.iter().map(|&i| Some(inputs[i].1.clone())).collect();

            let anchor_rows: Vec<(Option<i64>, Option<String>, Option<String>, Option<String>)> =
                client
                    .select(
                        "SELECT f.check_idx, r.subject_id, r.subject_set_type, r.subject_set_relation \
                         FROM unnest($1::bigint[], $2::text[], $3::text[], $4::text[]) \
                              AS f(check_idx, object_type, object_id, relation) \
                         JOIN auth.authz_relations r \
                           ON r.object_type      = f.object_type \
                          AND r.object_id        = f.object_id \
                          AND r.relation         = f.relation \
                          AND r.subject_set_type IS NOT NULL",
                        None,
                        &[a_ci.into(), a_ots.into(), a_ois.into(), a_rels.into()],
                    )?
                    .into_iter()
                    .map(|row| -> Result<_, spi::Error> {
                        Ok((
                            row.get::<i64>(1)?,
                            row.get::<String>(2)?,
                            row.get::<String>(3)?,
                            row.get::<String>(4)?,
                        ))
                    })
                    .collect::<Result<_, _>>()?;

            for (check_idx, si, sst, ssr) in anchor_rows {
                let idx = (check_idx.unwrap_or(1) - 1) as usize;
                if let (Some(t), Some(i), Some(r)) = (sst, si, ssr) {
                    let node = (t, i, r);
                    if let Some(state) = &mut states[idx] {
                        if state.visited.insert(node.clone()) {
                            state.frontier.push(node);
                        }
                    }
                }
            }

            // Mark checks with empty frontier as false.
            for &i in &undone {
                if let Some(state) = &states[i] {
                    if state.frontier.is_empty() {
                        results[i] = Some(false);
                    }
                }
            }
        }

        // --- BFS loop: one SQL query per level across all active checks ---
        loop {
            // Collect (check_idx, subject_id, ot, oi, rel) for all frontier nodes
            // from all undone checks.
            let mut f_ci: Vec<Option<i64>> = Vec::new();
            let mut f_sids: Vec<Option<String>> = Vec::new();
            let mut f_ots: Vec<Option<String>> = Vec::new();
            let mut f_ois: Vec<Option<String>> = Vec::new();
            let mut f_rels: Vec<Option<String>> = Vec::new();

            for (i, state_opt) in states.iter().enumerate() {
                if results[i].is_some() {
                    continue;
                }
                if let Some(state) = state_opt {
                    for (ot, oi, rel) in &state.frontier {
                        f_ci.push(Some(i as i64 + 1));
                        f_sids.push(Some(state.subject_id.clone()));
                        f_ots.push(Some(ot.clone()));
                        f_ois.push(Some(oi.clone()));
                        f_rels.push(Some(rel.clone()));
                    }
                }
            }

            if f_ci.is_empty() {
                break;
            }

            let level_rows: Vec<(
                Option<i64>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<bool>,
            )> = client
                .select(
                    "SELECT DISTINCT \
                         f.check_idx, \
                         r.subject_set_type, \
                         r.subject_id, \
                         r.subject_set_relation, \
                         (r.subject_id = f.subject_id AND r.subject_set_type IS NULL) AS is_match \
                     FROM unnest($1::bigint[], $2::text[], $3::text[], $4::text[], $5::text[]) \
                          AS f(check_idx, subject_id, ot, oi, rel) \
                     JOIN auth.authz_relations r \
                       ON r.object_type = f.ot \
                      AND r.object_id   = f.oi \
                      AND r.relation    = f.rel",
                    None,
                    &[
                        f_ci.into(),
                        f_sids.into(),
                        f_ots.into(),
                        f_ois.into(),
                        f_rels.into(),
                    ],
                )?
                .into_iter()
                .map(|row| -> Result<_, spi::Error> {
                    Ok((
                        row.get::<i64>(1)?,
                        row.get::<String>(2)?,
                        row.get::<String>(3)?,
                        row.get::<String>(4)?,
                        row.get::<bool>(5)?,
                    ))
                })
                .collect::<Result<_, _>>()?;

            // Clear frontiers; we'll rebuild next_frontiers from this level's results.
            for state_opt in &mut states {
                if let Some(s) = state_opt {
                    s.frontier.clear();
                }
            }

            for (check_idx, sst, si, ssr, is_match) in level_rows {
                let idx = (check_idx.unwrap_or(1) - 1) as usize;
                if results[idx].is_some() {
                    continue;
                }
                if is_match.unwrap_or(false) {
                    results[idx] = Some(true);
                    continue;
                }
                if let (Some(t), Some(i), Some(r)) = (sst, si, ssr) {
                    let node = (t, i, r);
                    if let Some(state) = &mut states[idx] {
                        if state.visited.insert(node.clone()) {
                            state.frontier.push(node);
                        }
                    }
                }
            }

            // Checks with now-empty frontier are exhausted → false.
            for (i, state_opt) in states.iter().enumerate() {
                if results[i].is_none() {
                    if let Some(state) = state_opt {
                        if state.frontier.is_empty() {
                            results[i] = Some(false);
                        }
                    }
                }
            }
        }

        // Any check still None has no frontier left → false.
        for r in &mut results {
            if r.is_none() {
                *r = Some(false);
            }
        }

        Ok::<_, spi::Error>(results)
    }) {
        Ok(r) => r,
        Err(e) => pgrx::error!("authz_check_parallel_batch: {e}"),
    }
}

// ── Path batch: N checks sharing a hierarchy path, P+1 SQL queries ───────────

/// authz_check_path_batch(subject_ids, relation_prefix, object_type_path, terminal_relations, object_ids) → bool[]
///
/// Batches N hierarchy path checks that share the same path structure but
/// have different (subject_id, object_id) pairs.  Issues exactly P+1 SQL
/// queries where P = relation_prefix.len() — one per intermediate hop plus
/// one terminal hop — regardless of N.
#[pg_extern(name = "authz_check_path_batch", schema = "auth", stable)]
fn authz_check_path_batch(
    subject_ids: pgrx::Array<&str>,
    relation_prefix: pgrx::Array<&str>,
    object_type_path: pgrx::Array<&str>,
    terminal_relations: pgrx::Array<&str>,
    object_ids: pgrx::Array<&str>,
) -> Vec<Option<bool>> {
    // Collect all input arrays into owned Vecs before entering Spi::connect.
    let sids: Vec<String> = subject_ids
        .iter()
        .map(|s| s.unwrap_or("").to_string())
        .collect();
    let oids: Vec<String> = object_ids
        .iter()
        .map(|o| o.unwrap_or("").to_string())
        .collect();
    let prefix: Vec<String> = relation_prefix
        .iter()
        .map(|r| r.unwrap_or("").to_string())
        .collect();
    let type_path: Vec<String> = object_type_path
        .iter()
        .map(|t| t.unwrap_or("").to_string())
        .collect();
    let term_rels: Vec<String> = terminal_relations
        .iter()
        .map(|r| r.unwrap_or("").to_string())
        .collect();

    let n = sids.len();
    if n == 0 || type_path.is_empty() {
        return vec![Some(false); n];
    }

    let p = prefix.len();
    // type_path must have P+1 entries (P intermediate + 1 terminal); guard
    // by checking length.
    if type_path.len() != p + 1 {
        pgrx::error!(
            "authz_check_path_batch: object_type_path length must be relation_prefix length + 1"
        );
    }

    // frontiers[i] = current object_id for check i (None means dropped out).
    let mut frontiers: Vec<Option<String>> = oids.into_iter().map(Some).collect();

    match Spi::connect(|client| {
        // --- Intermediate hops 0..P-1 ---
        for k in 0..p {
            let object_type = &type_path[k];
            let relation = &prefix[k];

            // Build (idx, obj_id) UNNEST from currently-active checks.
            let mut h_ci: Vec<Option<i64>> = Vec::new();
            let mut h_ois: Vec<Option<String>> = Vec::new();
            for (i, f) in frontiers.iter().enumerate() {
                if let Some(oid) = f {
                    h_ci.push(Some(i as i64 + 1));
                    h_ois.push(Some(oid.clone()));
                }
            }

            if h_ci.is_empty() {
                break;
            }

            let hop_rows: Vec<(Option<i64>, Option<String>)> = client
                .select(
                    "SELECT f.idx, r.subject_id AS next_obj \
                     FROM unnest($1::bigint[], $2::text[]) AS f(idx, obj_id) \
                     JOIN auth.authz_relations r \
                       ON r.object_type      = $3 \
                      AND r.object_id        = f.obj_id \
                      AND r.relation         = $4 \
                      AND r.subject_set_type IS NULL",
                    None,
                    &[
                        h_ci.into(),
                        h_ois.into(),
                        object_type.clone().into(),
                        relation.clone().into(),
                    ],
                )?
                .into_iter()
                .map(|row| -> Result<_, spi::Error> {
                    Ok((row.get::<i64>(1)?, row.get::<String>(2)?))
                })
                .collect::<Result<_, _>>()?;

            // Build next frontiers: any check without a matching row drops out.
            let mut next: Vec<Option<String>> = vec![None; n];
            for (idx_opt, next_obj) in hop_rows {
                let idx = (idx_opt.unwrap_or(1) - 1) as usize;
                if let Some(obj) = next_obj {
                    // If multiple rows match for the same check, the last one
                    // wins; this matches the "single hop" assumption of the
                    // hierarchy path and is sufficient for the batched form.
                    next[idx] = Some(obj);
                }
            }
            frontiers = next;
        }

        // --- Terminal hop ---
        let terminal_type = &type_path[p];

        let mut t_ci: Vec<Option<i64>> = Vec::new();
        let mut t_ois: Vec<Option<String>> = Vec::new();
        let mut t_sids: Vec<Option<String>> = Vec::new();
        for (i, f) in frontiers.iter().enumerate() {
            if let Some(oid) = f {
                t_ci.push(Some(i as i64 + 1));
                t_ois.push(Some(oid.clone()));
                t_sids.push(Some(sids[i].clone()));
            }
        }

        let mut results: Vec<Option<bool>> = vec![Some(false); n];

        if !t_ci.is_empty() {
            let term_rels_param: Vec<Option<String>> =
                term_rels.iter().map(|r| Some(r.clone())).collect();

            let term_rows: Vec<Option<i64>> = client
                .select(
                    "SELECT f.idx \
                     FROM unnest($1::bigint[], $2::text[], $3::text[]) \
                          AS f(idx, obj_id, target_sid) \
                     JOIN auth.authz_relations r \
                       ON r.object_type      = $4 \
                      AND r.object_id        = f.obj_id \
                      AND r.relation         = ANY($5::text[]) \
                      AND r.subject_set_type IS NULL \
                      AND r.subject_id       = f.target_sid",
                    None,
                    &[
                        t_ci.into(),
                        t_ois.into(),
                        t_sids.into(),
                        terminal_type.clone().into(),
                        term_rels_param.into(),
                    ],
                )?
                .into_iter()
                .map(|row| -> Result<_, spi::Error> { row.get::<i64>(1) })
                .collect::<Result<_, _>>()?;

            for idx_opt in term_rows {
                let idx = (idx_opt.unwrap_or(1) - 1) as usize;
                results[idx] = Some(true);
            }
        }

        Ok::<_, spi::Error>(results)
    }) {
        Ok(r) => r,
        Err(e) => pgrx::error!("authz_check_path_batch: {e}"),
    }
}
