use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use std::sync::Arc;

use crate::{
    authz::{
        cache::CheckKey,
        engine::{self, BatchOp},
        schema::{AuthzCheckCall, AuthzSchema, CompiledSchema, compile, validate_ident},
    },
    error::AuthError,
    http::AppState,
    pages,
    sessions::AuthContext,
    tokens,
};

type CheckGroup = HashMap<(Arc<str>, String), Vec<(usize, String)>>;
type PathBatch = HashMap<
    String,
    (
        Vec<String>,
        Vec<String>,
        Vec<String>,
        Vec<(usize, String, String)>,
    ),
>;

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize, IntoParams)]
pub struct CheckQuery {
    /// Explicit subject to check as. Defaults to the current session user.
    pub user: Option<String>,
    /// Permission name as defined in the authz schema (e.g. `"read"`, `"edit"`).
    pub permission: String,
    /// Resource type as defined in the authz schema.
    pub resource_type: String,
    /// ID of the resource instance to check against.
    pub resource_id: String,
}

/// Result of a single permission check.
#[derive(Debug, Serialize, ToSchema)]
pub struct CheckResponse {
    /// True if the subject has the requested permission on the resource.
    pub allowed: bool,
}

/// A relation tuple: `(object, relation, subject)`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RelationRequest {
    pub object: RelationObject,
    /// The relation name as defined in the authz schema (e.g. `"owner"`, `"member"`).
    pub relation: String,
    pub subject: RelationSubject,
}

/// The resource side of a relation tuple.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RelationObject {
    /// Resource type as defined in the authz schema.
    #[serde(rename = "type")]
    pub object_type: String,
    /// Unique identifier for this resource instance.
    pub id: String,
}

/// The subject (actor) side of a relation tuple.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RelationSubject {
    /// Subject ID — typically a user ID or another resource ID for subject sets.
    pub id: String,
    /// For subject sets: the type of the subject resource. Omit for direct user subjects.
    #[serde(rename = "type", default)]
    pub subject_type: Option<String>,
    /// For subject sets: the relation on the subject resource that grants membership.
    #[serde(default)]
    pub relation: Option<String>,
}

/// Batch of relation tuples to write and/or delete in a single transaction.
#[derive(Debug, Deserialize, ToSchema)]
pub struct BatchRequest {
    /// Relation tuples to create. Duplicate writes are silently ignored.
    #[serde(default)]
    pub writes: Vec<RelationRequest>,
    /// Relation tuples to delete. Missing deletes are silently ignored.
    #[serde(default)]
    pub deletes: Vec<RelationRequest>,
}

/// Result counts from a batch relation operation.
#[derive(Debug, Serialize, ToSchema)]
pub struct BatchResponse {
    pub written: u64,
    pub deleted: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BatchDecisionRequest {
    pub checks: Vec<DecisionCheck>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DecisionCheck {
    /// Explicit subject to check as. Defaults to the current session user.
    pub user: Option<String>,
    pub permission: String,
    pub resource_type: String,
    pub resource_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BatchDecisionResponse {
    /// Results in the same order as the input checks.
    pub results: Vec<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChecksRequest {
    pub checks: Vec<ChecksItem>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChecksItem {
    /// Explicit subject to check as. Defaults to the current session user.
    pub user: Option<String>,
    /// Permission name as defined in the authz schema.
    pub permission: String,
    /// Resource type as defined in the authz schema.
    pub resource_type: String,
    /// ID of the resource instance to check against.
    pub resource_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChecksResponse {
    /// Results in the same order as the input checks.
    pub results: Vec<bool>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct SubjectsQuery {
    pub object_type: String,
    pub object_id: String,
    /// The relation to expand (e.g. `"owner"`).
    pub relation: String,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct SubjectsByPermissionQuery {
    pub resource_type: String,
    pub resource_id: String,
    /// The permission to expand (e.g. `"edit"`). Resolves through the role hierarchy.
    pub permission: String,
}

/// Subjects who hold the queried relation or permission on a resource.
#[derive(Debug, Serialize, ToSchema)]
pub struct SubjectsResponse {
    pub subjects: Vec<Subject>,
}

/// A subject (actor) with the relation through which they hold access.
#[derive(Debug, Serialize, ToSchema)]
pub struct Subject {
    /// Subject ID.
    pub id: String,
    /// The direct relation through which this subject was found.
    pub relation: String,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ObjectsQuery {
    /// Explicit subject to list objects for. Defaults to the current session user.
    pub user: Option<String>,
    pub permission: String,
    pub resource_type: String,
    pub limit: Option<i64>,
    /// Opaque pagination cursor from a previous response's `next_page`.
    pub after: Option<String>,
}

/// Cursor-paginated list of resource IDs the subject can access.
#[derive(Debug, Serialize, ToSchema)]
pub struct ObjectsResponse {
    pub object_ids: Vec<String>,
    pub has_more: bool,
    /// Opaque cursor — pass as `after` for the next page.
    pub next_page: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct TraceQuery {
    /// Subject ID to trace access for.
    pub user: String,
    pub permission: String,
    pub resource_type: String,
    pub resource_id: String,
}

/// Trace result explaining why a permission check returned its outcome.
#[derive(Debug, Serialize, ToSchema)]
pub struct TraceResponse {
    /// Whether the specified user has the permission on the resource.
    pub allowed: bool,
    /// All subjects found during expansion — check if `user` appears here to understand the grant.
    pub subjects: Vec<Subject>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn schema_guard_to_compiled(guard: &Option<CompiledSchema>) -> Result<&CompiledSchema, AuthError> {
    guard.as_ref().ok_or(AuthError::AuthzNotEnabled)
}

fn resolve_batch_or_chain(
    schema: &CompiledSchema,
    resource_type: &str,
    permission: &str,
) -> Result<String, AuthError> {
    schema
        .build_batch_or_chain(resource_type, permission)
        .ok_or_else(|| {
            if schema.resource_exists(resource_type) {
                AuthError::AuthzUnknownPermission {
                    permission: permission.to_owned(),
                }
            } else {
                AuthError::AuthzUnknownResource {
                    resource_type: resource_type.to_owned(),
                }
            }
        })
}

fn resolve_or_chain(
    schema: &CompiledSchema,
    resource_type: &str,
    permission: &str,
    bundled: bool,
) -> Result<String, AuthError> {
    let chain = if bundled {
        schema.build_or_chain(resource_type, permission)
    } else {
        schema.build_standalone_or_chain(resource_type, permission)
    };
    chain.ok_or_else(|| {
        if schema.resource_exists(resource_type) {
            AuthError::AuthzUnknownPermission {
                permission: permission.to_owned(),
            }
        } else {
            AuthError::AuthzUnknownResource {
                resource_type: resource_type.to_owned(),
            }
        }
    })
}

fn into_batch_op(r: RelationRequest) -> BatchOp {
    BatchOp {
        // object_type was already validated by the caller before this fn is invoked.
        object_type: validate_ident(&r.object.object_type).expect("object_type already validated"),
        object_id: r.object.id,
        relation: r.relation,
        subject_id: r.subject.id,
        subject_set_type: r.subject.subject_type,
        subject_set_relation: r.subject.relation,
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// Check whether the current session user (or an explicit user) has a permission
/// on a resource. Uses a bundled session-validation + authz CTE for one DB round-trip
/// when checking the current session user.
#[utoipa::path(
    get,
    path = "/v1/authz/decisions",
    tag = "authz",
    params(CheckQuery),
    responses(
        (status = 200, body = CheckResponse),
        (status = 400, description = "Authz not enabled",           body = crate::error::ErrorResponse),
        (status = 401, description = "Unauthorized",                body = crate::error::ErrorResponse),
        (status = 422, description = "Unknown resource/permission", body = crate::error::ErrorResponse),
    )
)]
pub async fn check_permission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<CheckQuery>,
) -> Result<Json<CheckResponse>, AuthError> {
    let schema_guard = state.authz_schema.read().await;
    let schema = schema_guard_to_compiled(&schema_guard)?;

    if let Some(explicit_user) = params.user {
        let or_chain = resolve_or_chain(schema, &params.resource_type, &params.permission, false)?;
        let cache_key = CheckKey {
            subject_id: Arc::from(explicit_user.as_str()),
            resource_type: Arc::from(params.resource_type.as_str()),
            resource_id: Arc::from(params.resource_id.as_str()),
            permission: Arc::from(params.permission.as_str()),
        };
        if let Some(allowed) = state.authz_cache.get_check(&cache_key) {
            return Ok(Json(CheckResponse { allowed }));
        }
        let allowed =
            engine::check_standalone(&state.pool, &explicit_user, &params.resource_id, &or_chain)
                .await?;
        state.authz_cache.insert_check(cache_key, allowed);
        return Ok(Json(CheckResponse { allowed }));
    }

    // Hot path: session cache → check cache → DB (one round-trip on miss).
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_owned())
        .ok_or(AuthError::Unauthorized)?;

    let parsed = tokens::parse(&bearer).ok_or(AuthError::Unauthorized)?;
    let or_chain = resolve_or_chain(schema, &params.resource_type, &params.permission, true)?;

    // Try session cache first; if hit, can also try check cache (0 DB calls).
    if let Some(subject_id) = state.authz_cache.get_session(parsed.id) {
        let cache_key = CheckKey {
            subject_id: subject_id.clone(),
            resource_type: Arc::from(params.resource_type.as_str()),
            resource_id: Arc::from(params.resource_id.as_str()),
            permission: Arc::from(params.permission.as_str()),
        };
        if let Some(allowed) = state.authz_cache.get_check(&cache_key) {
            return Ok(Json(CheckResponse { allowed }));
        }
        // Session cached but check missed — standalone check (1 DB call).
        let standalone_chain =
            resolve_or_chain(schema, &params.resource_type, &params.permission, false)?;
        let allowed = engine::check_standalone(
            &state.pool,
            &subject_id,
            &params.resource_id,
            &standalone_chain,
        )
        .await?;
        state.authz_cache.insert_check(cache_key, allowed);
        return Ok(Json(CheckResponse { allowed }));
    }

    // Full miss: bundled session-validate + authz check in one DB round-trip.
    let idle_timeout = state.app_config.read().await.session_idle_timeout_seconds;
    let (subject_id, allowed) = engine::check_with_session(
        &state.pool,
        parsed.id,
        &parsed.secret_hash,
        &params.resource_id,
        &or_chain,
        idle_timeout,
    )
    .await?
    .ok_or(AuthError::TokenInvalid)?;

    let subject_id: Arc<str> = Arc::from(subject_id.as_str());
    state
        .authz_cache
        .insert_session(parsed.id, subject_id.clone());
    state.authz_cache.insert_check(
        CheckKey {
            subject_id,
            resource_type: Arc::from(params.resource_type.as_str()),
            resource_id: Arc::from(params.resource_id.as_str()),
            permission: Arc::from(params.permission.as_str()),
        },
        allowed,
    );

    Ok(Json(CheckResponse { allowed }))
}

/// Check multiple permissions in a single round-trip. All checks in the request share
/// the same session (Bearer token) unless `user` is set per-check for explicit subjects.
///
/// Checks with the same (subject, resource_type, permission) are batched into one SQL
/// UNNEST call, giving 7x better throughput vs equivalent sequential single checks.
/// Results are returned in the same order as the input.
#[utoipa::path(
    post,
    path = "/v1/authz/decisions",
    tag = "authz",
    request_body = BatchDecisionRequest,
    responses(
        (status = 200, body = BatchDecisionResponse),
        (status = 400, description = "Authz not enabled",           body = crate::error::ErrorResponse),
        (status = 401, description = "Unauthorized",                body = crate::error::ErrorResponse),
        (status = 422, description = "Unknown resource/permission", body = crate::error::ErrorResponse),
    )
)]
pub async fn batch_check_permissions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BatchDecisionRequest>,
) -> Result<Json<BatchDecisionResponse>, AuthError> {
    if req.checks.is_empty() {
        return Ok(Json(BatchDecisionResponse { results: vec![] }));
    }

    let schema_guard = state.authz_schema.read().await;
    let schema = schema_guard_to_compiled(&schema_guard)?;

    // Resolve session subject lazily — only if at least one check omits explicit user.
    let session_subject: Option<Arc<str>> = if req.checks.iter().any(|c| c.user.is_none()) {
        let bearer = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_owned())
            .ok_or(AuthError::Unauthorized)?;
        let parsed = tokens::parse(&bearer).ok_or(AuthError::Unauthorized)?;
        let idle_timeout = state.app_config.read().await.session_idle_timeout_seconds;
        let subject_id = if let Some(cached) = state.authz_cache.get_session(parsed.id) {
            cached
        } else {
            let resolved =
                engine::resolve_session(&state.pool, parsed.id, &parsed.secret_hash, idle_timeout)
                    .await?
                    .ok_or(AuthError::TokenInvalid)?;
            let arc: Arc<str> = Arc::from(resolved.as_str());
            state.authz_cache.insert_session(parsed.id, arc.clone());
            arc
        };
        Some(subject_id)
    } else {
        None
    };

    // Build groups: (subject_id, or_chain) → Vec<(original_index, object_id)>.
    // Checks sharing the same subject + permission + resource_type hit the same or_chain
    // and are batched into one UNNEST call.
    let mut results = vec![false; req.checks.len()];
    let mut groups: CheckGroup = HashMap::new();

    for (i, check) in req.checks.iter().enumerate() {
        let subject_id: Arc<str> = match &check.user {
            Some(u) => Arc::from(u.as_str()),
            None => session_subject
                .clone()
                .expect("invariant: session_subject set when user field is absent"),
        };
        let cache_key = CheckKey {
            subject_id: subject_id.clone(),
            resource_type: Arc::from(check.resource_type.as_str()),
            resource_id: Arc::from(check.resource_id.as_str()),
            permission: Arc::from(check.permission.as_str()),
        };
        if let Some(allowed) = state.authz_cache.get_check(&cache_key) {
            results[i] = allowed;
            continue;
        }
        let or_chain = resolve_batch_or_chain(schema, &check.resource_type, &check.permission)?;
        match groups.entry((subject_id, or_chain)) {
            Entry::Occupied(mut e) => e.get_mut().push((i, check.resource_id.clone())),
            Entry::Vacant(e) => {
                e.insert(vec![(i, check.resource_id.clone())]);
            }
        }
    }

    for ((subject_id, or_chain), items) in groups {
        let object_ids: Vec<String> = items.iter().map(|(_, oid)| oid.clone()).collect();
        let bools =
            engine::batch_check_standalone(&state.pool, &subject_id, &object_ids, &or_chain)
                .await?;
        for ((idx, oid), allowed) in items.iter().zip(bools) {
            results[*idx] = allowed;
            // Cache the result — we need the permission to build the key.
            let check = &req.checks[*idx];
            state.authz_cache.insert_check(
                CheckKey {
                    subject_id: subject_id.clone(),
                    resource_type: Arc::from(check.resource_type.as_str()),
                    resource_id: Arc::from(oid.as_str()),
                    permission: Arc::from(check.permission.as_str()),
                },
                allowed,
            );
        }
    }

    Ok(Json(BatchDecisionResponse { results }))
}

/// Check multiple permissions in a single request. When the parallel-batch pgrx extension
/// is loaded, single-hop checks are expanded into atomic (subject, relation, object_type,
/// object_id) tuples and evaluated in one BFS issuing D+1 SQL queries — independent of N.
/// Multi-hop permissions and deployments without the extension fall back to UNNEST grouping
/// (same path as POST /v1/authz/decisions).
#[utoipa::path(
    post,
    path = "/v1/authz/checks",
    tag = "authz",
    request_body = ChecksRequest,
    responses(
        (status = 200, body = ChecksResponse),
        (status = 400, description = "Authz not enabled",           body = crate::error::ErrorResponse),
        (status = 401, description = "Unauthorized",                body = crate::error::ErrorResponse),
        (status = 422, description = "Unknown resource/permission", body = crate::error::ErrorResponse),
    )
)]
pub async fn post_checks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ChecksRequest>,
) -> Result<Json<ChecksResponse>, AuthError> {
    if req.checks.is_empty() {
        return Ok(Json(ChecksResponse { results: vec![] }));
    }

    let schema_guard = state.authz_schema.read().await;
    let schema = schema_guard_to_compiled(&schema_guard)?;

    let session_subject: Option<Arc<str>> = if req.checks.iter().any(|c| c.user.is_none()) {
        let bearer = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_owned())
            .ok_or(AuthError::Unauthorized)?;
        let parsed = tokens::parse(&bearer).ok_or(AuthError::Unauthorized)?;
        let idle_timeout = state.app_config.read().await.session_idle_timeout_seconds;
        let subject_id = if let Some(cached) = state.authz_cache.get_session(parsed.id) {
            cached
        } else {
            let resolved =
                engine::resolve_session(&state.pool, parsed.id, &parsed.secret_hash, idle_timeout)
                    .await?
                    .ok_or(AuthError::TokenInvalid)?;
            let arc: Arc<str> = Arc::from(resolved.as_str());
            state.authz_cache.insert_session(parsed.id, arc.clone());
            arc
        };
        Some(subject_id)
    } else {
        None
    };

    let n = req.checks.len();
    let mut results = vec![false; n];

    // Atomic rows for SingleHop parallel batch.
    let mut parallel_rows: Vec<(String, String, String, String)> = Vec::new();
    let mut parallel_origin: Vec<usize> = Vec::new();
    // Subject per original index, kept for caching.
    let mut subjects: Vec<Option<Arc<str>>> = vec![None; n];
    // Tracks which indices are handled by the extension (SingleHop or MultiHop).
    let mut handled: Vec<bool> = vec![false; n];

    // MultiHop path batches: key encodes the shared path structure;
    // value is (relation_prefix, object_type_path, terminal_relations, items).
    let mut path_batches: PathBatch = HashMap::new();

    // Fallback for when the extension is not loaded.
    let mut fallback_groups: CheckGroup = HashMap::new();

    for (i, check) in req.checks.iter().enumerate() {
        let subject_id: Arc<str> = match &check.user {
            Some(u) => Arc::from(u.as_str()),
            None => session_subject
                .clone()
                .expect("invariant: session_subject set when user field is absent"),
        };
        subjects[i] = Some(subject_id.clone());

        let cache_key = CheckKey {
            subject_id: subject_id.clone(),
            resource_type: Arc::from(check.resource_type.as_str()),
            resource_id: Arc::from(check.resource_id.as_str()),
            permission: Arc::from(check.permission.as_str()),
        };
        if let Some(allowed) = state.authz_cache.get_check(&cache_key) {
            results[i] = allowed;
            continue;
        }

        let calls = schema
            .get_checks(&check.resource_type, &check.permission)
            .ok_or_else(|| {
                if schema.resource_exists(&check.resource_type) {
                    AuthError::AuthzUnknownPermission {
                        permission: check.permission.clone(),
                    }
                } else {
                    AuthError::AuthzUnknownResource {
                        resource_type: check.resource_type.clone(),
                    }
                }
            })?;

        if state.parallel_batch_available {
            for c in calls {
                match c {
                    AuthzCheckCall::SingleHop {
                        relations,
                        object_type,
                    } => {
                        for relation in relations {
                            parallel_rows.push((
                                subject_id.to_string(),
                                relation.to_string(),
                                object_type.to_string(),
                                check.resource_id.clone(),
                            ));
                            parallel_origin.push(i);
                            handled[i] = true;
                        }
                    }
                    AuthzCheckCall::MultiHop {
                        relation_prefix,
                        object_type_path,
                        terminal_relations,
                    } => {
                        // \x00/\x01 are safe delimiters: ValidIdent guarantees
                        // identifiers match [a-z][a-z0-9_]* and cannot contain them.
                        let key = format!(
                            "{}\x00{}\x00{}",
                            relation_prefix
                                .iter()
                                .map(|r| r.as_str())
                                .collect::<Vec<_>>()
                                .join("\x01"),
                            object_type_path
                                .iter()
                                .map(|r| r.as_str())
                                .collect::<Vec<_>>()
                                .join("\x01"),
                            terminal_relations
                                .iter()
                                .map(|r| r.as_str())
                                .collect::<Vec<_>>()
                                .join("\x01"),
                        );
                        path_batches
                            .entry(key)
                            .or_insert_with(|| {
                                (
                                    relation_prefix.iter().map(|r| r.to_string()).collect(),
                                    object_type_path.iter().map(|r| r.to_string()).collect(),
                                    terminal_relations.iter().map(|r| r.to_string()).collect(),
                                    Vec::new(),
                                )
                            })
                            .3
                            .push((i, subject_id.to_string(), check.resource_id.clone()));
                        handled[i] = true;
                    }
                }
            }
        } else {
            let or_chain = resolve_batch_or_chain(schema, &check.resource_type, &check.permission)?;
            match fallback_groups.entry((subject_id, or_chain)) {
                Entry::Occupied(mut e) => e.get_mut().push((i, check.resource_id.clone())),
                Entry::Vacant(e) => {
                    e.insert(vec![(i, check.resource_id.clone())]);
                }
            }
        }
    }

    // OR-aggregate results from SingleHop parallel batch and MultiHop path batches.
    let mut aggregated = vec![false; n];

    if !parallel_rows.is_empty() {
        let atomic_results = engine::parallel_batch_check(&state.pool, &parallel_rows).await?;
        for (k, allowed) in atomic_results.iter().enumerate() {
            if *allowed {
                aggregated[parallel_origin[k]] = true;
            }
        }
    }

    for (_, (rel_prefix, obj_type_path, term_rels, items)) in path_batches {
        let sids: Vec<String> = items.iter().map(|(_, s, _)| s.clone()).collect();
        let oids: Vec<String> = items.iter().map(|(_, _, o)| o.clone()).collect();
        let bools = engine::path_batch_check(
            &state.pool,
            &sids,
            &rel_prefix,
            &obj_type_path,
            &term_rels,
            &oids,
        )
        .await?;
        for ((idx, _, _), allowed) in items.iter().zip(bools) {
            if allowed {
                aggregated[*idx] = true;
            }
        }
    }

    for i in 0..n {
        if handled[i] {
            results[i] = aggregated[i];
            let check = &req.checks[i];
            let subject_id = subjects[i]
                .clone()
                .expect("invariant: subjects[i] populated for all handled[i] indices");
            state.authz_cache.insert_check(
                CheckKey {
                    subject_id,
                    resource_type: Arc::from(check.resource_type.as_str()),
                    resource_id: Arc::from(check.resource_id.as_str()),
                    permission: Arc::from(check.permission.as_str()),
                },
                aggregated[i],
            );
        }
    }

    for ((subject_id, or_chain), items) in fallback_groups {
        let object_ids: Vec<String> = items.iter().map(|(_, oid)| oid.clone()).collect();
        let bools =
            engine::batch_check_standalone(&state.pool, &subject_id, &object_ids, &or_chain)
                .await?;
        for ((idx, oid), allowed) in items.iter().zip(bools) {
            results[*idx] = allowed;
            let check = &req.checks[*idx];
            state.authz_cache.insert_check(
                CheckKey {
                    subject_id: subject_id.clone(),
                    resource_type: Arc::from(check.resource_type.as_str()),
                    resource_id: Arc::from(oid.as_str()),
                    permission: Arc::from(check.permission.as_str()),
                },
                allowed,
            );
        }
    }

    Ok(Json(ChecksResponse { results }))
}

/// Write a single relation tuple. Idempotent — duplicate writes are silently ignored.
#[utoipa::path(
    post,
    path = "/v1/authz/relations",
    tag = "authz",
    request_body = RelationRequest,
    responses(
        (status = 201, description = "Relation written"),
        (status = 400, description = "Authz not enabled", body = crate::error::ErrorResponse),
    )
)]
pub async fn write_relation(
    State(state): State<AppState>,
    Json(req): Json<RelationRequest>,
) -> Result<StatusCode, AuthError> {
    let object_type =
        validate_ident(&req.object.object_type).map_err(|e| AuthError::AuthzSchemaInvalid {
            message: e.to_string(),
        })?;
    {
        let g = state.authz_schema.read().await;
        schema_guard_to_compiled(&g)?;
    }
    engine::write_relation(
        &state.pool,
        &state.partition_cache,
        &object_type,
        &req.object.id,
        &req.relation,
        &req.subject.id,
        req.subject.subject_type.as_deref(),
        req.subject.relation.as_deref(),
    )
    .await?;
    state
        .authz_cache
        .invalidate_for_write(object_type.as_str(), &req.object.id, &req.subject.id);
    Ok(StatusCode::CREATED)
}

/// Delete a single relation tuple.
#[utoipa::path(
    delete,
    path = "/v1/authz/relations",
    tag = "authz",
    request_body = RelationRequest,
    responses(
        (status = 204, description = "Relation deleted"),
        (status = 400, description = "Authz not enabled", body = crate::error::ErrorResponse),
        (status = 404, description = "Relation not found", body = crate::error::ErrorResponse),
    )
)]
pub async fn delete_relation(
    State(state): State<AppState>,
    Json(req): Json<RelationRequest>,
) -> Result<StatusCode, AuthError> {
    validate_ident(&req.object.object_type).map_err(|e| AuthError::AuthzSchemaInvalid {
        message: e.to_string(),
    })?;
    {
        let g = state.authz_schema.read().await;
        schema_guard_to_compiled(&g)?;
    }
    let deleted = engine::delete_relation(
        &state.pool,
        &req.object.object_type,
        &req.object.id,
        &req.relation,
        &req.subject.id,
        req.subject.subject_type.as_deref(),
        req.subject.relation.as_deref(),
    )
    .await?;
    if deleted {
        state.authz_cache.invalidate_for_write(
            &req.object.object_type,
            &req.object.id,
            &req.subject.id,
        );
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AuthError::NotFound)
    }
}

/// Batch write and/or delete relation tuples in a single transaction.
#[utoipa::path(
    patch,
    path = "/v1/authz/relations",
    tag = "authz",
    request_body = BatchRequest,
    responses(
        (status = 200, body = BatchResponse),
        (status = 400, description = "Authz not enabled", body = crate::error::ErrorResponse),
    )
)]
pub async fn batch_relations(
    State(state): State<AppState>,
    Json(req): Json<BatchRequest>,
) -> Result<Json<BatchResponse>, AuthError> {
    for r in req.writes.iter().chain(req.deletes.iter()) {
        validate_ident(&r.object.object_type).map_err(|e| AuthError::AuthzSchemaInvalid {
            message: e.to_string(),
        })?;
    }
    {
        let g = state.authz_schema.read().await;
        schema_guard_to_compiled(&g)?;
    }
    let write_ops: Vec<_> = req.writes.into_iter().map(into_batch_op).collect();
    let delete_ops: Vec<_> = req.deletes.into_iter().map(into_batch_op).collect();
    for op in write_ops.iter().chain(delete_ops.iter()) {
        state.authz_cache.invalidate_for_write(
            op.object_type.as_str(),
            &op.object_id,
            &op.subject_id,
        );
    }
    let result =
        engine::batch_relations(&state.pool, &state.partition_cache, write_ops, delete_ops).await?;
    Ok(Json(BatchResponse {
        written: result.written,
        deleted: result.deleted,
    }))
}

/// Get the current authz schema. Returns null if authz is not enabled.
#[utoipa::path(
    get,
    path = "/v1/authz/schema",
    tag = "authz",
    responses(
        (status = 200, body = Option<AuthzSchema>),
    )
)]
pub async fn get_schema(
    State(state): State<AppState>,
) -> Result<Json<Option<AuthzSchema>>, AuthError> {
    let cfg = state.app_config.read().await;
    let schema = cfg
        .authz_schema
        .as_ref()
        .map(|v| serde_json::from_value::<AuthzSchema>(v.clone()))
        .transpose()
        .map_err(|e| AuthError::AuthzSchemaInvalid {
            message: e.to_string(),
        })?;
    Ok(Json(schema))
}

/// Replace the authz schema. Validates and compiles before persisting.
/// Setting schema to a valid document enables authz; this is the only way to enable it.
#[utoipa::path(
    put,
    path = "/v1/authz/schema",
    tag = "authz",
    request_body = AuthzSchema,
    responses(
        (status = 200, body = AuthzSchema),
        (status = 422, description = "Schema invalid", body = crate::error::ErrorResponse),
    )
)]
pub async fn put_schema(
    State(state): State<AppState>,
    Json(req): Json<AuthzSchema>,
) -> Result<Json<AuthzSchema>, AuthError> {
    let compiled = compile(&req).map_err(|e| AuthError::AuthzSchemaInvalid {
        message: e.to_string(),
    })?;

    let raw = serde_json::to_value(&req).map_err(|e| AuthError::internal(e.to_string()))?;

    sqlx::query!(
        "UPDATE auth.app_config SET authz_schema = $1 WHERE id = true",
        raw.clone() as serde_json::Value,
    )
    .execute(&state.pool)
    .await
    .map_err(AuthError::from)?;

    state.app_config.write().await.authz_schema = Some(raw);
    *state.authz_schema.write().await = Some(compiled);

    Ok(Json(req))
}

/// List all subjects with a given permission on a resource. Resolves through the
/// schema's role hierarchy to return every subject who can exercise the permission.
/// Only direct role assignments are expanded; access via parent hierarchy is not
/// included (use GET /v1/authz/objects from the subject's perspective for that).
#[utoipa::path(
    get,
    path = "/v1/authz/subjects",
    tag = "authz",
    security(("BearerAuth" = [])),
    params(SubjectsByPermissionQuery),
    responses(
        (status = 200, body = SubjectsResponse),
        (status = 400, description = "Authz not enabled",           body = crate::error::ErrorResponse),
        (status = 422, description = "Unknown resource/permission", body = crate::error::ErrorResponse),
    )
)]
pub async fn list_subjects(
    State(state): State<AppState>,
    Query(params): Query<SubjectsByPermissionQuery>,
) -> Result<Json<SubjectsResponse>, AuthError> {
    let schema_guard = state.authz_schema.read().await;
    let schema = schema_guard_to_compiled(&schema_guard)?;

    let checks = schema
        .get_checks(&params.resource_type, &params.permission)
        .ok_or_else(|| {
            if schema.resource_exists(&params.resource_type) {
                AuthError::AuthzUnknownPermission {
                    permission: params.permission.clone(),
                }
            } else {
                AuthError::AuthzUnknownResource {
                    resource_type: params.resource_type.clone(),
                }
            }
        })?;

    // Collect every direct relation that grants this permission via the role hierarchy.
    // MultiHop (parent resource) checks are not included — those require a different
    // query direction (use /v1/authz/objects from the subject side instead).
    let relations: Vec<String> = checks
        .iter()
        .filter_map(|c| {
            if let AuthzCheckCall::SingleHop { relations, .. } = c {
                Some(relations.iter().map(|r| r.to_string()))
            } else {
                None
            }
        })
        .flatten()
        .collect();

    let rows = engine::expand(
        &state.pool,
        &params.resource_type,
        &params.resource_id,
        &relations,
    )
    .await?;

    let subjects = rows
        .into_iter()
        .map(|r| Subject {
            id: r.subject_id,
            relation: r.relation,
        })
        .collect();

    Ok(Json(SubjectsResponse { subjects }))
}

/// List all subjects who hold the given relation on an object.
/// Resolves subject sets recursively. Admin-only — use GET /v1/authz/subjects
/// for the permission-scoped view available to authenticated users.
#[utoipa::path(
    get,
    path = "/v1/admin/authz/subjects",
    tag = "authz",
    params(SubjectsQuery),
    responses(
        (status = 200, body = SubjectsResponse),
        (status = 400, description = "Authz not enabled", body = crate::error::ErrorResponse),
    )
)]
pub async fn list_subjects_expand(
    State(state): State<AppState>,
    Query(params): Query<SubjectsQuery>,
) -> Result<Json<SubjectsResponse>, AuthError> {
    {
        let g = state.authz_schema.read().await;
        schema_guard_to_compiled(&g)?;
    }
    let rows = engine::expand(
        &state.pool,
        &params.object_type,
        &params.object_id,
        &[params.relation],
    )
    .await?;
    let subjects = rows
        .into_iter()
        .map(|r| Subject {
            id: r.subject_id,
            relation: r.relation,
        })
        .collect();
    Ok(Json(SubjectsResponse { subjects }))
}

/// List all objects of the given type that the current user (or an explicit user)
/// can access via the resolved roles for a permission. Includes both direct role
/// assignments and access granted via parent hierarchy.
#[utoipa::path(
    get,
    path = "/v1/authz/objects",
    tag = "authz",
    security(("BearerAuth" = [])),
    params(ObjectsQuery),
    responses(
        (status = 200, body = ObjectsResponse),
        (status = 400, description = "Authz not enabled",           body = crate::error::ErrorResponse),
        (status = 422, description = "Unknown resource/permission", body = crate::error::ErrorResponse),
    )
)]
pub async fn list_objects(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<AuthContext>,
    Query(params): Query<ObjectsQuery>,
) -> Result<Json<ObjectsResponse>, AuthError> {
    let schema_guard = state.authz_schema.read().await;
    let schema = schema_guard_to_compiled(&schema_guard)?;

    let subject_id = params.user.unwrap_or_else(|| ctx.user.id.to_string());
    let limit = pages::clamp_limit(params.limit);
    let cursor = pages::decode_cursor(params.after.as_deref());
    let cursor = cursor.as_deref();
    let fetch_limit = limit + 1;

    let checks = schema
        .get_checks(&params.resource_type, &params.permission)
        .ok_or_else(|| {
            if schema.resource_exists(&params.resource_type) {
                AuthError::AuthzUnknownPermission {
                    permission: params.permission.clone(),
                }
            } else {
                AuthError::AuthzUnknownResource {
                    resource_type: params.resource_type.clone(),
                }
            }
        })?;

    // Partition checks into single-hop direct relations and multi-hop parent paths.
    // Multi-hop groups by (parent_link_relation, parent_type) to batch roles together.
    let mut direct_relations: HashSet<String> = HashSet::new();
    let mut multi_hop: HashMap<(String, String), Vec<String>> = HashMap::new();
    for c in checks {
        match c {
            AuthzCheckCall::SingleHop { relations, .. } => {
                direct_relations.extend(relations.iter().map(|r| r.to_string()));
            }
            AuthzCheckCall::MultiHop {
                relation_prefix,
                object_type_path,
                terminal_relations,
            } => {
                multi_hop
                    .entry((
                        relation_prefix[0].to_string(),
                        object_type_path[1].to_string(),
                    ))
                    .or_default()
                    .extend(terminal_relations.iter().map(|r| r.to_string()));
            }
        }
    }

    let direct_relations: Vec<String> = direct_relations.into_iter().collect();
    let mut all_ids: HashSet<String> = HashSet::new();

    if !direct_relations.is_empty() {
        let ids = engine::enumerate_ids(
            &state.pool,
            &subject_id,
            &direct_relations,
            &params.resource_type,
            fetch_limit,
            cursor,
        )
        .await?;
        all_ids.extend(ids);
    }

    for ((parent_link_rel, parent_type), parent_roles) in &multi_hop {
        let ids = engine::enumerate_via_parent(
            &state.pool,
            &subject_id,
            &params.resource_type,
            parent_link_rel,
            parent_roles,
            parent_type,
            fetch_limit,
            cursor,
        )
        .await?;
        all_ids.extend(ids);
    }

    let mut object_ids: Vec<String> = all_ids.into_iter().collect();
    object_ids.sort_unstable();

    let has_more = object_ids.len() as i64 > limit;
    object_ids.truncate(limit as usize);
    let next_page = if has_more {
        object_ids.last().map(|id| pages::encode_cursor(id))
    } else {
        None
    };

    Ok(Json(ObjectsResponse {
        object_ids,
        has_more,
        next_page,
    }))
}

/// Explain why a permission check returned its result. Runs expand on all direct
/// role relations and reports which subjects appear, letting you trace a grant or
/// denial. Note: access granted purely via parent hierarchy is not reflected here.
#[utoipa::path(
    get,
    path = "/v1/authz/traces",
    tag = "authz",
    params(TraceQuery),
    responses(
        (status = 200, body = TraceResponse),
        (status = 400, description = "Authz not enabled",           body = crate::error::ErrorResponse),
        (status = 422, description = "Unknown resource/permission", body = crate::error::ErrorResponse),
    )
)]
pub async fn why_check(
    State(state): State<AppState>,
    Query(params): Query<TraceQuery>,
) -> Result<Json<TraceResponse>, AuthError> {
    let schema_guard = state.authz_schema.read().await;
    let schema = schema_guard_to_compiled(&schema_guard)?;

    let relations: Vec<String> = schema
        .get_checks(&params.resource_type, &params.permission)
        .ok_or_else(|| {
            if schema.resource_exists(&params.resource_type) {
                AuthError::AuthzUnknownPermission {
                    permission: params.permission.clone(),
                }
            } else {
                AuthError::AuthzUnknownResource {
                    resource_type: params.resource_type.clone(),
                }
            }
        })?
        .iter()
        .flat_map(|c| match c {
            AuthzCheckCall::SingleHop { relations, .. } => {
                relations.iter().map(|r| r.to_string()).collect::<Vec<_>>()
            }
            // Multi-hop hierarchy traversal can't be traced via expand; only direct
            // role assignments appear in the subject list.
            AuthzCheckCall::MultiHop { .. } => vec![],
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let rows = engine::expand(
        &state.pool,
        &params.resource_type,
        &params.resource_id,
        &relations,
    )
    .await?;

    let allowed = rows.iter().any(|r| r.subject_id == params.user);
    let subjects = rows
        .into_iter()
        .map(|r| Subject {
            id: r.subject_id,
            relation: r.relation,
        })
        .collect();

    Ok(Json(TraceResponse { allowed, subjects }))
}
