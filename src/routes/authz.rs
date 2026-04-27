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
        schema::{AuthzCheckCall, AuthzSchema, CompiledSchema, compile},
    },
    error::AuthError,
    http::AppState,
    sessions::SessionContext,
    tokens,
};

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize, IntoParams)]
pub struct CheckQuery {
    /// Explicit subject to check as. Defaults to the current session user.
    pub user: Option<String>,
    pub permission: String,
    pub resource_type: String,
    pub resource_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CheckResponse {
    pub allowed: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RelationRequest {
    pub object: RelationObject,
    pub relation: String,
    pub subject: RelationSubject,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RelationObject {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RelationSubject {
    pub id: String,
    #[serde(rename = "type", default)]
    pub subject_type: Option<String>,
    #[serde(default)]
    pub relation: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BatchRequest {
    #[serde(default)]
    pub writes: Vec<RelationRequest>,
    #[serde(default)]
    pub deletes: Vec<RelationRequest>,
}

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

#[derive(Debug, Deserialize, IntoParams)]
pub struct ExpandQuery {
    pub object_type: String,
    pub object_id: String,
    pub relation: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExpandResponse {
    pub subjects: Vec<ExpandSubject>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExpandSubject {
    pub id: String,
    pub relation: String,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct LookupQuery {
    pub user: Option<String>,
    pub permission: String,
    pub resource_type: String,
    #[serde(default = "default_limit")]
    pub limit: i64,
    pub cursor: Option<String>,
}

fn default_limit() -> i64 {
    100
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LookupResponse {
    pub object_ids: Vec<String>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct TraceQuery {
    pub user: String,
    pub permission: String,
    pub resource_type: String,
    pub resource_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TraceResponse {
    pub allowed: bool,
    pub subjects: Vec<ExpandSubject>,
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
        object_type: r.object.object_type,
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
    let (subject_id, allowed) = engine::check_with_session(
        &state.pool,
        parsed.id,
        &parsed.secret_hash,
        &params.resource_id,
        &or_chain,
    )
    .await?
    .ok_or(AuthError::Unauthorized)?;

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
        let subject_id = if let Some(cached) = state.authz_cache.get_session(parsed.id) {
            cached
        } else {
            let resolved = engine::resolve_session(&state.pool, parsed.id, &parsed.secret_hash)
                .await?
                .ok_or(AuthError::Unauthorized)?;
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
    let mut groups: HashMap<(Arc<str>, String), Vec<(usize, String)>> = HashMap::new();

    for (i, check) in req.checks.iter().enumerate() {
        let subject_id: Arc<str> = match &check.user {
            Some(u) => Arc::from(u.as_str()),
            None => session_subject.clone().unwrap(),
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
    let _ = {
        let g = state.authz_schema.read().await;
        schema_guard_to_compiled(&g)?;
    };
    engine::write_relation(
        &state.pool,
        &req.object.object_type,
        &req.object.id,
        &req.relation,
        &req.subject.id,
        req.subject.subject_type.as_deref(),
        req.subject.relation.as_deref(),
    )
    .await?;
    state.authz_cache.invalidate_for_write(
        &req.object.object_type,
        &req.object.id,
        &req.subject.id,
    );
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
    let _ = {
        let g = state.authz_schema.read().await;
        schema_guard_to_compiled(&g)?;
    };
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
    let _ = {
        let g = state.authz_schema.read().await;
        schema_guard_to_compiled(&g)?;
    };
    let write_ops: Vec<_> = req.writes.into_iter().map(into_batch_op).collect();
    let delete_ops: Vec<_> = req.deletes.into_iter().map(into_batch_op).collect();
    for op in write_ops.iter().chain(delete_ops.iter()) {
        state
            .authz_cache
            .invalidate_for_write(&op.object_type, &op.object_id, &op.subject_id);
    }
    let result = engine::batch_relations(&state.pool, write_ops, delete_ops).await?;
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

    let resource_names: Vec<&str> = req.resources.iter().map(|r| r.name.as_str()).collect();
    engine::ensure_partitions(&state.pool, &resource_names).await?;

    state.app_config.write().await.authz_schema = Some(raw);
    *state.authz_schema.write().await = Some(compiled);

    Ok(Json(req))
}

/// Expand a relation: return all subjects who hold the given relation on the object.
/// Resolves subject sets recursively.
#[utoipa::path(
    get,
    path = "/v1/authz/expansions",
    tag = "authz",
    params(ExpandQuery),
    responses(
        (status = 200, body = ExpandResponse),
        (status = 400, description = "Authz not enabled", body = crate::error::ErrorResponse),
    )
)]
pub async fn expand_relation(
    State(state): State<AppState>,
    Query(params): Query<ExpandQuery>,
) -> Result<Json<ExpandResponse>, AuthError> {
    let _ = {
        let g = state.authz_schema.read().await;
        schema_guard_to_compiled(&g)?;
    };
    let rows = engine::expand(
        &state.pool,
        &params.object_type,
        &params.object_id,
        &[params.relation],
    )
    .await?;
    let subjects = rows
        .into_iter()
        .map(|r| ExpandSubject {
            id: r.subject_id,
            relation: r.relation,
        })
        .collect();
    Ok(Json(ExpandResponse { subjects }))
}

/// List all objects of the given type that the current user (or an explicit user)
/// can access via the resolved roles for a permission. Includes both direct role
/// assignments and access granted via parent hierarchy.
#[utoipa::path(
    get,
    path = "/v1/authz/lookups",
    tag = "authz",
    security(("BearerAuth" = [])),
    params(LookupQuery),
    responses(
        (status = 200, body = LookupResponse),
        (status = 400, description = "Authz not enabled",           body = crate::error::ErrorResponse),
        (status = 422, description = "Unknown resource/permission", body = crate::error::ErrorResponse),
    )
)]
pub async fn lookup_objects(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<SessionContext>,
    Query(params): Query<LookupQuery>,
) -> Result<Json<LookupResponse>, AuthError> {
    let schema_guard = state.authz_schema.read().await;
    let schema = schema_guard_to_compiled(&schema_guard)?;

    let subject_id = params.user.unwrap_or_else(|| ctx.user.id.to_string());
    let limit = params.limit.clamp(1, 1000);
    let cursor = params.cursor.as_deref();
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
                direct_relations.extend(relations.iter().cloned());
            }
            AuthzCheckCall::MultiHop {
                relation_path,
                object_type_path,
            } => {
                multi_hop
                    .entry((relation_path[0].clone(), object_type_path[1].clone()))
                    .or_default()
                    .push(relation_path[1].clone());
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
    let next_cursor = if has_more {
        object_ids.last().cloned()
    } else {
        None
    };

    Ok(Json(LookupResponse {
        object_ids,
        next_cursor,
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
            AuthzCheckCall::SingleHop { relations, .. } => relations.clone(),
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
        .map(|r| ExpandSubject {
            id: r.subject_id,
            relation: r.relation,
        })
        .collect();

    Ok(Json(TraceResponse { allowed, subjects }))
}
