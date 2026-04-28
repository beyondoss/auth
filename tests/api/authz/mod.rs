//! Integration tests for the authorization (Zanzibar ReBAC) endpoints.
//!
//! ## Test matrix
//!
//! Use this as a checklist. Every `[ ]` must map to a `#[tokio::test]` somewhere
//! in this module before the authz test suite is considered complete.
//!
//! ### schema.rs — PUT/GET /v1/authz/schema
//! [x] schema_put_valid_round_trips
//! [x] schema_put_role_hierarchy_compiles_transitively  (owner > editor > viewer → owner grants viewer perms)
//! [x] schema_put_invalid_identifier_rejected           (uppercase / hyphen / leading digit)
//! [x] schema_put_wrong_version_rejected                (version != 1)
//! [x] schema_put_unknown_parent_resource_rejected
//! [x] schema_put_unknown_role_in_role_hierarchy_rejected
//! [x] schema_put_unknown_role_in_permissions_rejected
//!
//! ### relations.rs — POST / DELETE / PATCH /v1/authz/relations
//!
//! Write (POST):
//! [x] write_direct_relation_returns_201
//! [x] write_subject_set_relation_returns_201
//! [x] write_direct_relation_is_idempotent              (duplicate → 201, DB row count = 1)
//! [x] write_subject_set_relation_is_idempotent
//! [x] write_creates_partition_jit                      (new object_type → partition exists in DB)
//!
//! Delete (DELETE with JSON body):
//! [x] delete_existing_direct_relation_returns_204
//! [x] delete_existing_subject_set_relation_returns_204
//! [x] delete_nonexistent_returns_404
//! [x] delete_direct_body_does_not_match_subject_set_row   (NULL IS NOT DISTINCT FROM semantics)
//! [x] delete_subject_set_body_does_not_match_direct_row
//! [x] delete_second_call_returns_404                   (idempotency: already gone)
//!
//! Batch (PATCH):
//! [x] batch_writes_only_returns_correct_count
//! [x] batch_deletes_only_returns_correct_count
//! [x] batch_mixed_write_and_delete_atomic
//! [x] batch_empty_returns_zero_counts
//! [x] batch_idempotent_write_counts_zero               (ON CONFLICT → written = 0)
//! [x] batch_delete_nonexistent_counts_zero             (missing row → deleted = 0, not an error)
//!
//! ### decisions.rs — GET /v1/authz/decisions (single check)
//!
//! Direct grant — role × permission matrix:
//! [x] check_owner_can_read
//! [x] check_owner_can_write
//! [x] check_owner_can_delete
//! [x] check_editor_can_read
//! [x] check_editor_can_write
//! [x] check_editor_cannot_delete
//! [x] check_viewer_can_read
//! [x] check_viewer_cannot_write
//! [x] check_viewer_cannot_delete
//!
//! Negative / boundary:
//! [x] check_no_relation_denied
//! [x] check_wrong_object_denied                        (relation exists on a different object)
//! [x] check_wrong_subject_denied                       (relation exists for a different user)
//!
//! Subject-set (BFS) expansion:
//! [x] check_via_subject_set_one_hop                    (user ∈ group → group has role → allowed)
//! [x] check_via_subject_set_two_hops                   (user ∈ team ∈ group → group has role → allowed)
//! [x] check_via_subject_set_three_hops                 (user ∈ team ∈ group ∈ department → allowed)
//! [x] check_bfs_terminates_with_cycle                  (cyclic group membership; BFS must not loop)
//!
//! Multi-hop parent hierarchy:
//! [x] check_via_parent_hierarchy_direct_role           (doc → folder; user owns folder → allowed)
//! [x] check_via_parent_hierarchy_subject_set_on_parent_not_expanded
//!         (authz_check_path is direct-entity only; subject-set on parent → denied; expected behaviour)
//! [x] check_via_parent_hierarchy_no_parent_link_denied
//! [x] check_via_two_level_parent_hierarchy             (doc → folder → workspace; user owns workspace → allowed)
//! [x] check_via_two_level_parent_hierarchy_missing_link_denied
//!
//! Auth / error paths:
//! [x] check_with_explicit_user_param                   (standalone path, no session needed)
//! [x] check_with_session_bearer                        (bundled session+check path)
//! [x] check_no_auth_no_user_param_returns_401
//! [x] check_unknown_resource_type_returns_422
//! [x] check_unknown_permission_returns_422
//!
//! ### decisions.rs — POST /v1/authz/decisions (batch check)
//! [x] batch_check_empty_returns_empty_results
//! [x] batch_check_all_allowed
//! [x] batch_check_all_denied
//! [x] batch_check_mixed_preserves_input_order
//! [x] batch_check_unnest_grouping_correct_order        (multiple checks same subject+permission → UNNEST path)
//! [x] batch_check_all_use_session_subject
//! [x] batch_check_all_use_explicit_user
//! [x] batch_check_mixed_session_and_explicit_user
//! [x] batch_check_no_auth_with_session_check_returns_401
//! [x] batch_check_unknown_permission_returns_422
//!
//! ### subjects.rs — GET /v1/authz/subjects
//! [x] expand_object_with_direct_subjects
//! [x] expand_object_with_no_relations_returns_empty
//! [x] expand_via_subject_set_one_hop
//! [x] expand_via_subject_set_two_hops
//! [x] expand_only_requested_relation_returned          (other relations on same object not included)
//! [x] expand_cycle_terminates_safely
//!
//! ### objects.rs — GET /v1/authz/objects
//! [x] lookup_direct_grants_returned
//! [x] lookup_no_grants_returns_empty
//! [x] lookup_via_subject_set
//! [x] lookup_via_parent_hierarchy
//! [x] lookup_role_hierarchy_expands                    (owner role appears in viewer-permission lookup)
//! [x] lookup_pagination_limit_and_cursor
//! [x] lookup_cursor_page_two
//! [x] lookup_via_subject_set_and_parent_hierarchy  (subject-set on parent IS expanded by lookup, unlike check)
//! [x] lookup_unknown_permission_returns_422
//! [x] lookup_unknown_resource_type_returns_422
//!
//! ### traces.rs — GET /v1/authz/traces
//! [x] trace_allowed_subject_in_list_and_allowed_true
//! [x] trace_denied_subject_absent_and_allowed_false
//! [x] trace_subject_set_expanded_in_subjects
//! [x] trace_multi_hop_hierarchy_not_reflected          (known limitation; allowed via check but not in subjects)
//! [x] trace_unknown_permission_returns_422
//!
//! ### checks.rs — POST /v1/authz/checks (parallel BFS batch)
//! [x] checks_empty_returns_empty
//! [x] checks_all_allowed
//! [x] checks_all_denied
//! [x] checks_preserves_input_order
//! [x] checks_role_inheritance
//! [x] checks_via_subject_set
//! [x] checks_via_parent_hierarchy_falls_back_correctly
//! [x] checks_mixed_parallel_and_fallback
//! [x] checks_session_bearer
//! [x] checks_no_auth_with_session_check_returns_401
//! [x] checks_unknown_permission_returns_422
//! [x] checks_unknown_resource_type_returns_422
//!
//! ### decisions.rs — cache invalidation
//! [x] cache_check_false_then_write_then_check_true
//! [x] cache_check_true_then_delete_then_check_false

pub mod checks;
pub mod decisions;
pub mod objects;
pub mod relations;
pub mod schema;
pub mod subjects;
pub mod traces;

// ── Shared fixtures ────────────────────────────────────────────────────────────

use crate::helpers::TestClient;
pub use crate::helpers::exclusive;

/// Unique string ID for test isolation — use for every object/subject ID so
/// parallel tests never collide on relation tuple data.
pub fn uid() -> String {
    uuid::Uuid::now_v7().simple().to_string()
}

/// The standard document/folder schema used across all authz tests.
///
/// Roles: owner > editor > viewer (transitive)
/// Permissions:
///   document: read=[viewer], write=[editor], delete=[owner]
///   folder:   read=[viewer], write=[editor]
/// Hierarchy: document → folder (parent_relation="folder", parent_resource="folder")
pub fn doc_folder_schema() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "resources": [
            {
                "name": "document",
                "roles": ["owner", "editor", "viewer"],
                "role_hierarchy": [
                    {"superior": "owner",  "inferior": "editor"},
                    {"superior": "editor", "inferior": "viewer"}
                ],
                "permissions": {
                    "read":   ["viewer"],
                    "write":  ["editor"],
                    "delete": ["owner"]
                },
                "hierarchy": {
                    "parent_relation": "folder",
                    "parent_resource": "folder"
                }
            },
            {
                "name": "folder",
                "roles": ["owner", "editor", "viewer"],
                "role_hierarchy": [
                    {"superior": "owner",  "inferior": "editor"},
                    {"superior": "editor", "inferior": "viewer"}
                ],
                "permissions": {
                    "read":  ["viewer"],
                    "write": ["editor"]
                }
            }
        ]
    })
}

/// Acquire the exclusive lock and set the standard schema.
/// Hold the returned guard for the duration of the test.
pub async fn with_schema() -> tokio::sync::MutexGuard<'static, ()> {
    let guard = crate::helpers::exclusive().await;
    TestClient::new()
        .admin()
        .put("/v1/authz/schema", &doc_folder_schema())
        .await
        .assert_status(200);
    guard
}

/// Three-level hierarchy schema: document → folder → workspace.
///
/// Same roles and permissions as `doc_folder_schema`, but folder now has a
/// parent hierarchy pointing at workspace. Used to verify that the schema
/// compiler generates path checks for each ancestor level, not just one hop.
pub fn three_level_schema() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "resources": [
            {
                "name": "document",
                "roles": ["owner", "editor", "viewer"],
                "role_hierarchy": [
                    {"superior": "owner",  "inferior": "editor"},
                    {"superior": "editor", "inferior": "viewer"}
                ],
                "permissions": {
                    "read":   ["viewer"],
                    "write":  ["editor"],
                    "delete": ["owner"]
                },
                "hierarchy": {
                    "parent_relation": "folder",
                    "parent_resource": "folder"
                }
            },
            {
                "name": "folder",
                "roles": ["owner", "editor", "viewer"],
                "role_hierarchy": [
                    {"superior": "owner",  "inferior": "editor"},
                    {"superior": "editor", "inferior": "viewer"}
                ],
                "permissions": {
                    "read":  ["viewer"],
                    "write": ["editor"]
                },
                "hierarchy": {
                    "parent_relation": "workspace",
                    "parent_resource": "workspace"
                }
            },
            {
                "name": "workspace",
                "roles": ["owner", "editor", "viewer"],
                "role_hierarchy": [
                    {"superior": "owner",  "inferior": "editor"},
                    {"superior": "editor", "inferior": "viewer"}
                ],
                "permissions": {
                    "read":  ["viewer"],
                    "write": ["editor"]
                }
            }
        ]
    })
}

/// Acquire the exclusive lock and install the three-level hierarchy schema.
/// Hold the returned guard for the duration of the test.
pub async fn with_three_level_schema() -> tokio::sync::MutexGuard<'static, ()> {
    let guard = crate::helpers::exclusive().await;
    TestClient::new()
        .admin()
        .put("/v1/authz/schema", &three_level_schema())
        .await
        .assert_status(200);
    guard
}

/// Build a direct-subject relation request body.
pub fn direct_rel(
    obj_type: &str,
    obj_id: &str,
    relation: &str,
    subject_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "object":   {"type": obj_type, "id": obj_id},
        "relation": relation,
        "subject":  {"id": subject_id}
    })
}

/// Build a subject-set relation request body.
pub fn set_rel(
    obj_type: &str,
    obj_id: &str,
    relation: &str,
    subject_id: &str,
    subject_type: &str,
    subject_relation: &str,
) -> serde_json::Value {
    serde_json::json!({
        "object":   {"type": obj_type, "id": obj_id},
        "relation": relation,
        "subject":  {
            "id":       subject_id,
            "type":     subject_type,
            "relation": subject_relation
        }
    })
}

// ── Shared response types ──────────────────────────────────────────────────────
// Authz response types are not re-exported from lib.rs, so we define minimal
// local structs for deserialization in tests.

#[derive(serde::Deserialize, Debug)]
pub struct CheckResponse {
    pub allowed: bool,
}

#[derive(serde::Deserialize, Debug)]
pub struct BatchDecisionResponse {
    pub results: Vec<bool>,
}

#[derive(serde::Deserialize, Debug)]
pub struct SubjectsResponse {
    pub subjects: Vec<Subject>,
}

#[derive(serde::Deserialize, Debug)]
pub struct Subject {
    pub id: String,
    pub relation: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct ObjectsResponse {
    pub object_ids: Vec<String>,
    pub next_cursor: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
pub struct TraceResponse {
    pub allowed: bool,
    pub subjects: Vec<Subject>,
}

#[derive(serde::Deserialize, Debug)]
pub struct BatchRelationResponse {
    pub written: u64,
    pub deleted: u64,
}
