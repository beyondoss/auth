use crate::helpers::{signup, unique_email};

use super::*;

async fn post_checks(req: serde_json::Value) -> Vec<bool> {
    TestClient::new()
        .post("/v1/authz/checks", &req)
        .await
        .assert_status(200)
        .json::<BatchDecisionResponse>()
        .results
}

/// [x] checks_empty_returns_empty
#[tokio::test]
async fn checks_empty_returns_empty() {
    let _guard = with_schema().await;
    let res = post_checks(serde_json::json!({"checks": []})).await;
    assert!(res.is_empty());
}

/// [x] checks_all_allowed
#[tokio::test]
async fn checks_all_allowed() {
    let _guard = with_schema().await;
    let (doc1, doc2, user) = (uid(), uid(), uid());
    write_rel("document", &doc1, "owner", &user).await;
    write_rel("document", &doc2, "editor", &user).await;

    let req = serde_json::json!({"checks": [
        {"user": user, "permission": "read",  "resource_type": "document", "resource_id": doc1},
        {"user": user, "permission": "write", "resource_type": "document", "resource_id": doc2},
    ]});
    assert_eq!(post_checks(req).await, vec![true, true]);
}

/// [x] checks_all_denied
#[tokio::test]
async fn checks_all_denied() {
    let _guard = with_schema().await;
    let user = uid();
    let req = serde_json::json!({"checks": [
        {"user": user, "permission": "read",   "resource_type": "document", "resource_id": uid()},
        {"user": user, "permission": "write",  "resource_type": "document", "resource_id": uid()},
        {"user": user, "permission": "delete", "resource_type": "document", "resource_id": uid()},
    ]});
    assert_eq!(post_checks(req).await, vec![false, false, false]);
}

/// [x] checks_preserves_input_order
#[tokio::test]
async fn checks_preserves_input_order() {
    let _guard = with_schema().await;
    let (doc_owned, doc_none, user) = (uid(), uid(), uid());
    write_rel("document", &doc_owned, "viewer", &user).await;

    let req = serde_json::json!({"checks": [
        {"user": user, "permission": "read", "resource_type": "document", "resource_id": doc_owned},
        {"user": user, "permission": "read", "resource_type": "document", "resource_id": doc_none},
        {"user": user, "permission": "read", "resource_type": "document", "resource_id": doc_owned},
    ]});
    assert_eq!(post_checks(req).await, vec![true, false, true]);
}

/// [x] checks_role_inheritance
/// owner > editor > viewer — owner grants read (requires viewer-level)
#[tokio::test]
async fn checks_role_inheritance() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    write_rel("document", &doc, "owner", &user).await;

    let req = serde_json::json!({"checks": [
        {"user": user, "permission": "read",   "resource_type": "document", "resource_id": doc},
        {"user": user, "permission": "write",  "resource_type": "document", "resource_id": doc},
        {"user": user, "permission": "delete", "resource_type": "document", "resource_id": doc},
    ]});
    assert_eq!(post_checks(req).await, vec![true, true, true]);
}

/// [x] checks_via_subject_set
/// BFS traversal through subject-set chains works on the parallel path.
#[tokio::test]
async fn checks_via_subject_set() {
    let _guard = with_schema().await;
    let (doc, group, user) = (uid(), uid(), uid());
    write_set_rel("document", &doc, "editor", &group, "group", "member").await;
    write_rel("group", &group, "member", &user).await;

    let req = serde_json::json!({"checks": [
        {"user": user, "permission": "write", "resource_type": "document", "resource_id": doc},
    ]});
    assert_eq!(post_checks(req).await, vec![true]);
}

/// [x] checks_via_parent_hierarchy_falls_back_correctly
/// Permissions that require authz_check_path (MultiHop) fall back to the UNNEST path.
/// The result must still be correct.
#[tokio::test]
async fn checks_via_parent_hierarchy_falls_back_correctly() {
    let _guard = with_schema().await;
    let (doc, folder, user) = (uid(), uid(), uid());
    write_rel("document", &doc, "folder", &folder).await;
    write_rel("folder", &folder, "owner", &user).await;

    let req = serde_json::json!({"checks": [
        {"user": user, "permission": "delete", "resource_type": "document", "resource_id": doc},
    ]});
    // delete on document resolves to owner (SingleHop) OR authz_check_path(folder, owner) (MultiHop).
    // Falls back to batch_check_standalone for the whole check.
    assert_eq!(post_checks(req).await, vec![true]);
}

/// [x] checks_mixed_parallel_and_fallback
/// One check is SingleHop-only (parallel path), another involves MultiHop (fallback).
/// Both must resolve correctly and results must be in input order.
#[tokio::test]
async fn checks_mixed_parallel_and_fallback() {
    let _guard = with_schema().await;
    let (doc1, doc2, folder, user) = (uid(), uid(), uid(), uid());
    write_rel("document", &doc1, "viewer", &user).await;
    write_rel("document", &doc2, "folder", &folder).await;
    write_rel("folder", &folder, "owner", &user).await;

    let req = serde_json::json!({"checks": [
        // SingleHop: read on document with viewer role
        {"user": user, "permission": "read",   "resource_type": "document", "resource_id": doc1},
        // MultiHop: delete on document via folder hierarchy
        {"user": user, "permission": "delete", "resource_type": "document", "resource_id": doc2},
        // SingleHop: should be denied (no relation)
        {"user": user, "permission": "write",  "resource_type": "document", "resource_id": uid()},
    ]});
    assert_eq!(post_checks(req).await, vec![true, true, false]);
}

/// [x] checks_session_bearer
#[tokio::test]
async fn checks_session_bearer() {
    let _guard = with_schema().await;
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let user_id = auth.user.id.to_string();
    let doc = uid();
    write_rel("document", &doc, "viewer", &user_id).await;

    let req = serde_json::json!({"checks": [
        {"permission": "read", "resource_type": "document", "resource_id": doc},
    ]});
    let res = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/authz/checks", &req)
        .await
        .assert_status(200)
        .json::<BatchDecisionResponse>();
    assert_eq!(res.results, vec![true]);
}

/// [x] checks_no_auth_with_session_check_returns_401
#[tokio::test]
async fn checks_no_auth_with_session_check_returns_401() {
    let _guard = with_schema().await;
    let req = serde_json::json!({"checks": [
        {"permission": "read", "resource_type": "document", "resource_id": uid()},
    ]});
    TestClient::new()
        .post("/v1/authz/checks", &req)
        .await
        .assert_status(401);
}

/// [x] checks_unknown_permission_returns_422
#[tokio::test]
async fn checks_unknown_permission_returns_422() {
    let _guard = with_schema().await;
    let req = serde_json::json!({"checks": [
        {"user": uid(), "permission": "fly", "resource_type": "document", "resource_id": uid()},
    ]});
    TestClient::new()
        .post("/v1/authz/checks", &req)
        .await
        .assert_status(422);
}

/// [x] checks_unknown_resource_type_returns_422
#[tokio::test]
async fn checks_unknown_resource_type_returns_422() {
    let _guard = with_schema().await;
    let req = serde_json::json!({"checks": [
        {"user": uid(), "permission": "read", "resource_type": "nonexistent", "resource_id": uid()},
    ]});
    TestClient::new()
        .post("/v1/authz/checks", &req)
        .await
        .assert_status(422);
}

/// [x] checks_three_level_hierarchy
/// The three-level schema generates 1 SingleHop + 2 MultiHops for `read` on
/// `document`, which the compiler collapses into `authz_check_multi()`. Verify
/// all three grant paths (direct, 1-hop, 2-hop) resolve correctly.
#[tokio::test]
async fn checks_three_level_hierarchy() {
    let _guard = with_three_level_schema().await;
    let (doc, folder, workspace) = (uid(), uid(), uid());
    let (direct_user, folder_user, workspace_user) = (uid(), uid(), uid());

    // Link the hierarchy: document → folder → workspace.
    write_rel("document", &doc, "folder", &folder).await;
    write_rel("folder", &folder, "workspace", &workspace).await;

    write_rel("document", &doc, "viewer", &direct_user).await;
    write_rel("folder", &folder, "viewer", &folder_user).await;
    write_rel("workspace", &workspace, "viewer", &workspace_user).await;

    let req = serde_json::json!({"checks": [
        // SingleHop — direct viewer on document.
        {"user": direct_user,    "permission": "read", "resource_type": "document", "resource_id": doc},
        // 1-hop MultiHop — viewer via folder.
        {"user": folder_user,    "permission": "read", "resource_type": "document", "resource_id": doc},
        // 2-hop MultiHop — viewer via workspace; exercises authz_check_multi.
        {"user": workspace_user, "permission": "read", "resource_type": "document", "resource_id": doc},
        // No relation — must be denied.
        {"user": uid(),          "permission": "read", "resource_type": "document", "resource_id": doc},
    ]});
    assert_eq!(post_checks(req).await, vec![true, true, true, false]);
}

// ── Local helpers ──────────────────────────────────────────────────────────────

async fn write_rel(obj_type: &str, obj_id: &str, relation: &str, subject_id: &str) {
    TestClient::new()
        .admin()
        .post("/v1/authz/relations", &direct_rel(obj_type, obj_id, relation, subject_id))
        .await
        .assert_status(201);
}

async fn write_set_rel(
    obj_type: &str, obj_id: &str, relation: &str,
    subject_id: &str, subject_type: &str, subject_relation: &str,
) {
    TestClient::new()
        .admin()
        .post(
            "/v1/authz/relations",
            &set_rel(obj_type, obj_id, relation, subject_id, subject_type, subject_relation),
        )
        .await
        .assert_status(201);
}
