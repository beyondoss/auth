use crate::helpers::{TestClient, signup, unique_email};

use super::*;

// ── Local helpers ──────────────────────────────────────────────────────────────

async fn write(obj_type: &str, obj_id: &str, relation: &str, subject_id: &str) {
    TestClient::new()
        .admin()
        .post(
            "/v1/authz/relations",
            &direct_rel(obj_type, obj_id, relation, subject_id),
        )
        .await
        .assert_status(201);
}

async fn write_set(
    obj_type: &str,
    obj_id: &str,
    relation: &str,
    subject_id: &str,
    subject_type: &str,
    subject_relation: &str,
) {
    TestClient::new()
        .admin()
        .post(
            "/v1/authz/relations",
            &set_rel(
                obj_type,
                obj_id,
                relation,
                subject_id,
                subject_type,
                subject_relation,
            ),
        )
        .await
        .assert_status(201);
}

/// GET /v1/authz/decisions with an explicit `user=` param (standalone check path).
async fn check(user: &str, permission: &str, resource_type: &str, resource_id: &str) -> bool {
    TestClient::new()
        .get(&format!(
            "/v1/authz/decisions?user={user}&permission={permission}&resource_type={resource_type}&resource_id={resource_id}"
        ))
        .await
        .assert_status(200)
        .json::<CheckResponse>()
        .allowed
}

// ── Direct grant: role × permission matrix ─────────────────────────────────────
//
// Schema permissions:
//   read   = [viewer]  → granted to viewer, editor (inherits), owner (inherits)
//   write  = [editor]  → granted to editor, owner (inherits); NOT viewer
//   delete = [owner]   → granted to owner only

/// [x] check_owner_can_read
#[tokio::test]
async fn check_owner_can_read() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    write("document", &doc, "owner", &user).await;
    assert!(check(&user, "read", "document", &doc).await);
}

/// [x] check_owner_can_write
#[tokio::test]
async fn check_owner_can_write() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    write("document", &doc, "owner", &user).await;
    assert!(check(&user, "write", "document", &doc).await);
}

/// [x] check_owner_can_delete
#[tokio::test]
async fn check_owner_can_delete() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    write("document", &doc, "owner", &user).await;
    assert!(check(&user, "delete", "document", &doc).await);
}

/// [x] check_editor_can_read
#[tokio::test]
async fn check_editor_can_read() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    write("document", &doc, "editor", &user).await;
    assert!(check(&user, "read", "document", &doc).await);
}

/// [x] check_editor_can_write
#[tokio::test]
async fn check_editor_can_write() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    write("document", &doc, "editor", &user).await;
    assert!(check(&user, "write", "document", &doc).await);
}

/// [x] check_editor_cannot_delete
#[tokio::test]
async fn check_editor_cannot_delete() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    write("document", &doc, "editor", &user).await;
    assert!(!check(&user, "delete", "document", &doc).await);
}

/// [x] check_viewer_can_read
#[tokio::test]
async fn check_viewer_can_read() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    write("document", &doc, "viewer", &user).await;
    assert!(check(&user, "read", "document", &doc).await);
}

/// [x] check_viewer_cannot_write
#[tokio::test]
async fn check_viewer_cannot_write() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    write("document", &doc, "viewer", &user).await;
    assert!(!check(&user, "write", "document", &doc).await);
}

/// [x] check_viewer_cannot_delete
#[tokio::test]
async fn check_viewer_cannot_delete() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    write("document", &doc, "viewer", &user).await;
    assert!(!check(&user, "delete", "document", &doc).await);
}

// ── Negative / boundary ────────────────────────────────────────────────────────

/// [x] check_no_relation_denied
#[tokio::test]
async fn check_no_relation_denied() {
    let _guard = with_schema().await;
    assert!(!check(&uid(), "read", "document", &uid()).await);
}

/// [x] check_wrong_object_denied
/// Relation exists on doc_a; check is against doc_b → denied.
#[tokio::test]
async fn check_wrong_object_denied() {
    let _guard = with_schema().await;
    let (doc_a, doc_b, user) = (uid(), uid(), uid());
    write("document", &doc_a, "owner", &user).await;
    assert!(!check(&user, "read", "document", &doc_b).await);
}

/// [x] check_wrong_subject_denied
/// Relation exists for user_a; check is for user_b → denied.
#[tokio::test]
async fn check_wrong_subject_denied() {
    let _guard = with_schema().await;
    let (doc, user_a, user_b) = (uid(), uid(), uid());
    write("document", &doc, "owner", &user_a).await;
    assert!(!check(&user_b, "read", "document", &doc).await);
}

// ── Subject-set (BFS) expansion ────────────────────────────────────────────────

/// [x] check_via_subject_set_one_hop
/// user ∈ group → group has editor on doc → user can write (editor grants write)
#[tokio::test]
async fn check_via_subject_set_one_hop() {
    let _guard = with_schema().await;
    let (doc, group, user) = (uid(), uid(), uid());
    write_set("document", &doc, "editor", &group, "group", "member").await;
    write("group", &group, "member", &user).await;
    assert!(check(&user, "write", "document", &doc).await);
}

/// [x] check_via_subject_set_two_hops
/// user ∈ team → team ∈ group (subject-set within subject-set) → group has editor → user can write
#[tokio::test]
async fn check_via_subject_set_two_hops() {
    let _guard = with_schema().await;
    let (doc, group, team, user) = (uid(), uid(), uid(), uid());
    write_set("document", &doc, "editor", &group, "group", "member").await;
    write_set("group", &group, "member", &team, "team", "member").await;
    write("team", &team, "member", &user).await;
    assert!(check(&user, "write", "document", &doc).await);
}

// ── Multi-hop parent hierarchy ─────────────────────────────────────────────────

/// [x] check_via_parent_hierarchy_direct_role
/// doc has a folder link to folder:F; user is owner of folder:F directly.
/// authz_check_path walks document→folder→owner and finds the user.
#[tokio::test]
async fn check_via_parent_hierarchy_direct_role() {
    let _guard = with_schema().await;
    let (doc, folder, user) = (uid(), uid(), uid());
    // The "folder" relation on a document tuple is the parent link.
    write("document", &doc, "folder", &folder).await;
    write("folder", &folder, "owner", &user).await;
    assert!(check(&user, "delete", "document", &doc).await);
}

/// [x] check_via_parent_hierarchy_subject_set_on_parent_not_expanded
/// authz_check_path requires subject_set_type IS NULL at every hop, so a subject-set
/// on the parent (e.g. group owns folder) is NOT expanded. This is expected behaviour:
/// hierarchy traversal is strictly direct-entity only.
#[tokio::test]
async fn check_via_parent_hierarchy_subject_set_on_parent_not_expanded() {
    let _guard = with_schema().await;
    let (doc, folder, group, user) = (uid(), uid(), uid(), uid());
    write("document", &doc, "folder", &folder).await;
    write_set("folder", &folder, "owner", &group, "group", "member").await;
    write("group", &group, "member", &user).await;
    // The path check stops at subject_set_type IS NULL — group membership on folder
    // is not expanded, so the user does not inherit the folder owner grant.
    assert!(!check(&user, "delete", "document", &doc).await);
}

/// [x] check_via_parent_hierarchy_no_parent_link_denied
/// User owns the folder, but there is no folder-link tuple on the document.
#[tokio::test]
async fn check_via_parent_hierarchy_no_parent_link_denied() {
    let _guard = with_schema().await;
    let (doc, folder, user) = (uid(), uid(), uid());
    // Intentionally omit: write("document", &doc, "folder", &folder)
    write("folder", &folder, "owner", &user).await;
    assert!(!check(&user, "delete", "document", &doc).await);
}

// ── Auth / error paths ─────────────────────────────────────────────────────────

/// [x] check_with_explicit_user_param
/// The `user=` query param uses the standalone check path — no session needed.
#[tokio::test]
async fn check_with_explicit_user_param() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    write("document", &doc, "viewer", &user).await;
    // No bearer token on the client — explicit user= is sufficient.
    assert!(check(&user, "read", "document", &doc).await);
}

/// [x] check_with_session_bearer
/// No explicit `user=` param: the server bundles session validation + authz check
/// in a single DB round-trip using the bundled CTE path.
#[tokio::test]
async fn check_with_session_bearer() {
    let _guard = with_schema().await;
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let user_id = auth.user.id.to_string();
    let doc = uid();
    write("document", &doc, "viewer", &user_id).await;

    let res = TestClient::new()
        .bearer(&auth.session.token)
        .get(&format!(
            "/v1/authz/decisions?permission=read&resource_type=document&resource_id={doc}"
        ))
        .await
        .assert_status(200)
        .json::<CheckResponse>();
    assert!(res.allowed);
}

/// [x] check_no_auth_no_user_param_returns_401
#[tokio::test]
async fn check_no_auth_no_user_param_returns_401() {
    let _guard = with_schema().await;
    TestClient::new()
        .get("/v1/authz/decisions?permission=read&resource_type=document&resource_id=anything")
        .await
        .assert_status(401);
}

/// [x] check_unknown_resource_type_returns_422
#[tokio::test]
async fn check_unknown_resource_type_returns_422() {
    let _guard = with_schema().await;
    TestClient::new()
        .get(&format!(
            "/v1/authz/decisions?user={}&permission=read&resource_type=nonexistent&resource_id=x",
            uid()
        ))
        .await
        .assert_status(422);
}

/// [x] check_unknown_permission_returns_422
#[tokio::test]
async fn check_unknown_permission_returns_422() {
    let _guard = with_schema().await;
    TestClient::new()
        .get(&format!(
            "/v1/authz/decisions?user={}&permission=fly&resource_type=document&resource_id=x",
            uid()
        ))
        .await
        .assert_status(422);
}

// ── Batch decisions with parent hierarchy ──────────────────────────────────────

/// [x] batch_check_via_parent_hierarchy
/// Batch decisions must resolve correctly when a check requires authz_check_path
/// (MultiHop). This exercises the UNNEST batch path with hierarchy traversal,
/// confirming the schema-compiler fix covers the batch code path too.
#[tokio::test]
async fn batch_check_via_parent_hierarchy() {
    let _guard = with_schema().await;
    let (doc1, doc2, folder, user) = (uid(), uid(), uid(), uid());
    // doc1: user owns the folder (hierarchy grant)
    write("document", &doc1, "folder", &folder).await;
    write("folder", &folder, "owner", &user).await;
    // doc2: no grant at all
    let req = serde_json::json!({"checks": [
        {"user": user, "permission": "delete", "resource_type": "document", "resource_id": doc1},
        {"user": user, "permission": "delete", "resource_type": "document", "resource_id": doc2},
        {"user": user, "permission": "read",   "resource_type": "document", "resource_id": doc1},
    ]});
    let res = TestClient::new()
        .post("/v1/authz/decisions", &req)
        .await
        .assert_status(200)
        .json::<BatchDecisionResponse>();
    assert_eq!(res.results, vec![true, false, true]);
}

// ── Batch decisions — POST /v1/authz/decisions ─────────────────────────────────

/// [x] batch_check_empty_returns_empty_results
#[tokio::test]
async fn batch_check_empty_returns_empty_results() {
    let _guard = with_schema().await;
    let res = TestClient::new()
        .post("/v1/authz/decisions", &serde_json::json!({"checks": []}))
        .await
        .assert_status(200)
        .json::<BatchDecisionResponse>();
    assert!(res.results.is_empty());
}

/// [x] batch_check_all_allowed
#[tokio::test]
async fn batch_check_all_allowed() {
    let _guard = with_schema().await;
    let (doc1, doc2, user) = (uid(), uid(), uid());
    write("document", &doc1, "owner", &user).await;
    write("document", &doc2, "editor", &user).await;

    let req = serde_json::json!({"checks": [
        {"user": user, "permission": "read",  "resource_type": "document", "resource_id": doc1},
        {"user": user, "permission": "write", "resource_type": "document", "resource_id": doc2},
    ]});
    let res = TestClient::new()
        .post("/v1/authz/decisions", &req)
        .await
        .assert_status(200)
        .json::<BatchDecisionResponse>();
    assert_eq!(res.results, vec![true, true]);
}

/// [x] batch_check_all_denied
#[tokio::test]
async fn batch_check_all_denied() {
    let _guard = with_schema().await;
    let user = uid();
    let req = serde_json::json!({"checks": [
        {"user": user, "permission": "read",   "resource_type": "document", "resource_id": uid()},
        {"user": user, "permission": "write",  "resource_type": "document", "resource_id": uid()},
        {"user": user, "permission": "delete", "resource_type": "document", "resource_id": uid()},
    ]});
    let res = TestClient::new()
        .post("/v1/authz/decisions", &req)
        .await
        .assert_status(200)
        .json::<BatchDecisionResponse>();
    assert_eq!(res.results, vec![false, false, false]);
}

/// [x] batch_check_mixed_preserves_input_order
#[tokio::test]
async fn batch_check_mixed_preserves_input_order() {
    let _guard = with_schema().await;
    let (doc_owned, doc_none, user) = (uid(), uid(), uid());
    write("document", &doc_owned, "viewer", &user).await;

    let req = serde_json::json!({"checks": [
        {"user": user, "permission": "read", "resource_type": "document", "resource_id": doc_owned},
        {"user": user, "permission": "read", "resource_type": "document", "resource_id": doc_none},
        {"user": user, "permission": "read", "resource_type": "document", "resource_id": doc_owned},
    ]});
    let res = TestClient::new()
        .post("/v1/authz/decisions", &req)
        .await
        .assert_status(200)
        .json::<BatchDecisionResponse>();
    assert_eq!(
        res.results,
        vec![true, false, true],
        "results must match input order"
    );
}

/// [x] batch_check_unnest_grouping_correct_order
/// Checks sharing the same (subject, permission, resource_type) are grouped into one
/// UNNEST SQL call internally. Results must still come back in original input order.
#[tokio::test]
async fn batch_check_unnest_grouping_correct_order() {
    let _guard = with_schema().await;
    let user = uid();
    let (doc_a, doc_b, doc_c) = (uid(), uid(), uid());
    write("document", &doc_a, "viewer", &user).await;
    // doc_b — no grant
    write("document", &doc_c, "viewer", &user).await;

    let req = serde_json::json!({"checks": [
        {"user": user, "permission": "read", "resource_type": "document", "resource_id": doc_a},
        {"user": user, "permission": "read", "resource_type": "document", "resource_id": doc_b},
        {"user": user, "permission": "read", "resource_type": "document", "resource_id": doc_c},
    ]});
    let res = TestClient::new()
        .post("/v1/authz/decisions", &req)
        .await
        .assert_status(200)
        .json::<BatchDecisionResponse>();
    assert_eq!(res.results, vec![true, false, true]);
}

/// [x] batch_check_all_use_session_subject
/// No check has an explicit `user` field — all resolve to the session user.
#[tokio::test]
async fn batch_check_all_use_session_subject() {
    let _guard = with_schema().await;
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let user_id = auth.user.id.to_string();
    let doc = uid();
    write("document", &doc, "viewer", &user_id).await;

    let req = serde_json::json!({"checks": [
        {"permission": "read", "resource_type": "document", "resource_id": doc},
    ]});
    let res = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/authz/decisions", &req)
        .await
        .assert_status(200)
        .json::<BatchDecisionResponse>();
    assert_eq!(res.results, vec![true]);
}

/// [x] batch_check_all_use_explicit_user
#[tokio::test]
async fn batch_check_all_use_explicit_user() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    write("document", &doc, "owner", &user).await;

    let req = serde_json::json!({"checks": [
        {"user": user, "permission": "delete", "resource_type": "document", "resource_id": doc},
    ]});
    let res = TestClient::new()
        .post("/v1/authz/decisions", &req)
        .await
        .assert_status(200)
        .json::<BatchDecisionResponse>();
    assert_eq!(res.results, vec![true]);
}

/// [x] batch_check_mixed_session_and_explicit_user
/// Some checks use the session user, others override with `user=`. Both must resolve
/// independently and produce correct per-check results.
#[tokio::test]
async fn batch_check_mixed_session_and_explicit_user() {
    let _guard = with_schema().await;
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let session_uid = auth.user.id.to_string();
    let (explicit_user, doc_s, doc_e) = (uid(), uid(), uid());

    write("document", &doc_s, "viewer", &session_uid).await;
    write("document", &doc_e, "viewer", &explicit_user).await;

    let req = serde_json::json!({"checks": [
        // session user has access to doc_s
        {"permission": "read", "resource_type": "document", "resource_id": doc_s},
        // explicit_user has access to doc_e
        {"user": explicit_user, "permission": "read", "resource_type": "document", "resource_id": doc_e},
        // session user does NOT have access to doc_e
        {"permission": "read", "resource_type": "document", "resource_id": doc_e},
    ]});
    let res = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/authz/decisions", &req)
        .await
        .assert_status(200)
        .json::<BatchDecisionResponse>();
    assert_eq!(res.results, vec![true, true, false]);
}

/// [x] batch_check_no_auth_with_session_check_returns_401
/// At least one check has no explicit `user` field → the server requires a bearer token.
#[tokio::test]
async fn batch_check_no_auth_with_session_check_returns_401() {
    let _guard = with_schema().await;
    let req = serde_json::json!({"checks": [
        {"permission": "read", "resource_type": "document", "resource_id": uid()},
    ]});
    TestClient::new()
        .post("/v1/authz/decisions", &req)
        .await
        .assert_status(401);
}

/// [x] batch_check_unknown_permission_returns_422
#[tokio::test]
async fn batch_check_unknown_permission_returns_422() {
    let _guard = with_schema().await;
    let req = serde_json::json!({"checks": [
        {"user": uid(), "permission": "fly", "resource_type": "document", "resource_id": uid()},
    ]});
    TestClient::new()
        .post("/v1/authz/decisions", &req)
        .await
        .assert_status(422);
}

// ── Cache invalidation ─────────────────────────────────────────────────────────

/// [x] cache_check_false_then_write_then_check_true
/// The first check seeds the cache with false. The subsequent write bumps the object
/// and subject version slots, invalidating the cached entry. The re-check must hit
/// the DB and return true.
#[tokio::test]
async fn cache_check_false_then_write_then_check_true() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());

    assert!(
        !check(&user, "read", "document", &doc).await,
        "no relation yet → false"
    );

    write("document", &doc, "viewer", &user).await;

    assert!(
        check(&user, "read", "document", &doc).await,
        "cache must be invalidated after write"
    );
}

/// [x] cache_check_true_then_delete_then_check_false
#[tokio::test]
async fn cache_check_true_then_delete_then_check_false() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    let body = direct_rel("document", &doc, "viewer", &user);

    TestClient::new()
        .admin()
        .post("/v1/authz/relations", &body)
        .await
        .assert_status(201);
    assert!(
        check(&user, "read", "document", &doc).await,
        "relation exists → true"
    );

    TestClient::new()
        .admin()
        .delete_json("/v1/authz/relations", &body)
        .await
        .assert_status(204);
    assert!(
        !check(&user, "read", "document", &doc).await,
        "cache must be invalidated after delete"
    );
}

// ── Subject-set BFS depth and cycles ──────────────────────────────────────────

/// [x] check_via_subject_set_three_hops
/// user ∈ team → team ∈ group → group ∈ department → department has editor on doc
/// → user can write (3 BFS levels deep)
#[tokio::test]
async fn check_via_subject_set_three_hops() {
    let _guard = with_schema().await;
    let (doc, dept, group, team, user) = (uid(), uid(), uid(), uid(), uid());
    write_set("document", &doc, "editor", &dept, "department", "member").await;
    write_set("department", &dept, "member", &group, "group", "member").await;
    write_set("group", &group, "member", &team, "team", "member").await;
    write("team", &team, "member", &user).await;
    assert!(check(&user, "write", "document", &doc).await);
}

/// [x] check_bfs_terminates_with_cycle
/// A cycle in the subject-set graph (group_a ↔ group_b) must not cause an
/// infinite loop. The BFS visited-set prevents re-expanding seen nodes.
/// Verifies both that a reachable user is found (true) and that an unreachable
/// user is denied (false), confirming the BFS terminates with the correct answer.
#[tokio::test]
async fn check_bfs_terminates_with_cycle() {
    let _guard = with_schema().await;
    let (doc, group_a, group_b, member, non_member) = (uid(), uid(), uid(), uid(), uid());

    // doc → group_a (via subject-set)
    write_set("document", &doc, "viewer", &group_a, "group", "member").await;
    // Cycle: group_a contains group_b, group_b contains group_a
    write_set("group", &group_a, "member", &group_b, "group", "member").await;
    write_set("group", &group_b, "member", &group_a, "group", "member").await;
    // member is a direct member of group_b (reachable through one cycle iteration)
    write("group", &group_b, "member", &member).await;

    assert!(
        check(&member, "read", "document", &doc).await,
        "member reachable through cycle must be allowed"
    );
    assert!(
        !check(&non_member, "read", "document", &doc).await,
        "non-member must be denied even with cycle present"
    );
}

// ── Two-level parent hierarchy ─────────────────────────────────────────────────

/// [x] check_via_two_level_parent_hierarchy
/// With the three-level schema (document → folder → workspace):
/// user owns workspace → inherits owner on folder → inherits owner on document
/// → user can delete document through two levels of hierarchy traversal.
#[tokio::test]
async fn check_via_two_level_parent_hierarchy() {
    let _guard = with_three_level_schema().await;
    let (doc, folder, workspace, user) = (uid(), uid(), uid(), uid());
    write("document", &doc, "folder", &folder).await;
    write("folder", &folder, "workspace", &workspace).await;
    write("workspace", &workspace, "owner", &user).await;

    assert!(
        check(&user, "delete", "document", &doc).await,
        "owner of workspace must be able to delete document via two-level hierarchy"
    );
}

/// [x] check_via_two_level_parent_hierarchy_missing_link_denied
/// If the intermediate folder→workspace link is absent, the two-level path is broken
/// and the check must return false even though the user owns the workspace.
#[tokio::test]
async fn check_via_two_level_parent_hierarchy_missing_link_denied() {
    let _guard = with_three_level_schema().await;
    let (doc, folder, workspace, user) = (uid(), uid(), uid(), uid());
    write("document", &doc, "folder", &folder).await;
    // Intentionally omit: write("folder", &folder, "workspace", &workspace)
    write("workspace", &workspace, "owner", &user).await;

    assert!(
        !check(&user, "delete", "document", &doc).await,
        "broken hierarchy chain must deny access"
    );
}
