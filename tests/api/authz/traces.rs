use crate::helpers::TestClient;

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

async fn trace(
    user: &str,
    permission: &str,
    resource_type: &str,
    resource_id: &str,
) -> TraceResponse {
    TestClient::new()
        .admin()
        .get(&format!(
            "/v1/authz/traces?user={user}&permission={permission}&resource_type={resource_type}&resource_id={resource_id}"
        ))
        .await
        .assert_status(200)
        .json::<TraceResponse>()
}

// ── Tests ──────────────────────────────────────────────────────────────────────

/// [x] trace_allowed_subject_in_list_and_allowed_true
#[tokio::test]
async fn trace_allowed_subject_in_list_and_allowed_true() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    write("document", &doc, "viewer", &user).await;

    let res = trace(&user, "read", "document", &doc).await;
    assert!(res.allowed);
    assert!(res.subjects.iter().any(|s| s.id == user));
}

/// [x] trace_denied_subject_absent_and_allowed_false
/// The queried user has no grant; another user does. `allowed` is false, but the
/// other user must still appear in the subjects list.
#[tokio::test]
async fn trace_denied_subject_absent_and_allowed_false() {
    let _guard = with_schema().await;
    let (doc, other_user, no_access) = (uid(), uid(), uid());
    write("document", &doc, "viewer", &other_user).await;

    let res = trace(&no_access, "read", "document", &doc).await;
    assert!(!res.allowed);
    assert!(
        res.subjects.iter().any(|s| s.id == other_user),
        "other granted user must appear in subjects"
    );
    assert!(!res.subjects.iter().any(|s| s.id == no_access));
}

/// [x] trace_subject_set_expanded_in_subjects
/// group has viewer on doc; user is a member of group.
/// The trace must expand the subject-set and list the leaf user.
#[tokio::test]
async fn trace_subject_set_expanded_in_subjects() {
    let _guard = with_schema().await;
    let (doc, group, user) = (uid(), uid(), uid());
    write_set("document", &doc, "viewer", &group, "group", "member").await;
    write("group", &group, "member", &user).await;

    let res = trace(&user, "read", "document", &doc).await;
    assert!(res.allowed);
    assert!(
        res.subjects.iter().any(|s| s.id == user),
        "expanded leaf user must appear"
    );
}

/// [x] trace_multi_hop_hierarchy_not_reflected
/// The why_check handler only expands SingleHop (direct role) relations.
/// A grant that comes exclusively via the parent hierarchy (authz_check_path) is
/// not reflected in the subjects list — this is a documented limitation.
///
/// Concretely: user owns folder; doc links to folder. `authz_check` returns true,
/// but `why_check` does not see the hierarchy grant in its expand output.
#[tokio::test]
async fn trace_multi_hop_hierarchy_not_reflected() {
    let _guard = with_schema().await;
    let (doc, folder, user) = (uid(), uid(), uid());
    write("document", &doc, "folder", &folder).await;
    write("folder", &folder, "owner", &user).await;

    let res = trace(&user, "delete", "document", &doc).await;
    // No direct role on the document → expand returns nothing for the user.
    assert!(
        !res.subjects.iter().any(|s| s.id == user),
        "hierarchy-only grant must not appear in trace subjects (known limitation)"
    );
    // Corollary: allowed is also false from the trace's perspective, even though
    // the actual authz check would return true via authz_check_path.
    assert!(!res.allowed);
}

/// [x] trace_unknown_permission_returns_422
#[tokio::test]
async fn trace_unknown_permission_returns_422() {
    let _guard = with_schema().await;
    TestClient::new()
        .admin()
        .get(&format!(
            "/v1/authz/traces?user={}&permission=fly&resource_type=document&resource_id={}",
            uid(),
            uid()
        ))
        .await
        .assert_status(422);
}
