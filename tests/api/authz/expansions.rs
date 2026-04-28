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

async fn expand(object_type: &str, object_id: &str, relation: &str) -> ExpandResponse {
    TestClient::new()
        .admin()
        .get(&format!(
            "/v1/authz/expansions?object_type={object_type}&object_id={object_id}&relation={relation}"
        ))
        .await
        .assert_status(200)
        .json::<ExpandResponse>()
}

// ── Tests ──────────────────────────────────────────────────────────────────────

/// [x] expand_object_with_direct_subjects
#[tokio::test]
async fn expand_object_with_direct_subjects() {
    let _guard = with_schema().await;
    let (doc, user_a, user_b) = (uid(), uid(), uid());
    write("document", &doc, "viewer", &user_a).await;
    write("document", &doc, "viewer", &user_b).await;

    let res = expand("document", &doc, "viewer").await;
    let ids: std::collections::HashSet<_> = res.subjects.iter().map(|s| s.id.as_str()).collect();
    assert!(ids.contains(user_a.as_str()));
    assert!(ids.contains(user_b.as_str()));
}

/// [x] expand_object_with_no_relations_returns_empty
#[tokio::test]
async fn expand_object_with_no_relations_returns_empty() {
    let _guard = with_schema().await;
    let res = expand("document", &uid(), "viewer").await;
    assert!(res.subjects.is_empty());
}

/// [x] expand_via_subject_set_one_hop
/// group has viewer on doc; user is a direct member of group.
/// Expansion must recurse through the subject-set and return the leaf user,
/// not the intermediate group.
#[tokio::test]
async fn expand_via_subject_set_one_hop() {
    let _guard = with_schema().await;
    let (doc, group, user) = (uid(), uid(), uid());
    write_set("document", &doc, "viewer", &group, "group", "member").await;
    write("group", &group, "member", &user).await;

    let res = expand("document", &doc, "viewer").await;
    let ids: Vec<_> = res.subjects.iter().map(|s| s.id.as_str()).collect();
    assert!(
        ids.contains(&user.as_str()),
        "expanded leaf user must appear"
    );
    assert!(
        !ids.contains(&group.as_str()),
        "intermediate subject-set must not appear"
    );
}

/// [x] expand_via_subject_set_two_hops
/// team ∈ group → group has editor on doc. Expansion resolves through two subject-set
/// hops to the leaf user members of the team.
#[tokio::test]
async fn expand_via_subject_set_two_hops() {
    let _guard = with_schema().await;
    let (doc, group, team, user) = (uid(), uid(), uid(), uid());
    write_set("document", &doc, "editor", &group, "group", "member").await;
    write_set("group", &group, "member", &team, "team", "member").await;
    write("team", &team, "member", &user).await;

    let res = expand("document", &doc, "editor").await;
    let ids: Vec<_> = res.subjects.iter().map(|s| s.id.as_str()).collect();
    assert!(ids.contains(&user.as_str()));
}

/// [x] expand_only_requested_relation_returned
/// The object has both owner and viewer relations. Expanding "owner" must not
/// include subjects from the "viewer" relation.
#[tokio::test]
async fn expand_only_requested_relation_returned() {
    let _guard = with_schema().await;
    let (doc, owner_user, viewer_user) = (uid(), uid(), uid());
    write("document", &doc, "owner", &owner_user).await;
    write("document", &doc, "viewer", &viewer_user).await;

    let res = expand("document", &doc, "owner").await;
    let ids: Vec<_> = res.subjects.iter().map(|s| s.id.as_str()).collect();
    assert!(ids.contains(&owner_user.as_str()));
    assert!(
        !ids.contains(&viewer_user.as_str()),
        "viewer must not appear when expanding owner"
    );
}

/// [x] expand_cycle_terminates_safely
/// A subject-set cycle (A → B → A) must terminate without error. The CYCLE clause
/// in the recursive CTE detects revisited nodes and stops expanding them.
#[tokio::test]
async fn expand_cycle_terminates_safely() {
    let _guard = with_schema().await;
    let (doc, group_a, group_b) = (uid(), uid(), uid());
    write_set("document", &doc, "viewer", &group_a, "group", "member").await;
    // Cycle: A contains B, B contains A
    write_set("group", &group_a, "member", &group_b, "group", "member").await;
    write_set("group", &group_b, "member", &group_a, "group", "member").await;

    // The request must complete without a 500 or timeout — no direct leaf subjects
    // exist in the cycle so the result is empty, but it must not hang.
    let res = TestClient::new()
        .admin()
        .get(&format!(
            "/v1/authz/expansions?object_type=document&object_id={doc}&relation=viewer"
        ))
        .await
        .assert_status(200)
        .json::<ExpandResponse>();
    assert!(res.subjects.is_empty(), "no leaf subjects in a pure cycle");
}
