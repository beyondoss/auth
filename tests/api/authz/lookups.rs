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

/// Sign up a fresh user and return (bearer_token, user_id_string).
async fn fresh_user() -> (String, String) {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    (auth.session.token, auth.user.id.to_string())
}

async fn lookup(
    token: &str,
    user_param: Option<&str>,
    permission: &str,
    resource_type: &str,
    extra: &str,
) -> LookupResponse {
    let user_part = user_param.map(|u| format!("&user={u}")).unwrap_or_default();
    TestClient::new()
        .bearer(token)
        .get(&format!(
            "/v1/authz/lookups?permission={permission}&resource_type={resource_type}{user_part}{extra}"
        ))
        .await
        .assert_status(200)
        .json::<LookupResponse>()
}

// ── Tests ──────────────────────────────────────────────────────────────────────

/// [x] lookup_direct_grants_returned
#[tokio::test]
async fn lookup_direct_grants_returned() {
    let _guard = with_schema().await;
    let (token, user_id) = fresh_user().await;
    let (doc_a, doc_b) = (uid(), uid());
    write("document", &doc_a, "viewer", &user_id).await;
    write("document", &doc_b, "editor", &user_id).await;

    let res = lookup(&token, None, "read", "document", "").await;
    assert!(res.object_ids.contains(&doc_a));
    assert!(res.object_ids.contains(&doc_b));
}

/// [x] lookup_no_grants_returns_empty
#[tokio::test]
async fn lookup_no_grants_returns_empty() {
    let _guard = with_schema().await;
    let (token, _) = fresh_user().await;
    let res = lookup(&token, None, "read", "document", "").await;
    assert!(res.object_ids.is_empty());
}

/// [x] lookup_via_subject_set
/// user ∈ group → group has viewer on doc → lookup for read must include doc.
#[tokio::test]
async fn lookup_via_subject_set() {
    let _guard = with_schema().await;
    let (token, user_id) = fresh_user().await;
    let (doc, group) = (uid(), uid());
    write_set("document", &doc, "viewer", &group, "group", "member").await;
    write("group", &group, "member", &user_id).await;

    let res = lookup(&token, None, "read", "document", "").await;
    assert!(res.object_ids.contains(&doc));
}

/// [x] lookup_via_parent_hierarchy
/// user owns folder:F; doc:D links to folder:F via the "folder" relation.
/// enumerate_via_parent finds doc:D through the parent-ownership chain.
#[tokio::test]
async fn lookup_via_parent_hierarchy() {
    let _guard = with_schema().await;
    let (token, user_id) = fresh_user().await;
    let (doc, folder) = (uid(), uid());
    // The "folder" relation on a document tuple is the parent link.
    write("document", &doc, "folder", &folder).await;
    write("folder", &folder, "owner", &user_id).await;

    let res = lookup(&token, None, "read", "document", "").await;
    assert!(res.object_ids.contains(&doc));
}

/// [x] lookup_role_hierarchy_expands
/// User holds the owner role. lookup for the viewer-gated "read" permission must
/// still return the document because owner transitively satisfies viewer.
#[tokio::test]
async fn lookup_role_hierarchy_expands() {
    let _guard = with_schema().await;
    let (token, user_id) = fresh_user().await;
    let doc = uid();
    write("document", &doc, "owner", &user_id).await;

    let res = lookup(&token, None, "read", "document", "").await;
    assert!(res.object_ids.contains(&doc));
}

/// [x] lookup_pagination_limit_and_cursor
/// Requesting fewer results than exist must truncate the list and return a cursor.
#[tokio::test]
async fn lookup_pagination_limit_and_cursor() {
    let _guard = with_schema().await;
    let (token, user_id) = fresh_user().await;
    for _ in 0..3 {
        write("document", &uid(), "viewer", &user_id).await;
    }

    let res = lookup(&token, None, "read", "document", "&limit=2").await;
    assert_eq!(res.object_ids.len(), 2);
    assert!(
        res.next_cursor.is_some(),
        "next_cursor must be set when results are truncated"
    );
}

/// [x] lookup_cursor_page_two
/// Following the cursor from page 1 must return the remaining items with no further cursor.
#[tokio::test]
async fn lookup_cursor_page_two() {
    let _guard = with_schema().await;
    let (token, user_id) = fresh_user().await;
    let mut docs: Vec<String> = (0..3).map(|_| uid()).collect();
    docs.sort_unstable(); // object_ids are returned sorted; sort locally to know expected order
    for doc in &docs {
        write("document", doc, "viewer", &user_id).await;
    }

    let page1 = lookup(&token, None, "read", "document", "&limit=2").await;
    assert_eq!(page1.object_ids.len(), 2);
    let cursor = page1.next_cursor.expect("page 1 must have a cursor");

    let page2 = lookup(
        &token,
        None,
        "read",
        "document",
        &format!("&limit=2&cursor={cursor}"),
    )
    .await;
    assert!(
        !page2.object_ids.is_empty(),
        "page 2 must contain remaining items"
    );
    assert!(page2.next_cursor.is_none(), "no further pages after page 2");

    let all: std::collections::HashSet<_> = page1
        .object_ids
        .iter()
        .chain(page2.object_ids.iter())
        .collect();
    for doc in &docs {
        assert!(all.contains(doc), "{doc} must appear across pages");
    }
}

/// [x] lookup_via_subject_set_and_parent_hierarchy
/// user ∈ group → group has owner on folder (subject-set) → doc links to folder.
/// enumerate_via_parent uses authz_lookup_resources which expands subject-sets,
/// so the document must appear in the lookup result even though authz_check_path
/// would not follow the subject-set on the parent.
#[tokio::test]
async fn lookup_via_subject_set_and_parent_hierarchy() {
    let _guard = with_schema().await;
    let (token, user_id) = fresh_user().await;
    let (doc, folder, group) = (uid(), uid(), uid());
    write("document", &doc, "folder", &folder).await;
    write_set("folder", &folder, "owner", &group, "group", "member").await;
    write("group", &group, "member", &user_id).await;

    let res = lookup(&token, None, "read", "document", "").await;
    assert!(res.object_ids.contains(&doc));
}

/// [x] lookup_unknown_permission_returns_422
#[tokio::test]
async fn lookup_unknown_permission_returns_422() {
    let _guard = with_schema().await;
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/authz/lookups?permission=fly&resource_type=document")
        .await
        .assert_status(422);
}

/// [x] lookup_unknown_resource_type_returns_422
#[tokio::test]
async fn lookup_unknown_resource_type_returns_422() {
    let _guard = with_schema().await;
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/authz/lookups?permission=read&resource_type=nonexistent")
        .await
        .assert_status(422);
}
