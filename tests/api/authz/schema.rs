use crate::helpers::TestClient;

use super::*;

/// [x] schema_put_valid_round_trips
#[tokio::test]
async fn schema_put_valid_round_trips() {
    let _guard = exclusive().await;
    TestClient::new()
        .admin()
        .put("/v1/authz/schema", &doc_folder_schema())
        .await
        .assert_status(200);

    let body = TestClient::new()
        .admin()
        .get("/v1/authz/schema")
        .await
        .assert_status(200)
        .json::<serde_json::Value>();

    assert_eq!(body["version"], 1);
    assert_eq!(body["resources"][0]["name"], "document");
    assert_eq!(body["resources"][1]["name"], "folder");
}

/// [x] schema_put_role_hierarchy_compiles_transitively
/// Owner > editor > viewer (transitive). A user with the owner role must pass a
/// check that only names viewer as a direct-grant role.
#[tokio::test]
async fn schema_put_role_hierarchy_compiles_transitively() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());

    TestClient::new()
        .admin()
        .post(
            "/v1/authz/relations",
            &direct_rel("document", &doc, "owner", &user),
        )
        .await
        .assert_status(201);

    let res = TestClient::new()
        .get(&format!(
            "/v1/authz/decisions?user={user}&permission=read&resource_type=document&resource_id={doc}"
        ))
        .await
        .assert_status(200)
        .json::<CheckResponse>();
    assert!(
        res.allowed,
        "owner must inherit the viewer-gated read permission"
    );
}

/// [x] schema_put_invalid_identifier_rejected
#[tokio::test]
async fn schema_put_invalid_identifier_rejected() {
    let _guard = exclusive().await;
    let schema = serde_json::json!({
        "version": 1,
        "resources": [{
            "name": "My-Resource",
            "roles": ["owner"],
            "permissions": {"read": ["owner"]}
        }]
    });
    TestClient::new()
        .admin()
        .put("/v1/authz/schema", &schema)
        .await
        .assert_status(422);
}

/// [x] schema_put_wrong_version_rejected
#[tokio::test]
async fn schema_put_wrong_version_rejected() {
    let _guard = exclusive().await;
    let schema = serde_json::json!({
        "version": 2,
        "resources": [{"name": "doc", "roles": ["owner"], "permissions": {"read": ["owner"]}}]
    });
    TestClient::new()
        .admin()
        .put("/v1/authz/schema", &schema)
        .await
        .assert_status(422);
}

/// [x] schema_put_unknown_parent_resource_rejected
#[tokio::test]
async fn schema_put_unknown_parent_resource_rejected() {
    let _guard = exclusive().await;
    let schema = serde_json::json!({
        "version": 1,
        "resources": [{
            "name": "document",
            "roles": ["owner"],
            "permissions": {"read": ["owner"]},
            "hierarchy": {"parent_relation": "folder", "parent_resource": "nonexistent"}
        }]
    });
    TestClient::new()
        .admin()
        .put("/v1/authz/schema", &schema)
        .await
        .assert_status(422);
}

/// [x] schema_put_unknown_role_in_role_hierarchy_rejected
#[tokio::test]
async fn schema_put_unknown_role_in_role_hierarchy_rejected() {
    let _guard = exclusive().await;
    let schema = serde_json::json!({
        "version": 1,
        "resources": [{
            "name": "document",
            "roles": ["owner"],
            "role_hierarchy": [{"superior": "owner", "inferior": "phantom"}],
            "permissions": {"read": ["owner"]}
        }]
    });
    TestClient::new()
        .admin()
        .put("/v1/authz/schema", &schema)
        .await
        .assert_status(422);
}

/// [x] schema_put_unknown_role_in_permissions_rejected
#[tokio::test]
async fn schema_put_unknown_role_in_permissions_rejected() {
    let _guard = exclusive().await;
    let schema = serde_json::json!({
        "version": 1,
        "resources": [{
            "name": "document",
            "roles": ["owner"],
            "permissions": {"read": ["phantom"]}
        }]
    });
    TestClient::new()
        .admin()
        .put("/v1/authz/schema", &schema)
        .await
        .assert_status(422);
}

/// A schema with a cyclic role hierarchy (owner > editor > owner) must not hang
/// or panic the server. The `compute_inherited_roles` fixed-point loop terminates
/// when no new inferences can be added — cycles do not cause infinite loops.
/// The schema is accepted (200) and authorization checks work correctly.
#[tokio::test]
async fn schema_put_role_hierarchy_cycle_does_not_hang() {
    let _guard = exclusive().await;

    let schema = serde_json::json!({
        "version": 1,
        "resources": [{
            "name": "thing",
            "roles": ["owner", "editor"],
            "role_hierarchy": [
                {"superior": "owner",  "inferior": "editor"},
                {"superior": "editor", "inferior": "owner"}   // cycle
            ],
            "permissions": {
                "read": ["editor"]
            }
        }]
    });

    // Must respond quickly — not hang. The fixed-point loop terminates because
    // the role set is finite and bounded.
    TestClient::new()
        .admin()
        .put("/v1/authz/schema", &schema)
        .await
        .assert_status(200);

    // Verify the compiled schema still works: an owner should pass a read check
    // since owner > editor (directly) and read requires editor.
    let (thing_id, user_id) = (uid(), uid());
    TestClient::new()
        .admin()
        .post(
            "/v1/authz/relations",
            &direct_rel("thing", &thing_id, "owner", &user_id),
        )
        .await
        .assert_status(201);

    let res = TestClient::new()
        .get(&format!(
            "/v1/authz/decisions?user={user_id}&permission=read&resource_type=thing&resource_id={thing_id}"
        ))
        .await
        .assert_status(200)
        .json::<CheckResponse>();

    assert!(
        res.allowed,
        "owner must pass read check via cyclic role hierarchy"
    );
}
