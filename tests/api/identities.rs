use crate::helpers::{TestClient, login, signup, unique_email};

#[derive(serde::Deserialize)]
struct IdentityItem {
    id: uuid::Uuid,
    provider: String,
    display: String,
}

#[derive(serde::Deserialize)]
struct IdentitiesResponse {
    identities: Vec<IdentityItem>,
}

// ── GET /v1/identities ────────────────────────────────────────────────────────

#[tokio::test]
async fn list_identities_returns_password_identity() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/identities")
        .await
        .assert_status(200)
        .json::<IdentitiesResponse>();

    assert_eq!(resp.identities.len(), 1);
    assert_eq!(resp.identities[0].provider, "password");
    assert_eq!(resp.identities[0].display, email);
}

// ── POST /v1/identities ───────────────────────────────────────────────────────

#[tokio::test]
async fn add_password_when_already_has_one_returns_409() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/identities", &serde_json::json!({ "password": "new-pass-battery-horse" }))
        .await
        .assert_status(409);
}

#[tokio::test]
async fn add_password_requires_auth() {
    TestClient::new()
        .post("/v1/identities", &serde_json::json!({ "password": "new-pass-battery-horse" }))
        .await
        .assert_status(401);
}

// ── PATCH /v1/identities/{id} ─────────────────────────────────────────────────

#[tokio::test]
async fn update_password_allows_new_password_login() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;

    let identities = TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/identities")
        .await
        .assert_status(200)
        .json::<IdentitiesResponse>();

    let identity_id = identities.identities[0].id;

    TestClient::new()
        .bearer(&auth.session.token)
        .patch(
            &format!("/v1/identities/{identity_id}"),
            &serde_json::json!({
                "current_password": "correct-horse-battery-staple",
                "new_password": "new-horse-battery-staple",
            }),
        )
        .await
        .assert_status(204);

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password",
                "email": email,
                "password": "correct-horse-battery-staple",
            }),
        )
        .await
        .assert_status(401);

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password",
                "email": email,
                "password": "new-horse-battery-staple",
            }),
        )
        .await
        .assert_status(201);
}

#[tokio::test]
async fn update_password_wrong_current_password_returns_401() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let identities = TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/identities")
        .await
        .assert_status(200)
        .json::<IdentitiesResponse>();

    let identity_id = identities.identities[0].id;

    TestClient::new()
        .bearer(&auth.session.token)
        .patch(
            &format!("/v1/identities/{identity_id}"),
            &serde_json::json!({
                "current_password": "wrong-password-entirely",
                "new_password": "new-horse-battery-staple",
            }),
        )
        .await
        .assert_status(401);
}

#[tokio::test]
async fn update_password_revokes_other_sessions_keeps_current() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;
    let auth2 = login(&email, "correct-horse-battery-staple").await;

    let identities = TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/identities")
        .await
        .assert_status(200)
        .json::<IdentitiesResponse>();

    let identity_id = identities.identities[0].id;

    TestClient::new()
        .bearer(&auth.session.token)
        .patch(
            &format!("/v1/identities/{identity_id}"),
            &serde_json::json!({
                "current_password": "correct-horse-battery-staple",
                "new_password": "new-horse-battery-staple",
            }),
        )
        .await
        .assert_status(204);

    TestClient::new()
        .bearer(&auth2.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(401);

    TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(200);
}

// ── DELETE /v1/identities/{id} ────────────────────────────────────────────────

#[tokio::test]
async fn delete_last_identity_returns_409() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let identities = TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/identities")
        .await
        .assert_status(200)
        .json::<IdentitiesResponse>();

    let identity_id = identities.identities[0].id;

    TestClient::new()
        .bearer(&auth.session.token)
        .delete(&format!("/v1/identities/{identity_id}"))
        .await
        .assert_status(409);
}

