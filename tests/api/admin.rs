use crate::helpers::{TestClient, login, signup, unique_email};

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
}

// ── POST /v1/admin/impersonations ─────────────────────────────────────────────

#[tokio::test]
async fn impersonation_requires_admin_secret() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .post(
            "/v1/admin/impersonations",
            &serde_json::json!({ "user_id": auth.user.id }),
        )
        .await
        .assert_status(401);
}

#[tokio::test]
async fn impersonation_returns_working_bearer() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let impersonated = TestClient::new()
        .admin()
        .post(
            "/v1/admin/impersonations",
            &serde_json::json!({ "user_id": auth.user.id }),
        )
        .await
        .assert_status(201)
        .json::<beyond_auth::AuthResponse>();

    assert_eq!(impersonated.user.id, auth.user.id);

    TestClient::new()
        .bearer(&impersonated.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(200);
}

#[tokio::test]
async fn impersonation_nonexistent_user_returns_404() {
    TestClient::new()
        .admin()
        .post(
            "/v1/admin/impersonations",
            &serde_json::json!({ "user_id": uuid::Uuid::now_v7() }),
        )
        .await
        .assert_status(404);
}

// ── POST /v1/tokens ───────────────────────────────────────────────────────────

#[tokio::test]
async fn jwt_issuance_requires_auth() {
    TestClient::new()
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(401);
}

#[tokio::test]
async fn jwt_issuance_returns_signed_token() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;
    let auth = login(&email, "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(200)
        .json::<TokenResponse>();

    assert_eq!(resp.token_type, "Bearer");
    assert!(resp.expires_in > 0);
    assert_eq!(
        resp.access_token.split('.').count(),
        3,
        "access_token must be a three-part JWT"
    );
}

#[tokio::test]
async fn impersonated_session_issues_jwt() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let impersonated = TestClient::new()
        .admin()
        .post(
            "/v1/admin/impersonations",
            &serde_json::json!({ "user_id": auth.user.id }),
        )
        .await
        .assert_status(201)
        .json::<beyond_auth::AuthResponse>();

    let resp = TestClient::new()
        .bearer(&impersonated.session.token)
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(200)
        .json::<TokenResponse>();

    assert_eq!(
        resp.access_token.split('.').count(),
        3,
        "impersonated session must be able to issue a JWT"
    );
}
