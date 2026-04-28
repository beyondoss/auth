use crate::helpers::{TestClient, signup, unique_email};

#[derive(serde::Deserialize)]
struct PasswordResetResponse {
    token: String,
}

// ── POST /v1/password-resets ──────────────────────────────────────────────────

#[tokio::test]
async fn request_password_reset_returns_token() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .post("/v1/password-resets", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200)
        .json::<PasswordResetResponse>();

    assert!(resp.token.starts_with("pwr_"));
}

#[tokio::test]
async fn request_password_reset_unknown_email_returns_404() {
    TestClient::new()
        .post(
            "/v1/password-resets",
            &serde_json::json!({ "email": unique_email() }),
        )
        .await
        .assert_status(404);
}
