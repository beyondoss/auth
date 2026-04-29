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
        .post(
            "/v1/password-resets",
            &serde_json::json!({ "email": email }),
        )
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

#[tokio::test]
async fn request_password_reset_twice_succeeds_and_rotates_token() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    let first = TestClient::new()
        .post(
            "/v1/password-resets",
            &serde_json::json!({ "email": email }),
        )
        .await
        .assert_status(200)
        .json::<PasswordResetResponse>();

    let second = TestClient::new()
        .post(
            "/v1/password-resets",
            &serde_json::json!({ "email": email }),
        )
        .await
        .assert_status(200)
        .json::<PasswordResetResponse>();

    assert_ne!(
        first.token, second.token,
        "each request must issue a fresh token"
    );
}

#[tokio::test]
async fn rotated_password_reset_token_invalidates_previous() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    let first = TestClient::new()
        .post(
            "/v1/password-resets",
            &serde_json::json!({ "email": email }),
        )
        .await
        .assert_status(200)
        .json::<PasswordResetResponse>();

    // Rotate: second request issues a new token.
    TestClient::new()
        .post(
            "/v1/password-resets",
            &serde_json::json!({ "email": email }),
        )
        .await
        .assert_status(200);

    // The first token must now be rejected.
    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password_reset",
                "token": first.token,
                "new_password": "new-correct-horse-battery-staple"
            }),
        )
        .await
        .assert_status(401);
}
