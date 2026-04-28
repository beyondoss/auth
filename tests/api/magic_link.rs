use crate::helpers::{TestClient, signup, unique_email};

#[derive(serde::Deserialize)]
struct MagicLinkResponse {
    token: String,
}

// ── POST /v1/magic-links ──────────────────────────────────────────────────────

#[tokio::test]
async fn create_magic_link_returns_token() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .post("/v1/magic-links", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200)
        .json::<MagicLinkResponse>();

    assert!(resp.token.starts_with("ml_"));
}

#[tokio::test]
async fn create_magic_link_unknown_email_returns_404() {
    TestClient::new()
        .post(
            "/v1/magic-links",
            &serde_json::json!({ "email": unique_email() }),
        )
        .await
        .assert_status(404);
}
