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

#[tokio::test]
async fn create_magic_link_twice_succeeds_and_rotates_token() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    let first = TestClient::new()
        .post("/v1/magic-links", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200)
        .json::<MagicLinkResponse>();

    let second = TestClient::new()
        .post("/v1/magic-links", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200)
        .json::<MagicLinkResponse>();

    assert_ne!(first.token, second.token, "each request must issue a fresh token");
}

#[tokio::test]
async fn rotated_magic_link_token_invalidates_previous() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    let first = TestClient::new()
        .post("/v1/magic-links", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200)
        .json::<MagicLinkResponse>();

    // Rotate: second request issues a new token.
    TestClient::new()
        .post("/v1/magic-links", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200);

    // The first token must now be rejected.
    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "magic_link",
                "token": first.token
            }),
        )
        .await
        .assert_status(401);
}
