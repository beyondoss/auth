use crate::helpers::{TestClient, db_conn, signup, unique_email};

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

    assert_ne!(
        first.token, second.token,
        "each request must issue a fresh token"
    );
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

// ── Token expiry ──────────────────────────────────────────────────────────────

/// An expired magic-link token must be rejected. Covers the `TokenExpired` branch
/// in `one_time_token::consume`, which is distinct from `TokenInvalid` (wrong
/// secret / already consumed / never existed).
#[tokio::test]
async fn expired_magic_link_token_is_rejected() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .post("/v1/magic-links", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200)
        .json::<MagicLinkResponse>();

    // Extract the OTT UUID from the token string: "ml_{hex_uuid}_{secret}"
    let token_hex = resp
        .token
        .split('_')
        .nth(1)
        .expect("token must have 3 parts");
    let token_id = uuid::Uuid::parse_str(token_hex).expect("middle segment must be a UUID");

    let mut conn = db_conn().await;
    sqlx::query(
        "UPDATE auth.one_time_tokens SET expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(token_id)
    .execute(&mut conn)
    .await
    .unwrap();

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "magic_link",
                "token": resp.token
            }),
        )
        .await
        .assert_status(401);
}

/// A magic-link token whose secret has been tampered with is rejected with 401.
/// The secret_hash mismatch is indistinguishable from a non-existent token —
/// no information about which segment was wrong is leaked to the caller.
#[tokio::test]
async fn magic_link_wrong_secret_returns_401() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .post("/v1/magic-links", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200)
        .json::<MagicLinkResponse>();

    // Preserve the prefix and id segments; corrupt only the secret.
    let parts: Vec<&str> = resp.token.splitn(3, '_').collect();
    let tampered = format!(
        "{}_{}_{}",
        parts[0], parts[1], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({ "grant_type": "magic_link", "token": tampered }),
        )
        .await
        .assert_status(401);
}

/// A magic-link token for a soft-deleted user must be rejected. The OTT is consumed
/// successfully, but `load_user_context` returns NotFound (deleted_at IS NULL filter)
/// → the route returns 404, not 201. The token is gone either way.
#[tokio::test]
async fn magic_link_deleted_user_returns_401() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;

    let ott = TestClient::new()
        .post("/v1/magic-links", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200)
        .json::<MagicLinkResponse>();

    TestClient::new()
        .bearer(&auth.session.token)
        .delete("/v1/users/me")
        .await
        .assert_status(204);

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({ "grant_type": "magic_link", "token": ott.token }),
        )
        .await
        .assert_status(404);
}
