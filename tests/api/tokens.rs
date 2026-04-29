use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::helpers::{TestClient, db_conn, signup, unique_email};

// ── helpers ───────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i32,
    refresh_token: Option<String>,
}

fn decode_claims(token: &str) -> serde_json::Value {
    let part = token.split('.').nth(1).expect("JWT must have 3 parts");
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .expect("claims must be valid base64url");
    serde_json::from_slice(&bytes).expect("claims must be valid JSON")
}

async fn issue_token(session_token: &str) -> TokenResponse {
    TestClient::new()
        .bearer(session_token)
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(200)
        .json::<TokenResponse>()
}

// ── JWT issuance ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn session_token_issues_jwt_and_refresh_token() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let resp = issue_token(&auth.session.token).await;

    assert!(!resp.access_token.is_empty());
    assert_eq!(resp.expires_in, 900); // default access_token_ttl_seconds
    assert!(
        resp.refresh_token.is_some(),
        "session auth should return a refresh token"
    );
    assert!(
        resp.refresh_token.as_deref().unwrap().starts_with("rt_"),
        "refresh token should have rt_ prefix"
    );
}

#[tokio::test]
async fn jwt_contains_expected_claims() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let resp = issue_token(&auth.session.token).await;
    let claims = decode_claims(&resp.access_token);

    assert_eq!(claims["sub"], auth.user.id.to_string());
    assert!(claims["iss"].is_string());
    assert!(claims["aud"].is_string());
    assert!(claims["jti"].is_string());
    assert!(claims["iat"].is_number());
    assert!(claims["exp"].is_number());
    let exp = claims["exp"].as_i64().unwrap();
    let iat = claims["iat"].as_i64().unwrap();
    assert_eq!(exp - iat, 900);
}

#[tokio::test]
async fn unauthenticated_request_returns_401() {
    TestClient::new()
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(401);
}

#[tokio::test]
async fn invalid_bearer_returns_401() {
    TestClient::new()
        .bearer("notavalidtoken")
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(401);
}

// ── Custom claims ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn custom_claims_appear_in_jwt() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .post(
            "/v1/tokens",
            &serde_json::json!({
                "claims": {
                    "plan": "pro",
                    "org_role": "admin",
                    "feature_flags": ["new_ui", "billing_v2"]
                }
            }),
        )
        .await
        .assert_status(200)
        .json::<TokenResponse>();

    let claims = decode_claims(&resp.access_token);
    assert_eq!(claims["plan"], "pro");
    assert_eq!(claims["org_role"], "admin");
    assert_eq!(claims["feature_flags"][0], "new_ui");
}

#[tokio::test]
async fn custom_claims_cannot_override_reserved_sub() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .post(
            "/v1/tokens",
            &serde_json::json!({ "claims": { "sub": "attacker", "exp": 9999999999i64 } }),
        )
        .await
        .assert_status(200)
        .json::<TokenResponse>();

    let claims = decode_claims(&resp.access_token);
    assert_eq!(
        claims["sub"],
        auth.user.id.to_string(),
        "sub must not be overridden"
    );
    assert_ne!(claims["exp"], 9999999999i64, "exp must not be overridden");
}

#[tokio::test]
async fn no_body_issues_token_without_extra_claims() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    // POST with no body at all (no Content-Type)
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/tokens", crate::helpers::test_env().url))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", auth.session.token),
        )
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status().as_u16(), 200);
}

// ── Refresh token rotation ────────────────────────────────────────────────────

#[tokio::test]
async fn refresh_token_issues_new_jwt_and_rotates() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    // Get initial refresh token
    let first = issue_token(&auth.session.token).await;
    let rt1 = first.refresh_token.expect("should have refresh token");

    // Use the refresh token — should rotate
    let second = TestClient::new()
        .bearer(&rt1)
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(200)
        .json::<TokenResponse>();

    assert!(!second.access_token.is_empty());
    let rt2 = second
        .refresh_token
        .expect("rotation should return new refresh token");

    // New refresh token must be different
    assert_ne!(rt1, rt2, "refresh token must rotate on each use");
    assert!(rt2.starts_with("rt_"));
}

#[tokio::test]
async fn rotated_refresh_token_is_invalidated() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let first = issue_token(&auth.session.token).await;
    let rt1 = first.refresh_token.expect("should have refresh token");

    // Use rt1 once — rotates to rt2
    TestClient::new()
        .bearer(&rt1)
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(200);

    // Using the old rt1 again must fail
    TestClient::new()
        .bearer(&rt1)
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(401);
}

#[tokio::test]
async fn replay_detection_revokes_entire_family() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let first = issue_token(&auth.session.token).await;
    let rt1 = first.refresh_token.expect("should have refresh token");

    // Normal rotation: rt1 → rt2
    let second = TestClient::new()
        .bearer(&rt1)
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(200)
        .json::<TokenResponse>();
    let rt2 = second
        .refresh_token
        .expect("should have refresh token after rotation");

    // Replay rt1 — triggers family revocation
    TestClient::new()
        .bearer(&rt1)
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(401);

    // rt2 (the legitimate successor) must now also be revoked
    TestClient::new()
        .bearer(&rt2)
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(401);
}

#[tokio::test]
async fn expired_refresh_token_returns_401() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let resp = issue_token(&auth.session.token).await;
    let rt = resp.refresh_token.expect("should have refresh token");

    // Parse the token id so we can expire it in the DB
    let id_hex = rt.split('_').nth(1).expect("rt_ format");
    let token_id = uuid::Uuid::parse_str(id_hex).expect("valid uuid hex");

    let mut conn = db_conn().await;
    sqlx::query!(
        "UPDATE auth.tokens SET expires_at = now() - interval '1 second'
         WHERE id = $1",
        token_id,
    )
    .execute(&mut conn)
    .await
    .unwrap();

    TestClient::new()
        .bearer(&rt)
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(401);
}

#[tokio::test]
async fn refresh_token_jwt_contains_correct_sub() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let first = issue_token(&auth.session.token).await;
    let rt = first.refresh_token.expect("should have refresh token");

    let resp = TestClient::new()
        .bearer(&rt)
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(200)
        .json::<TokenResponse>();

    let claims = decode_claims(&resp.access_token);
    assert_eq!(claims["sub"], auth.user.id.to_string());
}

// ── API key auth ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn api_key_issues_jwt_without_refresh_token() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    // Create an API key
    #[derive(serde::Deserialize)]
    struct CreateKeyResponse {
        key: String,
    }
    let key_resp = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/keys", &serde_json::json!({ "name": "test" }))
        .await
        .assert_status(201)
        .json::<CreateKeyResponse>();

    let resp = TestClient::new()
        .x_api_key(&key_resp.key)
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(200)
        .json::<TokenResponse>();

    assert!(!resp.access_token.is_empty());
    assert!(
        resp.refresh_token.is_none(),
        "API keys must not receive refresh tokens"
    );
}
