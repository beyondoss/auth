use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::helpers::{TestClient, login, signup, unique_email};

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
}

#[derive(serde::Deserialize)]
struct JwkSet {
    keys: Vec<serde_json::Value>,
}

fn decode_claims(jwt: &str) -> serde_json::Value {
    let part = jwt.split('.').nth(1).expect("JWT must have 3 parts");
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .expect("claims must be valid base64url");
    serde_json::from_slice(&bytes).expect("claims must be valid JSON")
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

// ── JWKS endpoint ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn jwks_endpoint_returns_valid_ed25519_key() {
    let jwks = TestClient::new()
        .get("/v1/jwks.json")
        .await
        .assert_status(200)
        .json::<JwkSet>();

    assert!(!jwks.keys.is_empty());
    let key = &jwks.keys[0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert_eq!(key["use"], "sig");
    assert_eq!(key["alg"], "EdDSA");
    assert!(key["kid"].is_string(), "kid must be present");
    // Ed25519 public key is 32 bytes → 43 chars base64url no-pad
    assert_eq!(
        key["x"].as_str().expect("x must be a string").len(),
        43,
        "x must be a 43-char base64url-encoded Ed25519 public key"
    );
}

// ── JWT claims ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn jwt_claims_contain_correct_sub_and_no_impersonation_flag() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/tokens", &serde_json::json!({}))
        .await
        .assert_status(200)
        .json::<TokenResponse>();

    let claims = decode_claims(&resp.access_token);
    assert_eq!(claims["sub"], auth.user.id.to_string());
    assert!(
        claims.get("impersonated").is_none(),
        "impersonated flag must be absent for normal sessions"
    );
}

#[tokio::test]
async fn impersonated_jwt_carries_impersonated_flag() {
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

    let claims = decode_claims(&resp.access_token);
    assert_eq!(claims["sub"], auth.user.id.to_string());
    assert_eq!(
        claims["impersonated"], true,
        "impersonated JWT must carry the impersonated flag"
    );
}
