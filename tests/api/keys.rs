use crate::helpers::{TestClient, db_conn, signup, unique_email};

#[derive(serde::Deserialize)]
struct CreateKeyResponse {
    key: String,
    id: uuid::Uuid,
    name: String,
    #[allow(dead_code)]
    expires_at: String,
}

#[derive(serde::Deserialize)]
struct KeyRecord {
    id: uuid::Uuid,
    name: String,
}

#[derive(serde::Deserialize)]
struct KeysResponse {
    keys: Vec<KeyRecord>,
}

// ── POST /v1/keys ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_key_returns_token_and_metadata() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/keys", &serde_json::json!({ "name": "ci" }))
        .await
        .assert_status(201)
        .json::<CreateKeyResponse>();

    assert!(resp.key.starts_with("key_"), "token must use key_ prefix");
    assert_eq!(resp.name, "ci");
}

/// An API key token authenticates via `Authorization: Bearer key_...` — exercising
/// the `key` prefix dispatch branch in `middleware::auth::require_auth`.
#[tokio::test]
async fn created_key_authenticates_via_authorization_bearer() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/keys", &serde_json::json!({ "name": "test" }))
        .await
        .assert_status(201)
        .json::<CreateKeyResponse>();

    TestClient::new()
        .bearer(&resp.key)
        .get("/v1/users/me")
        .await
        .assert_status(200);
}

/// An API key token authenticates via the `x-api-key` header — the first extraction
/// branch in `require_auth`, taking priority over `Authorization: Bearer`.
#[tokio::test]
async fn created_key_authenticates_via_x_api_key_header() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/keys", &serde_json::json!({ "name": "test" }))
        .await
        .assert_status(201)
        .json::<CreateKeyResponse>();

    TestClient::new()
        .x_api_key(&resp.key)
        .get("/v1/users/me")
        .await
        .assert_status(200);
}

/// A key token with a wrong secret must be rejected — the secret_hash mismatch is
/// indistinguishable from a non-existent token (no timing oracle, no leaking which
/// segment was wrong).
#[tokio::test]
async fn key_wrong_secret_returns_401() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/keys", &serde_json::json!({ "name": "test" }))
        .await
        .assert_status(201)
        .json::<CreateKeyResponse>();

    // Token format: "key_{hex_id}_{secret_b64url}". Corrupt the secret segment.
    let parts: Vec<&str> = resp.key.splitn(3, '_').collect();
    let tampered = format!(
        "{}_{}_{}",
        parts[0], parts[1], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );

    TestClient::new()
        .bearer(&tampered)
        .get("/v1/users/me")
        .await
        .assert_status(401);
}

// ── GET /v1/keys ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_keys_includes_created_key() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let client = TestClient::new().bearer(&auth.session.token);

    let created = client
        .post("/v1/keys", &serde_json::json!({ "name": "listed" }))
        .await
        .assert_status(201)
        .json::<CreateKeyResponse>();

    let resp = client
        .get("/v1/keys")
        .await
        .assert_status(200)
        .json::<KeysResponse>();

    assert!(
        resp.keys.iter().any(|k| k.id == created.id),
        "created key must appear in list"
    );
}

// ── GET /v1/keys/{id} ─────────────────────────────────────────────────────────

#[tokio::test]
async fn get_key_by_id_returns_key() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let client = TestClient::new().bearer(&auth.session.token);

    let created = client
        .post("/v1/keys", &serde_json::json!({ "name": "named" }))
        .await
        .assert_status(201)
        .json::<CreateKeyResponse>();

    let fetched = client
        .get(&format!("/v1/keys/{}", created.id))
        .await
        .assert_status(200)
        .json::<KeyRecord>();

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.name, "named");
}

#[tokio::test]
async fn get_key_other_user_returns_404() {
    let user_a = signup(&unique_email(), "correct-horse-battery-staple").await;
    let user_b = signup(&unique_email(), "correct-horse-battery-staple").await;

    let created = TestClient::new()
        .bearer(&user_a.session.token)
        .post("/v1/keys", &serde_json::json!({ "name": "private" }))
        .await
        .assert_status(201)
        .json::<CreateKeyResponse>();

    TestClient::new()
        .bearer(&user_b.session.token)
        .get(&format!("/v1/keys/{}", created.id))
        .await
        .assert_status(404);
}

// ── DELETE /v1/keys/{id} ──────────────────────────────────────────────────────

#[tokio::test]
async fn delete_key_returns_204() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let client = TestClient::new().bearer(&auth.session.token);

    let created = client
        .post("/v1/keys", &serde_json::json!({ "name": "to-delete" }))
        .await
        .assert_status(201)
        .json::<CreateKeyResponse>();

    client
        .delete(&format!("/v1/keys/{}", created.id))
        .await
        .assert_status(204);
}

/// After deletion the backing token is gone; the key bearer must be rejected.
#[tokio::test]
async fn delete_key_invalidates_bearer() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let client = TestClient::new().bearer(&auth.session.token);

    let created = client
        .post("/v1/keys", &serde_json::json!({ "name": "revoke-me" }))
        .await
        .assert_status(201)
        .json::<CreateKeyResponse>();

    // Verify it works before deletion.
    TestClient::new()
        .bearer(&created.key)
        .get("/v1/users/me")
        .await
        .assert_status(200);

    client
        .delete(&format!("/v1/keys/{}", created.id))
        .await
        .assert_status(204);

    TestClient::new()
        .bearer(&created.key)
        .get("/v1/users/me")
        .await
        .assert_status(401);
}

#[tokio::test]
async fn delete_key_other_user_returns_404() {
    let user_a = signup(&unique_email(), "correct-horse-battery-staple").await;
    let user_b = signup(&unique_email(), "correct-horse-battery-staple").await;

    let created = TestClient::new()
        .bearer(&user_a.session.token)
        .post("/v1/keys", &serde_json::json!({ "name": "private" }))
        .await
        .assert_status(201)
        .json::<CreateKeyResponse>();

    TestClient::new()
        .bearer(&user_b.session.token)
        .delete(&format!("/v1/keys/{}", created.id))
        .await
        .assert_status(404);
}

// ── Expiry ────────────────────────────────────────────────────────────────────

/// An expired API key must be rejected. The validate() CTE checks `expires_at > now()`.
#[tokio::test]
async fn expired_key_returns_401() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let created = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/keys", &serde_json::json!({ "name": "short-lived" }))
        .await
        .assert_status(201)
        .json::<CreateKeyResponse>();

    // Push the token's expiry into the past.
    let mut conn = db_conn().await;
    sqlx::query(
        "UPDATE auth.tokens SET expires_at = now() - interval '1 second'
         WHERE id = (SELECT token_id FROM auth.keys WHERE id = $1)",
    )
    .bind(created.id)
    .execute(&mut conn)
    .await
    .unwrap();

    TestClient::new()
        .bearer(&created.key)
        .get("/v1/users/me")
        .await
        .assert_status(401);
}

// ── Soft-delete propagation ───────────────────────────────────────────────────

/// A soft-deleted user's API key must be rejected — `keys::validate()` joins
/// `auth.users WHERE deleted_at IS NULL`, so user deletion immediately invalidates
/// all existing keys without touching the tokens table.
#[tokio::test]
async fn deleted_user_key_returns_401() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let client = TestClient::new().bearer(&auth.session.token);

    let created = client
        .post("/v1/keys", &serde_json::json!({ "name": "orphan" }))
        .await
        .assert_status(201)
        .json::<CreateKeyResponse>();

    // Verify it works before deletion.
    TestClient::new()
        .bearer(&created.key)
        .get("/v1/users/me")
        .await
        .assert_status(200);

    client.delete("/v1/users/me").await.assert_status(204);

    TestClient::new()
        .bearer(&created.key)
        .get("/v1/users/me")
        .await
        .assert_status(401);
}
