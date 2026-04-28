use crate::helpers::{TestClient, signup, unique_email};

/// Minimal JSON that satisfies webauthn-rs `RegisterPublicKeyCredential` serde.
/// Used only to exercise state-token validation; the credential itself is never
/// cryptographically verified in these tests.
fn fake_reg_credential() -> serde_json::Value {
    serde_json::json!({
        "id": "aGVsbG8",
        "rawId": "aGVsbG8",
        "response": {
            "clientDataJSON": "aGVsbG8",
            "attestationObject": "aGVsbG8"
        },
        "type": "public-key",
        "extensions": {}
    })
}

/// Minimal JSON that satisfies webauthn-rs `PublicKeyCredential` serde.
fn fake_auth_credential() -> serde_json::Value {
    serde_json::json!({
        "id": "aGVsbG8",
        "rawId": "aGVsbG8",
        "response": {
            "clientDataJSON": "aGVsbG8",
            "authenticatorData": "aGVsbG8",
            "signature": "aGVsbG8",
            "userHandle": null
        },
        "type": "public-key"
    })
}

// ── POST /v1/passkey-registrations ───────────────────────────────────────────

#[derive(serde::Deserialize)]
struct BeginResponse {
    state_token: String,
}

#[tokio::test]
async fn begin_registration_requires_auth() {
    TestClient::new()
        .post("/v1/passkey-registrations", &serde_json::json!({}))
        .await
        .assert_status(401);
}

#[tokio::test]
async fn begin_registration_returns_state_token() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/passkey-registrations", &serde_json::json!({}))
        .await
        .assert_status(201)
        .json::<BeginResponse>();

    assert!(!resp.state_token.is_empty());
}

// ── POST /v1/passkeys (finish registration) ───────────────────────────────────

#[tokio::test]
async fn finish_registration_invalid_state_token_returns_401() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .post(
            "/v1/passkeys",
            &serde_json::json!({
                "state_token": "invalid.state.token",
                "credential": fake_reg_credential()
            }),
        )
        .await
        .assert_status(401);
}

// ── GET /v1/passkeys ──────────────────────────────────────────────────────────

#[tokio::test]
async fn list_passkeys_empty_when_none_registered() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let creds = TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/passkeys")
        .await
        .assert_status(200)
        .json::<Vec<serde_json::Value>>();

    assert!(creds.is_empty());
}

// ── PATCH /v1/passkeys/{id} ───────────────────────────────────────────────────

#[tokio::test]
async fn update_passkey_not_found_returns_404() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .patch(
            &format!("/v1/passkeys/{}", uuid::Uuid::now_v7()),
            &serde_json::json!({ "nickname": "My Key" }),
        )
        .await
        .assert_status(404);
}

// ── DELETE /v1/passkeys/{id} ──────────────────────────────────────────────────

#[tokio::test]
async fn delete_passkey_not_found_returns_404() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .delete(&format!("/v1/passkeys/{}", uuid::Uuid::now_v7()))
        .await
        .assert_status(404);
}

// ── POST /v1/passkey-authentications ─────────────────────────────────────────

#[tokio::test]
async fn begin_authentication_returns_state_token() {
    let resp = TestClient::new()
        .post("/v1/passkey-authentications", &serde_json::json!({}))
        .await
        .assert_status(200)
        .json::<BeginResponse>();

    assert!(!resp.state_token.is_empty());
}

// ── POST /v1/sessions (passkey grant) ─────────────────────────────────────────

#[tokio::test]
async fn passkey_session_grant_invalid_state_token_returns_401() {
    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "passkey",
                "state_token": "invalid.state.token",
                "credential": fake_auth_credential()
            }),
        )
        .await
        .assert_status(401);
}
