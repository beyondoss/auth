use crate::helpers::{TestClient, signup, unique_email};

#[derive(serde::Deserialize)]
struct EmailRecord {
    id: uuid::Uuid,
    email: String,
    verified_at: Option<chrono::DateTime<chrono::Utc>>,
    is_primary: bool,
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    token: String,
}

#[derive(serde::Deserialize)]
struct ConfirmVerificationResponse {
    verified_at: chrono::DateTime<chrono::Utc>,
}

// ── GET /v1/emails ────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_emails_returns_signup_email() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;

    let records = TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/emails")
        .await
        .assert_status(200)
        .json::<Vec<EmailRecord>>();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].email, email);
    assert!(records[0].is_primary);
    assert!(records[0].verified_at.is_none());
}

// ── POST /v1/emails ───────────────────────────────────────────────────────────

#[tokio::test]
async fn initiate_email_change_returns_token() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .post(
            "/v1/emails",
            &serde_json::json!({ "email": unique_email() }),
        )
        .await
        .assert_status(200)
        .json::<TokenResponse>();

    assert!(
        resp.token.starts_with("ec_"),
        "token must start with ec_, got: {}",
        resp.token
    );
}

#[tokio::test]
async fn initiate_email_change_duplicate_email_returns_409() {
    let user_a = signup(&unique_email(), "correct-horse-battery-staple").await;
    let user_b_email = unique_email();
    let user_b = signup(&user_b_email, "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&user_a.session.token)
        .post("/v1/emails", &serde_json::json!({ "email": user_b_email }))
        .await
        .assert_status(409);

    let _ = user_b;
}

#[tokio::test]
async fn initiate_email_change_requires_auth() {
    TestClient::new()
        .post(
            "/v1/emails",
            &serde_json::json!({ "email": unique_email() }),
        )
        .await
        .assert_status(401);
}

// ── POST /v1/emails/{id}/verifications ───────────────────────────────────────

#[tokio::test]
async fn create_verification_returns_token() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .post(
            &format!("/v1/emails/{}/verifications", auth.email.id),
            &serde_json::json!({}),
        )
        .await
        .assert_status(200)
        .json::<TokenResponse>();

    assert!(
        resp.token.starts_with("ev_"),
        "token must start with ev_, got: {}",
        resp.token
    );
}

#[tokio::test]
async fn create_verification_already_verified_returns_404() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let ev = TestClient::new()
        .bearer(&auth.session.token)
        .post(
            &format!("/v1/emails/{}/verifications", auth.email.id),
            &serde_json::json!({}),
        )
        .await
        .assert_status(200)
        .json::<TokenResponse>();

    TestClient::new()
        .post(
            "/v1/emails/verifications",
            &serde_json::json!({ "token": ev.token }),
        )
        .await
        .assert_status(200);

    TestClient::new()
        .bearer(&auth.session.token)
        .post(
            &format!("/v1/emails/{}/verifications", auth.email.id),
            &serde_json::json!({}),
        )
        .await
        .assert_status(404);
}

// ── POST /v1/emails/verifications ────────────────────────────────────────────

#[tokio::test]
async fn confirm_verification_marks_email_verified() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let ev = TestClient::new()
        .bearer(&auth.session.token)
        .post(
            &format!("/v1/emails/{}/verifications", auth.email.id),
            &serde_json::json!({}),
        )
        .await
        .assert_status(200)
        .json::<TokenResponse>();

    let confirmed = TestClient::new()
        .post(
            "/v1/emails/verifications",
            &serde_json::json!({ "token": ev.token }),
        )
        .await
        .assert_status(200)
        .json::<ConfirmVerificationResponse>();

    assert!(confirmed.verified_at <= chrono::Utc::now());

    let records = TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/emails")
        .await
        .assert_status(200)
        .json::<Vec<EmailRecord>>();

    assert!(
        records
            .iter()
            .any(|e| e.id == auth.email.id && e.verified_at.is_some()),
        "email must show as verified after confirmation"
    );
}

#[tokio::test]
async fn confirm_verification_token_consumed_only_once() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let ev = TestClient::new()
        .bearer(&auth.session.token)
        .post(
            &format!("/v1/emails/{}/verifications", auth.email.id),
            &serde_json::json!({}),
        )
        .await
        .assert_status(200)
        .json::<TokenResponse>();

    TestClient::new()
        .post(
            "/v1/emails/verifications",
            &serde_json::json!({ "token": ev.token }),
        )
        .await
        .assert_status(200);

    TestClient::new()
        .post(
            "/v1/emails/verifications",
            &serde_json::json!({ "token": ev.token }),
        )
        .await
        .assert_status(401);
}

// ── DELETE /v1/emails/{id} ────────────────────────────────────────────────────

#[tokio::test]
async fn remove_primary_email_returns_409() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .delete(&format!("/v1/emails/{}", auth.email.id))
        .await
        .assert_status(409);
}

#[tokio::test]
async fn remove_nonexistent_email_returns_404() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .delete(&format!("/v1/emails/{}", uuid::Uuid::now_v7()))
        .await
        .assert_status(404);
}

// ── PUT /v1/emails/{id} ───────────────────────────────────────────────────────

#[tokio::test]
async fn make_primary_unverified_email_returns_404() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .put(
            &format!("/v1/emails/{}", auth.email.id),
            &serde_json::json!({}),
        )
        .await
        .assert_status(404);
}

#[tokio::test]
async fn make_verified_email_primary_returns_204() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let ev = TestClient::new()
        .bearer(&auth.session.token)
        .post(
            &format!("/v1/emails/{}/verifications", auth.email.id),
            &serde_json::json!({}),
        )
        .await
        .assert_status(200)
        .json::<TokenResponse>();

    TestClient::new()
        .post(
            "/v1/emails/verifications",
            &serde_json::json!({ "token": ev.token }),
        )
        .await
        .assert_status(200);

    TestClient::new()
        .bearer(&auth.session.token)
        .put(
            &format!("/v1/emails/{}", auth.email.id),
            &serde_json::json!({}),
        )
        .await
        .assert_status(204);
}
