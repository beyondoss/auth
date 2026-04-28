use crate::helpers::{TestClient, enroll_totp, login, signup, totp_now, unique_email};

#[derive(serde::Deserialize)]
struct OttResponse {
    token: String,
}

#[derive(serde::Deserialize)]
struct StepUpResponse {
    step_up_token: String,
}

#[derive(serde::Deserialize)]
struct SessionItem {
    id: uuid::Uuid,
    current: bool,
}

#[derive(serde::Deserialize)]
struct SessionsResponse {
    sessions: Vec<SessionItem>,
}

/// Minimal shape for GET /v1/sessions/current (no `current` field).
#[derive(serde::Deserialize)]
struct CurrentSession {
    id: uuid::Uuid,
}

// ── Password grant ────────────────────────────────────────────────────────────

#[tokio::test]
async fn password_grant_invalid_credentials_returns_401() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password",
                "email": email,
                "password": "wrong-password"
            }),
        )
        .await
        .assert_status(401);
}

#[tokio::test]
async fn password_grant_unknown_email_returns_401() {
    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password",
                "email": unique_email(),
                "password": "correct-horse-battery-staple"
            }),
        )
        .await
        .assert_status(401);
}

// ── Magic-link grant ──────────────────────────────────────────────────────────

#[tokio::test]
async fn magic_link_grant_creates_session() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    let ott = TestClient::new()
        .post("/v1/magic-links", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200)
        .json::<OttResponse>();

    let auth = TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "magic_link",
                "token": ott.token
            }),
        )
        .await
        .assert_status(201)
        .json::<beyond_auth::AuthResponse>();

    assert_eq!(auth.email.email, email);
}

#[tokio::test]
async fn magic_link_grant_token_consumed_only_once() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    let ott = TestClient::new()
        .post("/v1/magic-links", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200)
        .json::<OttResponse>();

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "magic_link",
                "token": ott.token
            }),
        )
        .await
        .assert_status(201);

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "magic_link",
                "token": ott.token
            }),
        )
        .await
        .assert_status(401);
}

// ── Password-reset grant ──────────────────────────────────────────────────────

#[tokio::test]
async fn password_reset_grant_changes_password_and_creates_session() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    let ott = TestClient::new()
        .post("/v1/password-resets", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200)
        .json::<OttResponse>();

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password_reset",
                "token": ott.token,
                "new_password": "new-correct-horse-battery-staple"
            }),
        )
        .await
        .assert_status(201);

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password",
                "email": email,
                "password": "correct-horse-battery-staple"
            }),
        )
        .await
        .assert_status(401);

    login(&email, "new-correct-horse-battery-staple").await;
}

#[tokio::test]
async fn password_reset_grant_token_consumed_only_once() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    let ott = TestClient::new()
        .post("/v1/password-resets", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200)
        .json::<OttResponse>();

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password_reset",
                "token": ott.token,
                "new_password": "new-correct-horse-battery-staple"
            }),
        )
        .await
        .assert_status(201);

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password_reset",
                "token": ott.token,
                "new_password": "yet-another-correct-horse"
            }),
        )
        .await
        .assert_status(401);
}

#[tokio::test]
async fn password_reset_revokes_all_prior_sessions() {
    let email = unique_email();
    let original = signup(&email, "correct-horse-battery-staple").await;

    let ott = TestClient::new()
        .post("/v1/password-resets", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200)
        .json::<OttResponse>();

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password_reset",
                "token": ott.token,
                "new_password": "new-correct-horse-battery-staple"
            }),
        )
        .await
        .assert_status(201);

    TestClient::new()
        .bearer(&original.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(401);
}

// ── Email-change grant ────────────────────────────────────────────────────────

#[tokio::test]
async fn email_change_grant_updates_primary_email() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let new_email = unique_email();

    let ott = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/emails", &serde_json::json!({ "email": new_email }))
        .await
        .assert_status(200)
        .json::<OttResponse>();

    let new_auth = TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "email_change",
                "token": ott.token
            }),
        )
        .await
        .assert_status(201)
        .json::<beyond_auth::AuthResponse>();

    let me = TestClient::new()
        .bearer(&new_auth.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(200)
        .json::<beyond_auth::MeResponse>();

    assert_eq!(me.email.email, new_email);
}

#[tokio::test]
async fn email_change_grant_token_consumed_only_once() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let ott = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/emails", &serde_json::json!({ "email": unique_email() }))
        .await
        .assert_status(200)
        .json::<OttResponse>();

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "email_change",
                "token": ott.token
            }),
        )
        .await
        .assert_status(201);

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "email_change",
                "token": ott.token
            }),
        )
        .await
        .assert_status(401);
}

#[tokio::test]
async fn email_change_revokes_all_prior_sessions() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let ott = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/emails", &serde_json::json!({ "email": unique_email() }))
        .await
        .assert_status(200)
        .json::<OttResponse>();

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "email_change",
                "token": ott.token
            }),
        )
        .await
        .assert_status(201);

    TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(401);
}

// ── TOTP step-up grant ────────────────────────────────────────────────────────

#[tokio::test]
async fn totp_password_login_returns_step_up_when_enrolled() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;
    enroll_totp(&auth.session.token).await;

    let step_up = TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password",
                "email": email,
                "password": "correct-horse-battery-staple"
            }),
        )
        .await
        .assert_status(200)
        .json::<StepUpResponse>();

    assert!(!step_up.step_up_token.is_empty());
}

#[tokio::test]
async fn totp_step_up_valid_code_creates_session() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;
    let enrollment = enroll_totp(&auth.session.token).await;

    let step_up = TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password",
                "email": email,
                "password": "correct-horse-battery-staple"
            }),
        )
        .await
        .assert_status(200)
        .json::<StepUpResponse>();

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "totp_step_up",
                "step_up_token": step_up.step_up_token,
                "code": totp_now(&enrollment.secret_b32)
            }),
        )
        .await
        .assert_status(201);
}

#[tokio::test]
async fn totp_step_up_invalid_code_returns_401() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;
    enroll_totp(&auth.session.token).await;

    let step_up = TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password",
                "email": email,
                "password": "correct-horse-battery-staple"
            }),
        )
        .await
        .assert_status(200)
        .json::<StepUpResponse>();

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "totp_step_up",
                "step_up_token": step_up.step_up_token,
                "code": "000000"
            }),
        )
        .await
        .assert_status(401);
}

#[tokio::test]
async fn totp_step_up_replay_in_same_window_rejected() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;
    let enrollment = enroll_totp(&auth.session.token).await;

    let step_up = TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password",
                "email": email,
                "password": "correct-horse-battery-staple"
            }),
        )
        .await
        .assert_status(200)
        .json::<StepUpResponse>();

    let code = totp_now(&enrollment.secret_b32);

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "totp_step_up",
                "step_up_token": step_up.step_up_token,
                "code": code
            }),
        )
        .await
        .assert_status(201);

    let step_up2 = TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password",
                "email": email,
                "password": "correct-horse-battery-staple"
            }),
        )
        .await
        .assert_status(200)
        .json::<StepUpResponse>();

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "totp_step_up",
                "step_up_token": step_up2.step_up_token,
                "code": code
            }),
        )
        .await
        .assert_status(401);
}

#[tokio::test]
async fn totp_recovery_code_creates_session() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;
    let enrollment = enroll_totp(&auth.session.token).await;

    let step_up = TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password",
                "email": email,
                "password": "correct-horse-battery-staple"
            }),
        )
        .await
        .assert_status(200)
        .json::<StepUpResponse>();

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "totp_recovery",
                "step_up_token": step_up.step_up_token,
                "code": enrollment.recovery_codes[0]
            }),
        )
        .await
        .assert_status(201);
}

#[tokio::test]
async fn totp_recovery_code_consumed_only_once() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;
    let enrollment = enroll_totp(&auth.session.token).await;

    let step_up = TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password",
                "email": email,
                "password": "correct-horse-battery-staple"
            }),
        )
        .await
        .assert_status(200)
        .json::<StepUpResponse>();

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "totp_recovery",
                "step_up_token": step_up.step_up_token,
                "code": enrollment.recovery_codes[0]
            }),
        )
        .await
        .assert_status(201);

    let step_up2 = TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password",
                "email": email,
                "password": "correct-horse-battery-staple"
            }),
        )
        .await
        .assert_status(200)
        .json::<StepUpResponse>();

    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "totp_recovery",
                "step_up_token": step_up2.step_up_token,
                "code": enrollment.recovery_codes[0]
            }),
        )
        .await
        .assert_status(401);
}

// ── Session management ────────────────────────────────────────────────────────

#[tokio::test]
async fn list_sessions_shows_current_flag() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;
    login(&email, "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/sessions")
        .await
        .assert_status(200)
        .json::<SessionsResponse>();

    assert_eq!(resp.sessions.len(), 2);

    let current_sessions: Vec<_> = resp.sessions.iter().filter(|s| s.current).collect();
    assert_eq!(current_sessions.len(), 1);
    assert_eq!(current_sessions[0].id, auth.session.id);
}

#[tokio::test]
async fn get_current_session_returns_details() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let session = TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/sessions/current")
        .await
        .assert_status(200)
        .json::<CurrentSession>();

    assert_eq!(session.id, auth.session.id);
}

#[tokio::test]
async fn delete_current_session_invalidates_bearer() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .delete("/v1/sessions/current")
        .await
        .assert_status(204);

    TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(401);
}

#[tokio::test]
async fn delete_session_by_id_returns_204() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;
    let auth2 = login(&email, "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .delete(&format!("/v1/sessions/{}", auth2.session.id))
        .await
        .assert_status(204);

    TestClient::new()
        .bearer(&auth2.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(401);
}

#[tokio::test]
async fn delete_session_by_id_other_user_returns_404() {
    let user_a = signup(&unique_email(), "correct-horse-battery-staple").await;
    let user_b = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&user_a.session.token)
        .delete(&format!("/v1/sessions/{}", user_b.session.id))
        .await
        .assert_status(404);
}
