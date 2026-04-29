use crate::helpers::{
    TestClient, db_conn, enroll_totp, exclusive, login, signup, totp_now, unique_email,
};

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
        .post(
            "/v1/password-resets",
            &serde_json::json!({ "email": email }),
        )
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
        .post(
            "/v1/password-resets",
            &serde_json::json!({ "email": email }),
        )
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
async fn password_reset_grant_expired_token_returns_401() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    let ott = TestClient::new()
        .post(
            "/v1/password-resets",
            &serde_json::json!({ "email": email }),
        )
        .await
        .assert_status(200)
        .json::<OttResponse>();

    let token_hex = ott
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
                "grant_type": "password_reset",
                "token": ott.token,
                "new_password": "new-correct-horse-battery-staple"
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
        .post(
            "/v1/password-resets",
            &serde_json::json!({ "email": email }),
        )
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
        .post(
            "/v1/emails",
            &serde_json::json!({ "email": unique_email() }),
        )
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
        .post(
            "/v1/emails",
            &serde_json::json!({ "email": unique_email() }),
        )
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

// ── Soft-delete ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn deleted_user_cannot_login() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .delete("/v1/users/me")
        .await
        .assert_status(204);

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
}

// ── Concurrent token consumption ──────────────────────────────────────────────

#[tokio::test]
async fn magic_link_token_consumed_exactly_once_concurrently() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    let ott = TestClient::new()
        .post("/v1/magic-links", &serde_json::json!({ "email": email }))
        .await
        .assert_status(200)
        .json::<OttResponse>();

    let grant = serde_json::json!({
        "grant_type": "magic_link",
        "token": ott.token
    });

    let (c1, c2) = (TestClient::new(), TestClient::new());
    let (r1, r2) = tokio::join!(
        c1.post("/v1/sessions", &grant),
        c2.post("/v1/sessions", &grant),
    );

    let statuses = [r1.status(), r2.status()];
    assert_eq!(
        statuses.iter().filter(|&&s| s == 201).count(),
        1,
        "exactly one concurrent request must create a session"
    );
    assert_eq!(
        statuses.iter().filter(|&&s| s == 401).count(),
        1,
        "exactly one concurrent request must be rejected"
    );
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

// ── Deleted-user session invalidation ─────────────────────────────────────────

/// A bearer token held by a soft-deleted user must be rejected — the validate()
/// CTE joins `users WHERE deleted_at IS NULL`, so deletion immediately
/// invalidates all existing sessions without touching the tokens table.
#[tokio::test]
async fn deleted_user_existing_session_is_rejected() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .delete("/v1/users/me")
        .await
        .assert_status(204);

    TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(401);
}

// ── Token expiry ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn expired_session_token_is_rejected() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let mut conn = db_conn().await;
    sqlx::query(
        "UPDATE auth.tokens SET expires_at = now() - interval '1 second'
         WHERE id = (SELECT token_id FROM auth.sessions WHERE id = $1)",
    )
    .bind(auth.session.id)
    .execute(&mut conn)
    .await
    .unwrap();

    TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(401);
}

// ── last_used_at debounce ─────────────────────────────────────────────────────

/// The validate() CTE only writes last_used_at when it is NULL or older than
/// 1 minute. Two back-to-back requests within that window must leave the
/// timestamp unchanged after the first write.
#[tokio::test]
async fn last_used_at_debounce_skips_update_within_window() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    // First authenticated request — last_used_at starts NULL, gets set.
    TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(200);

    let mut conn = db_conn().await;
    let first: Option<String> = sqlx::query_scalar(
        "SELECT tok.last_used_at::text
         FROM auth.tokens tok
         INNER JOIN auth.sessions s ON s.token_id = tok.id
         WHERE s.id = $1",
    )
    .bind(auth.session.id)
    .fetch_one(&mut conn)
    .await
    .unwrap();

    assert!(first.is_some(), "first use must set last_used_at");

    // Immediate second request — debounce window (1 minute) has not elapsed.
    TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(200);

    let second: Option<String> = sqlx::query_scalar(
        "SELECT tok.last_used_at::text
         FROM auth.tokens tok
         INNER JOIN auth.sessions s ON s.token_id = tok.id
         WHERE s.id = $1",
    )
    .bind(auth.session.id)
    .fetch_one(&mut conn)
    .await
    .unwrap();

    assert_eq!(
        first, second,
        "debounce must skip last_used_at update within 1 minute"
    );
}

// ── Session idle timeout ──────────────────────────────────────────────────────

/// When a session's last_used_at falls outside the configured idle window,
/// subsequent requests must be rejected — the validate() CTE checks
/// `last_used_at > now() - make_interval(secs => $idle_timeout)`.
///
/// Uses `exclusive()` because it mutates the global session_idle_timeout_seconds
/// config. The timeout is always restored to NULL so other tests are unaffected.
#[tokio::test]
async fn idle_session_rejected_after_timeout() {
    let _guard = exclusive().await;

    // Set a 1-second idle window.
    TestClient::new()
        .admin()
        .patch(
            "/v1/admin/config",
            &serde_json::json!({ "session_idle_timeout_seconds": 1 }),
        )
        .await
        .assert_status(200);

    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    // First use sets last_used_at (starts NULL).
    TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(200);

    // Push last_used_at beyond the 1-second idle window.
    let mut conn = db_conn().await;
    sqlx::query(
        "UPDATE auth.tokens SET last_used_at = now() - interval '2 seconds'
         WHERE id = (SELECT token_id FROM auth.sessions WHERE id = $1)",
    )
    .bind(auth.session.id)
    .execute(&mut conn)
    .await
    .unwrap();

    TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(401);

    // Restore: clear idle timeout so parallel tests are not affected.
    TestClient::new()
        .admin()
        .patch(
            "/v1/admin/config",
            &serde_json::json!({ "session_idle_timeout_seconds": null }),
        )
        .await
        .assert_status(200);
}

// ── DELETE /v1/sessions ───────────────────────────────────────────────────────

#[tokio::test]
async fn delete_all_sessions_requires_auth() {
    TestClient::new()
        .delete("/v1/sessions")
        .await
        .assert_status(401);
}

#[tokio::test]
async fn delete_all_sessions_revokes_all() {
    let email = unique_email();
    let first = signup(&email, "correct-horse-battery-staple").await;
    let second = login(&email, "correct-horse-battery-staple").await;
    let third = login(&email, "correct-horse-battery-staple").await;

    // Revoke all sessions from the third session's bearer.
    TestClient::new()
        .bearer(&third.session.token)
        .delete("/v1/sessions")
        .await
        .assert_status(204);

    // All three tokens must be invalidated.
    for token in [
        &first.session.token,
        &second.session.token,
        &third.session.token,
    ] {
        TestClient::new()
            .bearer(token)
            .get("/v1/users/me")
            .await
            .assert_status(401);
    }
}

#[tokio::test]
async fn delete_all_sessions_except_current_keeps_current() {
    let email = unique_email();
    let first = signup(&email, "correct-horse-battery-staple").await;
    let second = login(&email, "correct-horse-battery-staple").await;

    // Revoke all except the current session (second).
    TestClient::new()
        .bearer(&second.session.token)
        .delete("/v1/sessions?except_current=true")
        .await
        .assert_status(204);

    // First session must be gone.
    TestClient::new()
        .bearer(&first.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(401);

    // Current session must still work.
    TestClient::new()
        .bearer(&second.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(200);
}

#[tokio::test]
async fn delete_all_sessions_idempotent_on_empty() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    // First call revokes everything.
    TestClient::new()
        .bearer(&auth.session.token)
        .delete("/v1/sessions")
        .await
        .assert_status(204);

    // No sessions remain — verify via DB.
    let mut conn = db_conn().await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth.sessions WHERE user_id = $1")
        .bind(auth.user.id)
        .fetch_one(&mut conn)
        .await
        .unwrap();

    assert_eq!(count, 0, "all sessions must be gone after delete_all");
}
