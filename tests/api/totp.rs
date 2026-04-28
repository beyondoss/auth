use crate::helpers::{TestClient, enroll_totp, login, signup, totp_now, unique_email};

#[derive(serde::Deserialize)]
struct EnrollmentResponse {
    secret_b32: String,
    recovery_codes: Vec<String>,
}

#[derive(serde::Deserialize)]
struct RecoveryCodesResponse {
    recovery_codes: Vec<String>,
}

// ── POST /v1/totp (begin enrollment) ─────────────────────────────────────────

#[tokio::test]
async fn begin_enrollment_returns_secret_and_recovery_codes() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let enrollment = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/totp", &serde_json::json!({}))
        .await
        .assert_status(200)
        .json::<EnrollmentResponse>();

    assert!(!enrollment.secret_b32.is_empty());
    assert_eq!(enrollment.recovery_codes.len(), 10);
}

#[tokio::test]
async fn begin_enrollment_restart_clears_in_progress_factor() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let enrollment1 = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/totp", &serde_json::json!({}))
        .await
        .assert_status(200)
        .json::<EnrollmentResponse>();

    let enrollment2 = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/totp", &serde_json::json!({}))
        .await
        .assert_status(200)
        .json::<EnrollmentResponse>();

    assert_ne!(enrollment1.secret_b32, enrollment2.secret_b32);

    let code = totp_now(&enrollment2.secret_b32);
    TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/totp/confirmations", &serde_json::json!({ "code": code }))
        .await
        .assert_status(204);
}

// ── POST /v1/totp/confirmations ───────────────────────────────────────────────

#[tokio::test]
async fn confirm_with_valid_code_returns_204() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let enrollment = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/totp", &serde_json::json!({}))
        .await
        .assert_status(200)
        .json::<EnrollmentResponse>();

    let code = totp_now(&enrollment.secret_b32);
    TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/totp/confirmations", &serde_json::json!({ "code": code }))
        .await
        .assert_status(204);
}

#[tokio::test]
async fn confirm_with_invalid_code_returns_401() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/totp", &serde_json::json!({}))
        .await
        .assert_status(200);

    TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/totp/confirmations", &serde_json::json!({ "code": "000000" }))
        .await
        .assert_status(401);
}

// ── DELETE /v1/totp ───────────────────────────────────────────────────────────

#[tokio::test]
async fn disable_totp_returns_204() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;
    enroll_totp(&auth.session.token).await;

    TestClient::new()
        .bearer(&auth.session.token)
        .delete("/v1/totp")
        .await
        .assert_status(204);

    login(&email, "correct-horse-battery-staple").await;
}

#[tokio::test]
async fn disable_when_not_enrolled_returns_404() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .delete("/v1/totp")
        .await
        .assert_status(404);
}

// ── POST /v1/totp/recovery-codes ──────────────────────────────────────────────

#[tokio::test]
async fn regenerate_recovery_codes_returns_10_new_codes() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let enrollment = enroll_totp(&auth.session.token).await;

    let code = totp_now(&enrollment.secret_b32);
    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/totp/recovery-codes", &serde_json::json!({ "code": code }))
        .await
        .assert_status(200)
        .json::<RecoveryCodesResponse>();

    assert_eq!(resp.recovery_codes.len(), 10);
    assert_ne!(resp.recovery_codes, enrollment.recovery_codes);
}

#[tokio::test]
async fn prior_recovery_codes_rejected_after_regeneration() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;
    let enrollment = enroll_totp(&auth.session.token).await;

    // Regenerate using a fresh TOTP code.
    let code = totp_now(&enrollment.secret_b32);
    TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/totp/recovery-codes", &serde_json::json!({ "code": code }))
        .await
        .assert_status(200);

    // The original recovery code must now be rejected.
    #[derive(serde::Deserialize)]
    struct StepUpResponse {
        step_up_token: String,
    }

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
        .assert_status(401);
}

#[tokio::test]
async fn regenerate_recovery_codes_invalid_totp_returns_401() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    enroll_totp(&auth.session.token).await;

    TestClient::new()
        .bearer(&auth.session.token)
        .post("/v1/totp/recovery-codes", &serde_json::json!({ "code": "000000" }))
        .await
        .assert_status(401);
}
