use crate::helpers::{TestClient, db_conn, signup, unique_email};

/// Full-chain example: signup → authenticated request → typed response → DB verification.
/// This test doubles as a harness smoke test — it exercises every helper in sequence.
#[tokio::test]
async fn get_me_returns_signed_up_user() {
    let email = unique_email();
    let auth = signup(&email, "correct-horse-battery-staple").await;

    let me = TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(200)
        .json::<beyond_auth::MeResponse>();

    assert_eq!(me.email.email, email);
    assert_eq!(me.org.id, auth.org.id);

    // Verify the row landed in the database — demonstrates db_conn() for side-effect checks.
    let mut conn = db_conn().await;
    let row = sqlx::query!("SELECT id FROM users WHERE id = $1", auth.user.id)
        .fetch_optional(&mut conn)
        .await
        .unwrap();
    assert!(row.is_some(), "user {} not found in database", auth.user.id);
}

// ── POST /v1/users ────────────────────────────────────────────────────────────

#[tokio::test]
async fn signup_duplicate_email_returns_409() {
    let email = unique_email();
    signup(&email, "correct-horse-battery-staple").await;

    TestClient::new()
        .post(
            "/v1/users",
            &serde_json::json!({ "email": email, "password": "correct-horse-battery-staple" }),
        )
        .await
        .assert_status(409);
}

#[tokio::test]
async fn signup_short_password_returns_422() {
    TestClient::new()
        .post(
            "/v1/users",
            &serde_json::json!({ "email": unique_email(), "password": "short" }),
        )
        .await
        .assert_status(422);
}

#[tokio::test]
async fn signup_common_password_returns_422() {
    TestClient::new()
        .post(
            "/v1/users",
            &serde_json::json!({ "email": unique_email(), "password": "password123" }),
        )
        .await
        .assert_status(422);
}

// ── GET /v1/users/me ──────────────────────────────────────────────────────────

#[tokio::test]
async fn get_me_without_auth_returns_401() {
    TestClient::new().get("/v1/users/me").await.assert_status(401);
}

// ── PATCH /v1/users/me ────────────────────────────────────────────────────────

#[tokio::test]
async fn update_me_updates_personal_org() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let updated = TestClient::new()
        .bearer(&auth.session.token)
        .patch(
            "/v1/users/me",
            &serde_json::json!({ "name": "New Display Name" }),
        )
        .await
        .assert_status(200)
        .json::<beyond_auth::MeResponse>();

    assert_eq!(updated.org.name, "New Display Name");
    assert_eq!(updated.org.id, auth.org.id);
}

#[tokio::test]
async fn update_me_slug_conflict_returns_409() {
    let a = signup(&unique_email(), "correct-horse-battery-staple").await;
    let b = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&b.session.token)
        .patch("/v1/users/me", &serde_json::json!({ "slug": a.org.slug }))
        .await
        .assert_status(409);
}

// ── DELETE /v1/users/me ───────────────────────────────────────────────────────

#[tokio::test]
async fn delete_me_returns_204_and_invalidates_session() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .delete("/v1/users/me")
        .await
        .assert_status(204);

    // The bearer token must no longer authenticate.
    TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/users/me")
        .await
        .assert_status(401);
}
