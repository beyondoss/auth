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
