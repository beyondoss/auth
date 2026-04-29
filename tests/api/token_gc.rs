use crate::helpers::{db_conn, signup, test_env, unique_email};

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn gc_pool() -> sqlx::PgPool {
    sqlx::PgPool::connect(&test_env().database_url)
        .await
        .expect("failed to open pool for GC test")
}

// ── one_time_tokens ───────────────────────────────────────────────────────────

#[tokio::test]
async fn gc_removes_expired_one_time_tokens() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let ott_id = uuid::Uuid::now_v7();
    let mut conn = db_conn().await;
    sqlx::query(
        "INSERT INTO auth.one_time_tokens (id, user_id, kind, secret, expires_at)
         VALUES ($1, $2, 'pwr', $3, now() - interval '1 hour')",
    )
    .bind(ott_id)
    .bind(auth.user.id)
    .bind(vec![0u8; 32])
    .execute(&mut conn)
    .await
    .unwrap();

    beyond_auth::token_gc::run_once(&gc_pool().await).await;

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth.one_time_tokens WHERE id = $1)")
            .bind(ott_id)
            .fetch_one(&mut conn)
            .await
            .unwrap();

    assert!(!exists, "expired OTT must be removed by GC");
}

#[tokio::test]
async fn gc_preserves_unexpired_one_time_tokens() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let ott_id = uuid::Uuid::now_v7();
    let mut conn = db_conn().await;
    sqlx::query(
        "INSERT INTO auth.one_time_tokens (id, user_id, kind, secret, expires_at)
         VALUES ($1, $2, 'pwr', $3, now() + interval '10 minutes')",
    )
    .bind(ott_id)
    .bind(auth.user.id)
    .bind(vec![0u8; 32])
    .execute(&mut conn)
    .await
    .unwrap();

    beyond_auth::token_gc::run_once(&gc_pool().await).await;

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth.one_time_tokens WHERE id = $1)")
            .bind(ott_id)
            .fetch_one(&mut conn)
            .await
            .unwrap();

    assert!(exists, "unexpired OTT must be preserved by GC");
}

// ── tokens + cascade ──────────────────────────────────────────────────────────

/// Session tokens expired more than 1 day ago are removed; their sessions are
/// cascade-deleted via the FK ON DELETE CASCADE on auth.sessions.token_id.
#[tokio::test]
async fn gc_removes_old_session_tokens_and_cascades_to_sessions() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let mut conn = db_conn().await;
    sqlx::query(
        "UPDATE auth.tokens SET expires_at = now() - interval '2 days'
         WHERE id = (SELECT token_id FROM auth.sessions WHERE id = $1)",
    )
    .bind(auth.session.id)
    .execute(&mut conn)
    .await
    .unwrap();

    beyond_auth::token_gc::run_once(&gc_pool().await).await;

    let session_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth.sessions WHERE id = $1)")
            .bind(auth.session.id)
            .fetch_one(&mut conn)
            .await
            .unwrap();

    assert!(
        !session_exists,
        "session must be cascade-deleted when its token is GC'd"
    );
}

/// Session tokens expired less than 1 day ago are kept (grace window for
/// in-flight requests). Their sessions must remain intact.
#[tokio::test]
async fn gc_preserves_recently_expired_session_tokens() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let mut conn = db_conn().await;
    sqlx::query(
        "UPDATE auth.tokens SET expires_at = now() - interval '1 hour'
         WHERE id = (SELECT token_id FROM auth.sessions WHERE id = $1)",
    )
    .bind(auth.session.id)
    .execute(&mut conn)
    .await
    .unwrap();

    beyond_auth::token_gc::run_once(&gc_pool().await).await;

    let session_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth.sessions WHERE id = $1)")
            .bind(auth.session.id)
            .fetch_one(&mut conn)
            .await
            .unwrap();

    assert!(
        session_exists,
        "recently-expired session token must be preserved within the 1-day grace window"
    );
}
