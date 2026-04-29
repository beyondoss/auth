use std::time::Duration;

use sqlx::PgPool;

/// Run one GC pass: delete expired one-time tokens and session tokens older than 1 day.
/// Session tokens expired less than 1 day ago are kept so in-flight requests that
/// grabbed a token just before expiry can still validate.
/// Also deletes idle-expired tokens when session_idle_timeout_seconds is configured.
pub async fn run_once(pool: &PgPool) {
    if let Err(e) = sqlx::query!("DELETE FROM auth.one_time_tokens WHERE expires_at < now()")
        .execute(pool)
        .await
    {
        tracing::error!(error = %e, "one_time_tokens gc failed");
    }
    // Expired tokens cascade-delete their sessions via FK ON DELETE CASCADE.
    if let Err(e) =
        sqlx::query!("DELETE FROM auth.tokens WHERE expires_at < now() - interval '1 day'")
            .execute(pool)
            .await
    {
        tracing::error!(error = %e, "tokens gc failed");
    }
    // Idle-expired tokens: only active when session_idle_timeout_seconds is set.
    if let Err(e) = sqlx::query!(
        r#"
        DELETE FROM auth.tokens t
        USING auth.app_config cfg
        WHERE cfg.id = true
          AND cfg.session_idle_timeout_seconds IS NOT NULL
          AND t.last_used_at IS NOT NULL
          AND t.last_used_at < now() - make_interval(secs => cfg.session_idle_timeout_seconds::float8)
        "#
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = %e, "idle session gc failed");
    }
}

pub async fn run(pool: PgPool) {
    loop {
        run_once(&pool).await;
        tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
    }
}
