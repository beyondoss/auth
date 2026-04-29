use std::time::Duration;

use sqlx::PgPool;

/// Run one GC pass: delete expired one-time tokens and session tokens older than 1 day.
/// Session tokens expired less than 1 day ago are kept so in-flight requests that
/// grabbed a token just before expiry can still validate.
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
}

pub async fn run(pool: PgPool) {
    loop {
        run_once(&pool).await;
        tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
    }
}
