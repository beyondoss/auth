#![allow(dead_code)]

use std::time::Duration;

use sqlx::PgPool;

pub async fn run(pool: PgPool) {
    loop {
        if let Err(e) = sqlx::query!("DELETE FROM auth.one_time_tokens WHERE expires_at < now()")
            .execute(&pool)
            .await
        {
            tracing::error!(error = %e, "one_time_tokens gc failed");
        }
        // Expired tokens cascade-delete their sessions via FK ON DELETE CASCADE.
        if let Err(e) = sqlx::query!(
            "DELETE FROM auth.tokens WHERE expires_at < now() - interval '1 day'"
        )
        .execute(&pool)
        .await
        {
            tracing::error!(error = %e, "tokens gc failed");
        }
        tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
    }
}
