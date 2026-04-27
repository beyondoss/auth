use std::time::Duration;

use sqlx::PgPool;

pub async fn run(pool: PgPool) {
    loop {
        if let Err(e) = sqlx::query!("DELETE FROM auth.one_time_token WHERE expires_at < now()")
            .execute(&pool)
            .await
        {
            tracing::error!(error = %e, "one_time_token gc failed");
        }
        tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
    }
}
