use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;

use crate::metrics::Metrics;

/// Run one GC pass: delete expired one-time tokens and session tokens older than 1 day.
/// Session tokens expired less than 1 day ago are kept so in-flight requests that
/// grabbed a token just before expiry can still validate.
/// Also deletes idle-expired tokens when session_idle_timeout_seconds is configured.
pub async fn run_once(pool: &PgPool, metrics: &Metrics) {
    let mut deleted_one_time: u64 = 0;
    let mut deleted_session: u64 = 0;
    let mut deleted_idle: u64 = 0;

    match sqlx::query!("DELETE FROM auth.one_time_tokens WHERE expires_at < now()")
        .execute(pool)
        .await
    {
        Ok(r) => {
            deleted_one_time = r.rows_affected();
            metrics
                .token_gc_deleted_total
                .with_label_values(&["one_time"])
                .inc_by(deleted_one_time as f64);
        }
        Err(e) => {
            tracing::error!(error = %e, "one_time_tokens gc failed");
            metrics.token_gc_errors_total.inc();
        }
    }

    // Expired tokens cascade-delete their sessions via FK ON DELETE CASCADE.
    match sqlx::query!("DELETE FROM auth.tokens WHERE expires_at < now() - interval '1 day'")
        .execute(pool)
        .await
    {
        Ok(r) => {
            deleted_session = r.rows_affected();
            metrics
                .token_gc_deleted_total
                .with_label_values(&["session"])
                .inc_by(deleted_session as f64);
        }
        Err(e) => {
            tracing::error!(error = %e, "tokens gc failed");
            metrics.token_gc_errors_total.inc();
        }
    }

    // Idle-expired tokens: only active when session_idle_timeout_seconds is set.
    match sqlx::query!(
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
        Ok(r) => {
            deleted_idle = r.rows_affected();
            metrics
                .token_gc_deleted_total
                .with_label_values(&["idle_session"])
                .inc_by(deleted_idle as f64);
        }
        Err(e) => {
            tracing::error!(error = %e, "idle session gc failed");
            metrics.token_gc_errors_total.inc();
        }
    }

    tracing::info!(
        deleted_one_time,
        deleted_session,
        deleted_idle,
        "token gc pass complete"
    );

    // Record the timestamp of this successful pass regardless of per-kind errors.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    metrics.token_gc_last_run_timestamp_seconds.set(now);
}

pub async fn run(pool: PgPool, metrics: Arc<Metrics>) {
    loop {
        run_once(&pool, &metrics).await;
        tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
    }
}
