use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;
use utoipa::ToSchema;

use crate::http::AppState;

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    /// `"ok"` or `"degraded"`.
    status: &'static str,
    /// Service version from `CARGO_PKG_VERSION`.
    version: &'static str,
}

/// Liveness probe. Returns 200 as long as the process can accept connections.
/// Does not check dependencies — use `/readyz` for that.
#[utoipa::path(
    get,
    path = "/livez",
    operation_id = "livez",
    tag = "system",
    responses((status = 200, body = HealthResponse))
)]
pub async fn livez_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Readiness probe. Performs a lightweight database ping.
/// Returns 503 when the database is unreachable — the orchestrator will
/// stop routing traffic until this returns 200.
#[utoipa::path(
    get,
    path = "/readyz",
    operation_id = "readyz",
    tag = "system",
    responses(
        (status = 200, body = HealthResponse),
        (status = 503, body = HealthResponse),
    )
)]
pub async fn readyz_handler(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    db_ping(&state).await
}

async fn db_ping(state: &AppState) -> (StatusCode, Json<HealthResponse>) {
    let ok = sqlx::query!("SELECT 1 AS ping")
        .fetch_one(&state.pool)
        .await
        .is_ok();

    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = HealthResponse {
        status: if ok { "ok" } else { "degraded" },
        version: env!("CARGO_PKG_VERSION"),
    };
    (status, Json(body))
}
