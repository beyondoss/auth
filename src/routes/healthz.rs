use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;
use utoipa::ToSchema;

use crate::http::AppState;

#[derive(Serialize, ToSchema)]
pub struct HealthzResponse {
    status: &'static str,
    version: &'static str,
}

#[utoipa::path(
    get,
    path = "/healthz",
    operation_id = "healthz",
    tag = "system",
    responses(
        (status = 200, body = HealthzResponse),
        (status = 503, body = HealthzResponse),
    )
)]
pub async fn handler(State(state): State<AppState>) -> (StatusCode, Json<HealthzResponse>) {
    let db_ok = sqlx::query!("SELECT 1 AS ping")
        .fetch_one(&state.pool)
        .await
        .is_ok();

    if db_ok {
        (
            StatusCode::OK,
            Json(HealthzResponse {
                status: "ok",
                version: env!("CARGO_PKG_VERSION"),
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthzResponse {
                status: "degraded",
                version: env!("CARGO_PKG_VERSION"),
            }),
        )
    }
}
