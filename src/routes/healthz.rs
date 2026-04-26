use axum::{Json, http::StatusCode};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct HealthzResponse {
    status: &'static str,
    version: &'static str,
}

#[utoipa::path(
    get,
    path = "/healthz",
    tag = "system",
    responses(
        (status = 200, body = HealthzResponse)
    )
)]
pub async fn handler() -> (StatusCode, Json<HealthzResponse>) {
    (
        StatusCode::OK,
        Json(HealthzResponse {
            status: "ok",
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}
