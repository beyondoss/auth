pub mod healthz;
pub mod jwks;

use axum::{Router, routing::get};
use utoipa::OpenApi;

use crate::http::AppState;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Beyond Auth",
        version = "1",
        description = "Per-project authentication and authorization service."
    ),
    paths(
        healthz::handler,
        jwks::handler,
    ),
    components(schemas(
        healthz::HealthzResponse,
        jwks::JwkSet,
        jwks::Jwk,
    )),
    tags(
        (name = "system", description = "Health and key material")
    )
)]
pub struct ApiDoc;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz::handler))
        .route("/v1/jwks.json", get(jwks::handler))
}
