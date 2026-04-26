pub mod healthz;
pub mod jwks;
pub mod sessions;
pub mod tokens;
pub mod users;

use axum::{
    Router, middleware as axum_middleware,
    routing::{delete, get, post},
};
use utoipa::OpenApi;

use crate::{http::AppState, middleware::auth::require_auth};

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

pub fn router(state: AppState) -> Router<AppState> {
    let public = Router::new()
        .route("/healthz", get(healthz::handler))
        .route("/v1/jwks.json", get(jwks::handler))
        .route("/v1/users", post(users::signup))
        .route("/v1/sessions", post(sessions::login));

    let authenticated = Router::new()
        .route("/v1/users/me", get(users::get_me).patch(users::update_me))
        .route("/v1/sessions", get(sessions::list))
        .route(
            "/v1/sessions/current",
            get(sessions::get_current).delete(sessions::delete_current),
        )
        .route("/v1/sessions/{id}", delete(sessions::delete_by_id))
        .route("/v1/tokens", post(tokens::issue))
        .route_layer(axum_middleware::from_fn_with_state(state, require_auth));

    Router::new().merge(public).merge(authenticated)
}
