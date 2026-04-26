use axum::{
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::http::AppState;

#[derive(Serialize, ToSchema)]
pub struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Serialize, ToSchema)]
pub struct Jwk {
    kty: String,
    crv: String,
    kid: String,
    #[serde(rename = "use")]
    use_: String,
    alg: String,
    x: String,
}

#[utoipa::path(
    get,
    path = "/v1/jwks.json",
    tag = "system",
    responses(
        (status = 200, body = JwkSet,
         headers(("Cache-Control" = String, description = "public, max-age=3600, must-revalidate")))
    )
)]
pub async fn handler(State(state): State<AppState>) -> Response {
    match Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::CACHE_CONTROL,
            "public, max-age=3600, must-revalidate",
        )
        .body(axum::body::Body::from(state.jwks.as_ref().clone()))
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "failed to build JWKS response");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
