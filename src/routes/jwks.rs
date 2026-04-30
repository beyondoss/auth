use axum::{
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::http::AppState;

/// JSON Web Key Set — the public keys used to verify JWTs issued by this service.
#[derive(Serialize, ToSchema)]
pub struct JwkSet {
    keys: Vec<Jwk>,
}

/// A single JSON Web Key (Ed25519 public key in JWK format).
#[derive(Serialize, ToSchema)]
pub struct Jwk {
    /// Key type — always `"OKP"` for Ed25519.
    kty: String,
    /// Curve — always `"Ed25519"`.
    crv: String,
    /// Key ID matching the `kid` claim in issued JWTs.
    kid: String,
    /// Intended use — always `"sig"`.
    #[serde(rename = "use")]
    use_: String,
    /// Algorithm — always `"EdDSA"`.
    alg: String,
    /// Base64url-encoded public key bytes.
    x: String,
}

/// The active JWT signing public keys in JWK Set format. Cached for 1 hour (`Cache-Control: public, max-age=3600`).
/// Use this endpoint to verify JWTs issued by `POST /v1/tokens`.
#[utoipa::path(
    get,
    path = "/v1/jwks.json",
    operation_id = "jwks",
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
