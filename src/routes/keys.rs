use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AuthError,
    http::AppState,
    keys::{self, Key},
    sessions::AuthContext,
    tokens::{Token, TokenPrefix},
};

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateRequest {
    pub name: String,
    /// When the key expires. Defaults to 100 years from now (effectively never).
    pub expires_at: Option<DateTime<Utc>>,
}

/// Returned only on creation — the `key` field is never shown again.
#[derive(Serialize, utoipa::ToSchema)]
pub struct CreateResponse {
    /// The full bearer token. Store it now — it cannot be retrieved later.
    pub key: String,
    #[serde(flatten)]
    pub info: Key,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct KeysResponse {
    pub keys: Vec<Key>,
}

/// Create an API key for the authenticated user. The full bearer token is returned in
/// `key` and is shown only once — store it immediately. Subsequent reads return only metadata.
#[utoipa::path(
    post,
    operation_id = "create_key",
    path = "/v1/keys",
    tag = "keys",
    security(("BearerAuth" = [])),
    request_body = CreateRequest,
    responses(
        (status = 201, description = "Key created", body = CreateResponse),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<CreateRequest>,
) -> Result<(StatusCode, Json<CreateResponse>), AuthError> {
    let expires_at = req
        .expires_at
        .unwrap_or_else(|| Utc::now() + Duration::days(365 * 100));

    let token = Token::new(TokenPrefix::Key);
    let bearer = token.to_string();
    let (key_id, stored_expires_at) =
        keys::create(&state.pool, ctx.user.id, &req.name, &token, expires_at).await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateResponse {
            key: bearer,
            info: Key {
                id: key_id,
                name: req.name,
                created_at: Utc::now(),
                last_used_at: None,
                expires_at: stored_expires_at,
            },
        }),
    ))
}

/// List all API keys for the authenticated user. Bearer token values are never returned
/// — only metadata (ID, name, created/used/expires timestamps).
#[utoipa::path(
    get,
    operation_id = "list_keys",
    path = "/v1/keys",
    tag = "keys",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, body = KeysResponse),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<KeysResponse>, AuthError> {
    let keys = keys::list(&state.pool, ctx.user.id).await?;
    Ok(Json(KeysResponse { keys }))
}

/// Get metadata for a single API key.
#[utoipa::path(
    get,
    operation_id = "get_key",
    path = "/v1/keys/{id}",
    tag = "keys",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Key ID")),
    responses(
        (status = 200, body = Key),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn get(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(key_id): Path<Uuid>,
) -> Result<Json<Key>, AuthError> {
    let key = keys::get(&state.pool, ctx.user.id, key_id)
        .await?
        .ok_or(AuthError::NotFound)?;
    Ok(Json(key))
}

/// Revoke an API key. The key is immediately invalid for authentication.
#[utoipa::path(
    delete,
    path = "/v1/keys/{id}",
    tag = "keys",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Key ID")),
    responses(
        (status = 204, description = "Key revoked"),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn delete(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(key_id): Path<Uuid>,
) -> Result<StatusCode, AuthError> {
    keys::delete(&state.pool, ctx.user.id, key_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
