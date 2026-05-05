use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};

use crate::{error::AuthError, http::AppState};

/// Get the current runtime configuration.
#[utoipa::path(
    get,
    operation_id = "get_admin_config",
    path = "/v1/admin/config",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, body = ConfigResponse),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn get(State(state): State<AppState>) -> Result<Json<ConfigResponse>, AuthError> {
    let cfg = state.app_config.read().await;
    Ok(Json(ConfigResponse {
        session_idle_timeout_seconds: cfg.session_idle_timeout_seconds,
        jwt_enabled: cfg.jwt_enabled,
    }))
}

/// Partial config update. Only fields explicitly set are updated.
/// Send `"session_idle_timeout_seconds": null` to clear the idle timeout.
/// Partial config update. Only fields present in the body are changed.
/// Send `"session_idle_timeout_seconds": null` to clear the idle timeout.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateConfigRequest {
    /// Seconds of inactivity before a session is considered expired.
    /// Omit to leave unchanged. Send `null` to disable (no idle timeout).
    #[serde(default, deserialize_with = "deserialize_double_option")]
    #[schema(nullable, example = 3600)]
    pub session_idle_timeout_seconds: Option<Option<i32>>,
    /// When true, `POST /v1/tokens` issues JWT access tokens.
    pub jwt_enabled: Option<bool>,
}

/// Current runtime configuration values.
#[derive(Serialize, utoipa::ToSchema)]
pub struct ConfigResponse {
    /// Seconds of inactivity before a session expires. Null means no idle timeout.
    pub session_idle_timeout_seconds: Option<i32>,
    /// Whether `POST /v1/tokens` is enabled for JWT issuance.
    pub jwt_enabled: bool,
}

/// Distinguish "field absent" from "field present with null".
fn deserialize_double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(de).map(Some)
}

#[utoipa::path(
    patch,
    path = "/v1/admin/config",
    tag = "admin",
    security(("BearerAuth" = [])),
    request_body = UpdateConfigRequest,
    responses(
        (status = 200, body = ConfigResponse),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn patch(
    State(state): State<AppState>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<(StatusCode, Json<ConfigResponse>), AuthError> {
    if let Some(timeout) = req.session_idle_timeout_seconds {
        sqlx::query!(
            "UPDATE auth.app_config SET session_idle_timeout_seconds = $1 WHERE id = true",
            timeout,
        )
        .execute(&state.pool)
        .await
        .map_err(AuthError::from)?;

        state.app_config.write().await.session_idle_timeout_seconds = timeout;
    }

    if let Some(enabled) = req.jwt_enabled {
        sqlx::query!(
            "UPDATE auth.app_config SET jwt_enabled = $1 WHERE id = true",
            enabled,
        )
        .execute(&state.pool)
        .await
        .map_err(AuthError::from)?;

        state.app_config.write().await.jwt_enabled = enabled;
    }

    let cfg = state.app_config.read().await;
    Ok((
        StatusCode::OK,
        Json(ConfigResponse {
            session_idle_timeout_seconds: cfg.session_idle_timeout_seconds,
            jwt_enabled: cfg.jwt_enabled,
        }),
    ))
}
