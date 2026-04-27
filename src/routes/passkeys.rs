use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{error::AuthError, http::AppState, mfa::passkeys as wn, sessions::SessionContext};

// ── Shared response types ─────────────────────────────────────────────────────

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct BeginResponse {
    /// WebAuthn options object — pass directly to the browser's WebAuthn API.
    #[schema(value_type = Object)]
    pub options: serde_json::Value,
    /// Opaque state token; include in the corresponding finish request.
    pub state_token: String,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct RegisteredCredential {
    pub id: Uuid,
    pub nickname: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ── Request bodies ────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct FinishRegistrationRequest {
    pub state_token: String,
    /// WebAuthn `PublicKeyCredential` response from the browser.
    #[schema(value_type = Object)]
    pub credential: webauthn_rs::prelude::RegisterPublicKeyCredential,
    pub nickname: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateCredentialRequest {
    pub nickname: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/passkey-registrations",
    operation_id = "begin_passkey_registration",
    tag = "passkeys",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, body = BeginResponse),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn begin_registration(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(ctx.user.id, &ctx.email.email, &ctx.org.name, None)
        .map_err(|e| AuthError::internal_with("passkeys start registration", e))?;

    let state_token = wn::pack_reg_state(&reg_state, ctx.user.id, &state.signing_key);

    Ok(Json(json!({
        "options": ccr,
        "state_token": state_token,
    })))
}

#[utoipa::path(
    post,
    path = "/v1/passkeys",
    operation_id = "create_passkey",
    tag = "passkeys",
    security(("BearerAuth" = [])),
    request_body = FinishRegistrationRequest,
    responses(
        (status = 201, body = RegisteredCredential),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn finish_registration(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Json(req): Json<FinishRegistrationRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AuthError> {
    let reg_state = wn::unpack_reg_state(&req.state_token, ctx.user.id, &state.signing_key)?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(|e| AuthError::internal_with("passkeys finish registration", e))?;

    let (id, created_at) =
        wn::store_credential(&state.pool, ctx.user.id, &passkey, req.nickname.as_deref()).await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "nickname": req.nickname,
            "created_at": created_at,
        })),
    ))
}

#[utoipa::path(
    get,
    path = "/v1/passkeys",
    operation_id = "list_passkeys",
    tag = "passkey",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, body = Vec<wn::CredentialRecord>),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn list_credentials(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<Json<Vec<wn::CredentialRecord>>, AuthError> {
    let creds = wn::credentials_for_user(&state.pool, ctx.user.id).await?;
    Ok(Json(creds))
}

#[utoipa::path(
    patch,
    path = "/v1/passkeys/{id}",
    operation_id = "update_passkey",
    tag = "passkeys",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Credential ID")),
    request_body = UpdateCredentialRequest,
    responses(
        (status = 204, description = "Credential updated"),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn update_credential(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCredentialRequest>,
) -> Result<StatusCode, AuthError> {
    wn::update_nickname(&state.pool, id, ctx.user.id, &req.nickname).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/v1/passkeys/{id}",
    operation_id = "delete_passkey",
    tag = "passkeys",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Credential ID")),
    responses(
        (status = 204, description = "Credential deleted"),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn delete_credential(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AuthError> {
    wn::delete_credential(&state.pool, id, ctx.user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/v1/passkey-authentications",
    operation_id = "begin_passkey_authentication",
    tag = "passkeys",
    responses(
        (status = 200, body = BeginResponse),
    )
)]
pub async fn begin_authentication(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let (rcr, auth_state) = state
        .webauthn
        .start_discoverable_authentication()
        .map_err(|e| AuthError::internal_with("passkeys start auth", e))?;

    let state_token = wn::pack_auth_state(&auth_state, &state.signing_key);

    Ok(Json(json!({
        "options": rcr,
        "state_token": state_token,
    })))
}
