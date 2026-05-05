use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{error::AuthError, http::AppState, mfa::passkeys as wn, sessions::AuthContext};

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

/// Request to rename a registered passkey credential.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateCredentialRequest {
    /// Human-readable label shown in credential lists.
    pub nickname: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// Begin WebAuthn passkey registration. Returns a `options` object to pass directly to
/// `navigator.credentials.create()` and a `state_token` to include in the subsequent
/// `POST /v1/passkeys` finish call. Two-step: begin here, finish with `POST /v1/passkeys`.
#[utoipa::path(
    post,
    path = "/v1/passkey-registrations",
    operation_id = "begin_passkey_registration",
    tag = "passkeys",
    security(("BearerAuth" = [])),
    responses(
        (status = 201, body = BeginResponse),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn begin_registration(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<(StatusCode, Json<serde_json::Value>), AuthError> {
    let webauthn = state
        .webauthn
        .as_deref()
        .ok_or(AuthError::PasskeysNotConfigured)?;
    let (ccr, reg_state) = webauthn
        .start_passkey_registration(ctx.user.id, &ctx.email.email, &ctx.org.name, None)
        .map_err(|e| AuthError::internal_with("passkeys start registration", e))?;

    let state_token = wn::pack_reg_state(&reg_state, ctx.user.id, &state.signing_key);

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "options": ccr,
            "state_token": state_token,
        })),
    ))
}

/// Complete passkey registration. Submit the `state_token` from `POST /v1/passkey-registrations`
/// and the `PublicKeyCredential` response from `navigator.credentials.create()`.
/// The registered credential can then be used to authenticate via `POST /v1/passkey-authentications`.
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
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<FinishRegistrationRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AuthError> {
    let reg_state = wn::unpack_reg_state(&req.state_token, ctx.user.id, &state.signing_key)?;

    let webauthn = state
        .webauthn
        .as_deref()
        .ok_or(AuthError::PasskeysNotConfigured)?;
    let passkey = webauthn
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

/// List all registered passkey credentials for the authenticated user.
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
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<Vec<wn::CredentialRecord>>, AuthError> {
    let creds = wn::credentials_for_user(&state.pool, ctx.user.id).await?;
    Ok(Json(creds))
}

/// Update the nickname of a registered passkey credential.
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
    Extension(ctx): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCredentialRequest>,
) -> Result<StatusCode, AuthError> {
    wn::update_nickname(&state.pool, id, ctx.user.id, &req.nickname).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Delete a registered passkey credential. The credential can no longer be used to authenticate.
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
    Extension(ctx): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AuthError> {
    wn::delete_credential(&state.pool, id, ctx.user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Begin WebAuthn passkey authentication (discoverable credential flow). Returns `options`
/// for `navigator.credentials.get()` and a `state_token`. Complete authentication by
/// posting `state_token` + credential to `POST /v1/sessions` with `grant_type=passkey`.
/// Unauthenticated — no bearer token required.
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
    let webauthn = state
        .webauthn
        .as_deref()
        .ok_or(AuthError::PasskeysNotConfigured)?;
    let (rcr, auth_state) = webauthn
        .start_discoverable_authentication()
        .map_err(|e| AuthError::internal_with("passkeys start auth", e))?;

    let state_token = wn::pack_auth_state(&auth_state, &state.signing_key);

    Ok(Json(json!({
        "options": rcr,
        "state_token": state_token,
    })))
}
