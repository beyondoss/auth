use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::prelude::DiscoverableKey;

use crate::{
    error::AuthError,
    http::AppState,
    mfa::{self, webauthn as wn},
    sessions::{self, RequestContext, SessionContext},
    tokens::{Token, TokenPrefix},
};

use super::users::make_auth_response;

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

#[derive(Deserialize, utoipa::ToSchema)]
pub struct FinishAuthenticationRequest {
    pub state_token: String,
    /// WebAuthn `PublicKeyCredential` response from the browser.
    #[schema(value_type = Object)]
    pub credential: webauthn_rs::prelude::PublicKeyCredential,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn request_context<'a>(headers: &'a HeaderMap) -> RequestContext<'a> {
    let ip_address = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(str::trim)
        });
    RequestContext {
        ip_address,
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok()),
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/webauthn/registrations",
    operation_id = "begin_webauthn_registration",
    tag = "webauthn",
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
    let display_name = ctx.user.display_name.as_deref().unwrap_or(&ctx.email.email);

    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(ctx.user.id, &ctx.email.email, display_name, None)
        .map_err(|e| AuthError::internal_with("webauthn start registration", e))?;

    let state_token = wn::pack_reg_state(&reg_state, ctx.user.id, &state.signing_key);

    Ok(Json(json!({
        "options": ccr,
        "state_token": state_token,
    })))
}

#[utoipa::path(
    put,
    path = "/v1/webauthn/registrations",
    operation_id = "finish_webauthn_registration",
    tag = "webauthn",
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
        .map_err(|e| AuthError::internal_with("webauthn finish registration", e))?;

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
    path = "/v1/webauthn/credentials",
    operation_id = "list_webauthn_credentials",
    tag = "webauthn",
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
    path = "/v1/webauthn/credentials/{id}",
    operation_id = "update_webauthn_credential",
    tag = "webauthn",
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
    path = "/v1/webauthn/credentials/{id}",
    operation_id = "delete_webauthn_credential",
    tag = "webauthn",
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
    path = "/v1/webauthn/authentications",
    operation_id = "begin_webauthn_authentication",
    tag = "webauthn",
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
        .map_err(|e| AuthError::internal_with("webauthn start auth", e))?;

    let state_token = wn::pack_auth_state(&auth_state, &state.signing_key);

    Ok(Json(json!({
        "options": rcr,
        "state_token": state_token,
    })))
}

#[utoipa::path(
    put,
    path = "/v1/webauthn/authentications",
    operation_id = "finish_webauthn_authentication",
    tag = "webauthn",
    request_body = FinishAuthenticationRequest,
    responses(
        (status = 201, body = super::users::AuthResponse, description = "Authentication successful"),
        (status = 200, body = super::sessions::StepUpResponse, description = "MFA step-up required"),
        (status = 400, body = crate::error::ErrorResponse),
    )
)]
pub async fn finish_authentication(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<FinishAuthenticationRequest>,
) -> Result<Response, AuthError> {
    let auth_state = wn::unpack_auth_state(&req.state_token, &state.signing_key)?;

    let cred_id_bytes: &[u8] = req.credential.raw_id.as_ref();
    let (row_id, user_id, mut passkey) = wn::find_credential(&state.pool, cred_id_bytes)
        .await?
        .ok_or(AuthError::InvalidCredentials)?;

    let dkey: DiscoverableKey = (&passkey).into();
    let creds: &[DiscoverableKey] = &[dkey];
    let auth_result = state
        .webauthn
        .finish_discoverable_authentication(&req.credential, auth_state, creds)
        .map_err(|e| AuthError::internal_with("webauthn finish auth", e))?;

    passkey.update_credential(&auth_result);
    wn::update_credential(&state.pool, row_id, &passkey).await?;

    if mfa::totp::is_enrolled(&state.pool, user_id).await? {
        let step_up_token = mfa::step_up::issue(user_id, "totp", &state.signing_key);
        return Ok((
            StatusCode::OK,
            Json(json!({
                "step_up_required": "totp",
                "step_up_token": step_up_token,
            })),
        )
            .into_response());
    }

    let req_ctx = request_context(&headers);
    let ttl = {
        let cfg = state.app_config.read().await;
        cfg.session_ttl_seconds
    };

    let session_token = Token::new(TokenPrefix::Session);
    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;
    let (session_id, expires_at) =
        sessions::create(&mut tx, &session_token, user_id, ttl, &req_ctx).await?;
    tx.commit().await.map_err(AuthError::from)?;

    let (user, tenant, email) = sessions::load_user_context(&state.pool, user_id).await?;

    Ok((
        StatusCode::CREATED,
        Json(make_auth_response(
            user,
            email,
            tenant,
            session_id,
            &session_token,
            expires_at,
        )),
    )
        .into_response())
}
