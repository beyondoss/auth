use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    email,
    error::AuthError,
    http::AppState,
    identities, mfa, one_time_token, passwords,
    sessions::{self, AuthContext, RequestContext},
    tokens::{Token, TokenPrefix},
};

use super::users::make_auth_response;

// ── Request / response shapes ────────────────────────────────────────────────

/// Credential payload for session creation. The `grant_type` field discriminates the variant.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum LoginRequest {
    /// Email + password login. If TOTP is enrolled, returns 200 with a `step_up_token`
    /// instead of a session — caller must complete MFA via `totp_step_up`.
    Password { email: String, password: String },
    /// Exchanges a token issued by `POST /v1/magic-links`. Single-use; expires in 15 min.
    MagicLink {
        /// The plaintext token from the magic-link response.
        token: String,
    },
    /// Exchanges a password-reset token, sets the new password, and creates a session.
    /// All existing sessions are invalidated.
    PasswordReset {
        /// The plaintext token from the password-reset response.
        token: String,
        new_password: String,
    },
    /// Exchanges an email-change token, promotes the new address to primary, and creates
    /// a session. All existing sessions are invalidated.
    EmailChange {
        /// The plaintext token from the email-change (`POST /v1/emails`) response.
        token: String,
    },
    /// Completes a TOTP MFA step-up. Present after a 200 response with `step_up_required`.
    TotpStepUp {
        /// The `step_up_token` from the preceding 200 step-up response.
        step_up_token: String,
        /// Six-digit TOTP code from the authenticator app.
        code: String,
    },
    /// Completes MFA using a single-use TOTP recovery code. Consumes the code permanently.
    TotpRecovery {
        /// The `step_up_token` from the preceding 200 step-up response.
        step_up_token: String,
        /// One of the recovery codes issued at TOTP enrollment or last regeneration.
        code: String,
    },
    /// Completes a WebAuthn passkey authentication flow.
    Passkey {
        /// The `state_token` from the `POST /v1/passkey-authentications` response.
        state_token: String,
        /// WebAuthn `PublicKeyCredential` response from the browser's `navigator.credentials.get()`.
        #[schema(value_type = Object)]
        credential: webauthn_rs::prelude::PublicKeyCredential,
    },
}

/// MFA method required to complete authentication.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum StepUpKind {
    Totp,
}

/// Returned when the user has TOTP enrolled — caller must complete the step-up flow.
#[derive(Serialize, utoipa::ToSchema)]
pub struct StepUpResponse {
    /// The MFA method required to complete authentication.
    pub step_up_required: StepUpKind,
    /// Short-lived signed token to present when completing the step-up.
    pub step_up_token: String,
}

/// Paginated list of active sessions for the authenticated user.
#[derive(Serialize, utoipa::ToSchema)]
pub struct SessionsResponse {
    pub sessions: Vec<crate::sessions::SessionListItem>,
}

/// Details of the session that authenticated the current request.
#[derive(Serialize, utoipa::ToSchema)]
pub struct CurrentSessionResponse {
    /// Session ID.
    pub id: Uuid,
    /// ID of the underlying bearer token used to authenticate this request.
    pub token_id: Uuid,
    /// IP address recorded at session creation, if available.
    pub ip_address: Option<String>,
    /// User-Agent recorded at session creation, if available.
    pub user_agent: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Time the bearer token was last presented, updated on each authenticated request.
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

// ── POST /v1/sessions ─────────────────────────────────────────────────────────

/// Authenticate and create a session. The `grant_type` field in the request body selects
/// the credential flow. On success, returns 201 with a session token. When the account has
/// TOTP enrolled and the grant type supports MFA, returns 200 with a `step_up_token` —
/// the caller must then re-POST with `grant_type=totp_step_up` to complete authentication.
#[utoipa::path(
    post,
    path = "/v1/sessions",
    operation_id = "create_session",
    tag = "sessions",
    request_body = LoginRequest,
    responses(
        (status = 201, description = "Session created", body = super::users::AuthResponse),
        (status = 200, description = "MFA step-up required", body = StepUpResponse),
        (status = 401, description = "Invalid credentials or token", body = crate::error::ErrorResponse),
        (status = 422, description = "Password validation failed", body = crate::error::ErrorResponse),
    )
)]
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Response, AuthError> {
    let req_ctx = sessions::request_context(&headers);
    let cfg = state.app_config.read().await;
    let ttl = cfg.session_ttl_seconds;
    drop(cfg);

    match req {
        LoginRequest::Password {
            email: addr,
            password,
        } => login_password(&state, &req_ctx, ttl, &addr, &password).await,
        LoginRequest::MagicLink { token } => {
            login_one_time_token(&state, &req_ctx, ttl, &token).await
        }
        LoginRequest::PasswordReset {
            token,
            new_password,
        } => login_password_reset(&state, &req_ctx, ttl, &token, &new_password).await,
        LoginRequest::EmailChange { token } => {
            login_email_change(&state, &req_ctx, ttl, &token).await
        }
        LoginRequest::TotpStepUp {
            step_up_token,
            code,
        } => login_totp_step_up(&state, &req_ctx, ttl, &step_up_token, &code).await,
        LoginRequest::TotpRecovery {
            step_up_token,
            code,
        } => login_totp_recovery(&state, &req_ctx, ttl, &step_up_token, &code).await,
        LoginRequest::Passkey {
            state_token,
            credential,
        } => login_passkey(&state, &req_ctx, ttl, &state_token, &credential).await,
    }
}

async fn login_password(
    state: &AppState,
    req_ctx: &RequestContext<'_>,
    ttl: i32,
    addr: &str,
    password: &str,
) -> Result<Response, AuthError> {
    let normalized = email::normalize(addr);

    // Fetch identity; return the same error for missing user and wrong password
    // to prevent user enumeration. Still call verify() on a dummy hash when no
    // identity exists so response time is indistinguishable.
    let identity = identities::find_password_secret(&state.pool, &normalized).await?;
    let (user_id, hash_str) = match identity {
        Some(row) => row,
        None => {
            let _ = passwords::verify(password, DUMMY_HASH);
            return Err(AuthError::InvalidCredentials);
        }
    };

    if !passwords::verify(password, &hash_str)? {
        return Err(AuthError::InvalidCredentials);
    }

    if mfa::totp::is_enrolled(&state.pool, user_id).await? {
        let step_up_token = mfa::step_up::issue(user_id, "totp", &state.signing_key);
        return Ok((
            StatusCode::OK,
            Json(StepUpResponse {
                step_up_required: StepUpKind::Totp,
                step_up_token,
            }),
        )
            .into_response());
    }

    let (user, org, email) = sessions::load_user_context(&state.pool, user_id).await?;
    let session_token = Token::new(TokenPrefix::Session);
    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;
    let (session_id, expires_at) =
        sessions::create(&mut tx, &session_token, user_id, ttl, req_ctx).await?;
    tx.commit().await.map_err(AuthError::from)?;

    Ok((
        StatusCode::CREATED,
        Json(make_auth_response(
            user,
            email,
            org,
            session_id,
            &session_token,
            expires_at,
        )),
    )
        .into_response())
}

async fn login_one_time_token(
    state: &AppState,
    req_ctx: &RequestContext<'_>,
    ttl: i32,
    raw_token: &str,
) -> Result<Response, AuthError> {
    let (user_id, _ctx) =
        one_time_token::consume(&state.pool, TokenPrefix::MagicLink, raw_token).await?;

    let (user, org, email) = sessions::load_user_context(&state.pool, user_id).await?;
    let session_token = Token::new(TokenPrefix::Session);
    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;
    let (session_id, expires_at) =
        sessions::create(&mut tx, &session_token, user_id, ttl, req_ctx).await?;
    tx.commit().await.map_err(AuthError::from)?;

    Ok((
        StatusCode::CREATED,
        Json(make_auth_response(
            user,
            email,
            org,
            session_id,
            &session_token,
            expires_at,
        )),
    )
        .into_response())
}

async fn login_password_reset(
    state: &AppState,
    req_ctx: &RequestContext<'_>,
    ttl: i32,
    raw_token: &str,
    new_password: &str,
) -> Result<Response, AuthError> {
    let (user_id, _ctx) =
        one_time_token::consume(&state.pool, TokenPrefix::PasswordReset, raw_token).await?;

    let new_hash = passwords::hash(new_password)?;
    let (user, org, email) = sessions::load_user_context(&state.pool, user_id).await?;

    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;

    sqlx::query!(
        "UPDATE auth.identities SET secret = $1 WHERE user_id = $2 AND provider = 'password'",
        new_hash.as_bytes() as &[u8],
        user_id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    sqlx::query!(
        "DELETE FROM auth.tokens WHERE id IN (
             SELECT token_id FROM auth.sessions WHERE user_id = $1
         )",
        user_id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    let session_token = Token::new(TokenPrefix::Session);
    let (session_id, expires_at) =
        sessions::create(&mut tx, &session_token, user_id, ttl, req_ctx).await?;
    tx.commit().await.map_err(AuthError::from)?;

    Ok((
        StatusCode::CREATED,
        Json(make_auth_response(
            user,
            email,
            org,
            session_id,
            &session_token,
            expires_at,
        )),
    )
        .into_response())
}

async fn login_email_change(
    state: &AppState,
    req_ctx: &RequestContext<'_>,
    ttl: i32,
    raw_token: &str,
) -> Result<Response, AuthError> {
    let (user_id, context) =
        one_time_token::consume(&state.pool, TokenPrefix::EmailChange, raw_token).await?;

    let new_email: String = context
        .as_ref()
        .and_then(|v| v.get("new_email"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| AuthError::internal("new_email missing from token context"))?;

    let email_id = uuid::Uuid::now_v7();
    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;

    sqlx::query!(
        "INSERT INTO auth.emails (id, user_id, email, verified_at)
         VALUES ($1, $2, $3::text, now())",
        email_id,
        user_id,
        new_email,
    )
    .execute(tx.as_mut())
    .await
    .map_err(|e: sqlx::Error| {
        if let sqlx::Error::Database(ref db) = e
            && db
                .constraint()
                .is_some_and(|c| c.contains("emails_email_idx"))
        {
            return AuthError::EmailAlreadyExists;
        }
        AuthError::from(e)
    })?;

    sqlx::query!(
        "UPDATE auth.users SET primary_email_id = $1 WHERE id = $2",
        email_id,
        user_id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    sqlx::query!(
        "DELETE FROM auth.tokens WHERE id IN (
             SELECT token_id FROM auth.sessions WHERE user_id = $1
         )",
        user_id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    let session_token = Token::new(TokenPrefix::Session);
    let (session_id, expires_at) =
        sessions::create(&mut tx, &session_token, user_id, ttl, req_ctx).await?;
    tx.commit().await.map_err(AuthError::from)?;

    // Load user context after commit so pool sees the new primary email.
    let (user, org, email) = sessions::load_user_context(&state.pool, user_id).await?;

    Ok((
        StatusCode::CREATED,
        Json(make_auth_response(
            user,
            email,
            org,
            session_id,
            &session_token,
            expires_at,
        )),
    )
        .into_response())
}

async fn login_totp_step_up(
    state: &AppState,
    req_ctx: &RequestContext<'_>,
    ttl: i32,
    step_up_token: &str,
    code: &str,
) -> Result<Response, AuthError> {
    let claims = mfa::step_up::verify(step_up_token, &state.signing_key)?;
    if claims.next_step != "totp" {
        return Err(AuthError::TokenInvalid);
    }

    mfa::totp::verify_step_up(&state.pool, claims.user_id, code, state.encryptor.as_ref()).await?;

    let (user, org, email) = sessions::load_user_context(&state.pool, claims.user_id).await?;
    let session_token = Token::new(TokenPrefix::Session);
    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;
    let (session_id, expires_at) =
        sessions::create(&mut tx, &session_token, claims.user_id, ttl, req_ctx).await?;
    tx.commit().await.map_err(AuthError::from)?;

    Ok((
        StatusCode::CREATED,
        Json(make_auth_response(
            user,
            email,
            org,
            session_id,
            &session_token,
            expires_at,
        )),
    )
        .into_response())
}

async fn login_totp_recovery(
    state: &AppState,
    req_ctx: &RequestContext<'_>,
    ttl: i32,
    step_up_token: &str,
    code: &str,
) -> Result<Response, AuthError> {
    let claims = mfa::step_up::verify(step_up_token, &state.signing_key)?;
    if claims.next_step != "totp" {
        return Err(AuthError::TokenInvalid);
    }

    mfa::totp::use_recovery_code(&state.pool, claims.user_id, code).await?;

    let (user, org, email) = sessions::load_user_context(&state.pool, claims.user_id).await?;
    let session_token = Token::new(TokenPrefix::Session);
    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;
    let (session_id, expires_at) =
        sessions::create(&mut tx, &session_token, claims.user_id, ttl, req_ctx).await?;
    tx.commit().await.map_err(AuthError::from)?;

    Ok((
        StatusCode::CREATED,
        Json(make_auth_response(
            user,
            email,
            org,
            session_id,
            &session_token,
            expires_at,
        )),
    )
        .into_response())
}

async fn login_passkey(
    state: &AppState,
    req_ctx: &RequestContext<'_>,
    ttl: i32,
    state_token: &str,
    credential: &webauthn_rs::prelude::PublicKeyCredential,
) -> Result<Response, AuthError> {
    let webauthn = state
        .webauthn
        .as_deref()
        .ok_or(AuthError::PasskeysNotConfigured)?;
    let user_id = mfa::passkeys::verify_authentication(
        &state.pool,
        webauthn,
        &state.signing_key,
        state_token,
        credential,
    )
    .await?;

    if mfa::totp::is_enrolled(&state.pool, user_id).await? {
        let step_up_token = mfa::step_up::issue(user_id, "totp", &state.signing_key);
        return Ok((
            StatusCode::OK,
            Json(StepUpResponse {
                step_up_required: StepUpKind::Totp,
                step_up_token,
            }),
        )
            .into_response());
    }

    let (user, org, email) = sessions::load_user_context(&state.pool, user_id).await?;
    let session_token = Token::new(TokenPrefix::Session);
    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;
    let (session_id, expires_at) =
        sessions::create(&mut tx, &session_token, user_id, ttl, req_ctx).await?;
    tx.commit().await.map_err(AuthError::from)?;

    Ok((
        StatusCode::CREATED,
        Json(make_auth_response(
            user,
            email,
            org,
            session_id,
            &session_token,
            expires_at,
        )),
    )
        .into_response())
}

// A known-invalid argon2id hash used for timing-safe dummy verifications.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// ── GET /v1/sessions ──────────────────────────────────────────────────────────

/// List all active sessions for the authenticated user. The current session is included.
#[utoipa::path(
    get,
    path = "/v1/sessions",
    operation_id = "list_sessions",
    tag = "sessions",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, body = SessionsResponse),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<SessionsResponse>, AuthError> {
    let sessions = sessions::list(&state.pool, ctx.user.id, ctx.token_id).await?;
    Ok(Json(SessionsResponse { sessions }))
}

// ── GET /v1/sessions/current ──────────────────────────────────────────────────

/// Return details about the session that authenticated the current request.
#[utoipa::path(
    get,
    path = "/v1/sessions/current",
    operation_id = "get_current_session",
    tag = "sessions",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, body = CurrentSessionResponse),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn get_current(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<CurrentSessionResponse>, AuthError> {
    let row = sessions::get_current_session(&state.pool, ctx.user.id, ctx.token_id)
        .await?
        .ok_or(AuthError::NotFound)?;

    Ok(Json(CurrentSessionResponse {
        id: row.id,
        token_id: row.token_id,
        ip_address: row.ip_address,
        user_agent: row.user_agent,
        created_at: row.created_at,
        expires_at: row.expires_at,
        last_used_at: row.last_used_at,
    }))
}

// ── DELETE /v1/sessions/current ───────────────────────────────────────────────

/// Revoke the session that authenticated the current request. The bearer token becomes
/// immediately invalid. Idempotent — safe to call if the session is already gone.
#[utoipa::path(
    delete,
    path = "/v1/sessions/current",
    operation_id = "revoke_current_session",
    tag = "sessions",
    security(("BearerAuth" = [])),
    responses(
        (status = 204, description = "Session revoked"),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn delete_current(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<StatusCode, AuthError> {
    // The middleware already authenticated this token. We trust ctx.token_id.
    // Idempotent: if already deleted, the no-op DELETE still returns 204.
    sqlx::query!("DELETE FROM auth.tokens WHERE id = $1", ctx.token_id)
        .execute(&state.pool)
        .await
        .map_err(AuthError::from)?;

    state.authz_cache.invalidate_session(ctx.token_id);

    Ok(StatusCode::NO_CONTENT)
}

// ── DELETE /v1/sessions ───────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::IntoParams)]
pub struct DeleteAllQuery {
    /// When true, the current session is preserved; all other sessions are revoked.
    /// Defaults to false — all sessions including the current one are revoked.
    #[serde(default)]
    pub except_current: bool,
}

/// Revoke all sessions for the authenticated user. Use `except_current=true` to keep
/// the current session active (e.g. "sign out everywhere else").
#[utoipa::path(
    delete,
    path = "/v1/sessions",
    operation_id = "delete_all_sessions",
    tag = "sessions",
    security(("BearerAuth" = [])),
    params(DeleteAllQuery),
    responses(
        (status = 204, description = "Sessions revoked"),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn delete_all(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Query(params): Query<DeleteAllQuery>,
) -> Result<StatusCode, AuthError> {
    let token_ids: Vec<Uuid> = if params.except_current {
        sqlx::query_scalar!(
            r#"
            WITH deleted AS (
                DELETE FROM auth.tokens
                WHERE id IN (
                    SELECT token_id FROM auth.sessions
                    WHERE user_id = $1 AND token_id != $2
                )
                RETURNING id
            )
            SELECT id AS "id: Uuid" FROM deleted
            "#,
            ctx.user.id,
            ctx.token_id,
        )
        .fetch_all(&state.pool)
        .await
        .map_err(AuthError::from)?
    } else {
        sqlx::query_scalar!(
            r#"
            WITH deleted AS (
                DELETE FROM auth.tokens
                WHERE id IN (
                    SELECT token_id FROM auth.sessions WHERE user_id = $1
                )
                RETURNING id
            )
            SELECT id AS "id: Uuid" FROM deleted
            "#,
            ctx.user.id,
        )
        .fetch_all(&state.pool)
        .await
        .map_err(AuthError::from)?
    };

    for token_id in token_ids {
        state.authz_cache.invalidate_session(token_id);
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── DELETE /v1/sessions/{id} ──────────────────────────────────────────────────

/// Revoke a specific session by ID. The caller can only revoke their own sessions;
/// attempting to revoke another user's session returns 404 (not 403) to prevent enumeration.
#[utoipa::path(
    delete,
    path = "/v1/sessions/{id}",
    operation_id = "revoke_session",
    tag = "sessions",
    security(("BearerAuth" = [])),
    params(("id" = uuid::Uuid, Path, description = "Session ID")),
    responses(
        (status = 204, description = "Session revoked"),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn delete_by_id(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, AuthError> {
    // Fast path: caller is revoking their own current session.
    if ctx.source.session_id() == Some(session_id) {
        sqlx::query!("DELETE FROM auth.tokens WHERE id = $1", ctx.token_id)
            .execute(&state.pool)
            .await
            .map_err(AuthError::from)?;
        state.authz_cache.invalidate_session(ctx.token_id);
        return Ok(StatusCode::NO_CONTENT);
    }

    // Delete the token only if the session belongs to the authenticated user.
    // Zero rows deleted → session doesn't exist or belongs to another user → 404.
    // Same response for both cases prevents IDOR information disclosure.
    // RETURNING id gives us the token_id for session cache invalidation.
    let deleted_token_id = sqlx::query_scalar!(
        r#"
        WITH target AS (
            SELECT s.token_id
            FROM auth.sessions s
            WHERE s.id = $1 AND s.user_id = $2
        ),
        deleted AS (
            DELETE FROM auth.tokens WHERE id = (SELECT token_id FROM target)
            RETURNING id
        )
        SELECT id AS "id: Uuid" FROM deleted
        "#,
        session_id,
        ctx.user.id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(AuthError::from)?;

    match deleted_token_id {
        None => Err(AuthError::NotFound),
        Some(token_id) => {
            state.authz_cache.invalidate_session(token_id);
            Ok(StatusCode::NO_CONTENT)
        }
    }
}
