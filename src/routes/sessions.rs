use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    email,
    error::AuthError,
    http::AppState,
    identities, mfa, one_time_token, passwords,
    sessions::{self, RequestContext, SessionContext},
    tokens::{Token, TokenPrefix},
};

use super::users::make_auth_response;

// ── Request / response shapes ────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum LoginRequest {
    Password { email: String, password: String },
    MagicLink { token: String },
    PasswordReset { token: String, new_password: String },
    EmailChange { token: String },
    TotpStepUp { step_up_token: String, code: String },
    TotpRecovery { step_up_token: String, code: String },
}

/// Returned when the user has TOTP enrolled — caller must complete the step-up flow.
#[derive(Serialize, utoipa::ToSchema)]
pub struct StepUpResponse {
    /// The MFA method required, e.g. `"totp"`.
    pub step_up_required: String,
    /// Short-lived signed token to present when completing the step-up.
    pub step_up_token: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct SessionsResponse {
    pub sessions: Vec<crate::sessions::SessionListItem>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct CurrentSessionResponse {
    pub id: Uuid,
    pub token_id: Uuid,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
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

// ── POST /v1/sessions ─────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/sessions",
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
    let req_ctx = request_context(&headers);
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
                step_up_required: "totp".into(),
                step_up_token,
            }),
        )
            .into_response());
    }

    let (user, tenant, email) = sessions::load_user_context(&state.pool, user_id).await?;
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
            tenant,
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
    let (user_id, _ctx) = one_time_token::consume(&state.pool, TokenPrefix::MagicLink, raw_token).await?;

    let (user, tenant, email) = sessions::load_user_context(&state.pool, user_id).await?;
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
            tenant,
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
    let (user_id, _ctx) = one_time_token::consume(&state.pool, TokenPrefix::PasswordReset, raw_token).await?;

    let new_hash = passwords::hash(new_password)?;

    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;

    sqlx::query!(
        "UPDATE auth.identity SET secret = $1 WHERE user_id = $2 AND provider = 'password'",
        new_hash,
        user_id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    sqlx::query!(
        "DELETE FROM auth.token WHERE id IN (
             SELECT token_id FROM auth.session WHERE user_id = $1
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

async fn login_email_change(
    state: &AppState,
    req_ctx: &RequestContext<'_>,
    ttl: i32,
    raw_token: &str,
) -> Result<Response, AuthError> {
    let (user_id, context) = one_time_token::consume(&state.pool, TokenPrefix::EmailChange, raw_token).await?;

    let new_email: String = context
        .as_ref()
        .and_then(|v| v.get("new_email"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| AuthError::internal("new_email missing from token context"))?;

    let email_id = uuid::Uuid::now_v7();
    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;

    sqlx::query!(
        "INSERT INTO auth.email (id, user_id, email, verified_at)
         VALUES ($1, $2, $3::citext, clock_timestamp())",
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
                .is_some_and(|c| c.contains("email_email_idx"))
        {
            return AuthError::EmailAlreadyExists;
        }
        AuthError::from(e)
    })?;

    sqlx::query!(
        "UPDATE auth.\"user\" SET primary_email_id = $1 WHERE id = $2",
        email_id,
        user_id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    sqlx::query!(
        "DELETE FROM auth.token WHERE id IN (
             SELECT token_id FROM auth.session WHERE user_id = $1
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

    mfa::totp::verify_step_up(&state.pool, claims.user_id, code).await?;

    let (user, tenant, email) = sessions::load_user_context(&state.pool, claims.user_id).await?;
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
            tenant,
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

    let (user, tenant, email) = sessions::load_user_context(&state.pool, claims.user_id).await?;
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
            tenant,
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
    Extension(ctx): Extension<SessionContext>,
) -> Result<Json<SessionsResponse>, AuthError> {
    let sessions = sessions::list(&state.pool, ctx.user.id, ctx.token_id).await?;
    Ok(Json(SessionsResponse { sessions }))
}

// ── GET /v1/sessions/current ──────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/sessions/current",
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
    Extension(ctx): Extension<SessionContext>,
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

#[utoipa::path(
    delete,
    path = "/v1/sessions/current",
    tag = "sessions",
    security(("BearerAuth" = [])),
    responses(
        (status = 204, description = "Session revoked"),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn delete_current(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<StatusCode, AuthError> {
    // The middleware already authenticated this token. We trust ctx.token_id.
    // Idempotent: if already deleted, the no-op DELETE still returns 204.
    sqlx::query!("DELETE FROM auth.token WHERE id = $1", ctx.token_id)
        .execute(&state.pool)
        .await
        .map_err(AuthError::from)?;

    Ok(StatusCode::NO_CONTENT)
}

// ── DELETE /v1/sessions/{id} ──────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/sessions/{id}",
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
    Extension(ctx): Extension<SessionContext>,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, AuthError> {
    // Fast path: caller is revoking their own current session.
    if session_id == ctx.session_id {
        sqlx::query!("DELETE FROM auth.token WHERE id = $1", ctx.token_id)
            .execute(&state.pool)
            .await
            .map_err(AuthError::from)?;
        return Ok(StatusCode::NO_CONTENT);
    }

    // Delete the token only if the session belongs to the authenticated user.
    // Zero rows deleted → session doesn't exist or belongs to another user → 404.
    // Same response for both cases prevents IDOR information disclosure.
    let result = sqlx::query!(
        r#"
        WITH target AS (
            SELECT s.token_id
            FROM auth.session s
            WHERE s.id = $1 AND s.user_id = $2
        )
        DELETE FROM auth.token WHERE id = (SELECT token_id FROM target)
        "#,
        session_id,
        ctx.user.id,
    )
    .execute(&state.pool)
    .await
    .map_err(AuthError::from)?;

    if result.rows_affected() == 0 {
        return Err(AuthError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}
