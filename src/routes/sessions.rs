use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode, header},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    email,
    error::AuthError,
    http::AppState,
    identities, passwords,
    sessions::{self, RequestContext, SessionContext, SessionListItem},
    tokens::{Token, TokenPrefix},
};

use super::users::{AuthResponse, make_auth_response};

// ── Request / response shapes ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginRequest {
    pub grant_type: String,
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct SessionsResponse {
    pub sessions: Vec<SessionListItem>,
}

#[derive(Serialize)]
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

fn request_context(headers: &HeaderMap) -> RequestContext<'_> {
    RequestContext {
        ip_address: headers
            .get("x-real-ip")
            .or_else(|| headers.get("x-forwarded-for"))
            .and_then(|v| v.to_str().ok()),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok()),
    }
}

// ── POST /v1/sessions ─────────────────────────────────────────────────────────

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), AuthError> {
    if req.grant_type != "password" {
        return Err(AuthError::InvalidCredentials);
    }

    let normalized = email::normalize(&req.email);

    // Fetch identity; return the same error for missing user and wrong password
    // to prevent user enumeration. Still call verify() on a dummy hash when no
    // identity exists so response time is indistinguishable.
    let identity = identities::find_password_secret(&state.pool, &normalized).await?;
    let (user_id, hash_str) = match identity {
        Some(row) => row,
        None => {
            let _ = passwords::verify(&req.password, DUMMY_HASH);
            return Err(AuthError::InvalidCredentials);
        }
    };

    if !passwords::verify(&req.password, &hash_str)? {
        return Err(AuthError::InvalidCredentials);
    }

    let (user, tenant, email) = sessions::load_user_context(&state.pool, user_id).await?;

    let token = Token::new(TokenPrefix::Session);
    let cfg = state.app_config.read().await;
    let ctx = request_context(&headers);

    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;
    let (session_id, expires_at) =
        sessions::create(&mut tx, &token, user_id, cfg.session_ttl_seconds, &ctx).await?;
    tx.commit().await.map_err(AuthError::from)?;

    Ok((
        StatusCode::CREATED,
        Json(make_auth_response(
            user, email, tenant, session_id, &token, expires_at,
        )),
    ))
}

// A known-invalid argon2id hash used for timing-safe dummy verifications.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// ── GET /v1/sessions ──────────────────────────────────────────────────────────

pub async fn list(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<Json<SessionsResponse>, AuthError> {
    let sessions = sessions::list(&state.pool, ctx.user.id, ctx.token_id).await?;
    Ok(Json(SessionsResponse { sessions }))
}

// ── GET /v1/sessions/current ──────────────────────────────────────────────────

pub async fn get_current(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<Json<CurrentSessionResponse>, AuthError> {
    let row = sessions::list(&state.pool, ctx.user.id, ctx.token_id)
        .await?
        .into_iter()
        .find(|s| s.current)
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

pub async fn delete_current(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<StatusCode, AuthError> {
    // The middleware already authenticated this token. We trust ctx.token_id.
    // Idempotent: if already deleted, the no-op DELETE still returns 204.
    sqlx::query("DELETE FROM auth.token WHERE id = $1")
        .bind(ctx.token_id)
        .execute(&state.pool)
        .await
        .map_err(AuthError::from)?;

    Ok(StatusCode::NO_CONTENT)
}

// ── DELETE /v1/sessions/{id} ──────────────────────────────────────────────────

pub async fn delete_by_id(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, AuthError> {
    // Fast path: caller is revoking their own current session.
    if session_id == ctx.session_id {
        sqlx::query("DELETE FROM auth.token WHERE id = $1")
            .bind(ctx.token_id)
            .execute(&state.pool)
            .await
            .map_err(AuthError::from)?;
        return Ok(StatusCode::NO_CONTENT);
    }

    // Delete the token only if the session belongs to the authenticated user.
    // Zero rows deleted → session doesn't exist or belongs to another user → 404.
    // Same response for both cases prevents IDOR information disclosure.
    let result = sqlx::query(
        r#"
        WITH target AS (
            SELECT s.token_id
            FROM auth.session s
            WHERE s.id = $1 AND s.user_id = $2
        )
        DELETE FROM auth.token WHERE id = (SELECT token_id FROM target)
        "#,
    )
    .bind(session_id)
    .bind(ctx.user.id)
    .execute(&state.pool)
    .await
    .map_err(AuthError::from)?;

    if result.rows_affected() == 0 {
        return Err(AuthError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}
