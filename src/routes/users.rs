use axum::{
    Json,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode, header},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    email,
    emails::{self, Email},
    error::AuthError,
    http::AppState,
    identities,
    orgs::{self, Org},
    passwords,
    sessions::{self, RequestContext, SessionContext},
    tokens::{Token, TokenPrefix},
    users::{self, User},
};

// ── Request / response shapes ────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct AuthResponse {
    pub user: UserBody,
    pub email: EmailBody,
    pub org: OrgBody,
    pub session: SessionBody,
}

#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct MeResponse {
    pub user: UserBody,
    pub email: EmailBody,
    pub org: OrgBody,
}

#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct UserBody {
    pub id: Uuid,
    pub primary_org_id: Uuid,
    pub name: String,
    pub image_url: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct EmailBody {
    pub id: Uuid,
    pub email: String,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct OrgBody {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub image_url: Option<String>,
}

#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct SessionBody {
    pub id: Uuid,
    /// Opaque bearer token — store securely, transmit as `Authorization: Bearer <token>`.
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
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

pub fn make_auth_response(
    user: User,
    email: Email,
    org: Org,
    session_id: Uuid,
    token: &Token,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> AuthResponse {
    AuthResponse {
        user: UserBody {
            id: user.id,
            primary_org_id: org.id,
            name: org.name.clone(),
            image_url: org.image_url.clone(),
            metadata: org.metadata.clone(),
            created_at: user.created_at,
        },
        email: EmailBody {
            id: email.id,
            email: email.email,
            verified_at: email.verified_at,
        },
        org: OrgBody {
            id: org.id,
            name: org.name,
            slug: org.slug,
            image_url: org.image_url,
        },
        session: SessionBody {
            id: session_id,
            token: token.to_string(),
            expires_at,
        },
    }
}

// ── DELETE /v1/users/me ───────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/users/me",
    tag = "users",
    security(("BearerAuth" = [])),
    responses(
        (status = 204),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn delete_me(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<StatusCode, AuthError> {
    let user_id = ctx.user.id;
    let org_id = ctx.user.primary_org_id;

    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;

    // Remove all session tokens first (sessions.user_id has ON DELETE RESTRICT).
    sqlx::query!(
        "DELETE FROM auth.tokens WHERE id IN (SELECT token_id FROM auth.sessions WHERE user_id = $1)",
        user_id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    sqlx::query!(
        "UPDATE auth.users SET deleted_at = now() WHERE id = $1",
        user_id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    sqlx::query!(
        "UPDATE auth.orgs SET deleted_at = now() WHERE id = $1",
        org_id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    tx.commit().await.map_err(AuthError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── POST /v1/users ────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/users",
    tag = "users",
    request_body = SignupRequest,
    responses(
        (status = 201, body = AuthResponse),
        (status = 409, description = "Email already registered", body = crate::error::ErrorResponse),
        (status = 422, description = "Password validation failed", body = crate::error::ErrorResponse),
    )
)]
pub async fn signup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SignupRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), AuthError> {
    let hash = passwords::hash(&req.password)?;
    let normalized = email::normalize(&req.email);

    let org_id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let email_id = Uuid::now_v7();

    let name = req
        .display_name
        .as_deref()
        .unwrap_or_else(|| normalized.split('@').next().unwrap_or("user"))
        .to_string();
    let slug = orgs::slugify(&name);

    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;

    let org = orgs::create(&mut tx, org_id, user_id, &name, &slug, None, None).await?;
    orgs::add_member(&mut tx, org_id, user_id, "owner").await?;
    let user = users::create(&mut tx, user_id, org_id, email_id).await?;
    let email = emails::create(&mut tx, email_id, user_id, &req.email).await?;

    identities::create(&mut tx, user_id, "password", &normalized, hash.as_bytes())
        .await
        .map_err(|e| {
            if let AuthError::Db { ref message, .. } = e
                && message.contains("identity_provider_subject_idx")
            {
                return AuthError::EmailAlreadyExists;
            }
            e
        })?;

    let token = Token::new(TokenPrefix::Session);
    let cfg = state.app_config.read().await;
    let ctx = request_context(&headers);
    let (session_id, expires_at) =
        sessions::create(&mut tx, &token, user_id, cfg.session_ttl_seconds, &ctx).await?;

    tx.commit().await.map_err(AuthError::from)?;

    Ok((
        StatusCode::CREATED,
        Json(make_auth_response(
            user, email, org, session_id, &token, expires_at,
        )),
    ))
}

// ── GET /v1/users/me ──────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/users/me",
    tag = "users",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, body = MeResponse),
        (status = 401, body = crate::error::ErrorResponse),
    )
)]
pub async fn get_me(Extension(ctx): Extension<SessionContext>) -> Json<MeResponse> {
    Json(MeResponse {
        user: UserBody {
            id: ctx.user.id,
            primary_org_id: ctx.user.primary_org_id,
            name: ctx.org.name.clone(),
            image_url: ctx.org.image_url.clone(),
            metadata: ctx.org.metadata.clone(),
            created_at: ctx.user.created_at,
        },
        email: EmailBody {
            id: ctx.email.id,
            email: ctx.email.email,
            verified_at: ctx.email.verified_at,
        },
        org: OrgBody {
            id: ctx.org.id,
            name: ctx.org.name,
            slug: ctx.org.slug,
            image_url: ctx.org.image_url,
        },
    })
}

// ── PATCH /v1/users/me ────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateMeRequest {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub image_url: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[utoipa::path(
    patch,
    path = "/v1/users/me",
    tag = "users",
    security(("BearerAuth" = [])),
    request_body = UpdateMeRequest,
    responses(
        (status = 200, body = MeResponse),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
        (status = 409, description = "Slug already taken", body = crate::error::ErrorResponse),
    )
)]
pub async fn update_me(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Json(patch): Json<UpdateMeRequest>,
) -> Result<Json<MeResponse>, AuthError> {
    let org = orgs::update(
        &state.pool,
        ctx.user.primary_org_id,
        patch.name.as_deref(),
        patch.slug.as_deref(),
        patch.image_url.as_deref(),
        patch.metadata,
    )
    .await?;
    Ok(Json(MeResponse {
        user: UserBody {
            id: ctx.user.id,
            primary_org_id: ctx.user.primary_org_id,
            name: org.name.clone(),
            image_url: org.image_url.clone(),
            metadata: org.metadata.clone(),
            created_at: ctx.user.created_at,
        },
        email: EmailBody {
            id: ctx.email.id,
            email: ctx.email.email,
            verified_at: ctx.email.verified_at,
        },
        org: OrgBody {
            id: org.id,
            name: org.name,
            slug: org.slug,
            image_url: org.image_url,
        },
    }))
}
