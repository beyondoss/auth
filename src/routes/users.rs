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
    identities, passwords,
    sessions::{self, RequestContext, SessionContext},
    tenants::{self, Tenant},
    tokens::{Token, TokenPrefix},
    users::{self, UpdateUser, User},
};

// ── Request / response shapes ────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AuthResponse {
    pub user: UserBody,
    pub email: EmailBody,
    pub tenant: TenantBody,
    pub session: SessionBody,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct MeResponse {
    pub user: UserBody,
    pub email: EmailBody,
    pub tenant: TenantBody,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct UserBody {
    pub id: Uuid,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct EmailBody {
    pub id: Uuid,
    pub email: String,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct TenantBody {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
}

#[derive(Serialize, utoipa::ToSchema)]
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
    tenant: Tenant,
    session_id: Uuid,
    token: &Token,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> AuthResponse {
    AuthResponse {
        user: UserBody {
            id: user.id,
            display_name: user.display_name,
            avatar_url: user.avatar_url,
            created_at: user.created_at,
        },
        email: EmailBody {
            id: email.id,
            email: email.email,
            verified_at: email.verified_at,
        },
        tenant: TenantBody {
            id: tenant.id,
            name: tenant.name,
            slug: tenant.slug,
        },
        session: SessionBody {
            id: session_id,
            token: token.to_string(),
            expires_at,
        },
    }
}

/// Generate a tenant slug from a display name or email local part.
/// Lowercase, replace non-alphanumeric with `-`, collapse runs, then append a
/// short random suffix so concurrent signups with the same name don't collide.
fn make_slug(base: &str) -> String {
    use rand_core::{OsRng, RngCore};

    let clean: String = base
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");

    let suffix = format!("{:06x}", OsRng.next_u32() & 0xFFFFFF);

    if clean.is_empty() {
        suffix
    } else {
        format!("{clean}-{suffix}")
    }
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

    let tenant_id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let email_id = Uuid::now_v7();

    let name = req
        .display_name
        .as_deref()
        .unwrap_or_else(|| normalized.split('@').next().unwrap_or("user"))
        .to_string();
    let slug = make_slug(&name);

    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;

    let tenant = tenants::create(&mut tx, tenant_id, user_id, &name, &slug).await?;
    let user = users::create(
        &mut tx,
        user_id,
        tenant_id,
        email_id,
        req.display_name.as_deref(),
    )
    .await?;
    let email = emails::create(&mut tx, email_id, user_id, &req.email).await?;

    identities::create(&mut tx, user_id, "password", &normalized, &hash)
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
            user, email, tenant, session_id, &token, expires_at,
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
            display_name: ctx.user.display_name,
            avatar_url: ctx.user.avatar_url,
            created_at: ctx.user.created_at,
        },
        email: EmailBody {
            id: ctx.email.id,
            email: ctx.email.email,
            verified_at: ctx.email.verified_at,
        },
        tenant: TenantBody {
            id: ctx.tenant.id,
            name: ctx.tenant.name,
            slug: ctx.tenant.slug,
        },
    })
}

// ── PATCH /v1/users/me ────────────────────────────────────────────────────────

#[utoipa::path(
    patch,
    path = "/v1/users/me",
    tag = "users",
    security(("BearerAuth" = [])),
    request_body = crate::users::UpdateUser,
    responses(
        (status = 200, body = MeResponse),
        (status = 401, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn update_me(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Json(patch): Json<UpdateUser>,
) -> Result<Json<MeResponse>, AuthError> {
    let user = users::update(&state.pool, ctx.user.id, &patch).await?;
    Ok(Json(MeResponse {
        user: UserBody {
            id: user.id,
            display_name: user.display_name,
            avatar_url: user.avatar_url,
            created_at: user.created_at,
        },
        email: EmailBody {
            id: ctx.email.id,
            email: ctx.email.email,
            verified_at: ctx.email.verified_at,
        },
        tenant: TenantBody {
            id: ctx.tenant.id,
            name: ctx.tenant.name,
            slug: ctx.tenant.slug,
        },
    }))
}
