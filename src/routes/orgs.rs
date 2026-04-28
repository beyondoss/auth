use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AuthError,
    http::AppState,
    invitations,
    orgs::{self, Org, OrgMember},
    sessions::SessionContext,
    tokens::{Token, TokenPrefix},
};

// ── Shared response types ────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
pub struct OrgResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub image_url: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct OrgsResponse {
    pub orgs: Vec<OrgResponse>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct MemberResponse {
    pub user_id: Uuid,
    pub role: String,
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct MembersResponse {
    pub members: Vec<MemberResponse>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct InvitationResponse {
    pub id: Uuid,
    pub org_id: Uuid,
    pub email: Option<String>,
    pub role: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Plaintext token — only present on creation, never returned again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct InvitationsResponse {
    pub invitations: Vec<InvitationResponse>,
}

fn org_response(org: Org) -> OrgResponse {
    OrgResponse {
        id: org.id,
        name: org.name,
        slug: org.slug,
        image_url: org.image_url,
        metadata: org.metadata,
        created_at: org.created_at,
    }
}

fn member_response(m: OrgMember) -> MemberResponse {
    MemberResponse {
        user_id: m.user_id,
        role: m.role,
        joined_at: m.joined_at,
    }
}

// ── Request types ────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateOrgRequest {
    pub name: String,
    pub slug: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateOrgRequest {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub image_url: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateMemberRequest {
    pub role: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateInvitationRequest {
    pub email: Option<String>,
    pub role: String,
}

// ── POST /v1/orgs ─────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/orgs",
    tag = "orgs",
    security(("BearerAuth" = [])),
    request_body = CreateOrgRequest,
    responses(
        (status = 201, body = OrgResponse),
        (status = 409, description = "Slug already taken", body = crate::error::ErrorResponse),
    )
)]
pub async fn create_org(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Json(req): Json<CreateOrgRequest>,
) -> Result<(StatusCode, Json<OrgResponse>), AuthError> {
    let org_id = Uuid::now_v7();
    let slug = req.slug.unwrap_or_else(|| orgs::slugify(&req.name));

    let mut tx = state.pool.begin().await.map_err(AuthError::from)?;

    let org = orgs::create(
        &mut tx,
        org_id,
        ctx.user.id,
        &req.name,
        &slug,
        None,
        req.metadata,
    )
    .await
    .map_err(|e| {
        if let AuthError::Db { ref message, .. } = e {
            if message.contains("org_slug_idx") {
                return AuthError::SlugConflict;
            }
        }
        e
    })?;

    orgs::add_member(&mut tx, org_id, ctx.user.id, "owner").await?;

    tx.commit().await.map_err(AuthError::from)?;

    Ok((StatusCode::CREATED, Json(org_response(org))))
}

// ── GET /v1/orgs ──────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/orgs",
    tag = "orgs",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, body = OrgsResponse),
    )
)]
pub async fn list_orgs(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<Json<OrgsResponse>, AuthError> {
    let orgs = orgs::list(&state.pool, ctx.user.id).await?;
    Ok(Json(OrgsResponse {
        orgs: orgs.into_iter().map(org_response).collect(),
    }))
}

// ── GET /v1/orgs/{id} ────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/orgs/{id}",
    tag = "orgs",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Org ID")),
    responses(
        (status = 200, body = OrgResponse),
        (status = 403, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn get_org(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<OrgResponse>, AuthError> {
    orgs::require_member(&state.pool, org_id, ctx.user.id).await?;
    let org = orgs::get(&state.pool, org_id).await?;
    Ok(Json(org_response(org)))
}

// ── PATCH /v1/orgs/{id} ──────────────────────────────────────────────────────

#[utoipa::path(
    patch,
    path = "/v1/orgs/{id}",
    tag = "orgs",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Org ID")),
    request_body = UpdateOrgRequest,
    responses(
        (status = 200, body = OrgResponse),
        (status = 403, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
        (status = 409, description = "Slug already taken", body = crate::error::ErrorResponse),
    )
)]
pub async fn update_org(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(org_id): Path<Uuid>,
    Json(req): Json<UpdateOrgRequest>,
) -> Result<Json<OrgResponse>, AuthError> {
    orgs::require_owner(&state.pool, org_id, ctx.user.id).await?;
    let org = orgs::update(
        &state.pool,
        org_id,
        req.name.as_deref(),
        req.slug.as_deref(),
        req.image_url.as_deref(),
        req.metadata,
    )
    .await?;
    Ok(Json(org_response(org)))
}

// ── DELETE /v1/orgs/{id} ─────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/orgs/{id}",
    tag = "orgs",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Org ID")),
    responses(
        (status = 204),
        (status = 403, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
        (status = 409, description = "Cannot delete personal org", body = crate::error::ErrorResponse),
    )
)]
pub async fn delete_org(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(org_id): Path<Uuid>,
) -> Result<StatusCode, AuthError> {
    orgs::require_owner(&state.pool, org_id, ctx.user.id).await?;
    orgs::soft_delete(&state.pool, org_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── GET /v1/orgs/{id}/members ────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/orgs/{id}/members",
    tag = "orgs",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Org ID")),
    responses(
        (status = 200, body = MembersResponse),
        (status = 403, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn list_members(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<MembersResponse>, AuthError> {
    orgs::require_member(&state.pool, org_id, ctx.user.id).await?;
    let members = orgs::list_members(&state.pool, org_id).await?;
    Ok(Json(MembersResponse {
        members: members.into_iter().map(member_response).collect(),
    }))
}

// ── PATCH /v1/orgs/{id}/members/{member_id} ──────────────────────────────────

#[utoipa::path(
    patch,
    path = "/v1/orgs/{id}/members/{member_id}",
    tag = "orgs",
    security(("BearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Org ID"),
        ("member_id" = Uuid, Path, description = "User ID of the member"),
    ),
    request_body = UpdateMemberRequest,
    responses(
        (status = 204),
        (status = 403, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
        (status = 409, description = "Would remove last owner", body = crate::error::ErrorResponse),
    )
)]
pub async fn update_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path((org_id, member_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateMemberRequest>,
) -> Result<StatusCode, AuthError> {
    orgs::require_owner(&state.pool, org_id, ctx.user.id).await?;
    orgs::update_member_role(&state.pool, org_id, member_id, &req.role).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── DELETE /v1/orgs/{id}/members/{member_id} ─────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/orgs/{id}/members/{member_id}",
    tag = "orgs",
    security(("BearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Org ID"),
        ("member_id" = Uuid, Path, description = "User ID of the member"),
    ),
    responses(
        (status = 204),
        (status = 403, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
        (status = 409, description = "Would remove last owner", body = crate::error::ErrorResponse),
    )
)]
pub async fn remove_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path((org_id, member_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AuthError> {
    if ctx.user.id != member_id {
        // Non-self removals require owner permission.
        orgs::require_owner(&state.pool, org_id, ctx.user.id).await?;
    } else {
        orgs::require_member(&state.pool, org_id, ctx.user.id).await?;
    }
    orgs::remove_member(&state.pool, org_id, member_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── POST /v1/orgs/{id}/invitations ───────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/orgs/{id}/invitations",
    tag = "orgs",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Org ID")),
    request_body = CreateInvitationRequest,
    responses(
        (status = 201, body = InvitationResponse),
        (status = 403, body = crate::error::ErrorResponse),
        (status = 409, description = "Pending invite for this email already exists", body = crate::error::ErrorResponse),
    )
)]
pub async fn create_invitation(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(org_id): Path<Uuid>,
    Json(req): Json<CreateInvitationRequest>,
) -> Result<(StatusCode, Json<InvitationResponse>), AuthError> {
    orgs::require_owner(&state.pool, org_id, ctx.user.id).await?;

    let token = Token::new(TokenPrefix::Invitation);
    let hash = token.secret_hash();
    let token_str = token.to_string();

    let inv = invitations::create(
        &state.pool,
        org_id,
        ctx.user.id,
        req.email.as_deref(),
        &req.role,
        &hash,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(InvitationResponse {
            id: inv.id,
            org_id: inv.org_id,
            email: inv.email,
            role: inv.role,
            created_at: inv.created_at,
            expires_at: inv.expires_at,
            token: Some(token_str),
        }),
    ))
}

// ── GET /v1/orgs/{id}/invitations ────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/orgs/{id}/invitations",
    tag = "orgs",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Org ID")),
    responses(
        (status = 200, body = InvitationsResponse),
        (status = 403, body = crate::error::ErrorResponse),
    )
)]
pub async fn list_invitations(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<InvitationsResponse>, AuthError> {
    orgs::require_owner(&state.pool, org_id, ctx.user.id).await?;
    let invs = invitations::list(&state.pool, org_id).await?;
    Ok(Json(InvitationsResponse {
        invitations: invs
            .into_iter()
            .map(|inv| InvitationResponse {
                id: inv.id,
                org_id: inv.org_id,
                email: inv.email,
                role: inv.role,
                created_at: inv.created_at,
                expires_at: inv.expires_at,
                token: None,
            })
            .collect(),
    }))
}

// ── POST /v1/orgs/{id}/invitations/{inv_id}/resends ──────────────────────────

#[utoipa::path(
    post,
    path = "/v1/orgs/{id}/invitations/{inv_id}/resends",
    tag = "orgs",
    security(("BearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Org ID"),
        ("inv_id" = Uuid, Path, description = "Invitation ID"),
    ),
    responses(
        (status = 201, body = InvitationResponse),
        (status = 403, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn resend_invitation(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path((org_id, inv_id)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, Json<InvitationResponse>), AuthError> {
    orgs::require_owner(&state.pool, org_id, ctx.user.id).await?;

    let token = Token::new(TokenPrefix::Invitation);
    let hash = token.secret_hash();
    let token_str = token.to_string();

    let inv = invitations::refresh_token(&state.pool, inv_id, org_id, &hash).await?;

    Ok((
        StatusCode::CREATED,
        Json(InvitationResponse {
            id: inv.id,
            org_id: inv.org_id,
            email: inv.email,
            role: inv.role,
            created_at: inv.created_at,
            expires_at: inv.expires_at,
            token: Some(token_str),
        }),
    ))
}

// ── DELETE /v1/orgs/{id}/invitations/{inv_id} ────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/orgs/{id}/invitations/{inv_id}",
    tag = "orgs",
    security(("BearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Org ID"),
        ("inv_id" = Uuid, Path, description = "Invitation ID"),
    ),
    responses(
        (status = 204),
        (status = 403, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn revoke_invitation(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path((org_id, inv_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AuthError> {
    orgs::require_owner(&state.pool, org_id, ctx.user.id).await?;
    invitations::revoke(&state.pool, inv_id, org_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
