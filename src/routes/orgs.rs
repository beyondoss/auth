use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AuthError,
    http::AppState,
    invitations,
    orgs::{self, Org, OrgMember},
    pages,
    sessions::AuthContext,
    tokens::{Token, TokenPrefix},
};

// ── Shared response types ────────────────────────────────────────────────────

/// An organization the authenticated user is a member of.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct OrgResponse {
    pub id: Uuid,
    pub name: String,
    /// URL-safe identifier, unique across all orgs.
    pub slug: String,
    #[schema(nullable)]
    pub image_url: Option<String>,
    /// Arbitrary JSON metadata.
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Cursor-paginated list of orgs.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct OrgsResponse {
    pub orgs: Vec<OrgResponse>,
    pub has_more: bool,
    /// Opaque cursor — pass as `after` to retrieve the next page.
    #[schema(nullable)]
    pub next_page: Option<String>,
}

/// An org membership record.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct MemberResponse {
    pub user_id: Uuid,
    /// Role within this org, e.g. `"owner"` or `"member"`.
    pub role: String,
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

/// Cursor-paginated list of org members.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct MembersResponse {
    pub members: Vec<MemberResponse>,
    pub has_more: bool,
    /// Opaque cursor — pass as `after` to retrieve the next page.
    #[schema(nullable)]
    pub next_page: Option<String>,
}

/// An org invitation. On creation, `token` is populated — it is never returned again.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct InvitationResponse {
    pub id: Uuid,
    pub org_id: Uuid,
    /// Email address the invitation is addressed to, if any. Null for open link invitations.
    #[schema(nullable)]
    pub email: Option<String>,
    /// Role the invitee will receive on acceptance.
    pub role: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Plaintext token — only present on creation, never returned again. Deliver this to the invitee.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable)]
    pub token: Option<String>,
}

/// Cursor-paginated list of pending org invitations.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct InvitationsResponse {
    pub invitations: Vec<InvitationResponse>,
    pub has_more: bool,
    /// Opaque cursor — pass as `after` to retrieve the next page.
    #[schema(nullable)]
    pub next_page: Option<String>,
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

#[derive(Deserialize, utoipa::IntoParams)]
pub struct PageQuery {
    pub after: Option<String>,
    pub limit: Option<i64>,
}

/// Request to create a new organization.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateOrgRequest {
    pub name: String,
    /// URL-safe identifier. Defaults to a slugified version of `name` if omitted.
    #[schema(nullable)]
    pub slug: Option<String>,
    #[schema(nullable, value_type = Object)]
    pub metadata: Option<serde_json::Value>,
}

/// Partial org update. Omitted fields are left unchanged.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateOrgRequest {
    #[schema(nullable)]
    pub name: Option<String>,
    /// URL-safe identifier. Returns 409 if already taken.
    #[schema(nullable)]
    pub slug: Option<String>,
    #[schema(nullable)]
    pub image_url: Option<String>,
    /// Full replacement of the org's metadata field.
    #[schema(nullable, value_type = Object)]
    pub metadata: Option<serde_json::Value>,
}

/// Request to change a member's role.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateMemberRequest {
    /// New role for the member, e.g. `"owner"` or `"member"`.
    pub role: String,
}

/// Request to create an invitation to the org.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateInvitationRequest {
    /// Email address to address the invitation to. Omit for an open link invitation
    /// that any user can accept.
    #[schema(nullable)]
    pub email: Option<String>,
    /// Role the invitee will receive on acceptance.
    pub role: String,
}

// ── POST /v1/orgs ─────────────────────────────────────────────────────────────

/// Create a new organization. The authenticated user becomes the owner.
/// Returns 409 if the slug is already taken.
#[utoipa::path(
    post,
    path = "/v1/orgs",
    operation_id = "create_org",
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
    Extension(ctx): Extension<AuthContext>,
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
    .await?;

    orgs::add_member(&mut tx, org_id, ctx.user.id, "owner").await?;

    tx.commit().await.map_err(AuthError::from)?;

    Ok((StatusCode::CREATED, Json(org_response(org))))
}

// ── GET /v1/orgs ──────────────────────────────────────────────────────────────

/// List all orgs the authenticated user is a member of, cursor-paginated.
#[utoipa::path(
    get,
    path = "/v1/orgs",
    operation_id = "list_orgs",
    tag = "orgs",
    security(("BearerAuth" = [])),
    params(PageQuery),
    responses(
        (status = 200, body = OrgsResponse),
    )
)]
pub async fn list_orgs(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OrgsResponse>, AuthError> {
    let limit = pages::clamp_limit(page.limit);
    let after = pages::decode_cursor(page.after.as_deref());
    let mut orgs = orgs::list(&state.pool, ctx.user.id, after.as_deref(), limit + 1).await?;
    let has_more = orgs.len() as i64 > limit;
    if has_more {
        orgs.truncate(limit as usize);
    }
    let next_page = if has_more {
        orgs.last().map(|o| pages::encode_cursor(&o.id.to_string()))
    } else {
        None
    };
    Ok(Json(OrgsResponse {
        orgs: orgs.into_iter().map(org_response).collect(),
        has_more,
        next_page,
    }))
}

// ── GET /v1/orgs/{id} ────────────────────────────────────────────────────────

/// Get an org by ID. Returns 403 if the authenticated user is not a member.
#[utoipa::path(
    get,
    path = "/v1/orgs/{id}",
    operation_id = "get_org",
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
    Extension(ctx): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<OrgResponse>, AuthError> {
    orgs::require_member(&state.pool, org_id, ctx.user.id).await?;
    let org = orgs::get(&state.pool, org_id).await?;
    Ok(Json(org_response(org)))
}

// ── PATCH /v1/orgs/{id} ──────────────────────────────────────────────────────

/// Update an org. Requires owner role. Only fields present in the body are changed.
#[utoipa::path(
    patch,
    path = "/v1/orgs/{id}",
    operation_id = "update_org",
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
    Extension(ctx): Extension<AuthContext>,
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

/// Soft-delete an org. Requires owner role. Returns 409 if this is the user's personal org
/// (personal orgs are deleted via `DELETE /v1/users/me`).
#[utoipa::path(
    delete,
    path = "/v1/orgs/{id}",
    operation_id = "delete_org",
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
    Extension(ctx): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<StatusCode, AuthError> {
    orgs::require_owner(&state.pool, org_id, ctx.user.id).await?;
    orgs::soft_delete(&state.pool, org_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── GET /v1/orgs/{id}/members ────────────────────────────────────────────────

/// List members of an org, cursor-paginated. Requires membership.
#[utoipa::path(
    get,
    path = "/v1/orgs/{id}/members",
    operation_id = "list_org_members",
    tag = "orgs",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Org ID"), PageQuery),
    responses(
        (status = 200, body = MembersResponse),
        (status = 403, body = crate::error::ErrorResponse),
        (status = 404, body = crate::error::ErrorResponse),
    )
)]
pub async fn list_members(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<MembersResponse>, AuthError> {
    orgs::require_member(&state.pool, org_id, ctx.user.id).await?;
    let limit = pages::clamp_limit(page.limit);
    let after = pages::decode_cursor(page.after.as_deref());
    let mut members = orgs::list_members(&state.pool, org_id, after.as_deref(), limit + 1).await?;
    let has_more = members.len() as i64 > limit;
    if has_more {
        members.truncate(limit as usize);
    }
    let next_page = if has_more {
        members
            .last()
            .map(|m| pages::encode_cursor(&m.user_id.to_string()))
    } else {
        None
    };
    Ok(Json(MembersResponse {
        members: members.into_iter().map(member_response).collect(),
        has_more,
        next_page,
    }))
}

// ── PATCH /v1/orgs/{id}/members/{member_id} ──────────────────────────────────

/// Update a member's role. Requires owner. Returns 409 if the change would leave the org
/// with no owners.
#[utoipa::path(
    patch,
    path = "/v1/orgs/{id}/members/{member_id}",
    operation_id = "update_org_member",
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
    Extension(ctx): Extension<AuthContext>,
    Path((org_id, member_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateMemberRequest>,
) -> Result<StatusCode, AuthError> {
    orgs::require_owner(&state.pool, org_id, ctx.user.id).await?;
    orgs::update_member_role(&state.pool, org_id, member_id, &req.role).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── DELETE /v1/orgs/{id}/members/{member_id} ─────────────────────────────────

/// Remove a member from an org. A user can remove themselves with only membership; removing
/// another member requires owner. Returns 409 if removing would leave the org with no owners.
#[utoipa::path(
    delete,
    path = "/v1/orgs/{id}/members/{member_id}",
    operation_id = "remove_org_member",
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
    Extension(ctx): Extension<AuthContext>,
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

/// Create an invitation. Requires owner. The response includes a one-time `token` — deliver
/// it to the invitee so they can call `POST /v1/invitations/{id}/acceptances`. Returns 409
/// if a pending invitation already exists for the same email.
#[utoipa::path(
    post,
    path = "/v1/orgs/{id}/invitations",
    operation_id = "create_invitation",
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
    Extension(ctx): Extension<AuthContext>,
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

/// List pending invitations for an org, cursor-paginated. Requires owner.
/// Tokens are not included in list responses — only in creation and resend responses.
#[utoipa::path(
    get,
    path = "/v1/orgs/{id}/invitations",
    operation_id = "list_org_invitations",
    tag = "orgs",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Org ID"), PageQuery),
    responses(
        (status = 200, body = InvitationsResponse),
        (status = 403, body = crate::error::ErrorResponse),
    )
)]
pub async fn list_invitations(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<InvitationsResponse>, AuthError> {
    orgs::require_owner(&state.pool, org_id, ctx.user.id).await?;
    let limit = pages::clamp_limit(page.limit);
    let after = pages::decode_cursor(page.after.as_deref());
    let mut invs = invitations::list(&state.pool, org_id, after.as_deref(), limit + 1).await?;
    let has_more = invs.len() as i64 > limit;
    if has_more {
        invs.truncate(limit as usize);
    }
    let next_page = if has_more {
        invs.last()
            .map(|inv| pages::encode_cursor(&inv.id.to_string()))
    } else {
        None
    };
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
        has_more,
        next_page,
    }))
}

// ── POST /v1/orgs/{id}/invitations/{inv_id}/resends ──────────────────────────

/// Re-issue an invitation token. Invalidates the previous token and returns a fresh one.
/// Use this when the original token expires or is lost. Requires owner.
#[utoipa::path(
    post,
    path = "/v1/orgs/{id}/invitations/{inv_id}/resends",
    operation_id = "resend_invitation",
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
    Extension(ctx): Extension<AuthContext>,
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

/// Revoke an invitation. The token is immediately invalidated. Requires owner.
#[utoipa::path(
    delete,
    path = "/v1/orgs/{id}/invitations/{inv_id}",
    operation_id = "revoke_invitation",
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
    Extension(ctx): Extension<AuthContext>,
    Path((org_id, inv_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AuthError> {
    orgs::require_owner(&state.pool, org_id, ctx.user.id).await?;
    invitations::revoke(&state.pool, inv_id, org_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
