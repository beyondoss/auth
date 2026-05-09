use axum::http::{HeaderMap, header};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{emails::Email, error::AuthError, orgs::Org, tokens::Token, users::User};

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct Session {
    pub id: Uuid,
    pub token_id: Uuid,
    pub user_id: Uuid,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// How the caller authenticated.
#[derive(Debug, Clone)]
pub enum AuthSource {
    Session(Uuid),
    Key,
}

impl AuthSource {
    pub fn session_id(&self) -> Option<Uuid> {
        match self {
            AuthSource::Session(id) => Some(*id),
            AuthSource::Key => None,
        }
    }
}

/// Validated caller context — extracted from the bearer token by auth middleware.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user: User,
    pub email: Email,
    pub org: Org,
    pub source: AuthSource,
    pub token_id: Uuid,
    pub is_impersonated: bool,
}

pub struct RequestContext<'a> {
    pub ip_address: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

pub fn request_context<'a>(headers: &'a HeaderMap) -> RequestContext<'a> {
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

/// Validate a bearer token and return the caller's context in one round-trip.
///
/// Bundled CTE:
/// - validates token id + secret hash + not expired
/// - debounces `last_used_at` (skips update if touched within the last minute)
/// - joins user, primary org, and primary email
///
/// Returns `None` for expired, missing, or wrong-secret tokens.
#[tracing::instrument(skip(pool, secret_hash), fields(token_id = %token_id), err)]
pub async fn validate(
    pool: &PgPool,
    token_id: Uuid,
    secret_hash: &[u8],
    idle_timeout_seconds: Option<i32>,
) -> Result<Option<AuthContext>, AuthError> {
    let row = sqlx::query!(
        r#"
        WITH valid_token AS (
            SELECT tokens.id AS token_id
            FROM auth.tokens
            WHERE tokens.id         = $1
              AND tokens.secret     = $2
              AND tokens.expires_at > now()
              AND (
                  $3::int4 IS NULL
                  OR tokens.last_used_at IS NULL
                  OR tokens.last_used_at > now() - make_interval(secs => $3::float8)
              )
            LIMIT 1
        ),
        update_attempt AS (
            UPDATE auth.tokens SET last_used_at = now()
            FROM valid_token
            WHERE auth.tokens.id = valid_token.token_id
              AND (auth.tokens.last_used_at IS NULL
                   OR auth.tokens.last_used_at < now() - interval '1 minute')
        )
        SELECT
            u.id                AS "user_id!: Uuid",
            u.primary_org_id    AS "primary_org_id!: Uuid",
            u.primary_email_id  AS "primary_email_id!: Uuid",
            u.created_at        AS "user_created_at!: DateTime<Utc>",
            t.id                AS "org_id!: Uuid",
            t.user_id           AS "org_user_id!: Uuid",
            t.name              AS "org_name!",
            t.slug              AS "org_slug!",
            t.image_url         AS "org_image_url",
            t.metadata          AS "org_metadata: serde_json::Value",
            t.created_at        AS "org_created_at!: DateTime<Utc>",
            t.updated_at        AS "org_updated_at!: DateTime<Utc>",
            t.deleted_at        AS "org_deleted_at",
            e.id                AS "email_id!: Uuid",
            e.email::text       AS "email!",
            e.verified_at,
            s.id                AS "session_id!: Uuid",
            v.token_id          AS "token_id!: Uuid"
        FROM valid_token v
        INNER JOIN auth.sessions  s ON s.token_id  = v.token_id
        INNER JOIN auth.users   u ON u.id = s.user_id AND u.deleted_at IS NULL
        INNER JOIN auth.orgs      t ON t.id = u.primary_org_id AND t.deleted_at IS NULL
        LEFT  JOIN auth.emails    e ON e.id = u.primary_email_id
        "#,
        token_id,
        secret_hash,
        idle_timeout_seconds,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?;

    Ok(row.map(|r| AuthContext {
        source: AuthSource::Session(r.session_id),
        token_id: r.token_id,
        is_impersonated: false,
        user: User {
            id: r.user_id,
            primary_org_id: r.primary_org_id,
            primary_email_id: r.primary_email_id,
            created_at: r.user_created_at,
        },
        org: Org {
            id: r.org_id,
            user_id: r.org_user_id,
            name: r.org_name,
            slug: r.org_slug,
            image_url: r.org_image_url,
            metadata: r.org_metadata,
            created_at: r.org_created_at,
            updated_at: r.org_updated_at,
            deleted_at: r.org_deleted_at,
        },
        email: Email {
            id: r.email_id,
            user_id: r.user_id,
            email: r.email,
            verified_at: r.verified_at,
        },
    }))
}

/// Create a token + session atomically within an existing transaction.
/// Uses the token's ID explicitly so the caller can format the bearer string
/// before the transaction commits.
#[tracing::instrument(skip(tx, token, ctx), fields(user_id = %user_id), err)]
pub async fn create(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token: &Token,
    user_id: Uuid,
    ttl_seconds: i32,
    ctx: &RequestContext<'_>,
) -> Result<(Uuid, DateTime<Utc>), AuthError> {
    let expires_at = sqlx::query_scalar!(
        "INSERT INTO auth.tokens (id, secret, expires_at)
         VALUES ($1, $2, now() + make_interval(secs => $3::int4))
         RETURNING expires_at",
        token.id,
        &token.secret_hash() as &[u8],
        ttl_seconds,
    )
    .fetch_one(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    let session_id = sqlx::query_scalar!(
        "INSERT INTO auth.sessions (user_id, token_id, ip_address, user_agent)
         VALUES ($1, $2, $3::text::inet, $4)
         RETURNING id",
        user_id,
        token.id,
        ctx.ip_address,
        ctx.user_agent,
    )
    .fetch_one(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    Ok((session_id, expires_at))
}

/// Fetch the single active session matching `token_id` for the given user.
/// Returns `None` if the session is expired or not found.
pub async fn get_current_session(
    pool: &PgPool,
    user_id: Uuid,
    token_id: Uuid,
) -> Result<Option<SessionListItem>, AuthError> {
    sqlx::query_as!(
        SessionListItem,
        r#"
        SELECT
            s.id,
            s.token_id,
            s.ip_address::text   AS ip_address,
            s.user_agent,
            s.created_at,
            tok.expires_at,
            tok.last_used_at,
            true                 AS "current!"
        FROM auth.sessions s
        INNER JOIN auth.tokens tok ON tok.id = s.token_id
        WHERE s.user_id  = $1
          AND s.token_id = $2
          AND tok.expires_at > now()
        "#,
        user_id,
        token_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)
}

/// List all non-expired sessions for the caller's user.
pub async fn list(
    pool: &PgPool,
    user_id: Uuid,
    current_token_id: Uuid,
) -> Result<Vec<SessionListItem>, AuthError> {
    sqlx::query_as!(
        SessionListItem,
        r#"
        SELECT
            s.id,
            s.token_id,
            s.ip_address::text   AS ip_address,
            s.user_agent,
            s.created_at,
            tok.expires_at,
            tok.last_used_at,
            (s.token_id = $2)    AS "current!"
        FROM auth.sessions s
        INNER JOIN auth.tokens tok ON tok.id = s.token_id
        WHERE s.user_id = $1
          AND tok.expires_at > now()
        ORDER BY tok.last_used_at DESC NULLS LAST, s.created_at DESC
        "#,
        user_id,
        current_token_id,
    )
    .fetch_all(pool)
    .await
    .map_err(AuthError::from)
}

/// Load user + primary org + primary email by user_id (for login response).
pub async fn load_user_context(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<(User, Org, Email), AuthError> {
    let r = sqlx::query!(
        r#"
        SELECT
            u.id                AS "user_id!: Uuid",
            u.primary_org_id    AS "primary_org_id!: Uuid",
            u.primary_email_id  AS "primary_email_id!: Uuid",
            u.created_at        AS "user_created_at!: DateTime<Utc>",
            t.id                AS "org_id!: Uuid",
            t.user_id           AS "org_user_id!: Uuid",
            t.name              AS "org_name!",
            t.slug              AS "org_slug!",
            t.image_url         AS "org_image_url",
            t.metadata          AS "org_metadata: serde_json::Value",
            t.created_at        AS "org_created_at!: DateTime<Utc>",
            t.updated_at        AS "org_updated_at!: DateTime<Utc>",
            t.deleted_at        AS "org_deleted_at",
            e.id                AS "email_id!: Uuid",
            e.email::text       AS "email!",
            e.verified_at
        FROM auth.users u
        INNER JOIN auth.orgs    t ON t.id = u.primary_org_id AND t.deleted_at IS NULL
        LEFT  JOIN auth.emails  e ON e.id = u.primary_email_id
        WHERE u.id = $1 AND u.deleted_at IS NULL
        "#,
        user_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?
    .ok_or(AuthError::NotFound)?;

    Ok((
        User {
            id: r.user_id,
            primary_org_id: r.primary_org_id,
            primary_email_id: r.primary_email_id,
            created_at: r.user_created_at,
        },
        Org {
            id: r.org_id,
            user_id: r.org_user_id,
            name: r.org_name,
            slug: r.org_slug,
            image_url: r.org_image_url,
            metadata: r.org_metadata,
            created_at: r.org_created_at,
            updated_at: r.org_updated_at,
            deleted_at: r.org_deleted_at,
        },
        Email {
            id: r.email_id,
            user_id: r.user_id,
            email: r.email,
            verified_at: r.verified_at,
        },
    ))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SessionListItem {
    pub id: Uuid,
    pub token_id: Uuid,
    #[schema(nullable)]
    pub ip_address: Option<String>,
    #[schema(nullable)]
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[schema(nullable)]
    pub last_used_at: Option<DateTime<Utc>>,
    /// Whether this is the caller's current session.
    pub current: bool,
}
