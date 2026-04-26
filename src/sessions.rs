use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{emails::Email, error::AuthError, tenants::Tenant, tokens::Token, users::User};

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

/// Validated caller context — extracted from the bearer token by `validate`.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub user: User,
    pub email: Email,
    pub tenant: Tenant,
    pub session_id: Uuid,
    pub token_id: Uuid,
}

pub struct RequestContext<'a> {
    pub ip_address: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// Validate a bearer token and return the caller's context in one round-trip.
///
/// Bundled CTE (translated from internal `GetMe`):
/// - validates token id + secret hash + not expired
/// - debounces `last_used_at` (skips update if touched within the last minute)
/// - joins user, personal tenant, and primary email
///
/// Returns `None` for expired, missing, or wrong-secret tokens.
pub async fn validate(
    pool: &PgPool,
    token_id: Uuid,
    secret_hash: &str,
) -> Result<Option<SessionContext>, AuthError> {
    let row = sqlx::query!(
        r#"
        WITH valid_token AS (
            SELECT token.id AS token_id
            FROM auth.token
            WHERE token.id         = $1
              AND token.secret     = $2
              AND token.expires_at > clock_timestamp()
            LIMIT 1
        ),
        update_attempt AS (
            UPDATE auth.token SET last_used_at = clock_timestamp()
            FROM valid_token
            WHERE auth.token.id = valid_token.token_id
              AND (auth.token.last_used_at IS NULL
                   OR auth.token.last_used_at < clock_timestamp() - interval '1 minute')
        )
        SELECT
            u.id                AS "user_id!: Uuid",
            u.personal_tenant_id AS "personal_tenant_id!: Uuid",
            u.primary_email_id  AS "primary_email_id!: Uuid",
            u.display_name,
            u.avatar_url,
            u.created_at        AS "user_created_at!: DateTime<Utc>",
            t.id                AS "tenant_id!: Uuid",
            t.user_id           AS "tenant_user_id!: Uuid",
            t.name              AS "tenant_name!",
            t.slug              AS "tenant_slug!",
            t.created_at        AS "tenant_created_at!: DateTime<Utc>",
            e.id                AS "email_id!: Uuid",
            e.email::text       AS "email!",
            e.verified_at,
            s.id                AS "session_id!: Uuid",
            v.token_id          AS "token_id!: Uuid"
        FROM valid_token v
        INNER JOIN auth.session  s ON s.token_id  = v.token_id
        INNER JOIN auth."user"   u ON u.id = s.user_id AND u.deleted_at IS NULL
        INNER JOIN auth.tenant   t ON t.id = u.personal_tenant_id AND t.deleted_at IS NULL
        LEFT  JOIN auth.email    e ON e.id = u.primary_email_id
        "#,
        token_id,
        secret_hash,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?;

    Ok(row.map(|r| SessionContext {
        session_id: r.session_id,
        token_id: r.token_id,
        user: User {
            id: r.user_id,
            personal_tenant_id: r.personal_tenant_id,
            primary_email_id: r.primary_email_id,
            display_name: r.display_name,
            avatar_url: r.avatar_url,
            created_at: r.user_created_at,
        },
        tenant: Tenant {
            id: r.tenant_id,
            user_id: r.tenant_user_id,
            name: r.tenant_name,
            slug: r.tenant_slug,
            created_at: r.tenant_created_at,
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
pub async fn create(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token: &Token,
    user_id: Uuid,
    ttl_seconds: i32,
    ctx: &RequestContext<'_>,
) -> Result<(Uuid, DateTime<Utc>), AuthError> {
    let expires_at = sqlx::query_scalar!(
        "INSERT INTO auth.token (id, secret, expires_at)
         VALUES ($1, $2, clock_timestamp() + make_interval(secs => $3::int4))
         RETURNING expires_at",
        token.id,
        token.secret_hash(),
        ttl_seconds,
    )
    .fetch_one(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    let session_id = sqlx::query_scalar!(
        "INSERT INTO auth.session (user_id, token_id, ip_address, user_agent)
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
        FROM auth.session s
        INNER JOIN auth.token tok ON tok.id = s.token_id
        WHERE s.user_id = $1
          AND tok.expires_at > clock_timestamp()
        ORDER BY tok.last_used_at DESC NULLS LAST, s.created_at DESC
        "#,
        user_id,
        current_token_id,
    )
    .fetch_all(pool)
    .await
    .map_err(AuthError::from)
}

/// Load user + personal tenant + primary email by user_id (for login response).
pub async fn load_user_context(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<(User, Tenant, Email), AuthError> {
    let r = sqlx::query!(
        r#"
        SELECT
            u.id                AS "user_id!: Uuid",
            u.personal_tenant_id AS "personal_tenant_id!: Uuid",
            u.primary_email_id  AS "primary_email_id!: Uuid",
            u.display_name,
            u.avatar_url,
            u.created_at        AS "user_created_at!: DateTime<Utc>",
            t.id                AS "tenant_id!: Uuid",
            t.user_id           AS "tenant_user_id!: Uuid",
            t.name              AS "tenant_name!",
            t.slug              AS "tenant_slug!",
            t.created_at        AS "tenant_created_at!: DateTime<Utc>",
            e.id                AS "email_id!: Uuid",
            e.email::text       AS "email!",
            e.verified_at
        FROM auth."user" u
        INNER JOIN auth.tenant t ON t.id = u.personal_tenant_id AND t.deleted_at IS NULL
        LEFT  JOIN auth.email  e ON e.id = u.primary_email_id
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
            personal_tenant_id: r.personal_tenant_id,
            primary_email_id: r.primary_email_id,
            display_name: r.display_name,
            avatar_url: r.avatar_url,
            created_at: r.user_created_at,
        },
        Tenant {
            id: r.tenant_id,
            user_id: r.tenant_user_id,
            name: r.tenant_name,
            slug: r.tenant_slug,
            created_at: r.tenant_created_at,
        },
        Email {
            id: r.email_id,
            user_id: r.user_id,
            email: r.email,
            verified_at: r.verified_at,
        },
    ))
}

#[derive(Debug, Serialize)]
pub struct SessionListItem {
    pub id: Uuid,
    pub token_id: Uuid,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub current: bool,
}
