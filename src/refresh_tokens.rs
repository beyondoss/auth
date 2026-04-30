use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{error::AuthError, tokens::Token};

pub struct ValidatedRefreshToken {
    pub token_id: Uuid,
    pub family_id: Uuid,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub is_impersonated: bool,
}

/// Insert a new refresh token into `auth.tokens` + `auth.refresh_tokens`.
/// `family_id` is a fresh UUID for the first token in a family, or the
/// existing family UUID when rotating.
pub async fn create(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token: &Token,
    session_id: Uuid,
    family_id: Uuid,
    ttl_seconds: i32,
) -> Result<(), AuthError> {
    sqlx::query!(
        "INSERT INTO auth.tokens (id, secret, expires_at)
         VALUES ($1, $2, now() + make_interval(secs => $3::int4))",
        token.id,
        &token.secret_hash() as &[u8],
        ttl_seconds,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    sqlx::query!(
        "INSERT INTO auth.refresh_tokens (token_id, session_id, family_id)
         VALUES ($1, $2, $3)",
        token.id,
        session_id,
        family_id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    Ok(())
}

/// Validate a refresh token (`rt_<id>_<secret>`).
///
/// - Returns `None` if the token is not found or has expired.
/// - Returns `Err(AuthError::Unauthorized)` on replay detection (the token was
///   already rotated), after revoking the entire token family.
pub async fn validate(
    pool: &PgPool,
    token_id: Uuid,
    secret_hash: &[u8],
) -> Result<Option<ValidatedRefreshToken>, AuthError> {
    let row = sqlx::query!(
        r#"
        SELECT
            rt.token_id         AS "token_id!: Uuid",
            rt.family_id        AS "family_id!: Uuid",
            rt.session_id       AS "session_id!: Uuid",
            rt.replaced_at,
            tok.expires_at      AS "expires_at!: DateTime<Utc>",
            u.id                AS "user_id!: Uuid"
        FROM auth.refresh_tokens rt
        INNER JOIN auth.tokens tok ON tok.id = rt.token_id
        INNER JOIN auth.sessions s ON s.id = rt.session_id
        INNER JOIN auth.users u ON u.id = s.user_id AND u.deleted_at IS NULL
        WHERE rt.token_id = $1
          AND tok.secret  = $2
        "#,
        token_id,
        secret_hash,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?;

    let row = match row {
        None => return Ok(None),
        Some(r) => r,
    };

    if row.expires_at <= Utc::now() {
        return Ok(None);
    }

    if row.replaced_at.is_some() {
        // Token was already rotated — possible theft. Revoke the whole family.
        revoke_family(pool, row.family_id).await?;
        return Err(AuthError::Unauthorized);
    }

    Ok(Some(ValidatedRefreshToken {
        token_id: row.token_id,
        family_id: row.family_id,
        session_id: row.session_id,
        user_id: row.user_id,
        is_impersonated: false,
    }))
}

/// Mark `old_token_id` as replaced and create a successor in the same family.
///
/// The UPDATE is guarded by `AND replaced_at IS NULL` to make rotation atomic
/// against concurrent requests presenting the same token. If another request
/// already rotated the token, 0 rows are affected: the entire family is revoked
/// (replay-theft response) and `Err(AuthError::Unauthorized)` is returned.
pub async fn rotate(
    pool: &PgPool,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    old_token_id: Uuid,
    new_token: &Token,
    session_id: Uuid,
    family_id: Uuid,
    ttl_seconds: i32,
) -> Result<(), AuthError> {
    let result = sqlx::query!(
        "UPDATE auth.refresh_tokens SET replaced_at = now()
         WHERE token_id = $1 AND replaced_at IS NULL",
        old_token_id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    if result.rows_affected() == 0 {
        revoke_family(pool, family_id).await?;
        return Err(AuthError::Unauthorized);
    }

    create(tx, new_token, session_id, family_id, ttl_seconds).await
}

/// Expire every token in the family immediately (replay attack response).
async fn revoke_family(pool: &PgPool, family_id: Uuid) -> Result<(), AuthError> {
    sqlx::query!(
        "UPDATE auth.tokens SET expires_at = now()
         FROM auth.refresh_tokens rt
         WHERE auth.tokens.id = rt.token_id
           AND rt.family_id   = $1",
        family_id,
    )
    .execute(pool)
    .await
    .map_err(AuthError::from)?;
    Ok(())
}
