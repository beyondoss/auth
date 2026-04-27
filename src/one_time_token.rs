use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::AuthError,
    tokens::{Token, TokenPrefix},
};

pub struct CreatedToken {
    pub token: Token,
    pub expires_at: DateTime<Utc>,
}

pub async fn create(
    pool: &PgPool,
    prefix: TokenPrefix,
    user_id: Uuid,
    ttl_seconds: i32,
    context: Option<serde_json::Value>,
) -> Result<CreatedToken, AuthError> {
    let token = Token::new(prefix);
    let expires_at = sqlx::query_scalar!(
        "INSERT INTO auth.one_time_tokens (id, user_id, kind, secret, expires_at, context)
         VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5::int4), $6)
         RETURNING expires_at",
        token.id,
        user_id,
        token.prefix.as_str(),
        &token.secret_hash() as &[u8],
        ttl_seconds,
        context,
    )
    .fetch_one(pool)
    .await
    .map_err(AuthError::from)?;

    Ok(CreatedToken { token, expires_at })
}

/// Atomically consume a one-time token. Returns (user_id, context) on success.
///
/// Uses DELETE...RETURNING — exactly one concurrent caller wins, no TOCTOU,
/// no dead rows. Distinguishes expired vs invalid for caller feedback.
pub async fn consume(
    pool: &PgPool,
    expected_prefix: TokenPrefix,
    raw_token: &str,
) -> Result<(Uuid, Option<serde_json::Value>), AuthError> {
    let parsed = crate::tokens::parse(raw_token).ok_or(AuthError::TokenInvalid)?;
    if parsed.prefix != expected_prefix.as_str() {
        return Err(AuthError::TokenInvalid);
    }

    let row = sqlx::query!(
        "DELETE FROM auth.one_time_tokens
         WHERE id = $1 AND secret = $2 AND kind = $3 AND expires_at > now()
         RETURNING user_id, context",
        parsed.id,
        &parsed.secret_hash as &[u8],
        expected_prefix.as_str(),
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?;

    if let Some(r) = row {
        return Ok((r.user_id, r.context));
    }

    // Distinguish expired vs invalid (wrong secret, already consumed, never existed)
    let exists = sqlx::query_scalar!(
        "SELECT expires_at FROM auth.one_time_tokens WHERE id = $1 AND secret = $2 AND kind = $3",
        parsed.id,
        &parsed.secret_hash as &[u8],
        expected_prefix.as_str(),
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?;

    match exists {
        Some(_) => Err(AuthError::TokenExpired),
        None => Err(AuthError::TokenInvalid),
    }
}
