use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AuthError;

#[derive(Debug, Clone, Serialize)]
pub struct Invitation {
    pub id: Uuid,
    pub org_id: Uuid,
    pub invited_by: Option<Uuid>,
    pub email: Option<String>,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Public view of an invitation — includes org name for the invitee's benefit.
#[derive(Debug, Clone, Serialize)]
pub struct InvitationView {
    pub id: Uuid,
    pub org_id: Uuid,
    pub org_name: String,
    pub role: String,
    pub expires_at: DateTime<Utc>,
}

pub async fn create(
    pool: &PgPool,
    org_id: Uuid,
    invited_by: Uuid,
    email: Option<&str>,
    role: &str,
    token_hash: &[u8],
) -> Result<Invitation, AuthError> {
    sqlx::query_as!(
        Invitation,
        r#"INSERT INTO auth.org_invitations (org_id, invited_by, email, role, token_hash)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, org_id, invited_by, email, role, created_at, expires_at"#,
        org_id,
        invited_by,
        email,
        role,
        token_hash,
    )
    .fetch_one(pool)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(ref db) = e {
            if db.constraint() == Some("org_invitations_email_unique") {
                return AuthError::Conflict;
            }
        }
        AuthError::from(e)
    })
}

pub async fn list(pool: &PgPool, org_id: Uuid) -> Result<Vec<Invitation>, AuthError> {
    sqlx::query_as!(
        Invitation,
        r#"SELECT id, org_id, invited_by, email, role, created_at, expires_at
           FROM auth.org_invitations
           WHERE org_id = $1 AND expires_at > now()
           ORDER BY created_at DESC"#,
        org_id,
    )
    .fetch_all(pool)
    .await
    .map_err(AuthError::from)
}

/// Look up an invitation by id + token hash for public view. Returns NotFound if
/// expired, missing, or token doesn't match — no distinction between cases.
pub async fn get_by_token(
    pool: &PgPool,
    inv_id: Uuid,
    token_hash: &[u8],
) -> Result<InvitationView, AuthError> {
    sqlx::query_as!(
        InvitationView,
        r#"SELECT i.id, i.org_id, o.name as org_name, i.role, i.expires_at
           FROM auth.org_invitations i
           JOIN auth.orgs o ON o.id = i.org_id
           WHERE i.id = $1
             AND i.token_hash = $2
             AND i.expires_at > now()"#,
        inv_id,
        token_hash,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?
    .ok_or(AuthError::InvitationNotFound)
}

/// Atomically consume an invitation: DELETE...RETURNING so there are no dead rows
/// and no TOCTOU window. Returns NotFound if expired, missing, or hash mismatch.
pub async fn consume(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    inv_id: Uuid,
    token_hash: &[u8],
) -> Result<Invitation, AuthError> {
    sqlx::query_as!(
        Invitation,
        r#"DELETE FROM auth.org_invitations
           WHERE id = $1
             AND token_hash = $2
             AND expires_at > now()
           RETURNING id, org_id, invited_by, email, role, created_at, expires_at"#,
        inv_id,
        token_hash,
    )
    .fetch_optional(tx.as_mut())
    .await
    .map_err(AuthError::from)?
    .ok_or(AuthError::InvitationNotFound)
}

/// Revoke an invitation without a token (owner action). Returns NotFound if missing.
pub async fn revoke(pool: &PgPool, inv_id: Uuid, org_id: Uuid) -> Result<(), AuthError> {
    let rows = sqlx::query!(
        "DELETE FROM auth.org_invitations WHERE id = $1 AND org_id = $2",
        inv_id,
        org_id,
    )
    .execute(pool)
    .await
    .map_err(AuthError::from)?
    .rows_affected();

    if rows == 0 {
        return Err(AuthError::InvitationNotFound);
    }

    Ok(())
}
