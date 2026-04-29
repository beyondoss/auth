use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AuthError;

#[derive(Debug, Clone, Serialize)]
pub struct Org {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub slug: String,
    pub image_url: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrgMember {
    pub user_id: Uuid,
    pub role: String,
    pub joined_at: DateTime<Utc>,
}

/// Lowercase, replace non-alphanumeric with `-`, collapse runs.
/// Appends a short random hex suffix to avoid collisions on concurrent creates.
pub fn slugify(base: &str) -> String {
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

pub async fn create(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    user_id: Uuid,
    name: &str,
    slug: &str,
    image_url: Option<&str>,
    metadata: Option<serde_json::Value>,
) -> Result<Org, AuthError> {
    sqlx::query_as!(
        Org,
        r#"INSERT INTO auth.orgs (id, user_id, name, slug, image_url, metadata)
         VALUES ($1, $2, $3, $4, $5, COALESCE($6, '{}'::jsonb))
         RETURNING id, user_id, name, slug, image_url,
                   metadata as "metadata: serde_json::Value",
                   created_at, updated_at, deleted_at"#,
        id,
        user_id,
        name,
        slug,
        image_url,
        metadata as Option<serde_json::Value>,
    )
    .fetch_one(tx.as_mut())
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(ref db) = e
            && db.constraint() == Some("orgs_slug_idx")
        {
            return AuthError::SlugConflict;
        }
        AuthError::from(e)
    })
}

pub async fn get(pool: &PgPool, org_id: Uuid) -> Result<Org, AuthError> {
    sqlx::query_as!(
        Org,
        r#"SELECT id, user_id, name, slug, image_url,
                  metadata as "metadata: serde_json::Value",
                  created_at, updated_at, deleted_at
           FROM auth.orgs
           WHERE id = $1 AND deleted_at IS NULL"#,
        org_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?
    .ok_or(AuthError::OrgNotFound)
}

/// All orgs the user belongs to (any relation), ordered by id ascending (UUIDv7 = time-ordered).
pub async fn list(
    pool: &PgPool,
    user_id: Uuid,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<Org>, AuthError> {
    let user_id_str = user_id.to_string();
    sqlx::query_as!(
        Org,
        r#"SELECT o.id, o.user_id, o.name, o.slug, o.image_url,
                  o.metadata as "metadata: serde_json::Value",
                  o.created_at, o.updated_at, o.deleted_at
           FROM auth.orgs o
           WHERE o.deleted_at IS NULL
             AND ($1::text IS NULL OR o.id > $1::uuid)
             AND EXISTS (
                 SELECT 1 FROM auth.authz_relations
                 WHERE object_type = 'org'
                   AND object_id   = o.id::text
                   AND subject_id  = $2
                   AND subject_set_type IS NULL
             )
           ORDER BY o.id ASC
           LIMIT $3"#,
        after,
        user_id_str,
        limit,
    )
    .fetch_all(pool)
    .await
    .map_err(AuthError::from)
}

pub async fn update(
    pool: &PgPool,
    org_id: Uuid,
    name: Option<&str>,
    slug: Option<&str>,
    image_url: Option<&str>,
    metadata: Option<serde_json::Value>,
) -> Result<Org, AuthError> {
    sqlx::query_as!(
        Org,
        r#"UPDATE auth.orgs
           SET name      = COALESCE($2, name),
               slug      = COALESCE($3, slug),
               image_url = COALESCE($4, image_url),
               metadata  = COALESCE($5, metadata)
           WHERE id = $1 AND deleted_at IS NULL
           RETURNING id, user_id, name, slug, image_url,
                     metadata as "metadata: serde_json::Value",
                     created_at, updated_at, deleted_at"#,
        org_id,
        name,
        slug,
        image_url,
        metadata as Option<serde_json::Value>,
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(ref db) = e
            && db.constraint() == Some("orgs_slug_idx")
        {
            return AuthError::SlugConflict;
        }
        AuthError::from(e)
    })?
    .ok_or(AuthError::OrgNotFound)
}

pub async fn soft_delete(pool: &PgPool, org_id: Uuid) -> Result<(), AuthError> {
    let mut tx = pool.begin().await.map_err(AuthError::from)?;

    let is_personal: bool = sqlx::query_scalar!(
        r#"SELECT EXISTS(
               SELECT 1 FROM auth.users
               WHERE primary_org_id = $1 AND deleted_at IS NULL
           ) as "exists!""#,
        org_id,
    )
    .fetch_one(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    if is_personal {
        return Err(AuthError::PersonalOrg);
    }

    let rows = sqlx::query!(
        "UPDATE auth.orgs SET deleted_at = clock_timestamp()
         WHERE id = $1 AND deleted_at IS NULL",
        org_id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?
    .rows_affected();

    if rows == 0 {
        return Err(AuthError::OrgNotFound);
    }

    tx.commit().await.map_err(AuthError::from)?;
    Ok(())
}

pub async fn list_members(
    pool: &PgPool,
    org_id: Uuid,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<OrgMember>, AuthError> {
    let org_id_str = org_id.to_string();
    sqlx::query_as!(
        OrgMember,
        r#"SELECT
               subject_id::uuid as "user_id!: Uuid",
               relation          as "role!",
               created_at        as "joined_at!: DateTime<Utc>"
           FROM auth.authz_relations
           WHERE object_type = 'org'
             AND object_id   = $1
             AND subject_set_type IS NULL
             AND ($2::text IS NULL OR subject_id > $2)
           ORDER BY subject_id ASC
           LIMIT $3"#,
        org_id_str,
        after,
        limit,
    )
    .fetch_all(pool)
    .await
    .map_err(AuthError::from)
}

pub async fn is_owner(pool: &PgPool, org_id: Uuid, user_id: Uuid) -> Result<bool, AuthError> {
    let org_id_str = org_id.to_string();
    let user_id_str = user_id.to_string();
    sqlx::query_scalar!(
        r#"SELECT EXISTS(
               SELECT 1 FROM auth.authz_relations
               WHERE object_type = 'org'
                 AND object_id   = $1
                 AND relation    = 'owner'
                 AND subject_id  = $2
                 AND subject_set_type IS NULL
           ) as "exists!""#,
        org_id_str,
        user_id_str,
    )
    .fetch_one(pool)
    .await
    .map_err(AuthError::from)
}

pub async fn is_member(pool: &PgPool, org_id: Uuid, user_id: Uuid) -> Result<bool, AuthError> {
    let org_id_str = org_id.to_string();
    let user_id_str = user_id.to_string();
    sqlx::query_scalar!(
        r#"SELECT EXISTS(
               SELECT 1 FROM auth.authz_relations
               WHERE object_type = 'org'
                 AND object_id   = $1
                 AND subject_id  = $2
                 AND subject_set_type IS NULL
           ) as "exists!""#,
        org_id_str,
        user_id_str,
    )
    .fetch_one(pool)
    .await
    .map_err(AuthError::from)
}

/// Insert a membership tuple. If the user is already a member, returns AlreadyMember.
pub async fn add_member(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    user_id: Uuid,
    role: &str,
) -> Result<(), AuthError> {
    let org_id_str = org_id.to_string();
    let user_id_str = user_id.to_string();

    let already_member: bool = sqlx::query_scalar!(
        r#"SELECT EXISTS(
               SELECT 1 FROM auth.authz_relations
               WHERE object_type = 'org'
                 AND object_id   = $1
                 AND subject_id  = $2
                 AND subject_set_type IS NULL
           ) as "exists!""#,
        org_id_str,
        user_id_str,
    )
    .fetch_one(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    if already_member {
        return Err(AuthError::AlreadyMember);
    }

    sqlx::query!(
        "INSERT INTO auth.authz_relations (object_type, object_id, relation, subject_id)
         VALUES ('org', $1, $2, $3)",
        org_id_str,
        role,
        user_id_str,
    )
    .execute(tx.as_mut())
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(ref db) = e
            && db.constraint().is_some()
        {
            return AuthError::AlreadyMember;
        }
        AuthError::from(e)
    })?;

    Ok(())
}

/// Replace the user's role in an org atomically.
/// - Returns `NotMember` if the user has no membership tuple.
/// - Returns `LastOwner` if demoting/removing the only owner.
///
/// `SELECT ... FOR UPDATE` on owner rows serializes concurrent last-owner checks:
/// two simultaneous demotions of the same last owner will interleave correctly
/// rather than both passing and leaving zero owners.
pub async fn update_member_role(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    role: &str,
) -> Result<(), AuthError> {
    let org_id_str = org_id.to_string();
    let user_id_str = user_id.to_string();
    let mut tx = pool.begin().await.map_err(AuthError::from)?;

    // Lock all owner rows for this org before making changes. This serializes
    // concurrent last-owner checks — a second request blocks here until we commit.
    sqlx::query!(
        "SELECT id FROM auth.authz_relations
         WHERE object_type = 'org' AND object_id = $1
           AND relation = 'owner' AND subject_set_type IS NULL
         FOR UPDATE",
        org_id_str,
    )
    .fetch_all(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    let old_role: Option<String> = sqlx::query_scalar!(
        "DELETE FROM auth.authz_relations
         WHERE object_type = 'org' AND object_id = $1
           AND subject_id = $2 AND subject_set_type IS NULL
         RETURNING relation",
        org_id_str,
        user_id_str,
    )
    .fetch_optional(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    if old_role.is_none() {
        return Err(AuthError::NotMember);
    }

    // After our DELETE is visible within the transaction, check remaining owners.
    if old_role.as_deref() == Some("owner") && role != "owner" {
        let remaining: i64 = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "count!" FROM auth.authz_relations
               WHERE object_type = 'org' AND object_id = $1
                 AND relation = 'owner' AND subject_set_type IS NULL"#,
            org_id_str,
        )
        .fetch_one(tx.as_mut())
        .await
        .map_err(AuthError::from)?;

        if remaining == 0 {
            return Err(AuthError::LastOwner);
        }
    }

    sqlx::query!(
        "INSERT INTO auth.authz_relations (object_type, object_id, relation, subject_id)
         VALUES ('org', $1, $2, $3)",
        org_id_str,
        role,
        user_id_str,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    tx.commit().await.map_err(AuthError::from)?;
    Ok(())
}

/// Remove a user from an org atomically.
/// - Returns `NotMember` if they weren't a member.
/// - Returns `LastOwner` if they are the only remaining owner.
pub async fn remove_member(pool: &PgPool, org_id: Uuid, user_id: Uuid) -> Result<(), AuthError> {
    let org_id_str = org_id.to_string();
    let user_id_str = user_id.to_string();
    let mut tx = pool.begin().await.map_err(AuthError::from)?;

    // Lock owner rows to serialize concurrent last-owner removals.
    sqlx::query!(
        "SELECT id FROM auth.authz_relations
         WHERE object_type = 'org' AND object_id = $1
           AND relation = 'owner' AND subject_set_type IS NULL
         FOR UPDATE",
        org_id_str,
    )
    .fetch_all(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    let old_role: Option<String> = sqlx::query_scalar!(
        "DELETE FROM auth.authz_relations
         WHERE object_type = 'org' AND object_id = $1
           AND subject_id = $2 AND subject_set_type IS NULL
         RETURNING relation",
        org_id_str,
        user_id_str,
    )
    .fetch_optional(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    if old_role.is_none() {
        return Err(AuthError::NotMember);
    }

    if old_role.as_deref() == Some("owner") {
        let remaining: i64 = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "count!" FROM auth.authz_relations
               WHERE object_type = 'org' AND object_id = $1
                 AND relation = 'owner' AND subject_set_type IS NULL"#,
            org_id_str,
        )
        .fetch_one(tx.as_mut())
        .await
        .map_err(AuthError::from)?;

        if remaining == 0 {
            return Err(AuthError::LastOwner);
        }
    }

    tx.commit().await.map_err(AuthError::from)?;
    Ok(())
}

pub async fn require_owner(pool: &PgPool, org_id: Uuid, user_id: Uuid) -> Result<(), AuthError> {
    if !is_owner(pool, org_id, user_id).await? {
        Err(AuthError::Forbidden)
    } else {
        Ok(())
    }
}

pub async fn require_member(pool: &PgPool, org_id: Uuid, user_id: Uuid) -> Result<(), AuthError> {
    if !is_member(pool, org_id, user_id).await? {
        Err(AuthError::NotMember)
    } else {
        Ok(())
    }
}
