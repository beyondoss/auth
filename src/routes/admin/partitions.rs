use axum::{
    extract::{Path, State},
    http::StatusCode,
};

use crate::{error::AuthError, http::AppState};

/// Ensure a dedicated LIST partition exists for `object_type`.
///
/// Idempotent — safe to call multiple times. Existing rows in the default
/// partition are moved to the new partition atomically.
#[utoipa::path(
    put,
    path = "/v1/admin/relation-partitions/{object_type}",
    tag = "admin",
    params(
        ("object_type" = String, Path, description = "Object type to partition (e.g. \"document\")")
    ),
    responses(
        (status = 204, description = "Partition exists (created or already present)"),
        (status = 422, description = "Invalid object_type identifier", body = crate::error::ErrorResponse),
    )
)]
pub async fn ensure_partition(
    State(state): State<AppState>,
    Path(object_type): Path<String>,
) -> Result<StatusCode, AuthError> {
    crate::authz::schema::validate_ident(&object_type).map_err(|_| {
        AuthError::AuthzSchemaInvalid {
            message: format!("invalid object_type {object_type:?}: must match [a-z][a-z0-9_]*"),
        }
    })?;

    // Identifier is validated — safe to interpolate as SQL literals.
    let sql = format!(
        r#"
        CREATE TABLE IF NOT EXISTS auth.relation_tuple_{object_type}
            PARTITION OF auth.relation_tuple
            FOR VALUES IN ('{object_type}');

        WITH moved AS (
            DELETE FROM auth.relation_tuple_default
            WHERE object_type = '{object_type}'
            RETURNING *
        )
        INSERT INTO auth.relation_tuple_{object_type}
            SELECT * FROM moved
        ON CONFLICT DO NOTHING;
        "#
    );

    sqlx::query(&sql)
        .execute(&state.pool)
        .await
        .map_err(AuthError::from)?;

    Ok(StatusCode::NO_CONTENT)
}
