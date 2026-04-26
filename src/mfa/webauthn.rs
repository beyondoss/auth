use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
use webauthn_rs::prelude::{DiscoverableAuthentication, Passkey, PasskeyRegistration};

use crate::{error::AuthError, keys::LoadedKey};

pub fn pack_reg_state(reg: &PasskeyRegistration, user_id: Uuid, key: &LoadedKey) -> String {
    let now = Utc::now().timestamp();
    let exp = now + 300;

    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&json!({
            "alg": "EdDSA",
            "typ": "webauthn_reg",
            "kid": key.id.to_string(),
        }))
        .expect("webauthn_reg header serialization is infallible"),
    );

    let state_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(reg).expect("PasskeyRegistration serialization is infallible"));

    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&json!({
            "sub": user_id.to_string(),
            "state": state_b64,
            "iat": now,
            "exp": exp,
        }))
        .expect("webauthn_reg claims serialization is infallible"),
    );

    let signing_input = format!("{header}.{claims}");
    let signature = key.signing_key.sign(signing_input.as_bytes());
    let sig_encoded = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    format!("{signing_input}.{sig_encoded}")
}

pub fn unpack_reg_state(
    token: &str,
    user_id: Uuid,
    key: &LoadedKey,
) -> Result<PasskeyRegistration, AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::TokenInvalid);
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AuthError::TokenInvalid)?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| AuthError::TokenInvalid)?;
    if header.get("typ").and_then(Value::as_str) != Some("webauthn_reg") {
        return Err(AuthError::TokenInvalid);
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AuthError::TokenInvalid)?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::TokenInvalid)?;
    let signature = Signature::from_bytes(&sig_array);

    key.signing_key
        .verifying_key()
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| AuthError::TokenInvalid)?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AuthError::TokenInvalid)?;
    let claims: Value =
        serde_json::from_slice(&claims_bytes).map_err(|_| AuthError::TokenInvalid)?;

    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(AuthError::TokenInvalid)?;
    if Utc::now().timestamp() >= exp {
        return Err(AuthError::TokenExpired);
    }

    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(AuthError::TokenInvalid)?;
    if sub != user_id {
        return Err(AuthError::TokenInvalid);
    }

    let state_b64 = claims
        .get("state")
        .and_then(Value::as_str)
        .ok_or(AuthError::TokenInvalid)?;
    let state_bytes = URL_SAFE_NO_PAD
        .decode(state_b64)
        .map_err(|_| AuthError::TokenInvalid)?;
    let reg: PasskeyRegistration =
        serde_json::from_slice(&state_bytes).map_err(|_| AuthError::TokenInvalid)?;

    Ok(reg)
}

pub fn pack_auth_state(auth: &DiscoverableAuthentication, key: &LoadedKey) -> String {
    let now = Utc::now().timestamp();
    let exp = now + 300;

    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&json!({
            "alg": "EdDSA",
            "typ": "webauthn_auth",
            "kid": key.id.to_string(),
        }))
        .expect("webauthn_auth header serialization is infallible"),
    );

    let state_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(auth).expect("DiscoverableAuthentication serialization is infallible"),
    );

    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&json!({
            "state": state_b64,
            "iat": now,
            "exp": exp,
        }))
        .expect("webauthn_auth claims serialization is infallible"),
    );

    let signing_input = format!("{header}.{claims}");
    let signature = key.signing_key.sign(signing_input.as_bytes());
    let sig_encoded = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    format!("{signing_input}.{sig_encoded}")
}

pub fn unpack_auth_state(
    token: &str,
    key: &LoadedKey,
) -> Result<DiscoverableAuthentication, AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::TokenInvalid);
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AuthError::TokenInvalid)?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| AuthError::TokenInvalid)?;
    if header.get("typ").and_then(Value::as_str) != Some("webauthn_auth") {
        return Err(AuthError::TokenInvalid);
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AuthError::TokenInvalid)?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::TokenInvalid)?;
    let signature = Signature::from_bytes(&sig_array);

    key.signing_key
        .verifying_key()
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| AuthError::TokenInvalid)?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AuthError::TokenInvalid)?;
    let claims: Value =
        serde_json::from_slice(&claims_bytes).map_err(|_| AuthError::TokenInvalid)?;

    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(AuthError::TokenInvalid)?;
    if Utc::now().timestamp() >= exp {
        return Err(AuthError::TokenExpired);
    }

    let state_b64 = claims
        .get("state")
        .and_then(Value::as_str)
        .ok_or(AuthError::TokenInvalid)?;
    let state_bytes = URL_SAFE_NO_PAD
        .decode(state_b64)
        .map_err(|_| AuthError::TokenInvalid)?;
    let auth: DiscoverableAuthentication =
        serde_json::from_slice(&state_bytes).map_err(|_| AuthError::TokenInvalid)?;

    Ok(auth)
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialRecord {
    pub id: Uuid,
    pub nickname: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

pub async fn store_credential(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    passkey: &Passkey,
    nickname: Option<&str>,
) -> Result<(Uuid, DateTime<Utc>), AuthError> {
    let cred_id: &[u8] = passkey.cred_id().as_ref();
    let data = serde_json::to_value(passkey)
        .map_err(|e| AuthError::internal_with("serialize passkey", e))?;
    let id = Uuid::now_v7();

    let row = sqlx::query!(
        r#"INSERT INTO auth.webauthn_credential (id, user_id, credential_id, credential_data, nickname)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, created_at"#,
        id,
        user_id,
        cred_id,
        data,
        nickname,
    )
    .fetch_one(pool)
    .await
    .map_err(AuthError::from)?;

    Ok((row.id, row.created_at))
}

pub async fn credentials_for_user(
    pool: &sqlx::PgPool,
    user_id: Uuid,
) -> Result<Vec<CredentialRecord>, AuthError> {
    let rows = sqlx::query!(
        r#"SELECT id, nickname, created_at, last_used_at
           FROM auth.webauthn_credential
           WHERE user_id = $1 AND deleted_at IS NULL
           ORDER BY created_at ASC"#,
        user_id,
    )
    .fetch_all(pool)
    .await
    .map_err(AuthError::from)?;

    Ok(rows
        .into_iter()
        .map(|r| CredentialRecord {
            id: r.id,
            nickname: r.nickname,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
        })
        .collect())
}

pub async fn find_credential(
    pool: &sqlx::PgPool,
    credential_id: &[u8],
) -> Result<Option<(Uuid, Uuid, Passkey)>, AuthError> {
    let row = sqlx::query!(
        r#"SELECT id, user_id, credential_data AS "credential_data: serde_json::Value"
           FROM auth.webauthn_credential
           WHERE credential_id = $1 AND deleted_at IS NULL"#,
        credential_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?;

    let Some(row) = row else { return Ok(None) };
    let passkey: Passkey = serde_json::from_value(row.credential_data)
        .map_err(|e| AuthError::internal_with("deserialize passkey", e))?;
    Ok(Some((row.id, row.user_id, passkey)))
}

pub async fn update_credential(
    pool: &sqlx::PgPool,
    row_id: Uuid,
    updated: &Passkey,
) -> Result<(), AuthError> {
    let data = serde_json::to_value(updated)
        .map_err(|e| AuthError::internal_with("serialize passkey", e))?;

    sqlx::query!(
        r#"UPDATE auth.webauthn_credential
           SET credential_data = $1, last_used_at = clock_timestamp()
           WHERE id = $2"#,
        data,
        row_id,
    )
    .execute(pool)
    .await
    .map_err(AuthError::from)?;

    Ok(())
}

pub async fn update_nickname(
    pool: &sqlx::PgPool,
    id: Uuid,
    user_id: Uuid,
    nickname: &str,
) -> Result<(), AuthError> {
    let result = sqlx::query!(
        r#"UPDATE auth.webauthn_credential
           SET nickname = $1
           WHERE id = $2 AND user_id = $3 AND deleted_at IS NULL"#,
        nickname,
        id,
        user_id,
    )
    .execute(pool)
    .await
    .map_err(AuthError::from)?;

    if result.rows_affected() == 0 {
        return Err(AuthError::NotFound);
    }

    Ok(())
}

pub async fn delete_credential(
    pool: &sqlx::PgPool,
    id: Uuid,
    user_id: Uuid,
) -> Result<(), AuthError> {
    let result = sqlx::query!(
        r#"DELETE FROM auth.webauthn_credential
           WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL"#,
        id,
        user_id,
    )
    .execute(pool)
    .await
    .map_err(AuthError::from)?;

    if result.rows_affected() == 0 {
        return Err(AuthError::NotFound);
    }

    Ok(())
}
