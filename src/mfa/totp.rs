use base64::{Engine, engine::general_purpose::STANDARD};
use qrcode::{QrCode, render::svg};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

use crate::{crypto::KeyEncryptor, error::AuthError};

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn make_totp(secret_bytes: &[u8]) -> Result<TOTP, AuthError> {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Raw(secret_bytes.to_vec()).to_bytes().map_err(|e| {
            AuthError::internal_with(
                "totp secret decoding",
                std::io::Error::other(format!("{e:?}")),
            )
        })?,
        None,
        String::new(),
    )
    .map_err(|e| {
        AuthError::internal_with("totp construction", std::io::Error::other(e.to_string()))
    })
}

fn make_totp_labeled(secret_bytes: &[u8], email: &str, issuer: &str) -> Result<TOTP, AuthError> {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Raw(secret_bytes.to_vec()).to_bytes().map_err(|e| {
            AuthError::internal_with(
                "totp secret decoding",
                std::io::Error::other(format!("{e:?}")),
            )
        })?,
        Some(issuer.to_string()),
        email.to_string(),
    )
    .map_err(|e| {
        AuthError::internal_with("totp construction", std::io::Error::other(e.to_string()))
    })
}

pub fn generate_secret() -> (Vec<u8>, String) {
    let raw = Secret::generate_secret();
    let bytes = raw.to_bytes().expect("Secret::Raw to_bytes is infallible");
    let encoded = match raw.to_encoded() {
        Secret::Encoded(s) => s,
        Secret::Raw(_) => unreachable!("to_encoded always returns Encoded"),
    };
    (bytes, encoded)
}

pub fn qr_data_url(uri: &str) -> Result<String, AuthError> {
    let code = QrCode::new(uri.as_bytes()).map_err(|e| {
        AuthError::internal_with("qr generation", std::io::Error::other(e.to_string()))
    })?;
    let svg = code
        .render::<svg::Color<'_>>()
        .min_dimensions(200, 200)
        .build();
    let b64 = STANDARD.encode(svg.as_bytes());
    Ok(format!("data:image/svg+xml;base64,{b64}"))
}

pub fn generate_recovery_codes() -> [String; 10] {
    use rand_core::{OsRng, RngCore};
    std::array::from_fn(|_| {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    })
}

pub fn verify_code(secret_bytes: &[u8], code: &str) -> bool {
    make_totp(secret_bytes)
        .map(|t| t.check_current(code).unwrap_or(false))
        .unwrap_or(false)
}

pub struct EnrollResponse {
    pub factor_id: Uuid,
    pub secret_b32: String,
    pub provisioning_uri: String,
    pub qr_data_url: String,
    pub recovery_codes: Vec<String>,
}

pub async fn enroll(
    pool: &PgPool,
    user_id: Uuid,
    email: &str,
    issuer: &str,
    encryptor: &dyn KeyEncryptor,
) -> Result<EnrollResponse, AuthError> {
    let mut tx = pool.begin().await.map_err(AuthError::from)?;

    sqlx::query!(
        "DELETE FROM auth.totp_factors WHERE user_id = $1 AND enrolled_at IS NULL",
        user_id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    let (secret_bytes, secret_b32) = generate_secret();
    let factor_id = Uuid::now_v7();
    let encrypted = encryptor
        .encrypt(&secret_bytes, factor_id.as_bytes())
        .map_err(|e| {
            AuthError::internal_with(
                "totp secret encryption",
                std::io::Error::other(e.to_string()),
            )
        })?;

    sqlx::query!(
        "INSERT INTO auth.totp_factors (id, user_id, secret) VALUES ($1, $2, $3)",
        factor_id,
        user_id,
        &encrypted as &[u8],
    )
    .execute(tx.as_mut())
    .await
    .map_err(|e| match AuthError::from(e) {
        AuthError::Db {
            constraint: Some(ref c),
            ..
        } if c == "totp_factors_user_id_idx" => AuthError::Conflict,
        e => e,
    })?;

    let codes = generate_recovery_codes();
    for code in &codes {
        let hash = sha256(code.as_bytes());
        let code_id = Uuid::now_v7();
        sqlx::query!(
            "INSERT INTO auth.totp_recovery_codes (id, factor_id, code_hash) VALUES ($1, $2, $3)",
            code_id,
            factor_id,
            &hash as &[u8],
        )
        .execute(tx.as_mut())
        .await
        .map_err(AuthError::from)?;
    }

    tx.commit().await.map_err(AuthError::from)?;

    let uri = make_totp_labeled(&secret_bytes, email, issuer)?.get_url();
    let qr = qr_data_url(&uri)?;

    Ok(EnrollResponse {
        factor_id,
        secret_b32,
        provisioning_uri: uri,
        qr_data_url: qr,
        recovery_codes: codes.to_vec(),
    })
}

pub async fn confirm(
    pool: &PgPool,
    user_id: Uuid,
    code: &str,
    encryptor: &dyn KeyEncryptor,
) -> Result<(), AuthError> {
    let mut tx = pool.begin().await.map_err(AuthError::from)?;

    let row = sqlx::query!(
        "SELECT id, secret FROM auth.totp_factors
         WHERE user_id = $1 AND enrolled_at IS NULL AND deleted_at IS NULL
         FOR UPDATE",
        user_id,
    )
    .fetch_optional(tx.as_mut())
    .await
    .map_err(AuthError::from)?
    .ok_or(AuthError::NotFound)?;

    let secret = encryptor
        .decrypt(&row.secret, row.id.as_bytes())
        .map_err(|e| {
            AuthError::internal_with(
                "totp secret decryption",
                std::io::Error::other(e.to_string()),
            )
        })?;

    if !verify_code(&secret, code) {
        return Err(AuthError::MfaError {
            message: "invalid code".into(),
        });
    }

    sqlx::query!(
        "UPDATE auth.totp_factors SET enrolled_at = now() WHERE id = $1",
        row.id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    tx.commit().await.map_err(AuthError::from)?;
    Ok(())
}

pub async fn is_enrolled(pool: &PgPool, user_id: Uuid) -> Result<bool, AuthError> {
    let row = sqlx::query!(
        "SELECT 1 AS one FROM auth.totp_factors
         WHERE user_id = $1 AND enrolled_at IS NOT NULL AND deleted_at IS NULL",
        user_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(AuthError::from)?;
    Ok(row.is_some())
}

pub async fn verify_step_up(
    pool: &PgPool,
    user_id: Uuid,
    code: &str,
    encryptor: &dyn KeyEncryptor,
) -> Result<(), AuthError> {
    let mut tx = pool.begin().await.map_err(AuthError::from)?;

    let row = sqlx::query!(
        "SELECT id, secret, last_used_at FROM auth.totp_factors
         WHERE user_id = $1 AND enrolled_at IS NOT NULL AND deleted_at IS NULL
         FOR UPDATE",
        user_id,
    )
    .fetch_optional(tx.as_mut())
    .await
    .map_err(AuthError::from)?
    .ok_or(AuthError::NotFound)?;

    let secret = encryptor
        .decrypt(&row.secret, row.id.as_bytes())
        .map_err(|e| {
            AuthError::internal_with(
                "totp secret decryption",
                std::io::Error::other(e.to_string()),
            )
        })?;

    if !verify_code(&secret, code) {
        return Err(AuthError::MfaError {
            message: "invalid code".into(),
        });
    }

    // TOTP::new is configured with skew=1 — a code presented at step N is
    // accepted if it matches the secret at step N-1, N, or N+1. So a code
    // legitimately used at step N can be cryptographically replayed at step
    // N+1 (it still verifies). The replay check therefore has to cover the
    // skew window on both sides: reject if |now_step - last_step| <= skew.
    const STEP_SECS: u64 = 30;
    const SKEW_STEPS: u64 = 1;
    let now_step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / STEP_SECS;
    if let Some(last_used) = row.last_used_at {
        let last_step = last_used.timestamp().max(0) as u64 / STEP_SECS;
        let delta = now_step.abs_diff(last_step);
        if delta <= SKEW_STEPS {
            return Err(AuthError::MfaError {
                message: "code already used".into(),
            });
        }
    }

    sqlx::query!(
        "UPDATE auth.totp_factors SET last_used_at = now() WHERE id = $1",
        row.id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    tx.commit().await.map_err(AuthError::from)?;
    Ok(())
}

pub async fn use_recovery_code(pool: &PgPool, user_id: Uuid, code: &str) -> Result<(), AuthError> {
    let mut tx = pool.begin().await.map_err(AuthError::from)?;

    let factor = sqlx::query!(
        "SELECT id FROM auth.totp_factors
         WHERE user_id = $1 AND enrolled_at IS NOT NULL AND deleted_at IS NULL
         FOR UPDATE",
        user_id,
    )
    .fetch_optional(tx.as_mut())
    .await
    .map_err(AuthError::from)?
    .ok_or(AuthError::NotFound)?;

    let rows = sqlx::query!(
        "SELECT id, code_hash FROM auth.totp_recovery_codes
         WHERE factor_id = $1 AND used_at IS NULL
         FOR UPDATE",
        factor.id,
    )
    .fetch_all(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    let provided_hash = sha256(code.as_bytes());
    let mut matched_id: Option<Uuid> = None;
    for row in &rows {
        let eq: bool = provided_hash
            .as_ref()
            .ct_eq(row.code_hash.as_slice())
            .into();
        if eq {
            matched_id = Some(row.id);
        }
    }

    let id = matched_id.ok_or(AuthError::TokenInvalid)?;

    sqlx::query!(
        "UPDATE auth.totp_recovery_codes SET used_at = now() WHERE id = $1",
        id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    tx.commit().await.map_err(AuthError::from)?;
    Ok(())
}

pub async fn regenerate_recovery_codes(
    pool: &PgPool,
    user_id: Uuid,
    totp_code: &str,
    encryptor: &dyn KeyEncryptor,
) -> Result<Vec<String>, AuthError> {
    let mut tx = pool.begin().await.map_err(AuthError::from)?;

    let row = sqlx::query!(
        "SELECT id, secret FROM auth.totp_factors
         WHERE user_id = $1 AND enrolled_at IS NOT NULL AND deleted_at IS NULL
         FOR UPDATE",
        user_id,
    )
    .fetch_optional(tx.as_mut())
    .await
    .map_err(AuthError::from)?
    .ok_or(AuthError::NotFound)?;

    let secret = encryptor
        .decrypt(&row.secret, row.id.as_bytes())
        .map_err(|e| {
            AuthError::internal_with(
                "totp secret decryption",
                std::io::Error::other(e.to_string()),
            )
        })?;

    if !verify_code(&secret, totp_code) {
        return Err(AuthError::MfaError {
            message: "invalid code".into(),
        });
    }

    sqlx::query!(
        "DELETE FROM auth.totp_recovery_codes WHERE factor_id = $1",
        row.id,
    )
    .execute(tx.as_mut())
    .await
    .map_err(AuthError::from)?;

    let codes = generate_recovery_codes();
    for code in &codes {
        let hash = sha256(code.as_bytes());
        let code_id = Uuid::now_v7();
        sqlx::query!(
            "INSERT INTO auth.totp_recovery_codes (id, factor_id, code_hash) VALUES ($1, $2, $3)",
            code_id,
            row.id,
            &hash as &[u8],
        )
        .execute(tx.as_mut())
        .await
        .map_err(AuthError::from)?;
    }

    tx.commit().await.map_err(AuthError::from)?;
    Ok(codes.to_vec())
}

pub async fn disable(pool: &PgPool, user_id: Uuid) -> Result<(), AuthError> {
    let result = sqlx::query!(
        "UPDATE auth.totp_factors SET deleted_at = now()
         WHERE user_id = $1 AND enrolled_at IS NOT NULL AND deleted_at IS NULL",
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
