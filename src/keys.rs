use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{
    SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use pkcs8::LineEnding;
use rand_core::OsRng;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::KeyEncryptor;

pub struct LoadedKey {
    pub id: Uuid,
    pub signing_key: SigningKey,
}

/// Inserts the default app_config row if one doesn't exist. Idempotent: safe to
/// call on every boot and under concurrent startup.
pub async fn ensure_app_config(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "INSERT INTO auth.app_config
             (jwt_mode, access_token_ttl_seconds, refresh_token_ttl_seconds, session_ttl_seconds)
         VALUES ('ed25519', 900, 2592000, 2592000)
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(pool)
    .await
    .context("failed to ensure app_config row")?;

    Ok(())
}

/// Loads the active signing key, generating and persisting one if none exists.
/// Atomic under concurrent startup: if two instances race, the unique index on
/// (status) WHERE status = 'active' ensures only one INSERT wins; the loser
/// falls back to reading the winner's key.
pub async fn load_or_create_active_key(pool: &PgPool, enc: &dyn KeyEncryptor) -> Result<LoadedKey> {
    if let Some(key) = fetch_active_key(pool, enc).await? {
        return Ok(key);
    }

    tracing::info!("no active signing key found, generating one");

    let signing_key = SigningKey::generate(&mut OsRng);
    let private_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode private key")?;
    let encrypted = enc.encrypt(private_pem.as_bytes())?;

    // ON CONFLICT DO NOTHING returns no rows if another instance beat us to it.
    let inserted_id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO auth.signing_key (algorithm, private_key_enc, status)
         VALUES ('ed25519', $1, 'active')
         ON CONFLICT (status) WHERE status = 'active' DO NOTHING
         RETURNING id",
    )
    .bind(&encrypted)
    .fetch_optional(pool)
    .await
    .context("failed to insert signing key")?;

    match inserted_id {
        Some(id) => {
            tracing::info!(kid = %id, "generated and stored new signing key");
            Ok(LoadedKey { id, signing_key })
        }
        None => {
            // Another instance won the race — load and use their key.
            fetch_active_key(pool, enc)
                .await?
                .context("active signing key disappeared after concurrent insert")
        }
    }
}

async fn fetch_active_key(pool: &PgPool, enc: &dyn KeyEncryptor) -> Result<Option<LoadedKey>> {
    let row: Option<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT id, private_key_enc FROM auth.signing_key WHERE status = 'active' LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .context("failed to query signing key")?;

    let Some((id, ciphertext)) = row else {
        return Ok(None);
    };

    let pem_bytes = Zeroizing::new(enc.decrypt(&ciphertext).context("failed to decrypt signing key")?);
    let pem = std::str::from_utf8(&pem_bytes).context("signing key PEM is not valid UTF-8")?;
    let signing_key = SigningKey::from_pkcs8_pem(pem).context("failed to parse signing key PEM")?;
    Ok(Some(LoadedKey { id, signing_key }))
}

pub fn render_jwks(key: &LoadedKey) -> String {
    let x = URL_SAFE_NO_PAD.encode(key.signing_key.verifying_key().as_bytes());

    serde_json::to_string(&json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": key.id.to_string(),
            "use": "sig",
            "alg": "EdDSA",
            "x": x,
        }]
    }))
    .expect("JWKS serialization is infallible")
}
