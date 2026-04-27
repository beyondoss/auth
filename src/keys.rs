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

#[derive(Clone)]
pub struct LoadedKey {
    pub id: Uuid,
    pub signing_key: SigningKey,
}

/// Inserts the default app_config row if one doesn't exist. Idempotent.
pub async fn ensure_app_config(pool: &PgPool) -> Result<()> {
    sqlx::query!(
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
/// Atomic under concurrent startup: the unique partial index on (status) WHERE
/// status = 'active' ensures only one INSERT wins; the loser reads the winner's key.
///
/// If the existing key was encrypted with an old KEK or without AAD (legacy),
/// it is immediately re-encrypted with the current key before returning.
pub async fn load_or_create_active_key(pool: &PgPool, enc: &dyn KeyEncryptor) -> Result<LoadedKey> {
    if let Some((key, needs_reencrypt)) = fetch_active_key(pool, enc).await? {
        if needs_reencrypt {
            reencrypt_key(pool, enc, &key).await?;
        }
        return Ok(key);
    }

    tracing::info!("no active signing key found, generating one");

    let signing_key = SigningKey::generate(&mut OsRng);
    let private_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode private key")?;

    // Generate the ID in Rust so we can use it as AAD before inserting.
    let id = Uuid::now_v7();
    let encrypted = enc.encrypt(private_pem.as_bytes(), id.as_bytes())?;

    // ON CONFLICT DO NOTHING returns no rows if another instance beat us to it.
    let inserted_id = sqlx::query_scalar!(
        "INSERT INTO auth.signing_keys (id, algorithm, private_key_enc, status)
         VALUES ($1, 'ed25519', $2, 'active')
         ON CONFLICT (status) WHERE status = 'active' DO NOTHING
         RETURNING id",
        id,
        encrypted,
    )
    .fetch_optional(pool)
    .await
    .context("failed to insert signing key")?;

    match inserted_id {
        Some(id) => {
            tracing::info!(kid = %id, "generated and stored new signing key");
            Ok(LoadedKey { id, signing_key })
        }
        None => {
            let (key, needs_reencrypt) = fetch_active_key(pool, enc)
                .await?
                .context("active signing key disappeared after concurrent insert")?;
            if needs_reencrypt {
                reencrypt_key(pool, enc, &key).await?;
            }
            Ok(key)
        }
    }
}

async fn fetch_active_key(
    pool: &PgPool,
    enc: &dyn KeyEncryptor,
) -> Result<Option<(LoadedKey, bool)>> {
    let row = sqlx::query!(
        "SELECT id, private_key_enc FROM auth.signing_keys WHERE status = 'active' LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .context("failed to query signing key")?;

    let Some(row) = row else {
        return Ok(None);
    };

    let (pem_bytes, needs_reencrypt) = enc
        .decrypt_with_fallback(&row.private_key_enc, row.id.as_bytes())
        .context("failed to decrypt signing key")?;
    let pem_bytes = Zeroizing::new(pem_bytes);

    let pem = std::str::from_utf8(&pem_bytes).context("signing key PEM is not valid UTF-8")?;
    let signing_key = SigningKey::from_pkcs8_pem(pem).context("failed to parse signing key PEM")?;

    Ok(Some((
        LoadedKey {
            id: row.id,
            signing_key,
        },
        needs_reencrypt,
    )))
}

async fn reencrypt_key(pool: &PgPool, enc: &dyn KeyEncryptor, key: &LoadedKey) -> Result<()> {
    let pem = key
        .signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode signing key for re-encryption")?;
    let encrypted = enc.encrypt(pem.as_bytes(), key.id.as_bytes())?;
    sqlx::query!(
        "UPDATE auth.signing_keys SET private_key_enc = $1 WHERE id = $2",
        encrypted,
        key.id,
    )
    .execute(pool)
    .await
    .context("failed to re-encrypt signing key")?;
    tracing::info!(kid = %key.id, "re-encrypted signing key with current KEK");
    Ok(())
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
