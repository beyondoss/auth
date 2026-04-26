use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, AeadCore, OsRng, Payload},
};
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Encrypts and decrypts signing key material at rest.
///
/// The default implementation (`LocalKeyEncryptor`) uses AES-256-GCM with a
/// static env var key. For production deployments, replace this with a
/// KMS-backed implementation (AWS KMS, GCP KMS, Vault Transit) so the KEK
/// never touches the application process and every decrypt is audited.
pub trait KeyEncryptor: Send + Sync {
    /// Encrypt `plaintext`, binding `aad` into the authentication tag.
    /// Decryption will fail if `aad` doesn't match — use the signing key's ID.
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt `ciphertext` using the current key, verifying `aad`.
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt `ciphertext`, trying the current key first, then falling back to
    /// old keys (for KEK rotation) and then to no-AAD (for legacy data that
    /// predates AAD binding). Returns `(plaintext, needs_reencrypt)`.
    /// When `needs_reencrypt` is true, the caller should re-encrypt and persist.
    fn decrypt_with_fallback(&self, ciphertext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, bool)> {
        self.decrypt(ciphertext, aad).map(|p| (p, false))
    }
}

/// AES-256-GCM encryptor keyed by a static env var, with optional old-key
/// fallback for zero-downtime KEK rotation.
///
/// Protects against database-only compromise. Does NOT protect against
/// full server compromise since the key lives in process memory. For
/// stronger guarantees, use a KMS-backed `KeyEncryptor`.
///
/// Wire format: 12-byte random nonce || GCM ciphertext+tag.
pub struct LocalKeyEncryptor {
    key: [u8; 32],
    old_keys: Vec<[u8; 32]>,
}

impl LocalKeyEncryptor {
    /// Build from base64url-encoded keys. `current` is used for all new
    /// encryptions; `old_keys` are tried in order when the current key fails,
    /// enabling zero-downtime KEK rotation.
    pub fn from_base64(current: &str, old_keys: &[&str]) -> Result<Self> {
        let key = decode_key(current)?;
        let old_keys = old_keys
            .iter()
            .map(|k| decode_key(k))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { key, old_keys })
    }
}

fn decode_key(b64: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64.trim())
        .map_err(|_| anyhow::anyhow!("encryption key is not valid base64url"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("encryption key must decode to exactly 32 bytes"))
}

fn aes_encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn aes_decrypt(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        bail!("ciphertext too short");
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))
}

impl KeyEncryptor for LocalKeyEncryptor {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        aes_encrypt(&self.key, plaintext, aad)
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        aes_decrypt(&self.key, ciphertext, aad)
    }

    /// Try in order:
    ///   1. current key + AAD          (normal path)
    ///   2. current key + no AAD       (legacy: data written before AAD was added)
    ///   3. each old key + AAD         (KEK rotation)
    ///   4. each old key + no AAD      (KEK rotation + legacy)
    fn decrypt_with_fallback(&self, ciphertext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, bool)> {
        if let Ok(plain) = aes_decrypt(&self.key, ciphertext, aad) {
            return Ok((plain, false));
        }
        if let Ok(plain) = aes_decrypt(&self.key, ciphertext, &[]) {
            return Ok((plain, true));
        }
        for old_key in &self.old_keys {
            if let Ok(plain) = aes_decrypt(old_key, ciphertext, aad) {
                return Ok((plain, true));
            }
            if let Ok(plain) = aes_decrypt(old_key, ciphertext, &[]) {
                return Ok((plain, true));
            }
        }
        bail!("decryption failed with all known keys")
    }
}
