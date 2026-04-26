use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, AeadCore, OsRng},
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
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// AES-256-GCM encryptor keyed by a static env var.
///
/// Protects against database-only compromise. Does NOT protect against
/// full server compromise since the key lives in process memory. For
/// stronger guarantees, use a KMS-backed `KeyEncryptor`.
///
/// Wire format: 12-byte random nonce || GCM ciphertext+tag.
pub struct LocalKeyEncryptor {
    key: [u8; 32],
}

impl LocalKeyEncryptor {
    /// Decodes the base64url-encoded key from `SIGNING_KEY_ENCRYPTION_KEY`.
    pub fn from_base64(b64: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| anyhow::anyhow!("SIGNING_KEY_ENCRYPTION_KEY is not valid base64url"))?;
        let key = bytes.try_into().map_err(|_| {
            anyhow::anyhow!("SIGNING_KEY_ENCRYPTION_KEY must decode to exactly 32 bytes")
        })?;
        Ok(Self { key })
    }
}

impl KeyEncryptor for LocalKeyEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            bail!("ciphertext too short");
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))
    }
}
