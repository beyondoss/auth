use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

pub struct PkceVerifier(String);
pub struct PkceChallenge(String);

impl PkceVerifier {
    pub fn new() -> Self {
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn challenge(&self) -> PkceChallenge {
        let digest = Sha256::digest(self.0.as_bytes());
        PkceChallenge(URL_SAFE_NO_PAD.encode(digest))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for PkceVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl PkceChallenge {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
