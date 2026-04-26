use std::fmt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

pub enum TokenPrefix {
    Session,
}

impl TokenPrefix {
    fn as_str(&self) -> &'static str {
        match self {
            TokenPrefix::Session => "session",
        }
    }
}

/// A newly-minted bearer token.
///
/// Format on the wire: `{prefix}_{id_hex}_{secret_b64url}`
/// - `id_hex`: UUID v7 as 32 lowercase hex chars (no dashes) — no underscores, safe as delimiter
/// - `secret_b64url`: 32 random bytes, base64url no-padding — may contain underscores, always last
///
/// The DB stores only `SHA-256(secret_bytes)` hex-encoded, never the raw secret.
pub struct Token {
    pub prefix: TokenPrefix,
    pub id: Uuid,
    secret: Zeroizing<[u8; 32]>,
}

impl Token {
    pub fn new(prefix: TokenPrefix) -> Self {
        let id = Uuid::now_v7();
        let mut secret = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(secret.as_mut());
        Self { prefix, id, secret }
    }

    /// SHA-256 of the secret bytes, hex-encoded. Store this in the DB.
    pub fn secret_hash(&self) -> String {
        sha256_hex(self.secret.as_ref())
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secret_b64 = URL_SAFE_NO_PAD.encode(self.secret.as_ref());
        write!(f, "{}_{}_{secret_b64}", self.prefix.as_str(), self.id.simple())
    }
}

/// Extracted from a bearer token string. Contains what you need to authenticate against the DB.
pub struct ParsedToken {
    pub id: Uuid,
    pub secret_hash: String,
}

/// Parse a bearer token string into its ID and secret hash.
/// Returns `None` if the format is invalid or any component fails to decode.
pub fn parse(s: &str) -> Option<ParsedToken> {
    // Split into exactly 3 parts: prefix, id_hex, secret_b64url
    // id_hex has no underscores; secret_b64url may, so splitn(3) is safe.
    let mut parts = s.splitn(3, '_');
    let _prefix = parts.next()?;
    let id_hex = parts.next()?;
    let secret_b64 = parts.next()?;

    if id_hex.len() != 32 {
        return None;
    }

    let id = Uuid::parse_str(id_hex).ok()?;

    let secret_bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(secret_b64).ok()?);
    if secret_bytes.len() != 32 {
        return None;
    }

    Some(ParsedToken { id, secret_hash: sha256_hex(&secret_bytes) })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    hash.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write as _;
        write!(s, "{b:02x}").unwrap();
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let token = Token::new(TokenPrefix::Session);
        let expected_id = token.id;
        let expected_hash = token.secret_hash();
        let s = token.to_string();

        let parsed = parse(&s).expect("parse should succeed");
        assert_eq!(parsed.id, expected_id);
        assert_eq!(parsed.secret_hash, expected_hash);
    }

    #[test]
    fn display_format() {
        let token = Token::new(TokenPrefix::Session);
        let s = token.to_string();
        let parts: Vec<&str> = s.splitn(3, '_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "session");
        assert_eq!(parts[1].len(), 32, "id_hex should be 32 chars");
        assert!(parts[1].chars().all(|c| c.is_ascii_hexdigit()), "id should be hex");
        // secret is 32 bytes → 43 base64url chars (no padding)
        assert_eq!(parts[2].len(), 43, "secret should be 43 base64url chars");
    }

    #[test]
    fn secret_hash_deterministic_within_token() {
        let token = Token::new(TokenPrefix::Session);
        assert_eq!(token.secret_hash(), token.secret_hash());
        assert_eq!(token.secret_hash().len(), 64, "SHA-256 hex is 64 chars");
    }

    #[test]
    fn parse_invalid_returns_none() {
        assert!(parse("").is_none());
        assert!(parse("session_notrightatall").is_none());
        assert!(parse("session_tooshort_abc").is_none());
        assert!(parse("notabearer").is_none());
    }

    #[test]
    fn two_tokens_have_different_secrets() {
        let a = Token::new(TokenPrefix::Session);
        let b = Token::new(TokenPrefix::Session);
        assert_ne!(a.secret_hash(), b.secret_hash());
    }
}
