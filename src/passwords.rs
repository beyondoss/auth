use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::{SaltString, rand_core::OsRng},
};

use crate::error::AuthError;

const MIN_LENGTH: usize = 8;

static COMMON_PASSWORDS: &str =
    include_str!("../tests/fixtures/common_passwords.txt");

/// Hash a password using Argon2id with OWASP 2024 recommended parameters.
/// Returns an error if the password is too short or too common.
pub fn hash(password: &str) -> Result<String, AuthError> {
    if password.len() < MIN_LENGTH {
        return Err(AuthError::PasswordTooShort);
    }
    if is_common(password) {
        return Err(AuthError::PasswordTooCommon);
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = argon2id();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AuthError::internal_with("password hashing failed", e))
}

/// Verify a password against an argon2 PHC hash string.
/// Returns `true` if it matches, `false` if it doesn't.
pub fn verify(password: &str, hash_str: &str) -> Result<bool, AuthError> {
    let parsed = PasswordHash::new(hash_str)
        .map_err(|e| AuthError::internal_with("invalid password hash", e))?;
    // Parameters come from the PHC string; Argon2::default() handles all variants.
    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

fn argon2id() -> Argon2<'static> {
    // OWASP 2024: m=19456 (19 MiB), t=2, p=1, output=32 bytes
    let params = Params::new(19_456, 2, 1, Some(32))
        .expect("argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn is_common(password: &str) -> bool {
    let lower = password.to_lowercase();
    COMMON_PASSWORDS.lines().any(|line| line == lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_produces_phc_string() {
        let h = hash("correct-horse-battery").unwrap();
        assert!(h.starts_with("$argon2id$"), "expected argon2id PHC string, got: {h}");
    }

    #[test]
    fn verify_correct_password() {
        let h = hash("correct-horse-battery").unwrap();
        assert!(verify("correct-horse-battery", &h).unwrap());
    }

    #[test]
    fn verify_wrong_password() {
        let h = hash("correct-horse-battery").unwrap();
        assert!(!verify("wrong-password-here!", &h).unwrap());
    }

    #[test]
    fn rejects_too_short() {
        assert!(matches!(hash("short"), Err(AuthError::PasswordTooShort)));
        assert!(matches!(hash("sevench"), Err(AuthError::PasswordTooShort)));
        assert!(hash("eightchr").is_ok());
    }

    #[test]
    fn rejects_common_password() {
        // "password" and "iloveyou" are both ≥ 8 chars and on the common list
        assert!(matches!(hash("password"), Err(AuthError::PasswordTooCommon)));
        assert!(matches!(hash("iloveyou"), Err(AuthError::PasswordTooCommon)));
        // case-insensitive match
        assert!(matches!(hash("PASSWORD"), Err(AuthError::PasswordTooCommon)));
    }

    #[test]
    fn different_hashes_for_same_password() {
        let h1 = hash("unique-passphrase-99").unwrap();
        let h2 = hash("unique-passphrase-99").unwrap();
        assert_ne!(h1, h2, "each hash should use a fresh random salt");
        assert!(verify("unique-passphrase-99", &h1).unwrap());
        assert!(verify("unique-passphrase-99", &h2).unwrap());
    }

    /// Verify Argon2 is slow enough to resist brute-force (≥ 100ms on typical hardware).
    /// Run with `cargo test -- --ignored` to include this check.
    #[test]
    #[ignore]
    fn hash_takes_at_least_100ms() {
        let start = std::time::Instant::now();
        hash("timing-check-passphrase").unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() >= 100,
            "argon2 should take ≥ 100ms, took {}ms",
            elapsed.as_millis()
        );
    }
}
