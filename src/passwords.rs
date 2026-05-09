use std::collections::HashSet;
use std::sync::LazyLock;

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::{SaltString, rand_core::OsRng},
};

use crate::error::AuthError;

const MIN_LENGTH: usize = 12;
const MAX_LENGTH: usize = 128;

static COMMON_PASSWORDS: &str = include_str!("../tests/fixtures/common_passwords.txt");
static COMMON_PASSWORDS_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| COMMON_PASSWORDS.lines().collect());

/// Hash a password using Argon2id with OWASP 2024 recommended parameters.
/// Returns an error if the password is too short or too common.
#[tracing::instrument(skip(password), err)]
pub fn hash(password: &str) -> Result<String, AuthError> {
    if password.len() < MIN_LENGTH {
        return Err(AuthError::PasswordTooShort);
    }
    if password.len() > MAX_LENGTH {
        return Err(AuthError::PasswordTooLong);
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
#[tracing::instrument(skip(password, hash_str), err)]
pub fn verify(password: &str, hash_str: &str) -> Result<bool, AuthError> {
    if password.len() > MAX_LENGTH {
        return Ok(false);
    }
    let parsed = PasswordHash::new(hash_str)
        .map_err(|e| AuthError::internal_with("invalid password hash", e))?;
    // Parameters come from the PHC string; Argon2::default() handles all variants.
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

fn argon2id() -> Argon2<'static> {
    // OWASP 2024: m=19456 (19 MiB), t=2, p=1, output=32 bytes
    let params = Params::new(19_456, 2, 1, Some(32)).expect("argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn is_common(password: &str) -> bool {
    let lower = password.to_lowercase();
    COMMON_PASSWORDS_SET.contains(lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_produces_phc_string() {
        let h = hash("correct-horse-battery").unwrap();
        assert!(
            h.starts_with("$argon2id$"),
            "expected argon2id PHC string, got: {h}"
        );
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
        assert!(matches!(
            hash("elevenchars"),
            Err(AuthError::PasswordTooShort)
        ));
        assert!(hash("twelvechars!").is_ok());
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(MAX_LENGTH + 1);
        assert!(matches!(hash(&long), Err(AuthError::PasswordTooLong)));
        let ok = "a".repeat(MAX_LENGTH);
        assert!(hash(&ok).is_ok());
    }

    #[test]
    fn verify_too_long_returns_false() {
        let h = hash("correct-horse-battery").unwrap();
        let long = "a".repeat(MAX_LENGTH + 1);
        assert!(!verify(&long, &h).unwrap());
    }

    #[test]
    fn rejects_common_password() {
        // these are all ≥ 12 chars and on the common list
        assert!(matches!(
            hash("qwertyqwerty"),
            Err(AuthError::PasswordTooCommon)
        ));
        assert!(matches!(
            hash("123456qwerty"),
            Err(AuthError::PasswordTooCommon)
        ));
        // case-insensitive match
        assert!(matches!(
            hash("QWERTYQWERTY"),
            Err(AuthError::PasswordTooCommon)
        ));
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
