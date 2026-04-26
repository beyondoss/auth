use chrono::Utc;
use ed25519_dalek::SigningKey;
use serde_json::json;
use uuid::Uuid;

use crate::error::AuthError;

/// Issue a short-lived EdDSA JWT for the given user.
pub fn issue_access_token(
    user_id: Uuid,
    issuer_url: &str,
    audience: &str,
    ttl_seconds: i32,
    kid: Uuid,
    signing_key: &SigningKey,
) -> Result<String, AuthError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::Signer;

    let now = Utc::now().timestamp();
    let exp = now + i64::from(ttl_seconds);

    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": kid.to_string(),
        }))
        .map_err(|e| AuthError::internal_with("JWT header serialization", e))?,
    );

    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&json!({
            "jti": Uuid::new_v4().to_string(),
            "sub": user_id.to_string(),
            "iss": issuer_url,
            "aud": audience,
            "iat": now,
            "nbf": now - 5,
            "exp": exp,
        }))
        .map_err(|e| AuthError::internal_with("JWT claims serialization", e))?,
    );

    let signing_input = format!("{header}.{claims}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_encoded = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{signing_input}.{sig_encoded}"))
}
