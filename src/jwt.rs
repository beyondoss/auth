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
    is_impersonated: bool,
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

    let mut claims_map = serde_json::json!({
        "jti": Uuid::new_v4().to_string(),
        "sub": user_id.to_string(),
        "iss": issuer_url,
        "aud": audience,
        "iat": now,
        "nbf": now - 5,
        "exp": exp,
    });
    if is_impersonated {
        claims_map["impersonated"] = serde_json::Value::Bool(true);
    }

    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&claims_map)
            .map_err(|e| AuthError::internal_with("JWT claims serialization", e))?,
    );

    let signing_input = format!("{header}.{claims}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_encoded = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{signing_input}.{sig_encoded}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signature, SigningKey};
    use rand_core::OsRng;

    fn test_key() -> (SigningKey, Uuid) {
        (SigningKey::generate(&mut OsRng), Uuid::now_v7())
    }

    fn decode_claims(token: &str) -> serde_json::Value {
        let part = token.split('.').nth(1).expect("JWT must have 3 parts");
        let bytes = URL_SAFE_NO_PAD
            .decode(part)
            .expect("claims must be valid base64url");
        serde_json::from_slice(&bytes).expect("claims must be valid JSON")
    }

    #[test]
    fn token_is_three_part_jwt() {
        let (key, kid) = test_key();
        let token =
            issue_access_token(Uuid::now_v7(), "https://iss", "aud", 3600, kid, &key, false)
                .unwrap();
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn claims_contain_correct_fields() {
        let (key, kid) = test_key();
        let user_id = Uuid::now_v7();
        let token = issue_access_token(
            user_id,
            "https://iss",
            "https://aud",
            3600,
            kid,
            &key,
            false,
        )
        .unwrap();
        let claims = decode_claims(&token);
        assert_eq!(claims["sub"], user_id.to_string());
        assert_eq!(claims["iss"], "https://iss");
        assert_eq!(claims["aud"], "https://aud");
        assert!(claims["jti"].is_string());
        let iat = claims["iat"].as_i64().unwrap();
        let exp = claims["exp"].as_i64().unwrap();
        let nbf = claims["nbf"].as_i64().unwrap();
        assert_eq!(exp - iat, 3600);
        assert_eq!(iat - nbf, 5);
    }

    #[test]
    fn impersonated_flag_absent_when_false() {
        let (key, kid) = test_key();
        let token =
            issue_access_token(Uuid::now_v7(), "https://iss", "aud", 3600, kid, &key, false)
                .unwrap();
        assert!(decode_claims(&token).get("impersonated").is_none());
    }

    #[test]
    fn impersonated_flag_present_when_true() {
        let (key, kid) = test_key();
        let token = issue_access_token(Uuid::now_v7(), "https://iss", "aud", 3600, kid, &key, true)
            .unwrap();
        assert_eq!(decode_claims(&token)["impersonated"], true);
    }

    #[test]
    fn signature_verifies_with_corresponding_public_key() {
        let (key, kid) = test_key();
        let token =
            issue_access_token(Uuid::now_v7(), "https://iss", "aud", 3600, kid, &key, false)
                .unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(parts[2])
            .unwrap()
            .try_into()
            .unwrap();
        let signature = Signature::from_bytes(&sig_bytes);
        key.verifying_key()
            .verify_strict(signing_input.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn each_token_has_unique_jti() {
        let (key, kid) = test_key();
        let uid = Uuid::now_v7();
        let t1 = issue_access_token(uid, "https://iss", "aud", 3600, kid, &key, false).unwrap();
        let t2 = issue_access_token(uid, "https://iss", "aud", 3600, kid, &key, false).unwrap();
        assert_ne!(decode_claims(&t1)["jti"], decode_claims(&t2)["jti"]);
    }
}
