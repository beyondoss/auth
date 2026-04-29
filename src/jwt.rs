use chrono::Utc;
use ed25519_dalek::SigningKey;
use serde_json::json;
use uuid::Uuid;

use crate::error::AuthError;

/// Issue a short-lived EdDSA JWT for the given user.
///
/// `extra_claims` are merged into the payload before standard claims are set,
/// so reserved keys (`sub`, `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`,
/// `impersonated`) always win and cannot be overridden by the caller.
#[allow(clippy::too_many_arguments)]
pub fn issue_access_token(
    user_id: Uuid,
    issuer_url: &str,
    audience: &str,
    ttl_seconds: i32,
    kid: Uuid,
    signing_key: &SigningKey,
    is_impersonated: bool,
    extra_claims: Option<&serde_json::Map<String, serde_json::Value>>,
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

    // Start with caller-supplied claims (if any), then overwrite reserved keys.
    let mut claims_map = match extra_claims {
        Some(extra) => serde_json::Value::Object(extra.clone()),
        None => serde_json::json!({}),
    };
    let map = claims_map.as_object_mut().expect("claims_map is an object");
    map.insert(
        "jti".into(),
        serde_json::Value::String(Uuid::new_v4().to_string()),
    );
    map.insert("sub".into(), serde_json::Value::String(user_id.to_string()));
    map.insert(
        "iss".into(),
        serde_json::Value::String(issuer_url.to_owned()),
    );
    map.insert("aud".into(), serde_json::Value::String(audience.to_owned()));
    map.insert("iat".into(), serde_json::Value::Number(now.into()));
    map.insert("nbf".into(), serde_json::Value::Number((now - 5).into()));
    map.insert("exp".into(), serde_json::Value::Number(exp.into()));
    if is_impersonated {
        map.insert("impersonated".into(), serde_json::Value::Bool(true));
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
        let token = issue_access_token(
            Uuid::now_v7(),
            "https://iss",
            "aud",
            3600,
            kid,
            &key,
            false,
            None,
        )
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
            None,
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
        let token = issue_access_token(
            Uuid::now_v7(),
            "https://iss",
            "aud",
            3600,
            kid,
            &key,
            false,
            None,
        )
        .unwrap();
        assert!(decode_claims(&token).get("impersonated").is_none());
    }

    #[test]
    fn impersonated_flag_present_when_true() {
        let (key, kid) = test_key();
        let token = issue_access_token(
            Uuid::now_v7(),
            "https://iss",
            "aud",
            3600,
            kid,
            &key,
            true,
            None,
        )
        .unwrap();
        assert_eq!(decode_claims(&token)["impersonated"], true);
    }

    #[test]
    fn extra_claims_appear_in_payload() {
        let (key, kid) = test_key();
        let mut extra = serde_json::Map::new();
        extra.insert("plan".into(), serde_json::Value::String("pro".into()));
        extra.insert("org_role".into(), serde_json::Value::String("admin".into()));
        let token = issue_access_token(
            Uuid::now_v7(),
            "https://iss",
            "aud",
            3600,
            kid,
            &key,
            false,
            Some(&extra),
        )
        .unwrap();
        let claims = decode_claims(&token);
        assert_eq!(claims["plan"], "pro");
        assert_eq!(claims["org_role"], "admin");
    }

    #[test]
    fn extra_claims_cannot_override_reserved_keys() {
        let (key, kid) = test_key();
        let user_id = Uuid::now_v7();
        let mut extra = serde_json::Map::new();
        extra.insert("sub".into(), serde_json::Value::String("attacker".into()));
        extra.insert(
            "exp".into(),
            serde_json::Value::Number(9999999999i64.into()),
        );
        let token = issue_access_token(
            user_id,
            "https://iss",
            "aud",
            3600,
            kid,
            &key,
            false,
            Some(&extra),
        )
        .unwrap();
        let claims = decode_claims(&token);
        assert_eq!(claims["sub"], user_id.to_string());
        assert_ne!(claims["exp"], 9999999999i64);
    }

    #[test]
    fn signature_verifies_with_corresponding_public_key() {
        let (key, kid) = test_key();
        let token = issue_access_token(
            Uuid::now_v7(),
            "https://iss",
            "aud",
            3600,
            kid,
            &key,
            false,
            None,
        )
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
        let t1 =
            issue_access_token(uid, "https://iss", "aud", 3600, kid, &key, false, None).unwrap();
        let t2 =
            issue_access_token(uid, "https://iss", "aud", 3600, kid, &key, false, None).unwrap();
        assert_ne!(decode_claims(&t1)["jti"], decode_claims(&t2)["jti"]);
    }
}
