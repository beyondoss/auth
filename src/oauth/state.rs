use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, Verifier};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{error::AuthError, signing_keys::LoadedKey};

#[derive(Debug)]
pub struct StateClaims {
    pub pkce_verifier: String,
    #[allow(dead_code)]
    pub redirect_url: String,
    /// Set when an authenticated user is linking an additional provider to their account.
    pub link_user_id: Option<Uuid>,
}

pub fn issue(
    pkce_verifier: &str,
    redirect_url: &str,
    link_user_id: Option<Uuid>,
    key: &LoadedKey,
) -> String {
    let now = Utc::now().timestamp();
    let exp = now + 300;

    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&json!({
            "alg": "EdDSA",
            "typ": "oauth_state",
            "kid": key.id.to_string(),
        }))
        .expect("oauth state header serialization is infallible"),
    );

    let mut claims_map = serde_json::Map::new();
    claims_map.insert("pkce_verifier".into(), json!(pkce_verifier));
    claims_map.insert("redirect_url".into(), json!(redirect_url));
    claims_map.insert("iat".into(), json!(now));
    claims_map.insert("exp".into(), json!(exp));
    if let Some(uid) = link_user_id {
        claims_map.insert("link_user_id".into(), json!(uid.to_string()));
    }

    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&Value::Object(claims_map))
            .expect("oauth state claims serialization is infallible"),
    );

    let signing_input = format!("{header}.{claims}");
    let signature = key.signing_key.sign(signing_input.as_bytes());
    let sig_encoded = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    format!("{signing_input}.{sig_encoded}")
}

pub fn verify(token: &str, key: &LoadedKey) -> Result<StateClaims, AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::TokenInvalid);
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AuthError::TokenInvalid)?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| AuthError::TokenInvalid)?;
    if header.get("typ").and_then(Value::as_str) != Some("oauth_state") {
        return Err(AuthError::TokenInvalid);
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AuthError::TokenInvalid)?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::TokenInvalid)?;
    let signature = Signature::from_bytes(&sig_array);

    key.signing_key
        .verifying_key()
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| AuthError::TokenInvalid)?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AuthError::TokenInvalid)?;
    let claims: Value =
        serde_json::from_slice(&claims_bytes).map_err(|_| AuthError::TokenInvalid)?;

    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(AuthError::TokenInvalid)?;
    if Utc::now().timestamp() >= exp {
        return Err(AuthError::TokenExpired);
    }

    let pkce_verifier = claims
        .get("pkce_verifier")
        .and_then(Value::as_str)
        .ok_or(AuthError::TokenInvalid)?
        .to_string();
    let redirect_url = claims
        .get("redirect_url")
        .and_then(Value::as_str)
        .ok_or(AuthError::TokenInvalid)?
        .to_string();
    let link_user_id = claims
        .get("link_user_id")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<Uuid>().ok());

    Ok(StateClaims {
        pkce_verifier,
        redirect_url,
        link_user_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn test_key() -> LoadedKey {
        LoadedKey {
            id: uuid::Uuid::now_v7(),
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    #[test]
    fn round_trip_preserves_all_claims() {
        let key = test_key();
        let link_id = uuid::Uuid::now_v7();
        let token = issue(
            "pkce_verifier_xyz",
            "https://example.com/cb",
            Some(link_id),
            &key,
        );
        let claims = verify(&token, &key).unwrap();
        assert_eq!(claims.pkce_verifier, "pkce_verifier_xyz");
        assert_eq!(claims.redirect_url, "https://example.com/cb");
        assert_eq!(claims.link_user_id, Some(link_id));
    }

    #[test]
    fn round_trip_without_link_user_id() {
        let key = test_key();
        let token = issue("verifier", "https://example.com/cb", None, &key);
        let claims = verify(&token, &key).unwrap();
        assert_eq!(claims.pkce_verifier, "verifier");
        assert!(claims.link_user_id.is_none());
    }

    #[test]
    fn tampered_signature_rejected() {
        let key = test_key();
        let token = issue("verifier", "https://example.com/cb", None, &key);
        // Corrupt the signature (third part).
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let bad_sig =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let tampered = format!("{}.{}.{}", parts[0], parts[1], bad_sig);
        assert!(verify(&tampered, &key).is_err());
    }

    #[test]
    fn wrong_signing_key_rejected() {
        let key1 = test_key();
        let key2 = test_key();
        let token = issue("verifier", "https://example.com/cb", None, &key1);
        assert!(verify(&token, &key2).is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let key = test_key();
        // Build an expired token by hand with past exp.
        let now = chrono::Utc::now().timestamp();
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(
                &json!({"alg":"EdDSA","typ":"oauth_state","kid":key.id.to_string()}),
            )
            .unwrap(),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(
                &json!({"pkce_verifier":"v","redirect_url":"u","iat":now-600,"exp":now-1}),
            )
            .unwrap(),
        );
        let signing_input = format!("{header}.{claims}");
        let sig = URL_SAFE_NO_PAD.encode(key.signing_key.sign(signing_input.as_bytes()).to_bytes());
        let token = format!("{signing_input}.{sig}");
        let err = verify(&token, &key).unwrap_err();
        assert!(matches!(err, crate::error::AuthError::TokenExpired));
    }

    #[test]
    fn malformed_token_rejected() {
        let key = test_key();
        assert!(verify("not.a.valid.jwt.at.all", &key).is_err());
        assert!(verify("only.two", &key).is_err());
        assert!(verify("", &key).is_err());
    }
}
