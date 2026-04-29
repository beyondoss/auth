use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, Verifier};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{error::AuthError, signing_keys::LoadedKey};

#[derive(Debug)]
pub struct StepUpClaims {
    pub user_id: Uuid,
    pub next_step: String,
}

pub fn issue(user_id: Uuid, next_step: &str, key: &LoadedKey) -> String {
    let now = Utc::now().timestamp();
    let exp = now + 300;

    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&json!({
            "alg": "EdDSA",
            "typ": "step_up",
            "kid": key.id.to_string(),
        }))
        .expect("step-up header serialization is infallible"),
    );

    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&json!({
            "sub": user_id.to_string(),
            "next_step": next_step,
            "iat": now,
            "exp": exp,
        }))
        .expect("step-up claims serialization is infallible"),
    );

    let signing_input = format!("{header}.{claims}");
    let signature = key.signing_key.sign(signing_input.as_bytes());
    let sig_encoded = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    format!("{signing_input}.{sig_encoded}")
}

pub fn verify(token: &str, key: &LoadedKey) -> Result<StepUpClaims, AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::TokenInvalid);
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AuthError::TokenInvalid)?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| AuthError::TokenInvalid)?;
    if header.get("typ").and_then(Value::as_str) != Some("step_up") {
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

    let user_id = claims
        .get("sub")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(AuthError::TokenInvalid)?;
    let next_step = claims
        .get("next_step")
        .and_then(Value::as_str)
        .ok_or(AuthError::TokenInvalid)?
        .to_string();

    Ok(StepUpClaims { user_id, next_step })
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
    fn round_trip_preserves_user_id_and_next_step() {
        let key = test_key();
        let user_id = Uuid::now_v7();
        let token = issue(user_id, "totp", &key);
        let claims = verify(&token, &key).unwrap();
        assert_eq!(claims.user_id, user_id);
        assert_eq!(claims.next_step, "totp");
    }

    #[test]
    fn tampered_signature_rejected() {
        let key = test_key();
        let token = issue(Uuid::now_v7(), "totp", &key);
        let bad_sig =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let tampered = format!("{}.{}.{}", parts[0], parts[1], bad_sig);
        assert!(verify(&tampered, &key).is_err());
    }

    #[test]
    fn wrong_signing_key_rejected() {
        let key1 = test_key();
        let key2 = test_key();
        let token = issue(Uuid::now_v7(), "totp", &key1);
        assert!(verify(&token, &key2).is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let key = test_key();
        let now = chrono::Utc::now().timestamp();
        let user_id = Uuid::now_v7();
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(&json!({"alg":"EdDSA","typ":"step_up","kid":key.id.to_string()}))
                .unwrap(),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(
                &json!({"sub":user_id.to_string(),"next_step":"totp","iat":now-600,"exp":now-1}),
            )
            .unwrap(),
        );
        let signing_input = format!("{header}.{claims}");
        let sig = URL_SAFE_NO_PAD.encode(key.signing_key.sign(signing_input.as_bytes()).to_bytes());
        let token = format!("{signing_input}.{sig}");
        let err = verify(&token, &key).unwrap_err();
        assert!(matches!(err, AuthError::TokenExpired));
    }

    #[test]
    fn malformed_token_rejected() {
        let key = test_key();
        assert!(verify("too.few", &key).is_err());
        assert!(verify("", &key).is_err());
    }

    #[test]
    fn wrong_typ_header_rejected() {
        let key = test_key();
        let now = chrono::Utc::now().timestamp();
        let user_id = Uuid::now_v7();
        // Use "oauth_state" typ instead of "step_up"
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(
                &json!({"alg":"EdDSA","typ":"oauth_state","kid":key.id.to_string()}),
            )
            .unwrap(),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(
                &json!({"sub":user_id.to_string(),"next_step":"totp","iat":now,"exp":now+300}),
            )
            .unwrap(),
        );
        let signing_input = format!("{header}.{claims}");
        let sig = URL_SAFE_NO_PAD.encode(key.signing_key.sign(signing_input.as_bytes()).to_bytes());
        let token = format!("{signing_input}.{sig}");
        assert!(verify(&token, &key).is_err());
    }
}
