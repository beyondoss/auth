use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, Verifier};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{error::AuthError, keys::LoadedKey};

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
