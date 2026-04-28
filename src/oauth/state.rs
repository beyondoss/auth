use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, Verifier};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{error::AuthError, keys::LoadedKey};

pub struct StateClaims {
    pub pkce_verifier: String,
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
