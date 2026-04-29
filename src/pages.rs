use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

pub const DEFAULT_LIMIT: i64 = 24;
pub const MAX_LIMIT: i64 = 1000;

pub fn clamp_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

pub fn encode_cursor(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

/// Decodes a base64url cursor. An invalid cursor silently resets to page one —
/// correct for a trusted internal service where garbled cursors are stale, not adversarial.
pub fn decode_cursor(cursor: Option<&str>) -> Option<String> {
    let c = cursor?;
    String::from_utf8(URL_SAFE_NO_PAD.decode(c).ok()?).ok()
}
