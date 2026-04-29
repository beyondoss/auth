use std::collections::HashMap;

use anyhow::{Context, Result};

/// Env vars fetched from the Firecracker Metadata Service.
pub struct MmdsEnv(HashMap<String, String>);

impl MmdsEnv {
    /// Returns the value for `key`, treating empty strings as absent.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str).filter(|s| !s.is_empty())
    }
}

/// Fetch the MMDS env map from `endpoint` (e.g. `http://169.254.169.254`).
///
/// Uses IMDSv2 token-based auth. Token failure is non-fatal — the metadata
/// fetch proceeds without the token header, matching the Firecracker default
/// that allows unauthenticated reads when no token requirement is configured.
///
/// Env vars live at `latest.meta-data.env` (IMDSv2 layout) with a fallback
/// to the flat `env` key for legacy MMDS configurations.
pub async fn fetch(endpoint: &str) -> Result<MmdsEnv> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;

    // IMDSv2: obtain a session token. Non-fatal if the endpoint doesn't
    // require it or the PUT fails — we proceed without the header.
    let token = get_token(&client, endpoint).await;

    let mut req = client
        .get(format!("{endpoint}/"))
        .header("Accept", "application/json");
    if let Some(ref t) = token {
        req = req.header("X-metadata-token", t);
    }

    let metadata: serde_json::Value = req
        .send()
        .await
        .context("MMDS request failed")?
        .json()
        .await
        .context("MMDS response is not valid JSON")?;

    // IMDSv2 path takes precedence over the legacy flat layout.
    let env_obj = metadata["latest"]["meta-data"]["env"]
        .as_object()
        .or_else(|| metadata["env"].as_object())
        .context("MMDS metadata has no env section")?;

    let map = env_obj
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
        .collect();

    Ok(MmdsEnv(map))
}

async fn get_token(client: &reqwest::Client, endpoint: &str) -> Option<String> {
    let resp = client
        .put(format!("{endpoint}/latest/api/token"))
        .header("X-metadata-token-ttl-seconds", "300")
        .header("Content-Length", "0")
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let body = resp.text().await.ok()?;
    let token = body.trim().to_owned();
    if token.is_empty() { None } else { Some(token) }
}
