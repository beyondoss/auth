pub mod apple;
pub mod github;
pub mod google;
pub mod microsoft;
pub mod oidc;
pub mod pkce;
pub mod state;

use std::collections::HashMap;

use uuid::Uuid;

use crate::{emails, error::AuthError, identities, orgs, users};

pub struct OAuthProfile {
    pub external_id: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub display_name: Option<String>,
    pub image_url: Option<String>,
}

#[derive(Clone)]
pub enum OAuthClient {
    Github(github::GithubClient),
    Google(google::GoogleClient),
    Apple(apple::AppleClient),
    Microsoft(microsoft::MicrosoftClient),
    Oidc(oidc::OidcClient),
}

impl OAuthClient {
    pub fn auth_url(&self, state: &str, pkce_challenge: &str, redirect_uri: &str) -> String {
        match self {
            Self::Github(c) => c.auth_url(state),
            Self::Google(c) => c.auth_url(state, pkce_challenge),
            Self::Apple(c) => c.auth_url(state, redirect_uri),
            Self::Microsoft(c) => c.auth_url(state, pkce_challenge),
            Self::Oidc(c) => c.auth_url(state, pkce_challenge),
        }
    }

    pub async fn exchange_and_profile(
        &self,
        code: &str,
        pkce_verifier: &str,
        redirect_uri: &str,
    ) -> Result<OAuthProfile, AuthError> {
        match self {
            Self::Github(c) => c.exchange_and_profile(code, redirect_uri).await,
            Self::Google(c) => {
                c.exchange_and_profile(code, pkce_verifier, redirect_uri)
                    .await
            }
            Self::Apple(c) => c.exchange_and_profile(code, redirect_uri).await,
            Self::Microsoft(c) => {
                c.exchange_and_profile(code, pkce_verifier, redirect_uri)
                    .await
            }
            Self::Oidc(c) => {
                c.exchange_and_profile(code, pkce_verifier, redirect_uri)
                    .await
            }
        }
    }

    pub fn provider_slug(&self) -> &str {
        match self {
            Self::Github(c) => c.provider_slug(),
            Self::Google(c) => c.provider_slug(),
            Self::Apple(c) => c.provider_slug(),
            Self::Microsoft(c) => c.provider_slug(),
            Self::Oidc(c) => c.provider_slug(),
        }
    }
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct OAuthProvidersConfig {
    pub github: Option<github::GithubConfig>,
    pub google: Option<google::GoogleConfig>,
    pub apple: Option<apple::AppleConfig>,
    pub microsoft: Option<microsoft::MicrosoftConfig>,
    pub oidc: Option<Vec<oidc::OidcConfig>>,
}

#[derive(Default)]
pub struct OAuthProviders {
    clients: HashMap<String, OAuthClient>,
}

impl OAuthProviders {
    pub fn get(&self, provider: &str) -> Option<&OAuthClient> {
        self.clients.get(provider)
    }

    pub fn encrypt_config(
        cfg: &OAuthProvidersConfig,
        encryptor: &dyn crate::crypto::KeyEncryptor,
    ) -> anyhow::Result<Vec<u8>> {
        let json = serde_json::to_vec(cfg)?;
        encryptor.encrypt(&json, b"oauth_providers")
    }

    pub fn decrypt_config(
        enc_bytes: &[u8],
        encryptor: &dyn crate::crypto::KeyEncryptor,
    ) -> anyhow::Result<OAuthProvidersConfig> {
        let plaintext = encryptor.decrypt(enc_bytes, b"oauth_providers")?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    pub async fn load(
        enc_bytes: Option<&[u8]>,
        encryptor: &dyn crate::crypto::KeyEncryptor,
        http: &reqwest::Client,
    ) -> anyhow::Result<Self> {
        let Some(bytes) = enc_bytes else {
            return Ok(Self::default());
        };
        if bytes.is_empty() {
            return Ok(Self::default());
        }

        let plaintext = encryptor.decrypt(bytes, b"oauth_providers")?;
        let cfg: OAuthProvidersConfig = serde_json::from_slice(&plaintext)?;

        let mut clients: HashMap<String, OAuthClient> = HashMap::new();

        if let Some(github_cfg) = cfg.github {
            clients.insert(
                "github".to_string(),
                OAuthClient::Github(github::GithubClient::new(http.clone(), github_cfg)),
            );
        }

        if let Some(google_cfg) = cfg.google {
            let client = google::GoogleClient::new(http.clone(), google_cfg).await?;
            clients.insert("google".to_string(), OAuthClient::Google(client));
        }

        if let Some(apple_cfg) = cfg.apple {
            let client = apple::AppleClient::new(http.clone(), apple_cfg)?;
            clients.insert("apple".to_string(), OAuthClient::Apple(client));
        }

        if let Some(ms_cfg) = cfg.microsoft {
            let client = microsoft::MicrosoftClient::new(http.clone(), ms_cfg).await?;
            clients.insert("microsoft".to_string(), OAuthClient::Microsoft(client));
        }

        if let Some(oidc_cfgs) = cfg.oidc {
            for oidc_cfg in oidc_cfgs {
                let id = oidc_cfg.id.clone();
                let client = oidc::OidcClient::new(http.clone(), oidc_cfg).await?;
                clients.insert(id, OAuthClient::Oidc(client));
            }
        }

        Ok(Self { clients })
    }
}

/// Generate a org slug from a display name or email local part.
fn make_slug(base: &str) -> String {
    use rand_core::{OsRng, RngCore};

    let clean: String = base
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");

    let suffix = format!("{:06x}", OsRng.next_u32() & 0xFFFFFF);

    if clean.is_empty() {
        suffix
    } else {
        format!("{clean}-{suffix}")
    }
}

fn is_identity_conflict(e: &AuthError) -> bool {
    matches!(e, AuthError::Db { message, .. } if message.contains("identities_provider_subject_idx"))
}

/// Link an OAuth identity to an existing user. Idempotent if already linked to the same user.
/// Returns `Err(Conflict)` if the identity is already claimed by a different user.
pub async fn link_identity(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    provider_slug: &str,
    external_id: &str,
) -> Result<(), AuthError> {
    let mut tx = pool.begin().await.map_err(AuthError::from)?;

    match identities::create(&mut tx, user_id, provider_slug, external_id, b"").await {
        Ok(_) => {
            tx.commit().await.map_err(AuthError::from)?;
            Ok(())
        }
        Err(e) if is_identity_conflict(&e) => {
            // Identity already exists — check if it belongs to this user (idempotent) or another (conflict).
            let existing = sqlx::query!(
                "SELECT user_id FROM auth.identities WHERE provider = $1 AND subject = $2 LIMIT 1",
                provider_slug,
                external_id,
            )
            .fetch_optional(tx.as_mut())
            .await
            .map_err(AuthError::from)?;

            match existing {
                Some(row) if row.user_id == user_id => Ok(()),
                _ => Err(AuthError::Conflict),
            }
        }
        Err(e) => Err(e),
    }
}

pub async fn find_or_create_oauth_user(
    pool: &sqlx::PgPool,
    profile: &OAuthProfile,
    provider_slug: &str,
    email_link_enabled: bool,
) -> Result<Uuid, AuthError> {
    let mut tx = pool.begin().await.map_err(AuthError::from)?;

    // 1. Look for an existing identity by (provider, subject)
    if let Some(row) = sqlx::query!(
        "SELECT user_id FROM auth.identities WHERE provider = $1 AND subject = $2 LIMIT 1",
        provider_slug,
        profile.external_id,
    )
    .fetch_optional(tx.as_mut())
    .await
    .map_err(AuthError::from)?
    {
        tx.commit().await.map_err(AuthError::from)?;
        return Ok(row.user_id);
    }

    // 2. Optional: link to an existing verified email
    if email_link_enabled
        && let Some(email) = profile.email.as_deref()
        && profile.email_verified == Some(true)
        && let Some(row) = sqlx::query!(
            r#"
            SELECT u.id AS "id!: Uuid"
            FROM auth.users u
            INNER JOIN auth.emails e ON e.id = u.primary_email_id
            WHERE e.email = $1::citext
              AND e.verified_at IS NOT NULL
              AND u.deleted_at IS NULL
            LIMIT 1
            "#,
            email,
        )
        .fetch_optional(tx.as_mut())
        .await
        .map_err(AuthError::from)?
    {
        match identities::create(&mut tx, row.id, provider_slug, &profile.external_id, b"")
            .await
        {
            Ok(_) => {}
            Err(e) if is_identity_conflict(&e) => { /* another request won the race; row.id is still correct */
            }
            Err(e) => return Err(e),
        }
        tx.commit().await.map_err(AuthError::from)?;
        return Ok(row.id);
    }

    // 3. Create a brand new user
    let user_id = Uuid::now_v7();
    let email_id = Uuid::now_v7();
    let org_id = Uuid::now_v7();

    let name = profile
        .display_name
        .as_deref()
        .or_else(|| profile.email.as_deref().and_then(|e| e.split('@').next()))
        .unwrap_or("user")
        .to_string();
    let slug = make_slug(&name);

    let _org = orgs::create(
        &mut tx,
        org_id,
        user_id,
        &name,
        &slug,
        profile.image_url.as_deref(),
        None,
    )
    .await?;
    let _user = users::create(&mut tx, user_id, org_id, email_id).await?;

    let email_str = profile.email.as_deref().unwrap_or("");
    let _email = emails::create(&mut tx, email_id, user_id, email_str).await?;

    if let Err(e) =
        identities::create(&mut tx, user_id, provider_slug, &profile.external_id, b"").await
    {
        if !is_identity_conflict(&e) {
            return Err(e);
        }
        // Another concurrent request created this identity first. Roll back our
        // orphaned user/org/email and return the winner's user_id.
        drop(tx);
        return sqlx::query_scalar!(
            r#"SELECT user_id AS "user_id: Uuid" FROM auth.identities WHERE provider = $1 AND subject = $2"#,
            provider_slug,
            profile.external_id,
        )
        .fetch_optional(pool)
        .await
        .map_err(AuthError::from)?
        .ok_or(AuthError::Conflict);
    }

    if profile.email_verified == Some(true) {
        sqlx::query!(
            "UPDATE auth.emails SET verified_at = now() WHERE id = $1",
            email_id,
        )
        .execute(tx.as_mut())
        .await
        .map_err(AuthError::from)?;
    }

    tx.commit().await.map_err(AuthError::from)?;

    Ok(user_id)
}
