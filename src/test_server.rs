use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    app_config,
    authz::cache::AuthzCache,
    crypto::LocalKeyEncryptor,
    http::AppState,
    keys,
    metrics::Metrics,
    oauth::OAuthProviders,
    tokens::{Token, TokenPrefix},
};

const ADMIN_SECRET: &str = "bench-admin-secret";
const ENC_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

pub struct BenchServer {
    pub url: String,
    pub admin_secret: &'static str,
    _handle: tokio::task::JoinHandle<()>,
}

pub struct BenchSession {
    pub user_id: Uuid,
    pub bearer: String,
}

pub async fn start(pool: PgPool) -> Result<BenchServer> {
    keys::ensure_app_config(&pool).await?;
    let enc_key = LocalKeyEncryptor::from_base64(ENC_KEY, &[])?;
    let loaded_key = keys::load_or_create_active_key(&pool, &enc_key).await?;
    let jwks = keys::render_jwks(&loaded_key);
    let app_config = app_config::load(&pool).await?;
    let compiled_authz = app_config::compile_authz_schema(&app_config).ok().flatten();

    let http_client = reqwest::Client::new();
    let wn_origin = reqwest::Url::parse("https://bench.local").unwrap();
    let webauthn = webauthn_rs::WebauthnBuilder::new("bench.local", &wn_origin)
        .unwrap()
        .build()
        .unwrap();
    let encryptor: Arc<dyn crate::crypto::KeyEncryptor> = Arc::new(enc_key);
    let authz_cache = Arc::new(AuthzCache::new(100_000, 50_000, Duration::from_secs(1800)));

    let state = AppState {
        pool: pool.clone(),
        jwks: Arc::new(bytes::Bytes::from(jwks)),
        signing_key: Arc::new(loaded_key),
        app_config: Arc::new(RwLock::new(app_config)),
        authz_schema: Arc::new(RwLock::new(compiled_authz)),
        metrics: Metrics::new(),
        admin_secret: ADMIN_SECRET.to_string(),
        http_client,
        oauth: Arc::new(RwLock::new(OAuthProviders::default())),
        webauthn: Arc::new(webauthn),
        encryptor,
        oauth_redirect_allowlist: vec![],
        public_url: None,
        authz_cache,
        partition_cache: Arc::new(RwLock::new(std::collections::HashSet::new())),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let url = format!("http://127.0.0.1:{port}");

    let handle = tokio::spawn(async move {
        crate::http::serve_with_listener(listener, state).await.ok();
    });

    Ok(BenchServer {
        url,
        admin_secret: ADMIN_SECRET,
        _handle: handle,
    })
}

/// Create a minimal user+session directly in the DB and return a valid bearer token.
/// Uses untyped sqlx queries — bench setup only, never on the hot path.
pub async fn create_session(pool: &PgPool) -> Result<BenchSession> {
    let user_id = Uuid::now_v7();
    let org_id = Uuid::now_v7();
    let email_id = Uuid::now_v7();
    let session_id = Uuid::now_v7();
    let token = Token::new(TokenPrefix::Session);
    let secret_hash = token.secret_hash();
    let bearer = format!("Bearer {token}");

    let mut tx = pool.begin().await?;

    // org → user circular FK: both DEFERRABLE INITIALLY DEFERRED
    sqlx::query("INSERT INTO auth.orgs (id, user_id, name, slug) VALUES ($1, $2, 'bench', $3)")
        .bind(org_id)
        .bind(user_id)
        .bind(format!("bench-{}", org_id.simple()))
        .execute(tx.as_mut())
        .await?;

    sqlx::query(
        "INSERT INTO auth.users (id, primary_org_id, primary_email_id) VALUES ($1, $2, $3)",
    )
    .bind(user_id)
    .bind(org_id)
    .bind(email_id)
    .execute(tx.as_mut())
    .await?;

    sqlx::query("INSERT INTO auth.emails (id, user_id, email) VALUES ($1, $2, $3)")
        .bind(email_id)
        .bind(user_id)
        .bind(format!("bench-{}@bench.local", user_id.simple()))
        .execute(tx.as_mut())
        .await?;

    sqlx::query(
        "INSERT INTO auth.tokens (id, secret, expires_at) \
         VALUES ($1, $2, now() + interval '1 day')",
    )
    .bind(token.id)
    .bind(secret_hash.as_slice())
    .execute(tx.as_mut())
    .await?;

    sqlx::query("INSERT INTO auth.sessions (id, user_id, token_id) VALUES ($1, $2, $3)")
        .bind(session_id)
        .bind(user_id)
        .bind(token.id)
        .execute(tx.as_mut())
        .await?;

    tx.commit().await?;

    Ok(BenchSession { user_id, bearer })
}
