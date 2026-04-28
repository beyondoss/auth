use std::path::Path;
use std::sync::OnceLock;

use testcontainers::ImageExt;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

// ── TestEnv ───────────────────────────────────────────────────────────────────

/// Shared test environment — initialized once for the entire test binary run.
pub struct TestEnv {
    pub url: String,
    pub admin_secret: String,
    /// Connection URL with `search_path=auth,public` — same scope as the app pool.
    pub database_url: String,
    /// Acquire before any test that mutates global server state (authz schema,
    /// OAuth providers, app config). All other tests continue in parallel.
    ///
    /// Convention: set the state you need at the start of the critical section;
    /// don't assume a prior test cleaned up after itself.
    pub exclusive: tokio::sync::Mutex<()>,
}

static TEST_ENV: OnceLock<TestEnv> = OnceLock::new();

/// Returns a reference to the shared test environment, initializing it on first call.
///
/// Spins up a Postgres testcontainer, runs all migrations, and starts the auth
/// server in-process on a random port. Subsequent calls return the cached value
/// immediately; the background thread keeps the container and server alive until
/// the process exits.
pub fn test_env() -> &'static TestEnv {
    TEST_ENV.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build integration test runtime");

            rt.block_on(async move {
                let container = Postgres::default()
                    .with_tag("18-alpine")
                    .start()
                    .await
                    .expect("failed to start postgres testcontainer");

                let port = container
                    .get_host_port_ipv4(5432)
                    .await
                    .expect("failed to get postgres port");

                // Include search_path so every connection in the pool resolves
                // auth-schema objects without qualification — same as db::connect.
                let database_url = format!(
                    "postgres://postgres:postgres@127.0.0.1:{port}/postgres\
                     ?options=-csearch_path%3Dauth%2Cpublic"
                );

                let migrations_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
                let migrator = sqlx::migrate::Migrator::new(migrations_dir.as_path())
                    .await
                    .expect("failed to load migrations");

                let pool = sqlx::PgPool::connect(&database_url)
                    .await
                    .expect("failed to connect to postgres");

                migrator.run(&pool).await.expect("migrations failed");

                let server = beyond_auth::test_server::start(pool)
                    .await
                    .expect("failed to start auth server");

                tx.send(TestEnv {
                    url: server.url.clone(),
                    admin_secret: server.admin_secret.to_string(),
                    database_url,
                    exclusive: tokio::sync::Mutex::new(()),
                })
                .expect("failed to send TestEnv");

                // Park the runtime to keep the server task and container alive.
                let _server = server;
                let _container = container;
                std::future::pending::<()>().await
            });
        });

        rx.recv()
            .expect("integration test environment setup failed")
    })
}

// ── Exclusive guard ───────────────────────────────────────────────────────────

/// Serializes tests that mutate global server state.
///
/// Hold the returned guard for the duration of the critical section; it releases
/// on drop (even on panic), allowing the next exclusive test to proceed.
pub async fn exclusive() -> tokio::sync::MutexGuard<'static, ()> {
    test_env().exclusive.lock().await
}

// ── TestResponse ─────────────────────────────────────────────────────────────

/// A buffered HTTP response.
///
/// The body is eagerly read so every assertion and deserialization failure can
/// print it. `json()` is sync — no `.await` needed after the HTTP call.
///
/// ```
/// let me = client.get("/v1/users/me").await
///     .assert_status(200)
///     .json::<beyond_auth::MeResponse>();
/// ```
pub struct TestResponse {
    status: u16,
    body: String,
}

impl TestResponse {
    async fn from_response(res: reqwest::Response) -> Self {
        let status = res.status().as_u16();
        let body = res.text().await.unwrap_or_default();
        Self { status, body }
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    /// Assert the status code, printing the response body on failure.
    #[track_caller]
    pub fn assert_status(self, expected: u16) -> Self {
        assert_eq!(
            self.status, expected,
            "expected status {expected}, got {}\nbody: {}",
            self.status, self.body
        );
        self
    }

    /// Deserialize the body as JSON, printing the raw body on failure.
    ///
    /// Sync — the body was already buffered during the HTTP call.
    #[track_caller]
    pub fn json<T: serde::de::DeserializeOwned>(self) -> T {
        serde_json::from_str::<T>(&self.body).unwrap_or_else(|e| {
            panic!(
                "failed to deserialize {} from response\nerror: {e}\nbody: {}",
                std::any::type_name::<T>(),
                self.body
            )
        })
    }

    pub fn text(self) -> String {
        self.body
    }
}

// ── TestClient ────────────────────────────────────────────────────────────────

/// A thin HTTP client pre-configured with the test server's base URL.
///
/// Build one per test (or per logical actor), then chain auth:
/// ```
/// let client = TestClient::new().bearer(&auth.session.token);
/// let admin  = TestClient::new().admin();
/// ```
pub struct TestClient {
    inner: reqwest::Client,
    base_url: String,
    auth: Option<String>,
}

impl TestClient {
    pub fn new() -> Self {
        let env = test_env();
        Self {
            inner: reqwest::Client::new(),
            base_url: env.url.clone(),
            auth: None,
        }
    }

    /// Set `Authorization: Bearer <token>` for all requests from this client.
    pub fn bearer(mut self, token: impl Into<String>) -> Self {
        self.auth = Some(token.into());
        self
    }

    /// Set `Authorization: Bearer <admin_secret>` for all requests from this client.
    pub fn admin(mut self) -> Self {
        self.auth = Some(test_env().admin_secret.clone());
        self
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.inner.request(method, url);
        if let Some(auth) = &self.auth {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {auth}"));
        }
        req
    }

    pub async fn get(&self, path: &str) -> TestResponse {
        let res = self
            .request(reqwest::Method::GET, path)
            .send()
            .await
            .expect("GET request failed");
        TestResponse::from_response(res).await
    }

    pub async fn post<B: serde::Serialize>(&self, path: &str, body: &B) -> TestResponse {
        let res = self
            .request(reqwest::Method::POST, path)
            .json(body)
            .send()
            .await
            .expect("POST request failed");
        TestResponse::from_response(res).await
    }

    pub async fn patch<B: serde::Serialize>(&self, path: &str, body: &B) -> TestResponse {
        let res = self
            .request(reqwest::Method::PATCH, path)
            .json(body)
            .send()
            .await
            .expect("PATCH request failed");
        TestResponse::from_response(res).await
    }

    pub async fn put<B: serde::Serialize>(&self, path: &str, body: &B) -> TestResponse {
        let res = self
            .request(reqwest::Method::PUT, path)
            .json(body)
            .send()
            .await
            .expect("PUT request failed");
        TestResponse::from_response(res).await
    }

    pub async fn delete(&self, path: &str) -> TestResponse {
        let res = self
            .request(reqwest::Method::DELETE, path)
            .send()
            .await
            .expect("DELETE request failed");
        TestResponse::from_response(res).await
    }

    pub async fn delete_json<B: serde::Serialize>(&self, path: &str, body: &B) -> TestResponse {
        let res = self
            .request(reqwest::Method::DELETE, path)
            .json(body)
            .send()
            .await
            .expect("DELETE request failed");
        TestResponse::from_response(res).await
    }
}

// ── DB access ─────────────────────────────────────────────────────────────────

/// Open a single database connection within the calling test's runtime.
///
/// Use for direct DB verification — checking side-effects the API doesn't surface
/// (soft-delete timestamps, token expiry, relation tuples, etc.). Call once per
/// test and reuse within that test; don't hold across `.await` points unnecessarily.
pub async fn db_conn() -> sqlx::PgConnection {
    use sqlx::Connection as _;
    sqlx::PgConnection::connect(&test_env().database_url)
        .await
        .expect("failed to open test db connection")
}

// ── Data helpers ──────────────────────────────────────────────────────────────

/// Generate a unique email address. UUID-based so parallel tests never collide.
pub fn unique_email() -> String {
    format!("test-{}@test.local", uuid::Uuid::now_v7().simple())
}

/// Sign up a new user via `POST /v1/users` and return the typed response.
///
/// Panics if signup fails — test setup errors should be loud.
pub async fn signup(email: &str, password: &str) -> beyond_auth::AuthResponse {
    TestClient::new()
        .post(
            "/v1/users",
            &serde_json::json!({ "email": email, "password": password }),
        )
        .await
        .assert_status(201)
        .json::<beyond_auth::AuthResponse>()
}

/// Log in via `POST /v1/sessions` with password credentials and return the typed response.
///
/// Assumes the user has no MFA enrolled. Panics on failure or if a step-up is required.
pub async fn login(email: &str, password: &str) -> beyond_auth::AuthResponse {
    TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "password",
                "email": email,
                "password": password,
            }),
        )
        .await
        .assert_status(201)
        .json::<beyond_auth::AuthResponse>()
}

// ── TOTP helpers ──────────────────────────────────────────────────────────────

/// Returned by `enroll_totp` — the fields tests actually need.
#[derive(serde::Deserialize)]
pub struct TotpEnrollment {
    pub secret_b32: String,
    pub recovery_codes: Vec<String>,
}

/// Enroll TOTP for a user: begins enrollment, generates the current code, confirms it.
///
/// Panics if any step fails — test setup errors should be loud.
pub async fn enroll_totp(bearer: &str) -> TotpEnrollment {
    let client = TestClient::new().bearer(bearer);

    let enrollment = client
        .post("/v1/totp", &serde_json::json!({}))
        .await
        .assert_status(200)
        .json::<TotpEnrollment>();

    let code = totp_now(&enrollment.secret_b32);
    client
        .post("/v1/totp/confirmations", &serde_json::json!({ "code": code }))
        .await
        .assert_status(204);

    enrollment
}

/// Generate the current 6-digit TOTP code from a base32-encoded secret.
pub fn totp_now(secret_b32: &str) -> String {
    use totp_rs::{Algorithm, Secret, TOTP};
    let bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .expect("valid base32 TOTP secret");
    TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, None, String::new())
        .expect("valid TOTP config")
        .generate_current()
        .expect("system time available")
}
