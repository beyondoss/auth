# API Integration Tests

End-to-end tests against a real server with a real Postgres database. No mocks.

```
mise run test:integration:api
# or
cargo test --test api
```

First run pulls `postgres:18-alpine` and compiles from scratch (~60s). Subsequent runs start in seconds — the image is cached, the binary is cached.

---

## Adding a test module

1. Create `tests/api/your_module.rs`
2. Add `mod your_module;` to `tests/api/main.rs`
3. Write tests

```rust
// tests/api/sessions.rs
use crate::helpers::{TestClient, login, signup, unique_email};

#[tokio::test]
async fn login_returns_session_token() {
    let email = unique_email();
    signup(&email, "hunter2-but-longer").await;
    let auth = login(&email, "hunter2-but-longer").await;
    assert!(!auth.session.token.is_empty());
}
```

---

## Helpers

### `signup` / `login`

Both return a typed `beyond_auth::AuthResponse` — not just the token. Use what you need.

```rust
let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
// auth.user.id, auth.org.id, auth.email.email, auth.session.token
```

`signup` → `POST /v1/users` → `201`\
`login` → `POST /v1/sessions` (password grant) → `201`

Both panic on failure. Test setup errors should be loud.

### `unique_email`

```rust
let email = unique_email(); // "test-018f3c...@test.local"
```

UUID v7 — monotonically increasing, guaranteed unique across parallel tests. No cleanup needed: each test owns its rows by construction.

### `TestClient`

```rust
let anon   = TestClient::new();
let authed = TestClient::new().bearer(&auth.session.token);
let admin  = TestClient::new().admin();
```

Both session auth and admin auth use `Authorization: Bearer` — that's how the server's middleware works. `.admin()` just sets the bearer value to the admin secret.

Methods: `get`, `post`, `patch`, `put`, `delete`. All return `TestResponse`.

```rust
let me = authed
    .patch("/v1/users/me", &serde_json::json!({ "name": "Alice" }))
    .await
    .assert_status(200)
    .json::<beyond_auth::MeResponse>();
assert_eq!(me.user.name, "Alice");
```

`assert_status` panics with the response body on mismatch — you see the actual error, not just a status code. `json()` is sync (no `.await`) because the body is buffered during the HTTP call. It also panics with the raw body if deserialization fails.

### `db_conn`

```rust
let mut conn = db_conn().await;
let row = sqlx::query!("SELECT deleted_at FROM auth.users WHERE id = $1", user_id)
    .fetch_one(&mut conn)
    .await
    .unwrap();
assert!(row.deleted_at.is_some());
```

A single Postgres connection created within your test's tokio runtime. Use it to verify side-effects the API doesn't surface: soft-delete timestamps, token expiry, relation tuples written to `auth.relation_tuples`, etc.

`search_path = auth, public` is already set — reference tables without schema-qualifying them.

**Why not share a pool from the server?** `sqlx::PgPool` uses tokio primitives that are bound to the runtime that created them. `#[tokio::test]` gives each test its own runtime. A per-test connection created inside that runtime is safe; sharing the server's pool across runtimes is not.

### `exclusive`

```rust
#[tokio::test]
async fn authz_schema_round_trip() {
    let _guard = exclusive().await;
    // PUT /v1/authz/schema, test behavior, optionally clean up
}
```

Serializes tests that mutate global server state: authz schema, OAuth provider config, app config. Everything else runs in parallel.

**Convention — set-don't-assume**: set the state you need at the start of the critical section. Don't rely on a prior test having cleaned up. If the previous test panicked mid-teardown, the guard still released (drop runs on panic), but the state may be dirty. Own your preconditions.

`tokio::sync::Mutex` works across the per-test runtimes here because `Waker::wake()` is runtime-agnostic — it notifies whichever executor owns the task, regardless of where the mutex was created.

---

## Typed responses

Response types are defined in `src/routes/` with `Serialize + ToSchema`. Add `Deserialize` when a test needs to deserialize one, then re-export it from `lib.rs`.

**Adding a new type** — two changes, pattern established in `users.rs`:

```rust
// src/routes/sessions.rs
#[derive(Serialize, Deserialize, ToSchema)]  // add Deserialize
pub struct SessionsResponse { ... }

// src/lib.rs
pub use routes::sessions::SessionsResponse;  // add re-export
```

Then use it:

```rust
let sessions = authed
    .get("/v1/sessions")
    .await
    .assert_status(200)
    .json::<beyond_auth::SessionsResponse>();
```

These are the exact types the server serializes — no translation layer, no duplication.

---

## Fast-path user creation

For tests where you need an authenticated user but don't care about testing the signup flow itself, bypass the API entirely:

```rust
use sqlx::PgPool;

let pool = PgPool::connect(&test_env().database_url).await.unwrap();
let session = beyond_auth::test_server::create_session(&pool).await.unwrap();
let client = TestClient::new().bearer(&session.bearer);
```

`create_session` inserts the user, org, email, token, and session directly in a transaction — faster than going through the API, no password hashing. Use it for authz tests, session management tests, anything where the user's origin doesn't matter.

---

## How the harness works

**One server for the whole binary run.** A background thread owns a dedicated tokio runtime. That runtime starts the Postgres container, runs migrations, starts the auth server, then parks on `pending()` forever — keeping the container and server task alive until the process exits.

**Why not `tokio::sync::OnceCell`?** `#[tokio::test]` creates a separate tokio runtime per test. `tokio::sync::OnceCell` is per-runtime. The background-thread approach gives every test a stable `&'static TestEnv` with no cross-runtime coordination.

**Why `std::sync::OnceLock`?** `TestEnv` contains only `String` and `tokio::sync::Mutex<()>` — both `Send + Sync` — so it can live in a static. The first test to call `test_env()` blocks (OS-level, not async) while the container starts; all subsequent calls return immediately.

The container startup is the only slow part. Once it's running, individual tests hit a local TCP port — latency is negligible.
