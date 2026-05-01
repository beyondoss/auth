---
kind: entity
title: Test Server
summary: Integration test harness spawning Postgres testcontainer and auth service with one-background-thread lifecycle.
sources:
  - .wiki/sources/2026-04-30-api-integration-tests.md
links:
  - entities/token.md
  - entities/session.md
last_verified_at: 2026-04-30
---

## Overview

The test harness manages a single shared Postgres testcontainer and auth service instance for the entire test run. All tests hit the same in-memory `TestEnv` static, which blocks on first access until the container and service are ready.

## Lifecycle

1. Background OS-level thread starts on first `test_env()` call
2. That thread spawns a dedicated `tokio` runtime
3. Runtime pulls Postgres 18 Docker image, starts testcontainer
4. Runs migrations against the test database
5. Spawns the `beyond-auth` binary on a free port
6. Polls `/healthz` until healthy (60s timeout)
7. Enables JWT issuance via `PATCH /v1/admin/config`
8. Parks on `pending()` forever—keeps container/server alive

## Why Background Thread

`#[tokio::test]` creates a separate runtime per test. `tokio::sync::OnceCell` is per-runtime, not process-global. A background OS-level thread with its own runtime avoids cross-runtime coordination issues.

## TestEnv

```rust
static TESTENV: OnceLock<TestEnv> = OnceLock::new();

pub struct TestEnv {
    pub database_url: String,
    pub server_url: String,
    pub admin_secret: String,
    pub exclusion_lock: tokio::sync::Mutex<()>,
}
```

All three URLs are `String` (not runtime-bound). `OnceLock` works because `TestEnv` is `Send + Sync`.

## Isolation

Tests are isolated by construction:

- Each test gets a unique UUID v7 email (monotonic, guaranteed unique across parallel tests)
- No cleanup needed—rows are owned by their test
- Parallel execution is safe by default

## Global State Mutations

Tests that mutate global state (authz schema, OAuth config) use the `exclusive()` mutex. Lock held for the critical section; automatically released on panic.

## Changelog

- 2026-04-30: Extracted from api-integration-tests raw source
