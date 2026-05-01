---
kind: source
title: API Integration Tests
summary: End-to-end testing harness using testcontainers and real Postgres, with helpers for auth flows and database introspection.
source_uri: .wiki/sources/inbox/2026-04-30-api-readme.raw.md
source_hash: (from raw archive)
ingested_at: 2026-04-30
---

## Synthesis

Integration tests run against a real Postgres instance spun up in a testcontainer. The harness manages the server lifecycle, database pool, and one-background-thread model for startup. Helpers provide typed responses, session creation, and exclusive-lock guards for mutation tests.

## Key Takeaways

- **One-server model**: Background thread owns the Postgres container, auth service, and testcontainer lifecycle for the entire test run.
- **Per-test isolation**: UUID v7-based email generation ensures each test owns its rows; no cleanup needed.
- **Typed responses**: Responses are deserialized into exact server types—no translation layer, no duplication.
- **TestClient**: Methods for `get`, `post`, `patch`, `put`, `delete`; `.assert_status()` panics with response body on mismatch.
- **Bearer auth**: Both session and admin auth use `Authorization: Bearer`; `.bearer()` or `.admin()` set the header.
- **Direct database access**: `db_conn()` gives a per-test Postgres connection (in correct runtime, separate from server pool).
- **Exclusive lock**: `exclusive()` mutex serializes tests that mutate global state (authz schema, OAuth config, app config).
- **Fast-path user creation**: `create_session()` bypasses API, inserts rows directly for authz/session tests.
- **Response helpers**: `.json::<Type>()` is sync; `.assert_status()` includes body on failure.

## Related Pages

- [Test Server](../entities/test-server.md)
