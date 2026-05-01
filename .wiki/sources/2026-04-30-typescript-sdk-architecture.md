---
kind: source
title: TypeScript SDK Architecture
summary: Data flows for session/JWT verification, authorization checks, and Next.js middleware with cookie helpers.
source_uri: .wiki/sources/inbox/2026-04-30-ts-architecture.raw.md
source_hash: (from raw archive)
ingested_at: 2026-04-30
---

## Synthesis

The TypeScript SDK wraps the auth service REST API with typed clients, session verifiers, JWT verifiers (JWKS + caching), authz clients, and Next.js-specific middleware/helpers. All operations delegate to the server for state; the SDK adds ergonomic interfaces and local verification optimization.

## Key Takeaways

- **Typed clients**: `createAdminClient` (raw typed fetch), `createAuthClient` (with auto-bearer header and namespaced methods).
- **Session verification**: Stateless `GET /v1/sessions/current` per call; returns `SessionContext | null` on 401; throws `AuthServiceError` on 5xx.
- **JWT verification**: Stateful JWKS caching (1-hour TTL, 30-second cooldown on refresh). Mandatory `sub` claim check. Retryable classification on errors.
- **Authz client**: Schema-defined checks via `check()` (user param), `checkSession()` (bearer token), `expand()` (who has access), `lookup()` (what can user access), `trace()` (audit).
- **Batch writes**: `PATCH /v1/authz/relations` with `{ writes, deletes }` body; short-circuits on empty input.
- **Cookie helpers**: Framework-agnostic (`sessionCookieAttrs`, `clearCookieAttrs`, `getSessionToken`). Cookie name determined by presence of `domain` field: no domain → `__Host-session` (pinned), with domain → `__Secure-session` (subdomains allowed).
- **Next.js middleware**: Public path matching, auth redirect, 5xx handling.
- **RSC helpers**: `getSession()` / `getMe()` memoized via `React.cache()` (falls back to identity if React unavailable).
- **Build**: ESM only, two entry points (core + next subpackage), strict TypeScript, erasable syntax (no enum/namespace).
- **Tests**: Live auth service + Postgres via testcontainers; `globalSetup` starts everything, polls `/healthz`, enables JWT.

## Related Pages

- [TypeScript SDK Client](../entities/ts-sdk-client.md)
- [JWT Verification](../concepts/jwt-verification.md)
- [Cookie Helpers](../concepts/cookie-helpers.md)
