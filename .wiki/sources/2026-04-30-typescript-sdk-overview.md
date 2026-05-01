---
kind: source
title: TypeScript SDK Overview
summary: Package exports, auth flows, session/JWT/authz verification, HTTP client, Next.js integration.
source_uri: .wiki/sources/inbox/2026-04-30-ts-readme.raw.md
source_hash: (from raw archive)
ingested_at: 2026-04-30
---

## Synthesis

The `@beyond.dev/auth` package provides auth flow helpers (sign up/in, MFA, passkeys, magic links), session/JWT verifiers, Zanzibar-style authorization, typed HTTP clients, and Next.js middleware/RSC helpers.

## Key Takeaways

- **Auth flows**: `createAuthFlowClient` handles sign up, sign in (password/magic link/passkey), password reset, MFA, sign out.
- **MFA step-up**: When TOTP is enrolled, password login returns `stepUpToken` (5 min TTL); exchange with TOTP code or recovery code for session.
- **Session verification**: `createSessionVerifier` checks opaque tokens via `GET /v1/sessions/current`.
- **JWT verification**: `createJwtVerifier` caches JWKS (1 hour), verifies locally, unknown `kid` triggers refresh.
- **Authorization**: `createAuthzClient` with schema support: `check()`, `checkSession()`, `expand()`, `lookup()`, `trace()`, `createRelation()`, `deleteRelation()`, `putSchema()`.
- **Schema typing**: `defineSchema()` enables compile-time type checking on resource types, permissions, relation names. Or import from JSON file.
- **HTTP client**: `createAdminClient` and `createAuthClient` with full REST endpoints.
- **Next.js**: Middleware, RSC helpers (`getSession()`, `getMe()`), cookie utilities.
- **Entry points**: ESM only; core package (`@beyond.dev/auth`) + Next.js subpackage (`@beyond.dev/auth/next`).

## Related Pages

- [TypeScript SDK Client](../entities/ts-sdk-client.md)
- [TypeScript SDK Architecture](../sources/2026-04-30-typescript-sdk-architecture.md)
