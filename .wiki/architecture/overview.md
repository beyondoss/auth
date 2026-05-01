---
kind: architecture
title: Architecture Overview
summary: Beyond-auth service architecture, data flows, and trust boundaries across core modules.
sources:
  - .wiki/sources/2026-04-30-auth-service-overview.md
  - .wiki/sources/2026-04-30-auth-architecture.md
  - .wiki/sources/2026-04-30-typescript-sdk-architecture.md
  - .wiki/sources/2026-04-30-authz-extension-architecture.md
links:
  - sources/2026-04-30-auth-architecture.md
  - sources/2026-04-30-typescript-sdk-architecture.md
  - sources/2026-04-30-authz-extension-architecture.md
last_verified_at: 2026-04-30
---

## System Overview

**beyond-auth** is a single-tenant, private-network authentication and authorization service. It consists of:

1. **Rust service** (`src/`) — HTTP server handling sessions, tokens, auth methods, organizations, and authorization
2. **TypeScript SDK** (`sdk/ts/`) — Client library for session/JWT verification, authz checks, Next.js integration
3. **PostgreSQL extension** (`authz_extension/`) — Native extension for Zanzibar-style permission checks

All state lives in PostgreSQL (`auth` schema).

## Core Flows

### Session Authentication

User login → password/OAuth/passkey/magic-link validation → create token + session row → return opaque bearer token.

On each request, bearer token is validated in a single SQL CTE: token lookup + `last_used_at` update + user/org/email join.

### JWT Issuance

Session holder requests JWT via `POST /v1/tokens` → load active signing key (decrypt with KEK) → build claims → sign with Ed25519 → return.

### Authorization (Opt-in)

Define schema (resource types, roles, permissions) → write relation tuples → check permissions via BFS over relation graph.

Single check is one query to the authz extension. Batch checks (N) cost `depth+1` queries via parallel batch function.

## Key Entities

- [Token](../entities/token.md) — Opaque credentials; all follow same format
- [Session](../entities/session.md) — Validated in one CTE; carries user/org/email
- [User](../entities/user.md) — Multi-email, multiple identities, personal org
- [Organization](../entities/organization.md) — Groups of users with roles
- [Identity](../entities/identity.md) — Auth method binding (password, OAuth, passkey, TOTP)
- [Signing Key](../entities/signing-key.md) — Ed25519 keypairs for JWT; KEK-encrypted at rest
- [OAuth](../entities/oauth.md) — Provider config and PKCE flow
- [Authorization Relation](../entities/authz-relation.md) — Raw data for BFS (direct grants + subject-sets)
- [Authorization Schema](../entities/authz-schema.md) — Resource types, roles, permission mappings

## Key Concepts

- [Refresh Token Replay Detection](../concepts/refresh-token-replay-detection.md) — Family-based revocation catches theft
- [One-Time Token Consumption](../concepts/one-time-token-consumption.md) — Atomic DELETE...RETURNING
- [Authorization](../concepts/authorization.md) — Zanzibar relation engine with BFS
- [JWT Verification](../concepts/jwt-verification.md) — Stateful JWKS caching, local verification
- [Cookie Helpers](../concepts/cookie-helpers.md) — Framework-agnostic session storage
- [Performance Testing](../concepts/performance-testing.md) — Concurrency sweep to identify constraints

## API Surfaces

- [Sessions API](../surfaces/sessions-api.md) — Login, refresh, revoke
- [Authorization API](../surfaces/authz-api.md) — Checks, relations, schema

## Trust Boundaries

**The service verifies:**

- Bearer token format, signature, expiry
- Argon2 password hashes
- Ed25519 JWT signatures
- OAuth state/PKCE
- WebAuthn assertions
- TOTP codes
- Admin secrets

**The service relies on the operator's infrastructure for:**

- TLS termination
- Rate limiting
- IP filtering
- DDoS mitigation

This service is **not** a public SaaS—it runs inside a customer's private network.

## Changelog

- 2026-04-30: Created from synthesis of 8 raw sources (auth README, architecture, API tests, TS SDK, authz extension, benchmarking)
