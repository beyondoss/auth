---
kind: source
title: Auth Service Architecture
summary: Data flows, state machines, core mechanisms, and trust boundaries for session/token validation, JWT issuance, and authorization checks.
source_uri: .wiki/sources/inbox/2026-04-30-auth-architecture.raw.md
source_hash: (from raw archive)
ingested_at: 2026-04-30
---

## Synthesis

The auth service validates tokens in a single bundled CTE, issues JWTs via Ed25519 signing keys, and delegates authorization to a PostgreSQL extension that performs BFS over relation tuples. Every flow is documented as a state machine with explicit error paths and failure modes.

## Key Takeaways

- **Session validation**: One CTE combining token lookup, `last_used_at` update, and user/org/email join—zero extra queries.
- **Middleware stack**: Request ID, tracing, 30-second timeout, panic recovery, then auth (if required).
- **JWT issuance**: Fetch active signing key, decrypt with KEK, build claims, sign with Ed25519, return with expiry.
- **Authorization**: Schema compilation to SQL calls → extension BFS for transitive group membership.
- **Authz cache**: LRU (100k entries, 30 min TTL, version-tagged); cache miss falls through to extension.
- **Password hashing**: Argon2id with OWASP 2024 parameters, common-password checking.
- **Signing key lifecycle**: Load or generate at startup, decrypt with KEK (or old KEK on rotation), old keys served in JWKS until token expiry.
- **Refresh token rotation**: Family-based replay detection—any replay of a rotated token revokes the entire family.
- **One-time tokens**: Consumed with `DELETE…RETURNING` (atomic, race-safe).
- **State machines**: User account, MFA step-up, session, signing key, OAuth flow.
- **Trust boundaries**: Service verifies tokens, passwords, signatures, PKCE, WebAuthn, TOTP, admin secrets; relies on operator's infrastructure for rate limiting and DDoS mitigation.
- **Failure modes**: DB unavailable → 503/500; concurrent signup → 409 Conflict; refresh token replay → family revoked; authz extension unavailable → authz checks fail (no data loss).

## Related Pages

- [Token](../entities/token.md)
- [Session](../entities/session.md)
- [Signing Key](../entities/signing-key.md)
- [Authorization](../concepts/authorization.md)
- [Refresh Token Replay Detection](../concepts/refresh-token-replay-detection.md)
