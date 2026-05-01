---
kind: source
title: Auth Service Overview
summary: High-level summary of the beyond-auth service, its features, configuration, and deployment model.
source_uri: .wiki/sources/inbox/2026-04-30-auth-readme.raw.md
source_hash: (from raw archive)
ingested_at: 2026-04-30
---

## Synthesis

The beyond-auth service is a single-tenant, private-network authentication system deployed inside each customer's infrastructure. It runs migrations on startup, stores auth state in a dedicated Postgres schema (`auth`), and provides REST endpoints for sessions, tokens, auth methods, organizations, and authorization checks.

## Key Takeaways

- **Single-tenant**: Each deployment serves exactly one project's users; no shared namespace.
- **Stateless**: No in-process state; scales to zero and restarts cleanly against the same DB.
- **Opaque sessions**: Short-lived bearer tokens validated in one SQL query; JWT exchange is opt-in.
- **Auth methods**: Passwords (Argon2id), magic links, TOTP/MFA, passkeys (WebAuthn), OAuth (GitHub, Google, Apple, Microsoft, OIDC).
- **Multi-email**: Users can attach and verify multiple email addresses.
- **Organizations**: Create orgs, manage members and roles, send/accept invitations.
- **Authorization**: Opt-in Zanzibar-style relation engine for permission checks.
- **API keys**: `key_` tokens for server-to-server auth.
- **Signing key encryption**: Ed25519 keys encrypted at rest with AES-256-GCM; zero-downtime rotation via old KEK values.
- **Token format**: All credentials follow `{prefix}_{uuid_v7_hex}_{32_random_bytes_b64url}`; secrets hashed with SHA-256.
- **JWT mode**: Opt-in; publishes keys at `/v1/jwks.json` for edge verification.
- **Configuration**: 15+ env vars and runtime-writable settings (session TTL, idle timeout, JWT enabled, issuer URL, etc.).
- **Database**: Operates within `auth` schema; migrations are additive-only; portable (export/restore via `pg_dump`).
- **Portability**: Self-hosted deployments fork the database to move to custom infrastructure.

## Related Pages

- [Token](../entities/token.md) — credential types, format, validation
- [Session](../entities/session.md) — session validation, lifecycle
- [Authorization](../concepts/authorization.md) — Zanzibar-style permission engine
- [Signing Key](../entities/signing-key.md) — JWT signing, key rotation
- [OAuth](../entities/oauth.md) — provider configuration, flows
