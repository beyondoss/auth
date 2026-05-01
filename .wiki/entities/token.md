---
kind: entity
title: Token
summary: Opaque credential in wire format {prefix}_{uuid7}_{secret_b64url}, validated via SHA-256 lookup.
sources:
  - .wiki/sources/2026-04-30-auth-service-overview.md
  - .wiki/sources/2026-04-30-auth-architecture.md
links:
  - entities/session.md
  - entities/signing-key.md
last_verified_at: 2026-04-30
---

## Overview

Tokens are the primary authentication credentials. All follow the same wire format: `<prefix>_<uuid7-hex>_<secret-b64url>`. The UUID v7 provides monotonic ordering (efficient indexing on expiry). The secret is 32 random bytes from `OsRng`. Only the SHA-256 hash of the secret is persisted in the database; the plaintext never survives a request.

## Token Types

| Prefix        | Lifetime               | Table                   | Purpose                                            |
| ------------- | ---------------------- | ----------------------- | -------------------------------------------------- |
| `session`     | 30 days (configurable) | tokens + sessions       | End-user session credential (main auth)            |
| `rt`          | 30 days (configurable) | tokens + refresh_tokens | SDK long-lived; rotates on use                     |
| `key`         | ∞ (manual revoke)      | tokens + keys           | Named API keys for server-to-server auth           |
| `ml`          | 15 min                 | one_time_tokens         | Magic link (passwordless login)                    |
| `pwr`         | 60 min                 | one_time_tokens         | Password reset                                     |
| `ev`          | 24 h                   | one_time_tokens         | Email verification                                 |
| `ec`          | 24 h                   | one_time_tokens         | Email change confirmation                          |
| `inv`         | 7 days                 | org_invitations         | Org invitation link                                |
| `impersonate` | 5 min                  | one_time_tokens         | MFA step-up (internal only, exchanged for session) |

## Validation

Token validation is a single indexed lookup:

1. Parse the bearer token: extract UUID and secret bytes
2. Compute SHA-256(secret)
3. Query: `SELECT id FROM auth.tokens WHERE id = $1 AND secret = digest($2,'sha256') AND expires_at > now()`
4. If found, update `last_used_at` (debounced to 1-minute intervals to avoid write amplification)

Session validation bundles this token lookup with the user/org/email join in a single CTE, avoiding a second query.

## Revocation

- **Session tokens**: Delete the row immediately (instant revocation)
- **Refresh tokens**: Soft-delete with a flag (family-based replay detection for theft)
- **One-time tokens**: Consume with `DELETE…RETURNING` (atomic, prevents race conditions)
- **API keys**: Soft-delete row (preserved for audit)
- **JWTs**: No revocation list; revoked at key rotation (old key removed from JWKS)

## Why SHA-256, Not Argon2

Tokens are already 32 random bytes — no dictionary-attack surface. SHA-256 is appropriate here: fast, non-iterative, sufficient against preimage attacks. Argon2 would be wasteful.

## Changelog

- 2026-04-30: Extracted from auth-readme and auth-architecture raw sources
