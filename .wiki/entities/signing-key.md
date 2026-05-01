---
kind: entity
title: Signing Key
summary: Ed25519 keypair for JWT issuance, encrypted at rest with AES-256-GCM.
sources:
  - .wiki/sources/2026-04-30-auth-service-overview.md
  - .wiki/sources/2026-04-30-auth-architecture.md
links:
  - entities/token.md
last_verified_at: 2026-04-30
---

## Overview

Signing keys are Ed25519 keypairs used to sign JWT access tokens. The private key is encrypted at rest in the database using AES-256-GCM with a key-encryption-key (KEK) from the environment. The public key is published at `/v1/jwks.json` for verification by clients.

## Lifecycle

```
generating ──insert ON CONFLICT DO NOTHING──► active
                                                 │
                                         admin initiates rotation
                                                 │
                                                 ▼
                                             inactive (served in JWKS until old JWTs expire)
```

At startup, the service attempts to load the active key. If none exists, one is generated and inserted with `ON CONFLICT DO NOTHING` — concurrent starters converge to the same key.

## Encryption & Rotation

**At rest**: Private key encrypted with `SIGNING_KEY_ENCRYPTION_KEY` (base64url-encoded 32-byte AES-256-GCM key).

**Decryption**: On startup, attempt to decrypt with the current KEK. If that fails, try `SIGNING_KEY_ENCRYPTION_KEY_OLD` values (comma-separated). On success, re-encrypt with the new KEK and update the row — zero-downtime rotation.

**AAD (Additional Authenticated Data)**: The key ID prevents ciphertext swapping.

## JWT Issuance

Session token holders can request a JWT via `POST /v1/tokens { grant_type: "access_token" }`:

1. Require valid session
2. Load active signing key, decrypt with KEK
3. Build claims: `sub`, `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`, `+ extra_claims` (user-supplied)
4. Sign with Ed25519
5. Return `{ access_token, expires_in, token_type: "Bearer" }`

## Key Rotation

Old keys are kept in the database with `status='inactive'` and served at `/v1/jwks.json` until all JWTs they signed expire. This allows in-flight tokens to verify without interruption.

## Changelog

- 2026-04-30: Extracted from auth-readme and auth-architecture raw sources
