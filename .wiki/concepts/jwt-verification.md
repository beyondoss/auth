---
kind: concept
title: JWT Verification
summary: Stateful JWKS caching (1-hour TTL, 30s cooldown on refresh) with mandatory sub claim check and retryable error classification.
sources:
  - .wiki/sources/2026-04-30-typescript-sdk-architecture.md
links:
  - entities/signing-key.md
  - entities/token.md
last_verified_at: 2026-04-30
---

## Overview

The TypeScript SDK's `createJwtVerifier` handles JWT verification locally without calling the auth service (after JWKS fetch). It uses `jose`'s `createRemoteJWKSet` for JWKS caching and adds:

- Mandatory `sub` claim validation
- Retryable error classification
- Clock skew tolerance

## JWKS Caching

- **First call**: Fetch JWKS from `jwksUri`, cache for 1 hour
- **Cache hit**: Verify signature locally
- **Cache miss after TTL**: Refresh JWKS, retry
- **Unknown `kid`**: Refresh JWKS once (30-second cooldown), retry
  - If still unknown, throw non-retryable error

## Error Handling

**Retryable**:

- Network timeouts (JWKS fetch)
- Non-`JOSEError` exceptions (general network failures)

**Non-retryable**:

- Bad signature
- Wrong issuer
- Expired token
- Missing `sub` claim
- Clock skew violation

## Mandatory Claims

- `sub` — throw if missing
- `iss` — checked if configured (must match)
- `aud` — checked if configured (must match)
- `exp` — checked (with `clockSkewSeconds` tolerance, default 30)
- `nbf` — checked (with tolerance)

## Session vs JWT Verification

|                          | Session verifier            | JWT verifier                                       |
| ------------------------ | --------------------------- | -------------------------------------------------- |
| Round-trip per request   | Yes                         | No (cache hit)                                     |
| Detects revocation       | Yes                         | No — JWT valid until expiry                        |
| Requires auth service up | Always                      | Only on cache miss                                 |
| Use when                 | Default; revocation matters | High request volume; short-lived tokens acceptable |

## Changelog

- 2026-04-30: Extracted from typescript-sdk-architecture raw source
