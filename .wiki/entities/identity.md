---
kind: entity
title: Identity
summary: Auth method binding (password hash, OAuth, passkey, TOTP) to a user.
sources:
  - .wiki/sources/2026-04-30-auth-service-overview.md
  - .wiki/sources/2026-04-30-auth-architecture.md
links:
  - entities/user.md
  - entities/oauth.md
last_verified_at: 2026-04-30
---

## Overview

Identities bind authentication methods to users. One user can have multiple identities:

- **Password**: Argon2id hash
- **OAuth**: Provider + subject ID link
- **Passkey**: WebAuthn credential stored in `auth.webauthn_credentials`
- **TOTP**: Enrolled 2FA with recovery codes

## Password Identity

Passwords are hashed with Argon2id using OWASP 2024 parameters:

- `m=19456` (19 MiB)
- `t=2` (2 iterations)
- `p=1` (1 parallelism)
- 32-byte output

Checked against a compiled common-password list at login time.

The PHC string is stored as `bytea` in `identities.secret`.

## OAuth Identity

Stores `(provider, subject_id, email_claimed)`. Subject ID is the provider's user identifier (sub claim).

## TOTP Identity

Enrolled TOTP returns recovery codes (10–16 codes, printed/stored by user). Recovery codes are one-time-use and consume a code when verified.

When TOTP is enrolled, password login returns a step-up token (5-minute TTL) instead of a session. The step-up must be exchanged with a TOTP code or recovery code for an actual session.

## Passkey Identity

WebAuthn credentials stored with flags, key handle, public key, and sign counter (for cloned-key detection).

## Changelog

- 2026-04-30: Extracted from auth-readme and auth-architecture raw sources
