---
kind: entity
title: WebAuthn Credential
summary: Passkey credential stored for FIDO2/WebAuthn authentication.
sources:
  - .wiki/sources/2026-04-30-auth-service-overview.md
  - .wiki/sources/2026-04-30-auth-architecture.md
links:
  - entities/identity.md
last_verified_at: 2026-04-30
---

## Overview

WebAuthn credentials (passkeys) are stored in `auth.webauthn_credentials` and linked to a user identity. They contain the credential key handle, public key, and signature counter for cloned-key detection.

## Lifecycle

### Registration

1. `POST /v1/users/webauthn/register/begin` — get WebAuthn options
2. User registers with browser/device
3. `POST /v1/users/webauthn/register/finish` — submit credential, store in DB

### Authentication

1. `POST /v1/sessions { grant_type: "webauthn", stateToken, credential }` — verify and create session

## Signature Counter

Tracks the number of signatures produced by this credential. If the counter on a new assertion is less than or equal to the stored counter, the credential may be cloned — authentication is rejected.

## Verification

The auth service verifies:

- Credential signature (FIDO2 Assertion)
- Challenge binding
- Cloned-key detection via counter

## Relying Party

Configured via env vars:

- `WEBAUTHN_RP_ID` — domain (e.g., `example.com`)
- `WEBAUTHN_RP_ORIGIN` — origin (e.g., `https://example.com`)

Must match the browser's origin for security.

## Changelog

- 2026-04-30: Extracted from auth-service-overview and auth-architecture raw sources
