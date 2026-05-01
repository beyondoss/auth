---
kind: entity
title: User
summary: End-user identity with emails, identities (passwords/OAuth), and a primary organization.
sources:
  - .wiki/sources/2026-04-30-auth-service-overview.md
  - .wiki/sources/2026-04-30-auth-architecture.md
links:
  - entities/session.md
  - entities/organization.md
last_verified_at: 2026-04-30
---

## Overview

A user is the core identity entity. Users have:

- One or more email addresses (multi-email support)
- One primary email (`primary_email_id`)
- One personal organization (`primary_org_id`) created at signup
- One or more identities (auth methods: password hash, OAuth links, passkey, TOTP)
- A soft-deletion flag (`deleted_at`)

## Lifecycle

```
(new) ──signup──► active ──admin_delete──► deleted
                    │
                    └──► email unverified (initial)
                               │
                         verify token ──► email verified
```

On signup, a user's primary email is initially unverified. Verification is triggered by sending an email-verification token (`ev` prefix) and consuming it via `POST /v1/emails/{id}/verify`.

## Multi-Email Support

Users can attach and verify multiple email addresses via:

1. `POST /v1/users/emails` — attach an email
2. `POST /v1/emails/{id}/verify` — verify it with a token
3. `PATCH /v1/users/me` — change primary email

All email addresses share one user account. Duplicate email detection prevents one email from belonging to two users.

## Deletion

Admin deletion sets `deleted_at`; no cascade. Sessions and tokens are not automatically revoked. Admin endpoints exist to clean up associated state.

## Changelog

- 2026-04-30: Extracted from auth-readme and auth-architecture raw sources
