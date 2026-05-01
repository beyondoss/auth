---
kind: surface
title: Sessions API
summary: POST /v1/sessions for login and token refresh; GET /v1/sessions for listing; DELETE for revocation.
sources:
  - .wiki/sources/2026-04-30-auth-service-overview.md
  - .wiki/sources/2026-04-30-auth-architecture.md
links:
  - entities/session.md
  - entities/token.md
last_verified_at: 2026-04-30
---

## Endpoints

### Create Session (Login)

```
POST /v1/sessions
```

Accepts one of several grant types:

- **password**: `{ email, password }` → validates Argon2 hash
- **magic_link**: `{ token }` → consumes one-time token
- **refresh_token**: `{ refresh_token }` → rotates and returns new token
- **oauth**: `{ provider, code, codeVerifier }` → exchanges OAuth code
- **passkey**: `{ stateToken, credential }` → verifies WebAuthn assertion

Response:

- **201 Created** (success): `{ user, org, email, session, refresh_token? }`
- **200 OK** (MFA required): `{ stepUpToken }` — exchange for session after TOTP/recovery
- **401 Unauthorized**: Invalid credentials, expired token, etc.

### Get Current Session

```
GET /v1/sessions/current
Authorization: Bearer <session_token>
```

Validates the token and returns `{ user, org, email, session_id }`.

Response:

- **200 OK**: Full session context
- **401 Unauthorized**: Invalid or expired token

### List Sessions

```
GET /v1/sessions
Authorization: Bearer <session_token>
```

Lists all sessions for the authenticated user.

Response:

- **200 OK**: `{ sessions: [...] }`

### Revoke Session

```
DELETE /v1/sessions/{id}
Authorization: Bearer <session_token>
```

Immediately invalidates the session (deletes the token row).

Response:

- **204 No Content**: Success
- **404 Not Found**: Session doesn't exist
- **401 Unauthorized**: Caller's token invalid

## Step-Up (MFA)

If TOTP is enrolled:

1. `POST /v1/sessions { email, password }` → 200 with `{ stepUpToken }`
2. `POST /v1/sessions { stepUpToken, totpCode }` or `{ stepUpToken, recoveryCode }` → 201 with session

## Changelog

- 2026-04-30: Extracted from auth-service-overview and auth-architecture raw sources
