---
kind: entity
title: Session
summary: Join between a token and a user; validated in one SQL CTE with automatic last_used_at debouncing.
sources:
  - .wiki/sources/2026-04-30-auth-service-overview.md
  - .wiki/sources/2026-04-30-auth-architecture.md
links:
  - entities/token.md
  - entities/user.md
last_verified_at: 2026-04-30
---

## Overview

A session is the result of successful authentication. It joins a [token](token.md) to a [user](user.md) and carries metadata: IP address, user agent, creation time, last-used time. Sessions expire at a configurable TTL (default 30 days) or after an idle timeout (if configured).

## Lifecycle

```
created ──────────────────────► active
  │                              │
  ├─── expires_at reached ─────► invalid (token GC deletes async)
  ├─── DELETE /v1/sessions/{id}─► deleted (immediate)
  └─── idle_timeout exceeded ──► invalid (checked at validation time)
```

## Validation: One Round-Trip

Session validation combines three operations in a single bundled CTE:

1. **Token lookup**: `WHERE id = $1 AND secret = digest($2,'sha256') AND expires_at > now()`
2. **last_used_at update**: `UPDATE auth.tokens SET last_used_at = now()` (skipped if < 1 min old to avoid write amplification)
3. **Full context join**: `JOIN auth.users, auth.orgs, auth.emails` to return the complete [AuthContext](../concepts/authcontext.md)

Result: one SQL request, full user/org/email data in the response. No second query needed.

## Why Debouncing last_used_at

Under load, every request would cause a token table write. A 1-minute debounce cuts writes by ~60× while keeping session freshness accurate enough for idle-timeout enforcement.

## Idle Timeout

Optional per-app configuration: if set to (e.g.) 1 hour, sessions are invalid if `last_used_at < now() - '1 hour'::interval`. Checked at validation time, not enforced by a background job.

## Changelog

- 2026-04-30: Extracted from auth-readme and auth-architecture raw sources
