---
kind: concept
title: Cookie Helpers
summary: Framework-agnostic cookie utilities; __Host-session (pinned) vs __Secure-session (subdomains).
sources:
  - .wiki/sources/2026-04-30-typescript-sdk-architecture.md
links:
  - entities/session.md
last_verified_at: 2026-04-30
---

## Overview

The SDK provides framework-agnostic cookie helpers that return plain objects. Callers apply them to their framework's cookie API.

## Helper Functions

- **`sessionCookieAttrs()`**: Returns cookie attributes for session storage
- **`clearCookieAttrs()`**: Returns attributes to clear a session cookie
- **`getSessionToken(request)`**: Parses `cookie` header manually; prefers `__Host-session`, falls back to `__Secure-session`, then `Authorization: Bearer`

## Cookie Name Selection

Determined by whether `domain` is set in the config:

- **No `domain` set**: Use `__Host-session` (pinned to exact origin, no subdomains)
- **`domain` set**: Use `__Secure-session` (allows subdomains)

## Hardcoded Attributes

Callers cannot weaken these:

- `HttpOnly` — prevents JavaScript access
- `Secure` — HTTPS only
- `SameSite=lax` — CSRF protection
- `Path=/` — site-wide

## Parsing Logic

`getSessionToken` reads the `cookie` header without a library dependency:

1. Check for `__Host-session` cookie
2. Fallback to `__Secure-session`
3. Fallback to `Authorization: Bearer` header
4. Return the token value or `null`

## Changelog

- 2026-04-30: Extracted from typescript-sdk-architecture raw source
