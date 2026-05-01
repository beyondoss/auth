---
kind: entity
title: OAuth
summary: OAuth 2.0 provider configuration and authorization-code flow with PKCE.
sources:
  - .wiki/sources/2026-04-30-auth-service-overview.md
  - .wiki/sources/2026-04-30-auth-architecture.md
links:
  - entities/user.md
  - entities/identity.md
last_verified_at: 2026-04-30
---

## Overview

OAuth providers are configured via the admin API (`PUT /v1/admin/oauth-providers`). Supported: GitHub, Google, Apple, Microsoft, and generic OpenID Connect. Provider credentials are encrypted at rest.

## Flow

```
GET /v1/oauth/{provider}?redirect_uri=...&code_challenge=...
  │
  ├── Generate PKCE verifier
  ├── Store in state token (signed HS256, 10 min TTL)
  ├── Redirect to provider
  │
  └─► User authenticates, provider redirects back
      │
      GET /v1/oauth/{provider}/callback?code=...&state=...
      │
      ├── Validate state token (signature, TTL)
      ├── Verify PKCE code_verifier matches code_challenge
      ├── Exchange code for access token
      ├── Fetch user profile
      │
      ├─ Does identity (provider, subject) already exist?
      │  ├── Yes → link to user
      │  └── No  → create user + identity
      │
      └── Create session
          Return HTML with postMessage to opener
```

## Identity Linking

When OAuth login succeeds:

1. Look up identity by `(provider, subject_id)`
2. If found, link to existing user
3. If not, create new user and identity

Optional `oauth_email_link` config: when true, match on email instead of subject ID, linking the identity to a user with that email.

## State Token

The state token is a signed JWT that holds the PKCE verifier and has a 10-minute TTL. It prevents CSRF and enables PKCE validation.

## Changelog

- 2026-04-30: Extracted from auth-readme and auth-architecture raw sources
