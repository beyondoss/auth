---
kind: concept
title: Refresh Token Replay Detection
summary: "Family-based revocation: stolen refresh tokens are caught regardless of rotation order."
sources:
  - .wiki/sources/2026-04-30-auth-architecture.md
links:
  - entities/token.md
last_verified_at: 2026-04-30
---

## Problem

When a refresh token is stolen, the legitimate client and attacker both have it. Per-token revocation only catches the attacker if the legitimate client rotates first. If the attacker uses the token before the victim, the theft goes undetected.

## Solution: Family-Based Revocation

Each refresh token is assigned a `family_id`. On rotation:

1. Old token is consumed (soft-deleted)
2. New token is issued in the same family
3. If a token that has already been rotated is presented again, the entire family is revoked

**Result**: Any replay of a rotated token immediately invalidates all tokens in that family—theft is caught regardless of order.

## Implementation

Every refresh token in `auth.refresh_tokens` has:

- `id` — the token UUID
- `family_id` — the family identifier (often the first token's UUID)
- `rotated_by` — the ID of the token that replaced this one (NULL if not yet rotated)
- `revoked_at` — soft-delete timestamp (NULL if active)

On `POST /v1/sessions { refresh_token }`:

1. Look up the refresh token row
2. Check if `rotated_by IS NOT NULL` (token has been rotated)
3. If yes: `UPDATE auth.refresh_tokens SET revoked_at = now() WHERE family_id = $family_id`
4. Return 401 Unauthorized

The victim can re-authenticate to get a new family.

## Changelog

- 2026-04-30: Extracted from auth-architecture raw source
