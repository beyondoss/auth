---
kind: concept
title: One-Time Token Consumption
summary: "Atomic DELETE...RETURNING eliminates race conditions: exactly one of N concurrent consumers succeeds."
sources:
  - .wiki/sources/2026-04-30-auth-architecture.md
links:
  - entities/token.md
last_verified_at: 2026-04-30
---

## Problem

One-time tokens (magic links, password reset, email verification, invitations) must be consumed exactly once. A naive `SELECT` + `UPDATE` approach has a race window: two concurrent requests can both SELECT the token, both UPDATE it, and both succeed (or both see a stale state).

## Solution: DELETE...RETURNING

```sql
DELETE FROM auth.one_time_tokens
WHERE id = $1
RETURNING *
```

This is atomic at the database level. If two concurrent requests execute this query with the same token ID, exactly one DELETE succeeds and returns a row; the other returns empty.

## Semantics

- **First consumer**: DELETE succeeds, gets the row, processes it
- **Second consumer**: DELETE returns no rows, request gets 401 Unauthorized

No status flag, no race window. The operation is idempotent: re-executing the same DELETE always succeeds (or always fails, depending on whether the row exists).

## Why Not a Status Flag

A status-flag approach would be:

```sql
SELECT * FROM one_time_tokens WHERE id = $1 AND consumed_at IS NULL;
UPDATE one_time_tokens SET consumed_at = now() WHERE id = $1;
```

This has a race: between SELECT and UPDATE, another request can consume the token. Both requests see SELECT succeed, then both UPDATE. Without an explicit lock, correctness is lost.

## Changelog

- 2026-04-30: Extracted from auth-architecture raw source
