---
kind: entity
title: TypeScript SDK Client
summary: Typed HTTP clients wrapping openapi-fetch with auth service endpoints.
sources:
  - .wiki/sources/2026-04-30-typescript-sdk-architecture.md
links:
  - entities/session.md
  - entities/signing-key.md
last_verified_at: 2026-04-30
---

## Overview

Two main client factories:

- **`createAdminClient`**: Raw typed fetch client (via `openapi-fetch`) with no default headers; callers supply `Authorization` per-request.
- **`createAuthClient`**: Wraps `openapi-fetch` and auto-adds `Authorization: Bearer <token>` to all requests. Exposes namespaced ergonomic methods.

## Typed Client

All paths, methods, request bodies, query parameters, and response shapes are inferred from `types.ts` (auto-generated from the OpenAPI spec). Compile-time type safety for every call.

## Namespaced Methods

`createAuthClient` exposes:

- `client.identities.*`
- `client.orgs.*`
- `client.orgs.members.*`
- `client.orgs.invitations.*`
- `client.invitations.*`

Plus all raw `openapi-fetch` methods for unmapped endpoints.

## Generic Type Parameter

```typescript
createAuthClient<{ OrgRole: "admin" | "member" }>();
```

The `OrgRole` generic constrains the `role` field on invitation bodies at compile time. It's a phantom type — nothing happens at runtime, only type checking.

## Configuration

| Option              | Effect                                                                               |
| ------------------- | ------------------------------------------------------------------------------------ |
| `baseUrl`           | Base URL of the auth service                                                         |
| `token`             | Prepended as `Authorization: Bearer <token>` on every request                        |
| `Config["OrgRole"]` | Generic type parameter — constrains `role` on invitation bodies at compile time only |

## Changelog

- 2026-04-30: Extracted from typescript-sdk-architecture raw source
