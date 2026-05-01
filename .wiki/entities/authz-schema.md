---
kind: entity
title: Authorization Schema
summary: JSON document declaring resource types, roles, and permission-to-role mappings; compiled at query time.
sources:
  - .wiki/sources/2026-04-30-auth-architecture.md
  - .wiki/sources/2026-04-30-authz-extension-overview.md
links:
  - concepts/authorization.md
last_verified_at: 2026-04-30
---

## Overview

The authz schema is a JSON document that defines the authorization model. It declares resource types, roles, and which roles grant which permissions.

## Structure

```json
{
  "version": 1,
  "resources": [
    {
      "name": "document",
      "roles": ["owner", "editor", "viewer"],
      "permissions": {
        "edit": ["owner", "editor"],
        "view": ["owner", "editor", "viewer"],
        "delete": ["owner"]
      }
    }
  ]
}
```

## Semantics

- **Resource**: A type that can be accessed (e.g., `document`, `folder`)
- **Role**: A label granted on an object (e.g., `editor`, `owner`)
- **Permission**: Derived from roles; a resource action checked at runtime (e.g., `view`, `edit`)

A user has permission `P` on resource `R` if they hold any role in `permissions[P]`.

## Optional: Role Hierarchy

Some schemas may include role hierarchy (not shown in basic form):

```json
"roleHierarchy": [
  ["owner", "editor"],
  ["editor", "viewer"]
]
```

Indicates that `owner` implies `editor` implies `viewer` (transitive).

## Compilation

The auth service schema compiler (`src/authz/schema.rs`) compiles the schema into SQL plans at startup or on update. It generates `Vec<AuthzCheckCall>`:

- **`SingleHop`**: Direct role check; one `auth.authz_check()` call
- **`MultiHop`**: Hierarchy walk; uses `auth.authz_check_path_batch()` for folder → document inference

## Runtime

Stored in `auth.app_config`, writable via `PUT /v1/authz/schema` (admin only).

## Versioning

Schema version is part of the authz cache key. On schema update, a version counter increments, invalidating all cached checks.

## Changelog

- 2026-04-30: Extracted from auth-architecture and authz-extension-overview raw sources
