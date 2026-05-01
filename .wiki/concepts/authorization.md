---
kind: concept
title: Authorization
summary: "Zanzibar-style relation engine: subject X holds relation Y on object Z via direct grants or transitive group membership."
sources:
  - .wiki/sources/2026-04-30-auth-architecture.md
  - .wiki/sources/2026-04-30-authz-extension-architecture.md
  - .wiki/sources/2026-04-30-authz-extension-overview.md
links:
  - entities/signing-key.md
last_verified_at: 2026-04-30
---

## Overview

Authorization (authz) is **opt-in**. Define a schema, write relation tuples, and check permissions. No schema = no authz cost.

It answers: "Does subject X hold relation Y on object Z?"

Implemented via a PostgreSQL extension that runs BFS over relation tuples stored in `auth.authz_relations`.

## Schema

JSON schema declares resource types, roles, and permission→role mappings:

```json
{
  "version": 1,
  "resources": [
    {
      "name": "document",
      "roles": ["owner", "viewer"],
      "permissions": {
        "edit": ["owner"],
        "view": ["owner", "viewer"]
      }
    }
  ]
}
```

## Two Permission Types

- **Direct grant**: `(object, relation, subject)` with `subject_set_type IS NULL`
- **Subject-set**: `(object, relation, group_id, group_type, group_relation)` — subject inherits relation if they hold `group_relation` on the group

## Relations vs Permissions

- **Relation**: An edge in the graph; `objectType:objectId#relation@subjectId`
- **Permission**: Derived from roles via schema; computed at check time

## Checks

### Single Check

```
GET /v1/authz/decisions?resource_type=document&resource_id=123&permission=edit
GET /v1/authz/decisions?resource_type=document&resource_id=123&permission=edit&user=456
```

### Batch Check

```
POST /v1/authz/checks
{
  "checks": [
    { "resource_type": "document", "resource_id": "123", "permission": "edit" },
    { "resource_type": "document", "resource_id": "123", "permission": "view", "user": "789" }
  ]
}
```

Uses parallel batch function (depth+1 queries for N checks).

## Caching

LRU cache (100k entries, 30 min TTL, version-tagged). Writes to `auth.authz_relations` increment a version counter; stale cache entries miss on the version tag and re-query.

## Extension Integration

The auth service calls the PostgreSQL extension via sqlx:

- Single check: `auth.authz_check(subject, relations[], object_type, object_id)`
- Batch: `auth.authz_check_parallel_batch(subjects[], relations[], object_types[], object_ids[])`
- Hierarchy: `auth.authz_check_path_batch(...)`

If the extension is unavailable at startup, the application logs a warning and falls back to non-extension authz (slower).

## Changelog

- 2026-04-30: Extracted from auth-architecture, authz-extension-architecture, and authz-extension-overview raw sources
