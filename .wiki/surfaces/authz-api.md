---
kind: surface
title: Authorization API
summary: Zanzibar permission checks, relation management, schema configuration, and audit tracing.
sources:
  - .wiki/sources/2026-04-30-auth-service-overview.md
  - .wiki/sources/2026-04-30-auth-architecture.md
  - .wiki/sources/2026-04-30-authz-extension-overview.md
links:
  - entities/authz-relation.md
  - entities/authz-schema.md
  - concepts/authorization.md
last_verified_at: 2026-04-30
---

## Endpoints

### Single Permission Check

```
GET /v1/authz/decisions
?resource_type=document&resource_id=123&permission=edit[&user=456]
Authorization: Bearer <session_token>
```

Checks if the authenticated user (or `user` param) has the permission.

Response:

- **200 OK**: `{ allowed: true }` or `{ allowed: false }`
- **401 Unauthorized**: Invalid token
- **422 Unprocessable Entity**: Unknown resource type or permission

### Batch Permission Checks

```
POST /v1/authz/checks
Authorization: Bearer <session_token>

{
  "checks": [
    { "resource_type": "document", "resource_id": "123", "permission": "edit" },
    { "resource_type": "document", "resource_id": "456", "permission": "view", "user": "789" }
  ]
}
```

Response:

- **200 OK**: `{ results: [{ allowed: true }, { allowed: false }] }`

Uses parallel batch extension function: `depth + 1` queries for N checks.

### Write Relation

```
POST /v1/authz/relations
{
  "object_type": "document",
  "object_id": "123",
  "relation": "editor",
  "subject_id": "user:456"
}
```

Creates a direct grant or subject-set tuple.

Response:

- **201 Created**: Relation written
- **409 Conflict**: Relation already exists

### Delete Relation

```
DELETE /v1/authz/relations/{id}
```

Removes a relation tuple.

Response:

- **204 No Content**: Deleted
- **404 Not Found**: Relation doesn't exist

### Batch Write / Delete Relations

```
PATCH /v1/authz/relations
{
  "writes": [ { ... }, ... ],
  "deletes": [ { ... }, ... ]
}
```

Atomically writes and deletes in one transaction.

### Get Schema

```
GET /v1/authz/schema
Authorization: Bearer <session_token>
```

Response:

- **200 OK**: `{ version, resources: [...] }`
- **404 Not Found**: No schema defined

### Put Schema

```
PUT /v1/authz/schema
Authorization: Bearer <admin_secret>
{
  "version": 1,
  "resources": [ ... ]
}
```

Updates the authorization schema. All cached checks are invalidated.

Response:

- **200 OK**: Schema updated
- **400 Bad Request**: Invalid schema syntax

### Expand (Who has access)

```
GET /v1/authz/subjects
?object_type=document&object_id=123&relation=editor
Authorization: Bearer <admin_secret>
```

Lists all subjects that hold the relation (direct + transitive group membership).

Response:

- **200 OK**: `{ subjects: ["user:1", "user:2", "group:5"] }`

### Lookup (What can user access)

```
GET /v1/authz/objects
?subject_id=user:1&resource_type=document&permission=read
Authorization: Bearer <session_token>
```

Lists all objects the subject can access with the permission.

Response:

- **200 OK**: `{ objects: ["doc:123", "doc:456"], limit: 50, has_more: false }`

### Trace (Audit)

```
GET /v1/authz/traces
?subject_id=user:1&object_type=document&object_id=123&permission=edit
Authorization: Bearer <admin_secret>
```

Returns the decision path: why was access allowed or denied?

Response:

- **200 OK**: `{ allowed: true, steps: [...] }`

## Changelog

- 2026-04-30: Extracted from auth-service-overview, auth-architecture, and authz-extension-overview raw sources
