---
kind: entity
title: Authorization Relation
summary: Tuple (object_id, object_type, relation, subject_id) in auth.authz_relations, the raw data for BFS traversal.
sources:
  - .wiki/sources/2026-04-30-authz-extension-architecture.md
  - .wiki/sources/2026-04-30-authz-extension-overview.md
links:
  - concepts/authorization.md
last_verified_at: 2026-04-30
---

## Overview

An authz relation is a single edge in the authorization graph. Stored in `auth.authz_relations` (partitioned by `object_type`).

## Tuple Form

```
(object_type, object_id, relation, subject_id, subject_set_type, subject_set_relation)
```

## Interpretations

**Direct grant**:

```
(doc, abc, editor, user:1, NULL, NULL)
```

User 1 is directly an editor of document abc.

**Subject-set (group membership)**:

```
(doc, abc, editor, team:5, user, member)
```

Any user who is a member of team:5 is an editor of document abc. Requires BFS expansion.

## Columns

| Column                 | Type         | Meaning                                          |
| ---------------------- | ------------ | ------------------------------------------------ |
| `object_type`          | text         | Resource type (e.g. `"doc"`, `"folder"`)         |
| `object_id`            | text         | Resource identifier                              |
| `relation`             | text         | Relation name (e.g. `"editor"`, `"member"`)      |
| `subject_id`           | text         | User or group identifier                         |
| `subject_set_type`     | text \| NULL | Non-NULL indicates a group membership row        |
| `subject_set_relation` | text \| NULL | Relation within the group type for BFS expansion |

## Semantics

- `subject_set_type IS NULL` → direct grant
- `subject_set_type IS NOT NULL` → subject-set; expand via BFS

## Indexing

- **Primary key** (`authz_relations_key`): unique on all columns—covers direct-grant EXISTS queries
- **Subject lookup** (`authz_relations_subject_lookup_idx`): `(subject_id, object_type, relation)`—reverse lookups
- **Subject-set** (`authz_relations_subject_set_idx`): partial on `(subject_set_type, subject_id, subject_set_relation) WHERE subject_set_type IS NOT NULL`—BFS expansion queries

## Changelog

- 2026-04-30: Extracted from authz-extension-architecture and authz-extension-overview raw sources
