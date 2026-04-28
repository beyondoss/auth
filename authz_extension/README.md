# authz_extension

PostgreSQL extension (PGRX/Rust) implementing BFS-based permission checks for the beyond-auth authorization engine.

Compiled to a native `.so` and loaded by PostgreSQL. All functions live in the `auth` schema and are called by the application layer in `/src/authz/`.

## Functions

### Single check

```sql
-- single relation
SELECT auth.authz_check(subject_id, relation, object_type, object_id);

-- OR across multiple relations
SELECT auth.authz_check(subject_id, relations::text[], object_type, object_id);
```

Returns `true` if the subject holds any of the relations on the object, after full subject-set (group membership) expansion.

**Algorithm**: direct-grant point-lookup first; BFS through subject-set rows if no direct match.

---

### Batch checks

#### Sequential — `authz_check_batch`

```sql
SELECT auth.authz_check_batch(
    ARRAY['user:1',  'user:2'],   -- subject_ids
    ARRAY['editor', 'viewer'],    -- relations
    ARRAY['doc',    'doc'],       -- object_types
    ARRAY['abc',    'xyz']        -- object_ids
);
-- → boolean[]
```

N checks in one SPI session. Query count: `N × (depth + 1)`. Use for small N or when order matters.

#### Parallel BFS — `authz_check_parallel_batch`

```sql
SELECT auth.authz_check_parallel_batch(
    subject_ids   ::text[],
    relations     ::text[],
    object_types  ::text[],
    object_ids    ::text[]
);
-- → boolean[]
```

All N checks share BFS expansion per depth level. Query count: `depth + 1` regardless of N. This is what `POST /v1/authz/checks` uses.

---

### Hierarchy path batch — `authz_check_path_batch`

```sql
SELECT auth.authz_check_path_batch(
    subject_ids      ::text[],
    relation_prefix  ::text[],   -- hops to walk outward
    object_type_path ::text[],   -- type at each hop
    terminal_relations::text[],  -- relations to check at the final ancestor
    object_ids       ::text[]
);
-- → boolean[]
```

Walks a fixed-depth relation chain (e.g., document → folder → workspace). Query count: `len(relation_prefix) + 1`. No subject-set expansion during hops—only at the terminal check.

---

### Combined direct + hierarchy — `authz_check_multi`

```sql
SELECT auth.authz_check_multi(
    subject_id        text,
    direct_relations  text[],
    relation_prefix   text[],
    object_type_path  text[],
    terminal_relations text[],
    object_id         text
);
-- → boolean
```

Combines a BFS check on the object itself with a hierarchy walk, in one SPI session.

1. Full BFS check against `direct_relations` on the object.
2. If false, walk `relation_prefix` hop-by-hop; check `terminal_relations` directly at each ancestor.

Replaces an `OR`-chain of separate check calls. Use when a permission can be held directly or inherited from a parent.

---

## Query cost summary

| Function | Query count |
|---|---|
| `authz_check` | `depth + 1` (1 on direct-grant hit) |
| `authz_check_batch` | `N × (depth + 1)` |
| `authz_check_parallel_batch` | `depth + 1` |
| `authz_check_path_batch` | `len(relation_prefix) + 1` |
| `authz_check_multi` | `depth + len(relation_prefix) + 2` |

## Data model

All functions read from `auth.authz_relations`:

| Column | Type | Meaning |
|---|---|---|
| `object_type` | text | Resource type (e.g. `"document"`) |
| `object_id` | text | Resource identifier |
| `relation` | text | Relation name (e.g. `"editor"`) |
| `subject_id` | text | User or group identifier |
| `subject_set_type` | text \| NULL | Non-NULL for group membership rows |
| `subject_set_relation` | text \| NULL | Relation within the group type |

Rows with `subject_set_type IS NULL` are direct grants. Rows with `subject_set_type` set expand to the members of that group/set via BFS.

## Build

Requires `pgrx` and a matching PostgreSQL installation.

```sh
cargo pgrx install --pg-config $(which pg_config)
```

Supports PostgreSQL 17 and 18 via feature flags `pg17` / `pg18` (default: `pg17`).

## Integration

The application layer compiles the user-defined authz schema into check plans (`/src/authz/schema.rs`) and calls these functions via `sqlx` in `/src/authz/engine.rs`. The extension has no knowledge of the schema—it receives raw tuples and runs BFS.
