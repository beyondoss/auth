# beyond-auth-extension

Evaluate transitive permissions inside PostgreSQL. Replaces N×depth round-trips with `depth+1` queries via BFS over the `auth.authz_relations` graph.

Compiled to a native `.so` via PGRX and loaded by PostgreSQL. All functions live in the `auth` schema. The application layer calls them through `sqlx` — the extension receives raw tuples and runs BFS without knowing your schema.

## Install

Requires `pgrx` and a matching PostgreSQL installation. Supports PostgreSQL 17 and 18.

```sh
# default: pg17
cargo pgrx install --pg-config $(which pg_config)

# pg18
cargo pgrx install --features pg18 --no-default-features --pg-config $(which pg_config)
```

If the extension is not loaded, the application falls back to serial checks and logs a warning. Install it.

## Functions

### Single check — `authz_check`

```sql
-- one relation
SELECT auth.authz_check('user:1', 'editor', 'doc', 'abc');

-- any of several relations
SELECT auth.authz_check('user:1', ARRAY['editor', 'owner'], 'doc', 'abc');
```

Returns `true` if the subject holds any of the given relations on the object, including via group membership. Tries a direct-grant point-lookup first; falls back to BFS if no direct match.

---

### Parallel BFS batch — `authz_check_parallel_batch`

```sql
SELECT auth.authz_check_parallel_batch(
    ARRAY['user:1', 'user:2'],    -- subject_ids
    ARRAY['editor', 'viewer'],    -- relations (one per check)
    ARRAY['doc',    'doc'],       -- object_types
    ARRAY['abc',    'xyz']        -- object_ids
);
-- → boolean[]
```

All N checks share BFS expansion per depth level. Query count: `depth + 1` regardless of N. This is what `POST /v1/authz/checks` uses.

---

### Sequential batch — `authz_check_batch`

```sql
SELECT auth.authz_check_batch(
    subject_ids   ::text[],
    relations     ::text[],
    object_types  ::text[],
    object_ids    ::text[]
);
-- → boolean[]
```

N independent BFS checks in one SPI session. Query count: `N × (depth + 1)`. Use for small N (≤4) where check order matters.

---

### Hierarchy path batch — `authz_check_path_batch`

```sql
SELECT auth.authz_check_path_batch(
    subject_ids       ::text[],
    relation_prefix   ::text[],    -- hops to walk outward (e.g. ['parent'])
    object_type_path  ::text[],    -- type at each hop (e.g. ['folder'])
    terminal_relations::text[],    -- relations to check at the ancestor
    object_ids        ::text[]
);
-- → boolean[]
```

Walks a fixed-depth relation chain (e.g., document → folder → workspace). Query count: `len(relation_prefix) + 1`. Uses direct-grant matches only at every hop — no BFS expansion.

---

### Combined direct + hierarchy — `authz_check_multi`

```sql
SELECT auth.authz_check_multi(
    'user:1',                        -- subject_id
    ARRAY['editor', 'owner'],        -- direct_relations
    ARRAY['parent'],                 -- relation_prefix
    ARRAY['folder'],                 -- object_type_path
    ARRAY['folder_editor'],          -- terminal_relations
    'doc:abc'                        -- object_id
);
-- → boolean
```

BFS check on the object itself, then a hierarchy walk if false — one SPI session. Use when a permission can be held directly or inherited from a parent resource.

---

## Query cost

| Function                     | Query count                         |
| ---------------------------- | ----------------------------------- |
| `authz_check`                | `depth + 1` (1 on direct-grant hit) |
| `authz_check_batch`          | `N × (depth + 1)`                   |
| `authz_check_parallel_batch` | `depth + 1`                         |
| `authz_check_path_batch`     | `len(relation_prefix) + 1`          |
| `authz_check_multi`          | `depth + len(relation_prefix) + 2`  |

## Data model

All functions read from `auth.authz_relations` (partitioned by `object_type`):

| Column                 | Type         | Meaning                                          |
| ---------------------- | ------------ | ------------------------------------------------ |
| `object_type`          | text         | Resource type (e.g. `"doc"`)                     |
| `object_id`            | text         | Resource identifier                              |
| `relation`             | text         | Relation name (e.g. `"editor"`)                  |
| `subject_id`           | text         | User or group identifier                         |
| `subject_set_type`     | text \| NULL | Non-NULL indicates a group membership row        |
| `subject_set_relation` | text \| NULL | Relation within the group type for BFS expansion |

`subject_set_type IS NULL` → direct grant. `subject_set_type` set → expand to members of that group via BFS.

**Example:**

```
(doc, abc, editor, user:1,  NULL,   NULL)   → user:1 is directly an editor of doc:abc
(doc, abc, editor, team:5,  member, NULL)   → any member of team:5 is an editor of doc:abc
```

The second row causes BFS: the engine checks if `subject_id` appears as a `member` of `team:5`.

## Integration

The authz schema compiler (`/src/authz/schema.rs`) compiles user-defined permission models into SQL plans and selects the right function per check type. The engine (`/src/authz/engine.rs`) calls `probe_parallel_batch` on startup to detect whether the extension is loaded, then routes batch checks to `authz_check_parallel_batch`. Hierarchy checks go to `authz_check_path_batch`. Mixed checks use `authz_check_multi`.
