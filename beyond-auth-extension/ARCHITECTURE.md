# beyond-auth-extension Architecture

A PostgreSQL extension (PGRX/Rust) that takes authorization tuples as input and answers "does subject X hold relation Y on object Z?" by performing breadth-first search through group-membership (subject-set) relationships stored in `auth.authz_relations`. Compiles to a `.so` shared library loaded directly into the PostgreSQL process.

## Data Flow

### Single check

```
Application
  │
  │  SELECT auth.authz_check('user:1', 'editor', 'document', 'doc:abc')
  ▼
PostgreSQL (in-process)
  │
  ├── Direct grant fast path ──────────────────────────────────────────────────┐
  │   SELECT EXISTS (... subject_set_type IS NULL)                             │
  │       hit → true                                                           │
  │       miss → continue                                                      │
  │                                                                            │
  ├── Anchor: fetch subject-set rows on object ─────────────────────────────── │
  │   SELECT subject_id, subject_set_type, subject_set_relation                │
  │   WHERE object_type=$1 AND object_id=$2 AND relation=ANY($3)               │
  │   AND subject_set_type IS NOT NULL                                         │
  │   seeds frontier = [(ot, oi, rel), ...]                                    │
  │                                                                            │
  ├── BFS loop (per level)                                                     │
  │   SELECT DISTINCT r.subject_set_type, r.subject_id, r.subject_set_relation,│
  │          (r.subject_id = $subject AND r.subject_set_type IS NULL) AS match │
  │   JOIN unnest(frontier) ON object_type/object_id/relation                  │
  │       match = true  → true ─────────────────────────────────────────────── │
  │       match = false → add to next frontier (if subject_set_type ≠ NULL)    │
  │       frontier empty → false                                               │
  │                                                                            ▼
  └──────────────────────────────────────────────────────────────── bool result
```

### Hierarchy path batch

```
Application
  │
  │  SELECT auth.authz_check_path_batch(
  │      subject_ids, object_ids,
  │      relation_prefix, object_type_path, terminal_relations)
  ▼
PostgreSQL (in-process)
  │
  ├── Hop 0..P-1 (intermediate hops, one query each)
  │   SELECT idx, r.subject_id AS next_obj_id
  │   FROM unnest(active_obj_ids) AS f(idx, obj_id)
  │   JOIN auth.authz_relations r ON
  │       r.object_type = object_type_path[k]
  │       r.object_id = f.obj_id
  │       r.relation = relation_prefix[k]
  │       r.subject_set_type IS NULL   ← direct rows only, no BFS expansion
  │   Checks with no row → Some(false), removed from active set
  │
  ├── Terminal hop (one query)
  │   SELECT idx
  │   FROM unnest(active_obj_ids) AS f(idx, obj_id, target_sid)
  │   JOIN auth.authz_relations r ON
  │       r.object_type = object_type_path[P]
  │       r.object_id = f.obj_id
  │       r.relation = ANY(terminal_relations)
  │       r.subject_set_type IS NULL
  │       r.subject_id = f.target_sid
  │   Matched checks → Some(true); unmatched → Some(false)
  │
  └── Vec<bool> (N results, ordered)
```

### Combined direct + hierarchy (`authz_check_multi`)

```
Application
  │
  │  SELECT auth.authz_check_multi(
  │      subject_id, direct_relations, relation_prefix,
  │      object_type_path, terminal_relations, object_id)
  ▼
PostgreSQL (in-process)
  │
  ├── BFS check on object_type_path[0] with direct_relations
  │   (same BFS kernel as single check above)
  │       match → true
  │       no match → continue
  │
  ├── Hierarchy walk (one query per hop in relation_prefix)
  │   For each k:
  │       SELECT subject_id (parent object id)
  │       WHERE object_type = object_type_path[k]
  │         AND object_id = current_id
  │         AND relation = relation_prefix[k]
  │         AND subject_set_type IS NULL
  │       no row → false
  │       got row → update current_id, then check terminal:
  │           SELECT EXISTS (... subject_id = subject_id
  │                         AND relation = ANY(terminal_relations))
  │           match → true
  │           no match → continue walking
  │
  └── bool result
```

Error paths (all variants): any `spi::Error` propagates via `pgrx::error!`, raising a PostgreSQL `ERROR` that aborts the transaction and returns an `Err` to the caller via sqlx.

### Parallel batch (recommended for N > 1)

```
Application
  │
  │  SELECT auth.authz_check_parallel_batch(
  │      subject_ids, relations, object_types, object_ids)
  ▼
PostgreSQL (in-process)
  │
  ├── Query 1: Direct grants (all N checks in one UNNEST JOIN)
  │       done_set := checks where match=true → Some(true)
  │       remaining := checks without direct grant
  │
  ├── Query 2: Anchor (all remaining in one UNNEST JOIN)
  │       seeds each check's frontier
  │       checks with empty frontier → Some(false)
  │
  ├── BFS loop (one query per level across ALL active checks)
  │       Build mega-frontier: [(check_idx, ot, oi, rel), ...]
  │       SELECT DISTINCT check_idx, match, subject_set_type, ...
  │       FROM unnest(mega_frontier) JOIN auth.authz_relations
  │           match=true  → check done, Some(true)
  │           not match   → update that check's frontier
  │           no rows     → check done, Some(false)
  │
  └── Vec<bool> (N results, ordered)
```

## Concepts & Terminology

| Term                   | What It Controls                                                                               | NOT                                                  |
| ---------------------- | ---------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| **Direct grant**       | A row where `subject_set_type IS NULL` — subject directly holds the relation                   | A subject-set membership that requires BFS expansion |
| **Subject-set**        | A row where `subject_set_type IS NOT NULL` — the grant is conditional on membership in a group | A direct permission grant                            |
| **Frontier**           | The set of `(object_type, object_id, relation)` nodes to expand in the next BFS level          | A result set or cache                                |
| **Node**               | A `(object_type, object_id, relation)` triple identifying one traversal point                  | A user or permission                                 |
| **Anchor**             | The initial BFS frontier, seeded from subject-set rows on the target object                    | The result of the traversal                          |
| **relation_prefix**    | Hierarchy edges to walk before reaching the terminal node (e.g., document → folder)            | Relations checked at the terminal node               |
| **terminal_relations** | Relations checked at the ancestor node after the hierarchy walk                                | The hop edges themselves                             |

## Core Mechanism

### The BFS kernel (`lib.rs:bfs_with_client`)

All single-check functions call this kernel. It runs inside one `Spi::connect` closure, reusing a single DB connection for all queries in one traversal.

**Steps:**

1. **Direct-grant fast path** (`lib.rs:24–47`): One `EXISTS` query. Returns immediately on hit. Avoids BFS for most checks in practice.

2. **Anchor** (`lib.rs:50–81`): Fetches all subject-set rows on the target object, seeding the BFS frontier. If empty, returns false immediately.

3. **BFS loop** (`lib.rs:84–129`): Per level, executes one SQL query that joins the current frontier against `auth.authz_relations`. Rows with `is_match = true` terminate the search. Non-match subject-set rows expand into the next frontier. A `HashSet<Node>` prevents re-visiting nodes, making the traversal cycle-safe.

**Cycle safety**: Group A → Group B → Group A is safe. Each node is added to `visited` before expansion; the loop skips visited nodes.

### Shared-frontier parallel batch (`lib.rs:authz_check_parallel_batch`)

The key optimization: N checks are expanded together in one SQL query per BFS level instead of N×depth queries.

Each check owns a `CheckState { subject_id, frontier, visited }`. The loop:

1. Collects `(check_idx, ot, oi, rel)` from all active frontiers into a single UNNEST
2. Executes one query expanding all frontier nodes
3. Distributes results back to the correct `CheckState` by `check_idx`
4. Marks completed checks, shrinks the active set

**Cost**: `depth + 1` queries total regardless of N. For 1 000 checks at depth 2, this is 3 queries instead of 3 000.

### Hierarchy path check (`lib.rs:authz_check_path_batch`, `lib.rs:authz_check_multi`)

Walks a fixed-depth object hierarchy (e.g., document → folder → workspace) without BFS expansion on intermediate hops — only direct `subject_set_type IS NULL` rows are followed during the walk. BFS subject-set expansion is applied only at the terminal node.

**Cost**: `len(relation_prefix) + 1` queries regardless of N.

## State Machine

BFS traversal per check:

```
initial
  │
  ├─ direct grant found ───────────────────────────────► true
  │
  ├─ anchor empty ─────────────────────────────────────► false
  │
  └─ anchored
       │
       ├─ match found in BFS level ─────────────────────► true
       ├─ frontier exhausted ───────────────────────────► false
       └─ frontier non-empty ──► expand next level ─────┘ (loop)
```

| From     | Condition                               | To        | What Happens                          |
| -------- | --------------------------------------- | --------- | ------------------------------------- |
| initial  | direct grant row exists                 | **true**  | Return immediately; 1 query total     |
| initial  | no direct grant, no subject-set rows    | **false** | Return immediately; 2 queries total   |
| initial  | no direct grant, subject-set rows found | anchored  | Frontier seeded                       |
| anchored | BFS row has `is_match = true`           | **true**  | Return immediately                    |
| anchored | BFS rows exist, none match              | anchored  | Frontier replaced with next level     |
| anchored | no BFS rows for frontier                | **false** | Subject unreachable through any group |

## Why It Behaves This Way

### Why BFS instead of recursive CTEs

The extension runs inside the PostgreSQL process (SPI), which lets it control iteration explicitly. BFS with a Rust-side `visited` set prevents redundant expansions and handles cycles without `WITH RECURSIVE … CYCLE` syntax, and it allows the parallel-batch pattern where multiple independent traversals share one SQL query per level. A recursive CTE can't batch N independent traversals in one query.

### Why the direct-grant fast path comes first

The direct-grant check is one indexed `EXISTS` query that hits the primary key covering index. In practice, most permission checks are direct grants (no group membership needed). Skipping the anchor and BFS loop for those saves 1–2 additional round-trips to the query executor on the hot path.

### Why the parallel batch uses a single UNNEST JOIN per level

Each BFS level across N checks shares the same table — only the frontier coordinates differ. Joining the entire frontier as a single `unnest($1::text[], $2::text[], $3::text[])` lets the PostgreSQL planner use the `authz_relations_subject_set_idx` index across all frontier nodes in one scan, avoiding N separate index lookups.

### Why hierarchy hops don't expand subject-sets

Hierarchy edges (document's parent folder) are stored as direct rows with `subject_set_type IS NULL`. The parent object pointer is a scalar — there's at most one parent per relation. Expanding subject-sets during the walk would change semantics (a group can't be the parent folder of a document). BFS is applied only at the terminal node where group membership is meaningful.

### Why the extension lives in the database instead of the application layer

Permission checks require joining against `auth.authz_relations`. Running BFS in the application layer would require fetching rows over the network for each level, turning a 3-query O(depth) traversal into N×depth network round-trips. By running inside PostgreSQL via SPI, all intermediate joins happen in shared memory with zero serialization overhead.

## Trust Boundaries

**What the extension verifies:**

- Subject, relation, object_type, object_id match rows in `auth.authz_relations`
- Group membership is transitively reachable via subject-set rows

**What passes through unchecked:**

- Whether the calling application is authorized to ask the question (PostgreSQL ACL on the function governs this)
- Whether `object_type` corresponds to a real partition (queries fall through to the DEFAULT partition silently)
- NULL values in input arrays (converted to `""` — treated as a non-existent subject, always returns false)

## Exported functions

| Function                     | Signature                                             | Cost             | Use                              |
| ---------------------------- | ----------------------------------------------------- | ---------------- | -------------------------------- |
| `authz_check`                | `(text, text, text, text) → bool`                     | depth+1          | Single check, one relation       |
| `authz_check`                | `(text, text[], text, text) → bool`                   | depth+1          | Single check, any-of relations   |
| `authz_check_batch`          | `(text[], text[], text[], text[]) → bool[]`           | N×(depth+1)      | Small batches, order matters     |
| `authz_check_parallel_batch` | `(text[], text[], text[], text[]) → bool[]`           | depth+1          | Large batches (preferred)        |
| `authz_check_path_batch`     | `(text[], text[], text[], text[], text[]) → bool[]`   | path_len+1       | Hierarchy, N checks, shared path |
| `authz_check_multi`          | `(text, text[], text[], text[], text[], text) → bool` | depth+path_len+2 | Direct OR hierarchy, one call    |

## Data Model

```
auth.authz_relations (PARTITION BY LIST (object_type))
┌─────────────────────┬──────┬─────────────────────────────────────────┐
│ Column              │ Type │ Meaning                                 │
├─────────────────────┼──────┼─────────────────────────────────────────┤
│ object_type         │ text │ Partition key ("document", "folder", …) │
│ object_id           │ text │ Specific object instance                │
│ relation            │ text │ Edge label ("editor", "member", …)      │
│ subject_id          │ text │ User ID or group ID                     │
│ subject_set_type    │ text │ NULL = direct grant; else = group type  │
│ subject_set_relation│ text │ Relation within subject_set_type group  │
└─────────────────────┴──────┴─────────────────────────────────────────┘
```

**Row interpretations:**

- `(doc, abc, editor, user:1, NULL, NULL)` → user:1 is an editor of doc:abc (direct)
- `(doc, abc, editor, team:5, user, member)` → any user who is a member of team:5 is an editor of doc:abc (subject-set, requires BFS expansion)

**Indexes:**

- `authz_relations_key` — unique on `(object_type, object_id, relation, subject_set_type, subject_id, subject_set_relation)` — covers direct-grant EXISTS queries
- `authz_relations_subject_lookup_idx` — `(subject_id, object_type, relation)` — supports reverse lookups
- `authz_relations_subject_set_idx` — partial on `(subject_set_type, subject_id, subject_set_relation) WHERE subject_set_type IS NOT NULL` — covers BFS expansion queries

## Configuration

### Build-time

```toml
# Cargo.toml [features]
pg17 = ["pgrx/pg17"] # opt-in — targets PostgreSQL 17
pg18 = ["pgrx/pg18"] # default — targets PostgreSQL 18
```

The feature flag controls which PGRX type system is compiled in. Build with `--features pg17 --no-default-features` to target PostgreSQL 17.

### Runtime

| Setting                | Where Controlled                                                                   | Effect                                                                                                            |
| ---------------------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Extension presence     | `engine.rs:probe_parallel_batch()` at startup                                      | Queries `pg_proc` for `auth.authz_check_parallel_batch`; falls back to pure-SQL path if absent, logs INFO warning |
| Object type partitions | SQL DDL: `ALTER TABLE auth.authz_relations ADD PARTITION …`                        | Missing partition → queries fall to DEFAULT partition, return false silently                                      |
| Result cache size      | `AuthzCache::new(100_000, 50_000, Duration::from_secs(1800))` in application layer | 30-minute TTL; 100k max entries; eviction threshold at 50k                                                        |

## Integration

The host binary (`beyond-auth`) calls into the extension through `authz/engine.rs`, which wraps each PostgreSQL function in a typed sqlx query. The schema compiler (`authz/schema.rs`) decides _which_ function to call per (resource, permission) pair at request time.

```
POST /v1/authz/checks
  │
  ├─ bearer token → subject_id (routes/authz.rs)
  ├─ compiled schema → Vec<AuthzCheckCall>  (authz/schema.rs)
  │     SingleHop  → parallel_batch_check  (authz_check_parallel_batch)
  │     MultiHop   → path_batch_check      (authz_check_path_batch)
  │     Direct+Hierarchy → multi check     (authz_check_multi)
  │     No extension → batch_check_standalone (pure-SQL fallback)
  └─ results cached in AuthzCache, returned as ChecksResponse
```

**Fallback chain:** If `probe_parallel_batch()` returns false at startup, all checks route through `batch_check_standalone()`, which calls the pure-SQL `auth.authz_check` and `auth.authz_check_path` functions (implemented as recursive CTEs in the migration). Behavior is identical; throughput is lower.

**Schema compilation:** Role inheritance is resolved once at startup (transitive closure of `role_inheritance` edges). The resulting role lists are baked into the SQL call sites — no per-request schema traversal.

## Failure Modes

| Failure                               | What Actually Happens                                                                         | Recovery                                          |
| ------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| `spi::Error` on any query             | `pgrx::error!` raises PostgreSQL ERROR; transaction aborts; sqlx returns `Err`                | Application retries the request                   |
| NULL in input array                   | Coerced to `""` (empty string); permission check returns false silently                       | Caller validates inputs before invoking           |
| Circular group membership (A → B → A) | `visited: HashSet<Node>` skips already-seen nodes; BFS terminates normally                    | None needed                                       |
| Object type has no partition          | Row falls to DEFAULT partition; query succeeds, returns false (no rows)                       | None needed                                       |
| Very deep group hierarchy             | One SQL query per level; memory grows with frontier width, not depth                          | Practical limit governed by PostgreSQL `work_mem` |
| Extension not loaded                  | `probe_parallel_batch` in `engine.rs` detects absence; falls back to non-extension authz path | Automatic; logged at INFO                         |
