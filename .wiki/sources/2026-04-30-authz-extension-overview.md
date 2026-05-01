---
kind: source
title: Authorization Extension Overview
summary: PostgreSQL extension (PGRX) for Zanzibar-style permission checks with parallel batch optimization.
source_uri: .wiki/sources/inbox/2026-04-30-authz-extension-readme.raw.md
source_hash: (from raw archive)
ingested_at: 2026-04-30
---

## Synthesis

The `authz_extension` Rust + PGRX extension runs inside PostgreSQL and evaluates transitive permissions via BFS. It reduces N permission checks and depth-D group hierarchies from O(N×D) round-trips to O(D+1) queries.

## Key Takeaways

- **Installation**: `cargo pgrx install` (default pg17) or `--features pg18` for PostgreSQL 18.
- **Functions**: Single check, parallel batch, sequential batch, hierarchy path, combined direct+hierarchy.
- **`authz_check(subject, relations, object_type, object_id)`**: One relation or array of relations. Returns bool.
- **`authz_check_parallel_batch(subjects[], relations[], object_types[], object_ids[])`**: N checks, depth+1 queries. Preferred for batches.
- **`authz_check_batch(subjects[], relations[], object_types[], object_ids[])`**: N checks, N×(depth+1) queries. Use for N≤4 where order matters.
- **`authz_check_path_batch(subjects[], relation_prefix[], object_type_path[], terminal_relations[], object_ids[])`**: Hierarchy walk (document → folder) + direct grants at ancestor; len(relation_prefix)+1 queries.
- **`authz_check_multi(subject, direct_relations[], relation_prefix[], object_type_path[], terminal_relations[], object_id)`**: BFS on object itself, then hierarchy walk if false; one SPI session.
- **Query cost table**: Shows exact query count per function.
- **Data model**: `auth.authz_relations` with subject-set distinction (NULL = direct, else = group).
- **Integration**: `src/authz/schema.rs` compiles schemas to SQL plans. `src/authz/engine.rs` detects extension and routes batch checks appropriately.
- **Fallback**: If extension unavailable, logs warning and uses non-extension authz path.

## Related Pages

- [Authorization](../concepts/authorization.md)
- [Authorization Extension Architecture](../sources/2026-04-30-authz-extension-architecture.md)
