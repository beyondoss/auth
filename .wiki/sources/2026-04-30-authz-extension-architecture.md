---
kind: source
title: Authorization Extension Architecture
summary: PostgreSQL extension (PGRX/Rust) running BFS over relation tuples; parallel batch reduces N checks to depth+1 queries.
source_uri: .wiki/sources/inbox/2026-04-30-authz-extension-architecture.raw.md
source_hash: (from raw archive)
ingested_at: 2026-04-30
---

## Synthesis

The `authz_extension` is a native PostgreSQL extension that performs breadth-first search on authorization relation tuples. It lives in the database process, eliminating round-trips that a service-side BFS would require. Parallel batching merges N independent checks into one query per depth level.

## Key Takeaways

- **BFS kernel**: `lib.rs:bfs_with_client` runs all traversals inside one `Spi::connect` closure.
- **Direct-grant fast path**: One indexed `EXISTS` query returns immediately on hit; avoids anchor + BFS loop.
- **Anchor**: Fetches subject-set rows on target object, seeds BFS frontier.
- **BFS loop**: Per level, one query expanding the frontier; stops on match or exhaustion.
- **Parallel batch**: Single query per level shared across all N checks; cost = `depth+1` regardless of N (vs `N×depth` for serial).
- **Hierarchy path check**: Walks fixed-depth object chain (document → folder) without BFS expansion on intermediate hops; expansion only at terminal node.
- **Cycle safety**: `HashSet<Node>` visited set prevents re-visiting; handles circular group membership.
- **Functions**: `authz_check` (single), `authz_check_batch` (serial), `authz_check_parallel_batch` (parallel, preferred), `authz_check_path_batch` (hierarchy), `authz_check_multi` (direct OR hierarchy).
- **Data model**: `auth.authz_relations` partitioned by `object_type`. Row interpretation: `subject_set_type IS NULL` = direct grant; else = group membership requiring BFS.
- **Indexes**: Primary key covers direct-grant queries; partial `subject_set_idx` for BFS expansion.
- **Fallback**: If extension unavailable, application detects and logs warning; falls back to non-extension path.

## Related Pages

- [Authorization](../concepts/authorization.md)
