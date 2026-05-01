---
kind: source
title: Benchmarking
summary: Generic benchmark harness with testcontainer Postgres, concurrent workload driving, and markdown report output.
source_uri: .wiki/sources/inbox/2026-04-30-bench-readme.raw.md
source_hash: (from raw archive)
ingested_at: 2026-04-30
---

## Synthesis

A dev-time benchmarking framework that spins up an isolated Postgres testcontainer, runs scenarios against the auth service, measures latency and throughput at multiple concurrency levels, and emits a deterministic markdown report. Reports diff cleanly (no timestamps) for easy comparisons.

## Key Takeaways

- **Harness**: Testcontainer Postgres, migrations, concurrent worker loop, latency capture, `pg_stat_*` deltas.
- **Scenarios**: Implement `Scenario` trait; one file per scenario under `bench/src/scenarios/<subsystem>/<name>.rs`.
- **Scenario interface**: `name()`, `question()`, `setup()` (idempotent seed), `run()` (one unit of work, called concurrently).
- **Concurrency sweep**: Each concurrency value runs as a separate level. Reports show ops/sec and latency percentiles (p50, p99, max).
- **Constraint identification**: Saturation point is where ops/sec plateaus while p99 climbs—indicates the bottleneck.
- **Reports**: Markdown format, deterministic (no timestamps), includes scenario question, throughput/latency table, and collapsed `pg_stat_*` deltas.
- **Direct SQL**: Drives the auth service SQL directly—HTTP layer is known noise; can be added as a separate scenario set.
- **Not production**: Dev-time only. Not a regression gate yet, but format supports diffs for future comparison mode.
- **Subsystems**: Group scenarios by subsystem (`sessions/`, `tokens/`, `authz/`, etc.); each gets `pub fn all() -> Vec<Arc<dyn Scenario>>`.

## Related Pages

- [Performance Testing](../concepts/performance-testing.md)
