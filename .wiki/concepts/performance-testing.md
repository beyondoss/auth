---
kind: concept
title: Performance Testing
summary: Concurrency sweep benchmarking with deterministic reports; identify constraint at saturation.
sources:
  - .wiki/sources/2026-04-30-benchmarking.md
links: []
last_verified_at: 2026-04-30
---

## Overview

The benchmark harness measures ops/sec and latency percentiles across concurrency levels. Use it to identify the bottleneck (Theory of Constraints).

## Running Scenarios

```bash
mise run bench                                     # full sweep, defaults
cargo run --release -p bench -- list               # list scenarios
cargo run --release -p bench -- run single_check   # one scenario
cargo run --release -p bench -- run-all \
    --duration-secs 10 --warmup-secs 2 \
    --concurrency 1,8,32,128 \
    --output bench/out/report.md
```

## Reading Reports

Each scenario section shows:

1. **Question**: What does this measure?
2. **Table**: ops/sec and latency percentiles (p50, p99, max) per concurrency level
3. **Collapsed details**: `pg_stat_database`, `pg_stat_wal` deltas, scenario-specific extras

## Identifying the Constraint

The constraint is the highest concurrency level where ops/sec plateaus while p99 latency keeps climbing.

- If ops/sec is still growing at the max concurrency, you didn't saturate—re-run with higher cap.
- Once you've found the saturation point, that's your bottleneck: the single tightest constraint.

## Adding a Scenario

Implement `Scenario`:

```rust
#[async_trait]
impl Scenario for MyScenario {
    fn name(&self) -> &str {
        "subsystem::my_scenario"
    }
    fn question(&self) -> &str {
        "what does this measure?"
    }
    async fn setup(&self, pool: &PgPool) -> Result<()> { /* idempotent seed */
    }
    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> { /* one unit of work */
    }
}
```

Register in the subsystem's `mod.rs::all()`.

## Why Direct SQL

HTTP overhead is known and well-understood. The harness drives SQL directly to isolate the auth service's own performance. Add HTTP as a sibling scenario set if needed.

## Changelog

- 2026-04-30: Extracted from benchmarking raw source
