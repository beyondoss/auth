# bench

Generic benchmark harness for the auth service. Spins up an isolated Postgres
testcontainer, runs migrations against it, drives concurrent workloads, and
emits a markdown report.

## Run

```sh
mise run bench                                     # full sweep, defaults
cargo run --release -p bench -- list               # list scenarios
cargo run --release -p bench -- run single_check   # one scenario
cargo run --release -p bench -- run-all \
    --duration-secs 10 --warmup-secs 2 \
    --concurrency 1,8,32,128 \
    --output bench/out/report.md
```

`--concurrency` is the sweep — each value is run as a separate level. Reports
are deterministic (no timestamps in body) so they diff cleanly across runs.

## Reading a report

Each scenario answers one question (printed under the heading). The table
shows ops/sec and latency percentiles per concurrency level. The collapsed
section underneath has Postgres-side counter deltas (`pg_stat_database`,
`pg_stat_wal`) plus any scenario-specific extras.

The constraint at saturation is the highest concurrency level where ops/sec
plateaus while p99 keeps climbing. If ops/sec is still growing at the highest
concurrency you ran, you didn't saturate — re-run with a higher cap.

## Adding a scenario

Implement the `Scenario` trait. One file under
`bench/src/scenarios/<subsystem>/<name>.rs`, then register in the subsystem's
`mod.rs::all()`.

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
    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        /* one unit of work; called concurrently in a hot loop */
    }
}
```

The harness handles the testcontainer, migrations, latency capture,
`pg_stat_*` deltas, and report rendering. Don't touch those files.

## Adding a new subsystem

`mkdir bench/src/scenarios/<name>/`, drop in scenario files, expose
`pub fn all() -> Vec<Arc<dyn Scenario>>`, and call it from
`bench/src/scenarios/mod.rs::all()`.

## What this is not

- Not production observability — dev-time only.
- Not over-HTTP — drives SQL directly. The HTTP layer is well-understood
  noise; if you need it, add it as a sibling scenario set.
- Not a regression gate (yet) — the report format is diff-friendly so a
  comparison mode can be added later without retooling.
