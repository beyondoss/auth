#!/usr/bin/env bash
# Runs the migration-ablation sweep: baseline (current) + 3 single-change reverts.
# Assumes /tmp/migration_{current,no_unlogged,no_hash,no_stmt_trigger}.sql exist.
# Restores migrations/0004_authz.sql to current on exit.
set -euo pipefail

cd "$(dirname "$0")/../.."

BENCH_BIN=target/release/bench
test -x "$BENCH_BIN" || { echo "build the bench first: cargo build --release -p bench"; exit 1; }
test -f /tmp/migration_current.sql        || { echo "missing /tmp/migration_current.sql"; exit 1; }
test -f /tmp/migration_no_unlogged.sql    || { echo "missing /tmp/migration_no_unlogged.sql"; exit 1; }
test -f /tmp/migration_no_hash.sql        || { echo "missing /tmp/migration_no_hash.sql"; exit 1; }
test -f /tmp/migration_no_stmt_trigger.sql || { echo "missing /tmp/migration_no_stmt_trigger.sql"; exit 1; }

cleanup() {
    echo "[ablations] restoring current migration"
    cp /tmp/migration_current.sql migrations/0004_authz.sql
}
trap cleanup EXIT

DURATION="${DURATION:-8}"
WARMUP="${WARMUP:-2}"
CONCURRENCY="${CONCURRENCY:-1,8,32}"

run_one() {
    local label="$1"
    local migration="$2"
    echo "[ablations] === $label ==="
    cp "$migration" migrations/0004_authz.sql
    "$BENCH_BIN" run-all \
        --duration-secs "$DURATION" \
        --warmup-secs "$WARMUP" \
        --concurrency "$CONCURRENCY" \
        --output "bench/out/${label}.md"
}

run_one baseline_current /tmp/migration_current.sql
run_one no_unlogged      /tmp/migration_no_unlogged.sql
run_one no_hash          /tmp/migration_no_hash.sql
run_one no_stmt_trigger  /tmp/migration_no_stmt_trigger.sql

echo "[ablations] all runs complete. Reports in bench/out/{baseline_current,no_unlogged,no_hash,no_stmt_trigger}.{md,json}"
