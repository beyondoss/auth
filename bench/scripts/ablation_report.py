#!/usr/bin/env python3
"""Render an ablation report comparing N treatment runs against a baseline.

Usage:
    ablation_report.py BASELINE.json [--treatment NAME=TREATMENT.json] ...

Produces markdown on stdout with one row per scenario × concurrency level,
columns: baseline ops/sec + p99, then per-treatment deltas (ops/sec %, p99 %).

Positive ops% = treatment improved.  Positive p99% = treatment got SLOWER.
"""

import argparse
import json
import sys


def load(path):
    with open(path) as f:
        data = json.load(f)
    by_name = {r["name"]: r for r in data}
    return by_name


def pct(base, treat):
    if base == 0:
        return 0.0
    return (treat - base) / base * 100.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("baseline", help="baseline JSON path")
    ap.add_argument(
        "--treatment",
        action="append",
        default=[],
        help="NAME=path (repeatable)",
    )
    ap.add_argument("--baseline-name", default="baseline")
    args = ap.parse_args()

    base = load(args.baseline)
    treatments = []
    for spec in args.treatment:
        if "=" not in spec:
            sys.exit(f"--treatment must be NAME=path, got {spec!r}")
        name, path = spec.split("=", 1)
        treatments.append((name, load(path)))

    out = []
    out.append("# ablation report")
    out.append("")
    out.append(f"_Baseline: `{args.baseline_name}` ({args.baseline})_")
    for name, _ in treatments:
        for spec in args.treatment:
            if spec.startswith(name + "="):
                _, path = spec.split("=", 1)
                out.append(f"_Treatment `{name}`: {path}_")
                break
    out.append("")
    out.append(
        "_ops% column: positive means treatment is FASTER than baseline. "
        "p99% column: positive means treatment is SLOWER (regression)._"
    )
    out.append("")

    scenario_names = sorted(base.keys())

    # One mega-table per scenario.
    for sname in scenario_names:
        bs = base[sname]
        out.append(f"## `{sname}`")
        if bs.get("question"):
            out.append("")
            out.append(f"_{bs['question']}_")
        out.append("")
        # Header
        header_cells = ["concurrency", "base ops/s", "base p99 µs"]
        sep_cells = ["---:", "---:", "---:"]
        for tname, _ in treatments:
            header_cells.extend([f"{tname} ops%", f"{tname} p99%"])
            sep_cells.extend(["---:", "---:"])
        out.append("| " + " | ".join(header_cells) + " |")
        out.append("|" + "|".join(sep_cells) + "|")

        by_conc_b = {l["concurrency"]: l for l in bs["levels"]}
        concs = sorted(by_conc_b.keys())
        for c in concs:
            bl = by_conc_b[c]
            row = [
                str(c),
                f"{bl['ops_per_sec']:.0f}",
                f"{bl['latency']['p99_us']}",
            ]
            for tname, treport in treatments:
                tr = treport.get(sname)
                if tr is None:
                    row.extend(["—", "—"])
                    continue
                tl = next(
                    (l for l in tr["levels"] if l["concurrency"] == c), None
                )
                if tl is None:
                    row.extend(["—", "—"])
                    continue
                d_ops = pct(bl["ops_per_sec"], tl["ops_per_sec"])
                d_p99 = pct(bl["latency"]["p99_us"], tl["latency"]["p99_us"])
                row.append(f"{d_ops:+.1f}%")
                row.append(f"{d_p99:+.1f}%")
            out.append("| " + " | ".join(row) + " |")
        out.append("")

    print("\n".join(out))


if __name__ == "__main__":
    main()
