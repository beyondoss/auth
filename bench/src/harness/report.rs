use std::collections::HashMap;
use std::fmt::Write;

use super::runner::{LevelReport, ScenarioReport};

pub fn render_report(reports: &[ScenarioReport], host_info: &str) -> String {
    let mut out = String::new();
    writeln!(out, "# bench report").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "## Host").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "```").unwrap();
    writeln!(out, "{}", host_info.trim_end()).unwrap();
    writeln!(out, "```").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "## Scenarios").unwrap();
    writeln!(out).unwrap();
    for r in reports {
        writeln!(out, "- [`{}`](#{})", r.name, anchor(&r.name)).unwrap();
    }
    writeln!(out).unwrap();
    for r in reports {
        render_scenario(&mut out, r);
    }
    out
}

fn render_scenario(out: &mut String, r: &ScenarioReport) {
    writeln!(out, "## `{}`", r.name).unwrap();
    if !r.question.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "_{}_", r.question).unwrap();
    }
    writeln!(out).unwrap();
    writeln!(
        out,
        "| concurrency | ops | ops/sec | errors | p50 µs | p95 µs | p99 µs | p99.9 µs | max µs |"
    )
    .unwrap();
    writeln!(out, "|---:|---:|---:|---:|---:|---:|---:|---:|---:|").unwrap();
    for lv in &r.levels {
        writeln!(
            out,
            "| {} | {} | {:.0} | {} | {} | {} | {} | {} | {} |",
            lv.concurrency,
            lv.ops,
            lv.ops_per_sec,
            lv.errors,
            lv.latency.p50_us,
            lv.latency.p95_us,
            lv.latency.p99_us,
            lv.latency.p999_us,
            lv.latency.max_us,
        )
        .unwrap();
    }

    writeln!(out).unwrap();
    writeln!(
        out,
        "<details><summary>Server-side metrics (deltas)</summary>"
    )
    .unwrap();
    writeln!(out).unwrap();
    for lv in &r.levels {
        writeln!(out, "**concurrency = {}**", lv.concurrency).unwrap();
        writeln!(out).unwrap();
        writeln!(out, "| metric | value | unit |").unwrap();
        writeln!(out, "|---|---:|---|").unwrap();
        for m in &lv.server_metrics {
            let formatted = if m.value.is_nan() {
                "NaN".to_string()
            } else if m.value.fract() == 0.0 {
                format!("{:.0}", m.value)
            } else {
                format!("{:.4}", m.value)
            };
            writeln!(out, "| {} | {} | {} |", m.name, formatted, m.unit).unwrap();
        }
        for m in &lv.extra_metrics {
            let formatted = if m.value.is_nan() {
                "NaN".to_string()
            } else if m.value.fract() == 0.0 {
                format!("{:.0}", m.value)
            } else {
                format!("{:.4}", m.value)
            };
            writeln!(out, "| {} | {} | {} |", m.name, formatted, m.unit).unwrap();
        }
        writeln!(out).unwrap();
    }
    writeln!(out, "</details>").unwrap();
    writeln!(out).unwrap();
}

fn anchor(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// Compare two report sets — typically a baseline (e.g. `main`) and a
/// treatment (a branch with one optimization applied). Emits a markdown
/// document with per-scenario delta tables. Positive numbers in throughput
/// columns mean the treatment improved; positive numbers in latency columns
/// mean the treatment got *slower* (regression).
pub fn render_compare(baseline: &[ScenarioReport], treatment: &[ScenarioReport]) -> String {
    let base_by_name: HashMap<&str, &ScenarioReport> =
        baseline.iter().map(|r| (r.name.as_str(), r)).collect();
    let treat_by_name: HashMap<&str, &ScenarioReport> =
        treatment.iter().map(|r| (r.name.as_str(), r)).collect();

    let mut out = String::new();
    writeln!(out, "# bench compare").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "_Throughput delta: + means treatment improved. Latency delta: + means treatment got SLOWER (regression)._"
    )
    .unwrap();
    writeln!(out).unwrap();

    let mut names: Vec<&str> = base_by_name
        .keys()
        .chain(treat_by_name.keys())
        .copied()
        .collect();
    names.sort();
    names.dedup();

    for name in names {
        let base = base_by_name.get(name);
        let treat = treat_by_name.get(name);
        writeln!(out, "## `{name}`").unwrap();
        writeln!(out).unwrap();
        match (base, treat) {
            (Some(b), Some(t)) => render_scenario_diff(&mut out, b, t),
            (Some(_), None) => {
                writeln!(
                    out,
                    "_present in baseline only — scenario removed in treatment_"
                )
                .unwrap();
                writeln!(out).unwrap();
            }
            (None, Some(_)) => {
                writeln!(out, "_present in treatment only — new scenario_").unwrap();
                writeln!(out).unwrap();
            }
            (None, None) => unreachable!(),
        }
    }
    out
}

fn render_scenario_diff(out: &mut String, base: &ScenarioReport, treat: &ScenarioReport) {
    writeln!(
        out,
        "| concurrency | base ops/s | treat ops/s | Δ ops/s | base p99 µs | treat p99 µs | Δ p99 µs |"
    )
    .unwrap();
    writeln!(out, "|---:|---:|---:|---:|---:|---:|---:|").unwrap();

    let by_conc_base: HashMap<usize, &LevelReport> =
        base.levels.iter().map(|l| (l.concurrency, l)).collect();
    let by_conc_treat: HashMap<usize, &LevelReport> =
        treat.levels.iter().map(|l| (l.concurrency, l)).collect();
    let mut concs: Vec<usize> = by_conc_base
        .keys()
        .chain(by_conc_treat.keys())
        .copied()
        .collect();
    concs.sort();
    concs.dedup();

    for c in concs {
        let bl = by_conc_base.get(&c);
        let tl = by_conc_treat.get(&c);
        match (bl, tl) {
            (Some(b), Some(t)) => {
                let dops = pct(b.ops_per_sec, t.ops_per_sec);
                let dp99 = pct_lat(b.latency.p99_us as f64, t.latency.p99_us as f64);
                writeln!(
                    out,
                    "| {} | {:.0} | {:.0} | {:+.1}% | {} | {} | {:+.1}% |",
                    c, b.ops_per_sec, t.ops_per_sec, dops, b.latency.p99_us, t.latency.p99_us, dp99,
                )
                .unwrap();
            }
            (Some(b), None) => writeln!(
                out,
                "| {} | {:.0} | — | — | {} | — | — |",
                c, b.ops_per_sec, b.latency.p99_us
            )
            .unwrap(),
            (None, Some(t)) => writeln!(
                out,
                "| {} | — | {:.0} | — | — | {} | — |",
                c, t.ops_per_sec, t.latency.p99_us
            )
            .unwrap(),
            (None, None) => unreachable!(),
        }
    }
    writeln!(out).unwrap();
}

fn pct(base: f64, treat: f64) -> f64 {
    if base == 0.0 {
        0.0
    } else {
        (treat - base) / base * 100.0
    }
}

fn pct_lat(base: f64, treat: f64) -> f64 {
    if base == 0.0 {
        0.0
    } else {
        (treat - base) / base * 100.0
    }
}
