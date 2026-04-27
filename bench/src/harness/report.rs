use std::fmt::Write;

use super::runner::ScenarioReport;

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
    writeln!(
        out,
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    )
    .unwrap();
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
    writeln!(out, "<details><summary>Server-side metrics (deltas)</summary>").unwrap();
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
