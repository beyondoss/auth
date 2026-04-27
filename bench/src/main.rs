use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sqlx::PgPool;
use testcontainers::ImageExt;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

use bench::harness::{RunConfig, ScenarioReport, render_compare, render_report, run_scenario};
use bench::scenarios;

#[derive(Parser)]
#[command(name = "bench", about = "generic benchmark harness")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List all registered scenarios.
    List,
    /// Run a single scenario by name (substring match).
    Run {
        scenario: String,
        #[arg(long, default_value = "10")]
        duration_secs: u64,
        #[arg(long, default_value = "2")]
        warmup_secs: u64,
        #[arg(long, value_delimiter = ',', default_value = "1,8,32,128")]
        concurrency: Vec<usize>,
        #[arg(long, default_value = "bench/out/report.md")]
        output: PathBuf,
    },
    /// Run every registered scenario.
    RunAll {
        #[arg(long, default_value = "10")]
        duration_secs: u64,
        #[arg(long, default_value = "2")]
        warmup_secs: u64,
        #[arg(long, value_delimiter = ',', default_value = "1,8,32,128")]
        concurrency: Vec<usize>,
        #[arg(long, default_value = "bench/out/report.md")]
        output: PathBuf,
    },
    /// Diff two JSON reports — e.g. baseline vs a treatment branch.
    Compare {
        baseline: PathBuf,
        treatment: PathBuf,
        #[arg(long, default_value = "bench/out/compare.md")]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::List => {
            for s in scenarios::all() {
                println!("{}", s.name());
            }
            Ok(())
        }
        Cmd::Run {
            scenario,
            duration_secs,
            warmup_secs,
            concurrency,
            output,
        } => {
            let cfg = RunConfig {
                concurrency,
                duration: Duration::from_secs(duration_secs),
                warmup: Duration::from_secs(warmup_secs),
                seed: 0x5EED_5EED_5EED_5EED,
            };
            let scenarios: Vec<_> = scenarios::all()
                .into_iter()
                .filter(|s| s.name().contains(&scenario))
                .collect();
            if scenarios.is_empty() {
                anyhow::bail!("no scenarios match '{scenario}'");
            }
            run_set(&scenarios, &cfg, &output).await
        }
        Cmd::RunAll {
            duration_secs,
            warmup_secs,
            concurrency,
            output,
        } => {
            let cfg = RunConfig {
                concurrency,
                duration: Duration::from_secs(duration_secs),
                warmup: Duration::from_secs(warmup_secs),
                seed: 0x5EED_5EED_5EED_5EED,
            };
            let scenarios = scenarios::all();
            run_set(&scenarios, &cfg, &output).await
        }
        Cmd::Compare {
            baseline,
            treatment,
            output,
        } => {
            let base: Vec<ScenarioReport> = serde_json::from_str(
                &std::fs::read_to_string(&baseline)
                    .with_context(|| format!("reading baseline {}", baseline.display()))?,
            )?;
            let treat: Vec<ScenarioReport> = serde_json::from_str(
                &std::fs::read_to_string(&treatment)
                    .with_context(|| format!("reading treatment {}", treatment.display()))?,
            )?;
            let body = render_compare(&base, &treat);
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(&output, &body)?;
            eprintln!("[bench] compare report: {}", output.display());
            println!("{body}");
            Ok(())
        }
    }
}

async fn run_set(
    scenarios: &[std::sync::Arc<dyn bench::harness::Scenario>],
    cfg: &RunConfig,
    output: &std::path::Path,
) -> Result<()> {
    eprintln!("[bench] starting postgres testcontainer (postgres:18-alpine)");
    let container = Postgres::default()
        .with_tag("18-alpine")
        .start()
        .await
        .context("failed to start postgres container")?;
    let port = container.get_host_port_ipv4(5432).await?;
    let url = format!(
        "postgres://postgres:postgres@127.0.0.1:{port}/postgres?options=-csearch_path%3Dauth%2Cpublic"
    );

    let pool = PgPool::connect(&url)
        .await
        .context("failed to connect to postgres")?;

    eprintln!("[bench] running migrations");
    sqlx::migrate!("../migrations")
        .run(&pool)
        .await
        .context("failed to run migrations")?;

    let mut reports: Vec<ScenarioReport> = Vec::new();
    for scenario in scenarios {
        let r = run_scenario(scenario.clone(), &pool, cfg).await?;
        reports.push(r);
    }

    pool.close().await;

    let host = host_info();
    let body = render_report(&reports, &host);

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(output, &body).context("failed to write report")?;

    // Sidecar JSON next to the markdown — same stem, .json extension. Used by
    // `bench compare` to diff baseline vs treatment runs.
    let json_path = output.with_extension("json");
    let json = serde_json::to_string_pretty(&reports)?;
    std::fs::write(&json_path, json).context("failed to write JSON report")?;

    eprintln!(
        "[bench] reports written: {} (markdown), {} (json)",
        output.display(),
        json_path.display()
    );
    println!("{body}");
    Ok(())
}

fn host_info() -> String {
    let mut s = String::new();
    s.push_str(&format!("os: {}\n", std::env::consts::OS));
    s.push_str(&format!("arch: {}\n", std::env::consts::ARCH));
    if let Ok(cpu) = std::process::Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
    {
        if cpu.status.success() {
            s.push_str(&format!(
                "cpu: {}",
                String::from_utf8_lossy(&cpu.stdout).trim_end()
            ));
            s.push('\n');
        }
    }
    if let Ok(mem) = std::process::Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
    {
        if mem.status.success() {
            if let Ok(bytes) = String::from_utf8_lossy(&mem.stdout).trim().parse::<u64>() {
                s.push_str(&format!("memory: {} GiB\n", bytes / 1024 / 1024 / 1024));
            }
        }
    }
    s
}
