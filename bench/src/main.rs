use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use sqlx::PgPool;
use testcontainers::CopyTargetOptions;
use testcontainers::ImageExt;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

use bench::harness::{RunConfig, ScenarioReport, render_compare, render_report, run_scenario};
use bench::scenarios;
use bench::scenarios::authz::corpus::{FlatCorpus, seed_all};
use bench::scenarios::authz::{CHAIN_DEPTHS, MIXED_NOISE_DEPTHS};

#[derive(Parser)]
#[command(name = "bench", about = "generic benchmark harness")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Profile {
    /// Tight defaults for fast feedback: concurrency [1,8], 5s/1s.
    Quick,
    /// Full sweep: concurrency [1,8,32,128], 30s/5s.
    Full,
}

impl Profile {
    fn concurrency(self) -> Vec<usize> {
        match self {
            Profile::Quick => vec![1, 8],
            Profile::Full => vec![1, 8, 32, 128],
        }
    }
    fn duration_secs(self) -> u64 {
        match self {
            Profile::Quick => 5,
            Profile::Full => 30,
        }
    }
    fn warmup_secs(self) -> u64 {
        match self {
            Profile::Quick => 1,
            Profile::Full => 5,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// List all registered scenarios.
    List,
    /// Run a single scenario by name (substring match).
    Run {
        scenario: String,
        #[arg(long, value_enum, default_value_t = Profile::Full)]
        profile: Profile,
        #[arg(long)]
        duration_secs: Option<u64>,
        #[arg(long)]
        warmup_secs: Option<u64>,
        #[arg(long, value_delimiter = ',')]
        concurrency: Option<Vec<usize>>,
        #[arg(long, default_value = "bench/out/report.md")]
        output: PathBuf,
        /// PostgreSQL shared_buffers (e.g. "32MB"). Constrains the buffer cache
        /// to simulate cold-disk I/O at production scale.
        #[arg(long)]
        shared_buffers: Option<String>,
    },
    /// Run every registered scenario.
    RunAll {
        #[arg(long, value_enum, default_value_t = Profile::Full)]
        profile: Profile,
        #[arg(long)]
        duration_secs: Option<u64>,
        #[arg(long)]
        warmup_secs: Option<u64>,
        #[arg(long, value_delimiter = ',')]
        concurrency: Option<Vec<usize>>,
        #[arg(long, default_value = "bench/out/report.md")]
        output: PathBuf,
        /// PostgreSQL shared_buffers (e.g. "32MB"). Constrains the buffer cache
        /// to simulate cold-disk I/O at production scale.
        #[arg(long)]
        shared_buffers: Option<String>,
    },
    /// Diff two JSON reports — e.g. baseline vs a treatment branch.
    Compare {
        baseline: PathBuf,
        treatment: PathBuf,
        #[arg(long, default_value = "bench/out/compare.md")]
        output: PathBuf,
    },
}

fn build_cfg(
    profile: Profile,
    duration_secs: Option<u64>,
    warmup_secs: Option<u64>,
    concurrency: Option<Vec<usize>>,
) -> RunConfig {
    RunConfig {
        concurrency: concurrency.unwrap_or_else(|| profile.concurrency()),
        duration: Duration::from_secs(duration_secs.unwrap_or(profile.duration_secs())),
        warmup: Duration::from_secs(warmup_secs.unwrap_or(profile.warmup_secs())),
        seed: 0x5EED_5EED_5EED_5EED,
    }
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
            profile,
            duration_secs,
            warmup_secs,
            concurrency,
            output,
            shared_buffers,
        } => {
            let cfg = build_cfg(profile, duration_secs, warmup_secs, concurrency);
            let scenarios: Vec<_> = scenarios::all()
                .into_iter()
                .filter(|s| s.name().contains(&scenario))
                .collect();
            if scenarios.is_empty() {
                anyhow::bail!("no scenarios match '{scenario}'");
            }
            run_set(&scenarios, &cfg, &output, shared_buffers.as_deref()).await
        }
        Cmd::RunAll {
            profile,
            duration_secs,
            warmup_secs,
            concurrency,
            output,
            shared_buffers,
        } => {
            let cfg = build_cfg(profile, duration_secs, warmup_secs, concurrency);
            let scenarios = scenarios::all();
            run_set(&scenarios, &cfg, &output, shared_buffers.as_deref()).await
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

// pkglibdir inside postgres:18 (`pg_config --pkglibdir`)
const CONTAINER_LIBDIR: &str = "/usr/lib/postgresql/18/lib";

/// Find a pre-built Linux `.so` for the beyond-auth-extension across common cross-compilation targets.
/// Returns the first path that exists, or None if none are present.
fn find_extension_so() -> Option<PathBuf> {
    let candidates: &[&str] = &[
        // ARM64 Linux GNU (M-series Mac → postgres:18 on ARM)
        "target/aarch64-unknown-linux-gnu/release/libbeyond_auth.so",
        // x86_64 Linux GNU (Intel Mac → postgres:18 on x86)
        "target/x86_64-unknown-linux-gnu/release/libbeyond_auth.so",
    ];
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

async fn run_set(
    scenarios: &[std::sync::Arc<dyn bench::harness::Scenario>],
    cfg: &RunConfig,
    output: &std::path::Path,
    shared_buffers: Option<&str>,
) -> Result<()> {
    let sb = shared_buffers.unwrap_or("128MB");

    let so_path = find_extension_so();
    if let Some(ref p) = so_path {
        eprintln!("[bench] found extension library: {}", p.display());
    } else {
        eprintln!(
            "[bench] no pre-built Linux beyond-auth-extension .so found; \
             migration 0006 will fall back to PL/pgSQL (baseline run). \
             Run `mise run extension:build:linux` then re-run for the treatment."
        );
    }

    eprintln!("[bench] starting postgres testcontainer (postgres:18, shared_buffers={sb})");
    let pg = Postgres::default().with_tag("18").with_cmd([
        "-c",
        "fsync=off",
        "-c",
        &format!("shared_buffers={sb}"),
        "-c",
        &format!("effective_cache_size={sb}"),
    ]);
    let pg = match so_path.as_deref() {
        Some(p) => pg.with_copy_to(
            CopyTargetOptions::new(format!("{CONTAINER_LIBDIR}/beyond_auth.so"))
                .with_mode(0o755),
            Path::new(p),
        ),
        None => pg,
    };
    let container = pg
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

    // Load migrations at runtime (NOT via the compile-time `sqlx::migrate!`
    // macro) so swapping migration files on disk between bench runs takes
    // effect without needing to recompile the bench binary. Without this,
    // ablation comparisons silently use the same embedded migration set.
    eprintln!("[bench] running migrations");
    let migrations_path = std::env::var("BENCH_MIGRATIONS_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("migrations"));
    eprintln!("[bench] migrations path: {}", migrations_path.display());
    let migrator = sqlx::migrate::Migrator::new(migrations_path.as_path())
        .await
        .context("failed to load migrations")?;
    migrator
        .run(&pool)
        .await
        .context("failed to run migrations")?;

    // Seed the shared corpus once for the entire run. Individual scenario
    // setups are no-ops or near no-ops; scale_sweep and bulk_write manage
    // their own prefixed data inside their own setups.
    eprintln!("[bench] seeding shared corpus (flat + chain depths + mixed-depth)");
    seed_all(
        &pool,
        &FlatCorpus::default(),
        CHAIN_DEPTHS,
        MIXED_NOISE_DEPTHS,
    )
    .await
    .context("failed to seed shared corpus")?;

    eprintln!("[bench] starting auth service (in-process)");
    let bench_server = beyond_auth::test_server::start(pool.clone())
        .await
        .context("failed to start bench server")?;
    eprintln!("[bench] auth service at {}", bench_server.url);

    let http_scenarios: Vec<std::sync::Arc<dyn bench::harness::Scenario>> = vec![
        std::sync::Arc::new(bench::scenarios::http::warm_check::WarmCheck::new(
            &bench_server,
        )),
        std::sync::Arc::new(bench::scenarios::http::cold_check::ColdCheck::new(
            &bench_server,
        )),
    ];
    let all_scenarios: Vec<_> = scenarios.iter().cloned().chain(http_scenarios).collect();

    let mut reports: Vec<ScenarioReport> = Vec::new();
    for scenario in &all_scenarios {
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
        && cpu.status.success()
    {
        s.push_str(&format!(
            "cpu: {}",
            String::from_utf8_lossy(&cpu.stdout).trim_end()
        ));
        s.push('\n');
    }
    if let Ok(mem) = std::process::Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        && mem.status.success()
        && let Ok(bytes) = String::from_utf8_lossy(&mem.stdout).trim().parse::<u64>()
    {
        s.push_str(&format!("memory: {} GiB\n", bytes / 1024 / 1024 / 1024));
    }
    s
}
