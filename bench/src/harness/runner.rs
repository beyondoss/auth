use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use hdrhistogram::Histogram;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::Mutex;

use super::metrics::{LatencyStats, Metric, PgStatSnapshot, new_histogram, record_duration};
use super::scenario::{Scenario, WorkerCtx};

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub concurrency: Vec<usize>,
    pub duration: Duration,
    pub warmup: Duration,
    pub seed: u64,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            concurrency: vec![1, 8, 32, 128],
            duration: Duration::from_secs(10),
            warmup: Duration::from_secs(2),
            seed: 0x5EED_5EED_5EED_5EED,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelReport {
    pub concurrency: usize,
    pub duration_secs: f64,
    pub ops: u64,
    pub ops_per_sec: f64,
    pub errors: u64,
    pub latency: LatencyStats,
    pub server_metrics: Vec<Metric>,
    pub extra_metrics: Vec<Metric>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioReport {
    pub name: String,
    pub question: String,
    pub levels: Vec<LevelReport>,
}

pub async fn run_scenario(
    scenario: Arc<dyn Scenario>,
    pool: &PgPool,
    cfg: &RunConfig,
) -> Result<ScenarioReport> {
    eprintln!("[scenario] {} — setup", scenario.name());
    scenario.setup(pool).await?;

    let mut report = ScenarioReport {
        name: scenario.name().to_string(),
        question: scenario.question().to_string(),
        levels: Vec::new(),
    };

    for &concurrency in &cfg.concurrency {
        eprintln!(
            "[scenario] {} — concurrency={} warmup={:?} duration={:?}",
            scenario.name(),
            concurrency,
            cfg.warmup,
            cfg.duration
        );
        let _ = run_level(
            scenario.clone(),
            pool,
            concurrency,
            cfg.warmup,
            cfg.seed.wrapping_add(0xDEAD),
        )
        .await?;

        let pre = PgStatSnapshot::capture(pool).await?;
        let level = run_level(scenario.clone(), pool, concurrency, cfg.duration, cfg.seed).await?;
        let post = PgStatSnapshot::capture(pool).await?;
        let server_metrics = post.delta(&pre);
        let extra_metrics = scenario.extra_metrics(pool).await?;

        let elapsed = level.elapsed.as_secs_f64();
        let ops = level.histogram.len();
        let ops_per_sec = if elapsed > 0.0 {
            ops as f64 / elapsed
        } else {
            0.0
        };
        let latency = LatencyStats::from_histogram(&level.histogram);

        report.levels.push(LevelReport {
            concurrency,
            duration_secs: elapsed,
            ops,
            ops_per_sec,
            errors: level.errors,
            latency,
            server_metrics,
            extra_metrics,
        });
    }

    Ok(report)
}

struct LevelOutcome {
    histogram: Histogram<u64>,
    errors: u64,
    elapsed: Duration,
}

async fn run_level(
    scenario: Arc<dyn Scenario>,
    pool: &PgPool,
    concurrency: usize,
    duration: Duration,
    seed: u64,
) -> Result<LevelOutcome> {
    let deadline = Instant::now() + duration;
    let combined = Arc::new(Mutex::new(new_histogram()));
    let errors = Arc::new(Mutex::new(0u64));

    let mut handles = Vec::with_capacity(concurrency);
    for worker_id in 0..concurrency {
        let pool = pool.clone();
        let combined = combined.clone();
        let errors = errors.clone();
        let scenario = scenario.clone();
        let worker_seed = seed.wrapping_add(worker_id as u64 * 0x9E37_79B9_7F4A_7C15);
        handles.push(tokio::spawn(async move {
            let mut local_hist = new_histogram();
            let mut local_errs = 0u64;
            let mut ctx = WorkerCtx {
                pool: &pool,
                worker_id,
                rng: SmallRng::seed_from_u64(worker_seed),
            };
            while Instant::now() < deadline {
                let start = Instant::now();
                match scenario.run(&mut ctx).await {
                    Ok(()) => record_duration(&mut local_hist, start.elapsed()),
                    Err(e) => {
                        local_errs += 1;
                        if local_errs <= 3 {
                            eprintln!("[worker {worker_id}] error: {e:#}");
                        }
                    }
                }
            }
            let mut combined = combined.lock().await;
            combined.add(&local_hist).expect("histogram bounds match");
            let mut errs = errors.lock().await;
            *errs += local_errs;
        }));
    }

    let started = Instant::now();
    for h in handles {
        h.await?;
    }
    let elapsed = started.elapsed();

    let histogram = Arc::try_unwrap(combined)
        .map_err(|_| anyhow::anyhow!("workers still hold histogram"))?
        .into_inner();
    let errors = *errors.lock().await;

    Ok(LevelOutcome {
        histogram,
        errors,
        elapsed,
    })
}
