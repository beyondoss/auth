// Allocator throughput comparison: mimalloc (default) vs jemalloc (--features jemalloc)
//
// Simulates two patterns found in a Tokio service at scale:
//   1. Same-thread: alloc and free on the same worker (common for short request futures)
//   2. Cross-thread: alloc on thread A, free on thread B (Tokio work-stealing)
//
// Run both allocators and compare:
//   cargo run --bin alloc_compare --package bench --release
//   cargo run --bin alloc_compare --package bench --release --features jemalloc

#[cfg(feature = "jemalloc")]
use tikv_jemallocator::Jemalloc;
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[cfg(not(feature = "jemalloc"))]
use mimalloc::MiMalloc;
#[cfg(not(feature = "jemalloc"))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use uuid::Uuid;

const DURATION: Duration = Duration::from_secs(5);
const THREAD_COUNTS: &[usize] = &[1, 2, 4, 8, 16];

// ── JWT hot path (mirrors jwt.rs exactly) ────────────────────────────────────

fn jwt_issue(signing_key: &SigningKey, kid: Uuid, user_id: Uuid) -> String {
    let now = Utc::now().timestamp();
    let exp = now + 3600i64;

    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&serde_json::json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": kid.to_string(),
        }))
        .unwrap(),
    );

    let mut claims = serde_json::json!({});
    let map = claims.as_object_mut().unwrap();
    map.insert("jti".into(), Uuid::new_v4().to_string().into());
    map.insert("sub".into(), user_id.to_string().into());
    map.insert("iss".into(), "https://auth.example.com".into());
    map.insert("aud".into(), "https://api.example.com".into());
    map.insert("iat".into(), now.into());
    map.insert("nbf".into(), (now - 5).into());
    map.insert("exp".into(), exp.into());

    let claims_enc = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());
    let signing_input = format!("{header}.{claims_enc}");
    let sig = signing_key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

fn json_ser_auth_response(user_id: Uuid) -> String {
    serde_json::to_string(&serde_json::json!({
        "token": "at_01JTEST000000000000000000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "session_id": "01JTEST000000000000000000",
        "expires_at": "2025-04-29T12:00:00Z",
        "user": {
            "id": user_id.to_string(),
            "email": "user@example.com",
            "name": "Test User",
            "created_at": "2024-01-01T00:00:00Z"
        }
    }))
    .unwrap()
}

// ── Benchmark harness ─────────────────────────────────────────────────────────

struct Run {
    ops: u64,
    elapsed: Duration,
}

/// Same-thread pattern: allocate and free on the same thread.
fn bench_same_thread(
    n_threads: usize,
    signing_key: Arc<SigningKey>,
    kid: Uuid,
    user_id: Uuid,
) -> Run {
    let stop = Arc::new(AtomicBool::new(false));
    let ops_total = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(Barrier::new(n_threads + 1));

    let handles: Vec<_> = (0..n_threads)
        .map(|_| {
            let stop = Arc::clone(&stop);
            let ops = Arc::clone(&ops_total);
            let barrier = Arc::clone(&barrier);
            let key = Arc::clone(&signing_key);
            std::thread::spawn(move || {
                barrier.wait();
                let mut local_ops = 0u64;
                while !stop.load(Relaxed) {
                    // Alloc and free on the same thread — the common case.
                    let token = black_box(jwt_issue(&key, kid, user_id));
                    let resp = black_box(json_ser_auth_response(user_id));
                    drop(token);
                    drop(resp);
                    local_ops += 1;
                }
                ops.fetch_add(local_ops, Relaxed);
            })
        })
        .collect();

    barrier.wait();
    let start = Instant::now();
    std::thread::sleep(DURATION);
    stop.store(true, Relaxed);
    for h in handles {
        h.join().unwrap();
    }

    Run {
        ops: ops_total.load(Relaxed),
        elapsed: start.elapsed(),
    }
}

/// Cross-thread pattern: producer allocates, consumer frees.
/// Mimics Tokio work-stealing where a future created on worker-A is polled
/// (and its allocations dropped) on worker-B.
fn bench_cross_thread(
    n_threads: usize,
    signing_key: Arc<SigningKey>,
    kid: Uuid,
    user_id: Uuid,
) -> Run {
    use std::sync::mpsc::{SyncSender, sync_channel};

    let stop = Arc::new(AtomicBool::new(false));
    let ops_total = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(Barrier::new(n_threads * 2 + 1));

    // Each producer/consumer pair shares a bounded channel.
    let pairs: Vec<(SyncSender<(String, String)>, _)> = (0..n_threads)
        .map(|_| sync_channel::<(String, String)>(32))
        .collect();

    let mut handles = Vec::new();

    for (tx, rx) in pairs {
        // Producer: allocates JWTs and auth responses, ships them to the consumer.
        {
            let stop = Arc::clone(&stop);
            let barrier = Arc::clone(&barrier);
            let key = Arc::clone(&signing_key);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                while !stop.load(Relaxed) {
                    let token = jwt_issue(&key, kid, user_id);
                    let resp = json_ser_auth_response(user_id);
                    // Ignore send errors when consumer has exited.
                    let _ = tx.send((token, resp));
                }
            }));
        }

        // Consumer: receives and drops allocations made on the producer thread.
        {
            let stop = Arc::clone(&stop);
            let ops = Arc::clone(&ops_total);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let mut local_ops = 0u64;
                while !stop.load(Relaxed) {
                    if let Ok(pair) = rx.recv_timeout(Duration::from_millis(10)) {
                        drop(black_box(pair));
                        local_ops += 1;
                    }
                }
                ops.fetch_add(local_ops, Relaxed);
            }));
        }
    }

    barrier.wait();
    let start = Instant::now();
    std::thread::sleep(DURATION);
    stop.store(true, Relaxed);
    for h in handles {
        h.join().unwrap();
    }

    Run {
        ops: ops_total.load(Relaxed),
        elapsed: start.elapsed(),
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let allocator = if cfg!(feature = "jemalloc") {
        "jemalloc"
    } else {
        "mimalloc v3"
    };
    println!("Allocator: {allocator}");
    println!("Duration per run: {}s\n", DURATION.as_secs());

    let signing_key = Arc::new(SigningKey::generate(&mut OsRng));
    let kid = Uuid::now_v7();
    let user_id = Uuid::now_v7();

    // ── Same-thread ──────────────────────────────────────────────────────────
    println!("Pattern: same-thread (alloc + free on same worker)");
    println!(
        "{:<10}  {:>14}  {:>14}",
        "threads", "ops/sec", "ops/sec/thread"
    );
    for &n in THREAD_COUNTS {
        let r = bench_same_thread(n, Arc::clone(&signing_key), kid, user_id);
        let ops_sec = r.ops as f64 / r.elapsed.as_secs_f64();
        println!("{:<10}  {:>14.0}  {:>14.0}", n, ops_sec, ops_sec / n as f64,);
    }

    println!();

    // ── Cross-thread ─────────────────────────────────────────────────────────
    println!("Pattern: cross-thread (alloc on producer, free on consumer)");
    println!("{:<10}  {:>14}  {:>14}", "pairs", "ops/sec", "ops/sec/pair");
    for &n in THREAD_COUNTS {
        let r = bench_cross_thread(n, Arc::clone(&signing_key), kid, user_id);
        let ops_sec = r.ops as f64 / r.elapsed.as_secs_f64();
        println!("{:<10}  {:>14.0}  {:>14.0}", n, ops_sec, ops_sec / n as f64,);
    }
}
