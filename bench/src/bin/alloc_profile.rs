// Allocation-size profiling binary.
//
// Replaces the global allocator with a stats-tracking wrapper, exercises the
// service's hot paths (JWT issue, token round-trip, JSON serde, Argon2 verify),
// and prints a size-bucketed histogram so we can pick the right global allocator.
//
// Run with:
//   cargo run --bin alloc_profile --package bench --release

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use uuid::Uuid;

// ── Tracking allocator ────────────────────────────────────────────────────────

// Buckets (inclusive upper bound shown in label):
//   0: 0–7 B
//   1: 8–15 B
//   2: 16–31 B
//   3: 32–63 B
//   4: 64–127 B      ← mimalloc "small" limit (~64 B)
//   5: 128–255 B
//   6: 256–511 B
//   7: 512–1023 B    ← mimalloc degradation starts above here
//   8: 1 K–4 K
//   9: 4 K–16 K
//  10: 16 K–64 K     ← jemalloc pulls ahead above ~1 KB
//  11: 64 K+         ← jemalloc dominates
const NUM_BUCKETS: usize = 12;
const LABELS: [&str; NUM_BUCKETS] = [
    "0–7 B",
    "8–15 B",
    "16–31 B",
    "32–63 B",
    "64–127 B",
    "128–255 B",
    "256–511 B",
    "512 B–1 K",
    "1 K–4 K",
    "4 K–16 K",
    "16 K–64 K",
    "64 K+",
];

static COUNTS: [AtomicU64; NUM_BUCKETS] = [const { AtomicU64::new(0) }; NUM_BUCKETS];
static BYTES: [AtomicU64; NUM_BUCKETS] = [const { AtomicU64::new(0) }; NUM_BUCKETS];

struct StatsAlloc;

#[global_allocator]
static GLOBAL: StatsAlloc = StatsAlloc;

unsafe impl GlobalAlloc for StatsAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        track(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        track(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Count only the growth so we don't double-count the initial alloc.
        if new_size > layout.size() {
            track(new_size - layout.size());
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[inline]
fn track(size: usize) {
    let b = bucket(size);
    COUNTS[b].fetch_add(1, Relaxed);
    BYTES[b].fetch_add(size as u64, Relaxed);
}

fn bucket(sz: usize) -> usize {
    match sz {
        0..=7 => 0,
        8..=15 => 1,
        16..=31 => 2,
        32..=63 => 3,
        64..=127 => 4,
        128..=255 => 5,
        256..=511 => 6,
        512..=1023 => 7,
        1024..=4095 => 8,
        4096..=16383 => 9,
        16384..=65535 => 10,
        _ => 11,
    }
}

fn snap_counts() -> [u64; NUM_BUCKETS] {
    std::array::from_fn(|i| COUNTS[i].load(Relaxed))
}

fn snap_bytes() -> [u64; NUM_BUCKETS] {
    std::array::from_fn(|i| BYTES[i].load(Relaxed))
}

// ── Measurement helpers ───────────────────────────────────────────────────────

struct Snap {
    counts: [u64; NUM_BUCKETS],
    bytes: [u64; NUM_BUCKETS],
}

fn measure<F: Fn()>(name: &str, iters: usize, f: F) {
    let before = Snap {
        counts: snap_counts(),
        bytes: snap_bytes(),
    };

    for _ in 0..iters {
        f();
    }

    let after = Snap {
        counts: snap_counts(),
        bytes: snap_bytes(),
    };

    let total_allocs: u64 = (0..NUM_BUCKETS)
        .map(|i| after.counts[i] - before.counts[i])
        .sum();
    let total_bytes: u64 = (0..NUM_BUCKETS)
        .map(|i| after.bytes[i] - before.bytes[i])
        .sum();

    println!("\n╔═ {name} ── {iters} iters ══════════════════════════════════");
    println!(
        "║  {:<12}  {:>9}  {:>9}  {:>12}  {:>10}",
        "bucket", "allocs", "alloc/it", "bytes", "bytes/it"
    );

    for (i, label) in LABELS.iter().enumerate().take(NUM_BUCKETS) {
        let c = after.counts[i] - before.counts[i];
        let b = after.bytes[i] - before.bytes[i];
        if c == 0 {
            continue;
        }
        println!(
            "║  {:<12}  {:>9}  {:>9.1}  {:>12}  {:>10.1}",
            label,
            c,
            c as f64 / iters as f64,
            b,
            b as f64 / iters as f64,
        );
    }

    println!(
        "║  {:<12}  {:>9}  {:>9.1}  {:>12}  {:>10.1}",
        "TOTAL",
        total_allocs,
        total_allocs as f64 / iters as f64,
        total_bytes,
        total_bytes as f64 / iters as f64,
    );

    // Highlight the mimalloc-vs-jemalloc split.
    let small = (0..4usize)
        .map(|i| after.counts[i] - before.counts[i])
        .sum::<u64>(); // < 64 B
    let medium = (4..8usize)
        .map(|i| after.counts[i] - before.counts[i])
        .sum::<u64>(); // 64 B – 1 K
    let large = (8..NUM_BUCKETS)
        .map(|i| after.counts[i] - before.counts[i])
        .sum::<u64>(); // > 1 K
    if total_allocs > 0 {
        println!(
            "║  split: <64B {:.0}%  64B-1K {:.0}%  >1K {:.0}%",
            small as f64 / total_allocs as f64 * 100.0,
            medium as f64 / total_allocs as f64 * 100.0,
            large as f64 / total_allocs as f64 * 100.0,
        );
    }
    println!("╚══════════════════════════════════════════════════════");
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    // Generate fixtures once — key generation itself is not a hot path.
    let signing_key = SigningKey::generate(&mut OsRng);
    let kid = Uuid::now_v7();
    let user_id = Uuid::now_v7();

    // Pre-hash a password for the verify benchmark.
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(b"hunter2!Correct", &salt)
        .unwrap()
        .to_string();

    // Extra claims (3 fields) — present in org-scoped JWTs.
    let mut extra_claims = serde_json::Map::new();
    extra_claims.insert("org_id".into(), Uuid::now_v7().to_string().into());
    extra_claims.insert("org_role".into(), "admin".into());
    extra_claims.insert("plan".into(), "pro".into());

    println!("Allocation profiling — hot paths");
    println!("All measurements exclude startup / key-gen overhead.");

    // ── JWT: no extra claims ─────────────────────────────────────────────────
    measure("jwt_issue / no extra claims", 10_000, || {
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
        let _token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
    });

    // ── JWT: with extra claims (clone path in jwt.rs:41) ────────────────────
    measure("jwt_issue / 3 extra claims (clone path)", 10_000, || {
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

        // This is exactly what jwt.rs:41 does.
        let mut claims = serde_json::Value::Object(extra_claims.clone());
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
        let _token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
    });

    // ── JSON: login request deserialization ───────────────────────────────────
    measure("json_deser / login request (~50 B)", 10_000, || {
        let _: serde_json::Value =
            serde_json::from_str(r#"{"email":"user@example.com","password":"hunter2!Abc"}"#)
                .unwrap();
    });

    // ── JSON: auth response serialization ────────────────────────────────────
    measure("json_ser / auth response (~400 B)", 10_000, || {
        let _s = serde_json::to_string(&serde_json::json!({
            "token": "at_01JTEST000000000000000000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "session_id": "01JTEST000000000000000000",
            "expires_at": "2025-04-29T12:00:00Z",
            "user": {
                "id": user_id.to_string(),
                "email": "user@example.com",
                "name": "Test User",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
        }))
        .unwrap();
    });

    // ── JSON: me response (richer object) ────────────────────────────────────
    measure("json_ser / me response (~650 B)", 10_000, || {
        let _s = serde_json::to_string(&serde_json::json!({
            "id": user_id.to_string(),
            "email": "user@example.com",
            "name": "Test User",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-06-01T00:00:00Z",
            "orgs": [
                {
                    "id": Uuid::now_v7().to_string(),
                    "name": "Acme Corp",
                    "role": "admin",
                    "plan": "pro",
                    "created_at": "2024-01-01T00:00:00Z"
                }
            ],
            "mfa_enabled": true,
            "passkeys": []
        }))
        .unwrap();
    });

    // ── Argon2: password verify ───────────────────────────────────────────────
    // Only 3 iters — intentionally slow (≥100 ms each).
    measure("argon2_verify (3 iters)", 3, || {
        let parsed = PasswordHash::new(&password_hash).unwrap();
        Argon2::default()
            .verify_password(b"hunter2!Correct", &parsed)
            .unwrap();
    });

    // ── Overall summary ───────────────────────────────────────────────────────
    let total_c: u64 = COUNTS.iter().map(|a| a.load(Relaxed)).sum();
    let total_b: u64 = BYTES.iter().map(|a| a.load(Relaxed)).sum();

    println!("\n╔═ Overall (all measured operations) ══════════════════════");
    println!(
        "║  {:<12}  {:>9}  {:>7}  {:>12}  {:>7}",
        "bucket", "allocs", "%count", "bytes", "%bytes"
    );
    for i in 0..NUM_BUCKETS {
        let c = COUNTS[i].load(Relaxed);
        let b = BYTES[i].load(Relaxed);
        if c == 0 {
            continue;
        }
        println!(
            "║  {:<12}  {:>9}  {:>6.1}%  {:>12}  {:>6.1}%",
            LABELS[i],
            c,
            c as f64 / total_c as f64 * 100.0,
            b,
            b as f64 / total_b as f64 * 100.0,
        );
    }
    let small = (0..4usize).map(|i| COUNTS[i].load(Relaxed)).sum::<u64>();
    let medium = (4..8usize).map(|i| COUNTS[i].load(Relaxed)).sum::<u64>();
    let large = (8..NUM_BUCKETS)
        .map(|i| COUNTS[i].load(Relaxed))
        .sum::<u64>();
    println!(
        "║  split: <64B {:.0}%  64B-1K {:.0}%  >1K {:.0}%",
        small as f64 / total_c as f64 * 100.0,
        medium as f64 / total_c as f64 * 100.0,
        large as f64 / total_c as f64 * 100.0,
    );
    println!("║  total allocs: {total_c}  total bytes: {total_b}");
    println!("╚══════════════════════════════════════════════════════");
}
