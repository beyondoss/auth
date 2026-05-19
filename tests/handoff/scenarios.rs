//! End-to-end handoff scenarios. See `/home/jared/.claude/plans/mossy-splashing-otter.md`
//! for the rationale behind each test.

use std::thread;
use std::time::{Duration, Instant};

use crate::harness::{AuthHarness, HealthzLoop, LoginLoop, generate_tls_material, tls_client};

#[test]
fn cold_start_serves_traffic() {
    let mut h = AuthHarness::new();
    h.cold_start();

    let url = format!("{}/livez", h.base_url());
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let res = client.get(&url).send().expect("GET /livez");
    assert_eq!(
        res.status().as_u16(),
        200,
        "cold-start /livez should be 200"
    );
}

#[test]
fn single_handoff_preserves_in_flight_requests() {
    let mut h = AuthHarness::new();
    h.cold_start();

    // Hammer /livez from 8 concurrent clients while we swap the binary.
    // Any non-200 means the handoff dropped a request — the load-bearing
    // claim is that this never happens.
    let concurrency: usize = 8;
    let traffic = HealthzLoop::start(h.base_url(), concurrency);
    thread::sleep(Duration::from_millis(200));

    let summary = h.handoff();
    assert!(
        summary.committed,
        "handoff aborted: {:?}",
        summary.abort_reason
    );

    thread::sleep(Duration::from_millis(200));
    let stats = traffic.stop();
    assert!(stats.acked > 0, "no requests acked: {stats:?}");
    // graceful_shutdown closes idle keep-alive connections during the swap.
    // Each concurrent client may see exactly one such connection-closed
    // error on its next send; the actual ceiling is roughly `concurrency`,
    // not a percentage of throughput (a low-rps run on a slow CI runner
    // would otherwise look worse than a high-rps local run for the same
    // absolute behaviour). +2 slack for keep-alive races.
    let allowed_errors = (concurrency + 2) as u64;
    assert!(
        stats.errors <= allowed_errors,
        "handoff error count too high: acked={} errors={} (allowed={allowed_errors}, concurrency={concurrency})",
        stats.acked,
        stats.errors,
    );
}

#[test]
fn bearer_token_from_incumbent_valid_on_successor() {
    let mut h = AuthHarness::new();
    h.cold_start();

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Sign up against O — gives us a bearer token issued by O's signing
    // key material, which lives in Postgres (encrypted at rest). The
    // successor reads the same DB on startup, so the token must validate.
    let email = format!("handoff-{}@example.test", uuid::Uuid::new_v4().simple());
    let signup: serde_json::Value = client
        .post(format!("{}/v1/users", h.base_url()))
        .json(&serde_json::json!({
            "email": email,
            "password": "correct-horse-battery-staple",
        }))
        .send()
        .expect("signup request")
        .json()
        .expect("signup json");
    let bearer = signup
        .get("session")
        .and_then(|s| s.get("token"))
        .and_then(|t| t.as_str())
        .unwrap_or_else(|| panic!("no session.token in signup response: {signup}"))
        .to_string();

    // /v1/users/me against O — sanity check.
    let me = client
        .get(format!("{}/v1/users/me", h.base_url()))
        .bearer_auth(&bearer)
        .send()
        .expect("me request (pre-handoff)");
    assert_eq!(me.status().as_u16(), 200, "pre-handoff /me failed");

    // Hand off to N.
    let s = h.handoff();
    assert!(s.committed, "handoff aborted: {:?}", s.abort_reason);

    // Same bearer against N — proves the signing key survived the swap.
    let me = client
        .get(format!("{}/v1/users/me", h.base_url()))
        .bearer_auth(&bearer)
        .send()
        .expect("me request (post-handoff)");
    assert_eq!(
        me.status().as_u16(),
        200,
        "post-handoff /me failed — bearer token didn't survive"
    );
}

#[test]
fn db_backed_load_survives_handoff() {
    // Production traffic isn't /livez — it's DB-backed endpoints that
    // write through Postgres and validate JWTs against the signing key
    // material on disk. This test exercises that path across a handoff.
    //
    // Concurrency sized to auth's actual bottleneck (Argon2 on signup
    // dominates wall-clock — ~25ms per request at default cost). 12
    // threads is below the default DB pool size (16) and saturates the
    // CPU on a typical CI runner; pushing higher just queues on pool
    // acquire without exercising new code.
    let mut h = AuthHarness::new();
    h.cold_start();

    let concurrency: usize = 12;
    let traffic = LoginLoop::start(h.base_url(), concurrency);
    // Generous pre-handoff window so the loop accumulates a representative
    // baseline even under CI's Argon2-bottlenecked throughput.
    thread::sleep(Duration::from_secs(3));

    let summary = h.handoff();
    assert!(
        summary.committed,
        "handoff aborted: {:?}",
        summary.abort_reason
    );

    // Same generous window post-handoff so we actually sample the successor.
    thread::sleep(Duration::from_secs(3));

    let stats = traffic.stop();
    // Floor below what local hits but well above zero: confirms the
    // signup/validate path executed before and after the swap.
    assert!(
        stats.acked >= concurrency as u64,
        "didn't generate enough load to be meaningful: {stats:?}"
    );
    // Same rationale as single_handoff_preserves_in_flight_requests:
    // graceful_shutdown closes idle keep-alive connections at swap time,
    // so each concurrent client may see one connection-closed error. The
    // ceiling tracks concurrency, not a percentage of throughput.
    let allowed_errors = (concurrency + 4) as u64;
    assert!(
        stats.errors <= allowed_errors,
        "DB-backed handoff error count too high: acked={} errors={} (allowed={allowed_errors}, concurrency={concurrency})",
        stats.acked,
        stats.errors,
    );
}

#[test]
fn stale_lock_breaks_cleanly_after_sigkill() {
    let mut h = AuthHarness::new();
    h.cold_start();
    h.sigkill_current();
    // Cold-start again on the same data dir: `acquire_or_break_stale`
    // must reclaim the pidfile lock left behind by the killed process.
    h.cold_start_after_crash();

    let url = format!("{}/livez", h.base_url());
    let res = reqwest::blocking::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(2))
        .send()
        .expect("GET /livez after stale-break");
    assert_eq!(res.status().as_u16(), 200);
}

#[test]
fn two_processes_on_same_data_dir_are_prevented() {
    let mut h = AuthHarness::new();
    h.cold_start();

    // A competitor pointing at the same data dir, on a different port and
    // socket, with no FD inheritance. Must refuse to start because the
    // flock is held.
    let mut competitor = h.try_spawn_competitor();
    let exit = wait_with_timeout(&mut competitor, Duration::from_secs(10));
    assert!(
        exit.is_some(),
        "competitor still alive after 10s — flock invariant broken"
    );
    let status = exit.unwrap();
    assert!(
        !status.success(),
        "competitor exited successfully; flock invariant broken (status: {status:?})"
    );
}

#[test]
fn successor_crash_before_ready_triggers_resume() {
    let mut h = AuthHarness::new();
    h.cold_start();

    // Successor panics in `serve()` after the lock acquire but before
    // `announce_and_bind`. The supervisor should abort the handoff and the
    // incumbent's `AuthDrainable::resume_after_abort` should clear the
    // accept-paused flag — meaning O continues serving traffic.
    let summary = h.handoff_with_env(&[("BEYOND_AUTH_TEST_PANIC_BEFORE_READY".into(), "1".into())]);
    assert!(
        !summary.committed,
        "handoff committed despite successor panic"
    );

    // Old process should still be serving.
    let url = format!("{}/livez", h.base_url());
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let res = client.get(&url).send().expect("post-abort /livez");
    assert_eq!(
        res.status().as_u16(),
        200,
        "incumbent stopped serving after aborted handoff"
    );
}

#[test]
fn seal_failure_aborts_and_incumbent_keeps_serving() {
    let mut h = AuthHarness::new();

    // Plant the tripwire and start the incumbent with the env var pointing
    // at it. `AuthDrainable::seal` (which runs on this process during
    // handoff) will see the file, return `Err`, and delete it — so the
    // next handoff seals cleanly.
    let tripwire = h.data_dir().join("fail-seal-once");
    std::fs::write(&tripwire, b"").expect("plant tripwire");
    h.cold_start_with_env(&[(
        "BEYOND_AUTH_TEST_FAIL_SEAL_ONCE_FILE".into(),
        tripwire.to_string_lossy().into_owned(),
    )]);

    let summary = h.handoff();
    assert!(!summary.committed, "handoff committed despite seal failure");
    assert!(
        !tripwire.exists(),
        "tripwire should have been consumed by the failing seal"
    );

    // Incumbent must still be serving.
    let url = format!("{}/livez", h.base_url());
    let res = reqwest::blocking::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(3))
        .send()
        .expect("post-seal-failure /livez");
    assert_eq!(res.status().as_u16(), 200);

    // Second handoff (tripwire consumed) should commit.
    let summary = h.handoff();
    assert!(
        summary.committed,
        "second handoff aborted unexpectedly: {:?}",
        summary.abort_reason
    );
}

#[test]
fn back_to_back_handoffs_under_load() {
    let mut h = AuthHarness::new();
    h.cold_start();

    let traffic = HealthzLoop::start(h.base_url(), 4);
    thread::sleep(Duration::from_millis(100));

    for i in 0..5 {
        let s = h.handoff();
        assert!(s.committed, "handoff #{i} aborted: {:?}", s.abort_reason);
        thread::sleep(Duration::from_millis(100));
    }

    thread::sleep(Duration::from_millis(100));
    let stats = traffic.stop();
    assert!(stats.acked > 0, "no traffic during 5 handoffs");
    // 5 handoffs → 5 graceful_shutdown windows where keep-alive clients
    // see a brief connection-closed and reconnect. Keep the tolerance
    // tight (under 1%) but not zero.
    let total = stats.acked + stats.errors;
    let rate = stats.errors as f64 / total as f64;
    assert!(
        rate < 0.01,
        "back-to-back handoff error rate too high: acked={} errors={} ({:.3}%)",
        stats.acked,
        stats.errors,
        rate * 100.0
    );
}

#[test]
fn drain_signal_resets_across_multiple_aborts() {
    // DrainSignal latches its flag on trigger() to win the wake-race vs
    // tasks accepted just before drain. `resume_after_abort` must reset
    // that flag — otherwise a second drain on the same incumbent would
    // be a no-op for connection tasks accepted between aborts.
    //
    // Drive 3 successive aborts, verifying the incumbent keeps serving
    // /livez between each, then commit cleanly.
    let mut h = AuthHarness::new();
    h.cold_start();

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let url = format!("{}/livez", h.base_url());

    for i in 0..3 {
        let s = h.handoff_with_env(&[("BEYOND_AUTH_TEST_PANIC_BEFORE_READY".into(), "1".into())]);
        assert!(!s.committed, "abort cycle #{i} unexpectedly committed");
        let r = client
            .get(&url)
            .send()
            .unwrap_or_else(|e| panic!("post-abort-{i} /livez failed: {e}"));
        assert_eq!(
            r.status().as_u16(),
            200,
            "incumbent stopped serving after abort cycle #{i}",
        );
    }

    // Final clean handoff. If the abort cycles left state stuck, the
    // successor would never observe drain completion. Successor reads
    // BEYOND_AUTH_TEST_PANIC_BEFORE_READY from its env on each spawn,
    // and handoff() (no _with_env) doesn't set it.
    let s = h.handoff();
    assert!(
        s.committed,
        "post-abort-cycles commit failed: {:?}",
        s.abort_reason
    );
    let r = client.get(&url).send().expect("post-commit /livez");
    assert_eq!(
        r.status().as_u16(),
        200,
        "successor not serving after commit"
    );
}

#[test]
fn heartbeats_keep_supervisor_alive_through_slow_drain() {
    // The handoff lib emits Heartbeat frames every ~2s during long-running
    // drain/seal hooks so the supervisor's per-recv liveness timeout (10s)
    // doesn't trip on slow-but-progressing drains. If the heartbeat thread
    // ever regresses, a >10s drain would be killed mid-flight.
    //
    // We force a 12s drain via the BEYOND_AUTH_TEST_SLOW_DRAIN_MS hook
    // and crank the supervisor's drain_grace to 20s. Without heartbeats,
    // the supervisor would error out around 10s with a peer-dead timeout.
    let mut h = AuthHarness::new()
        .with_spec_deadline(Duration::from_secs(45))
        .with_spec_drain_grace(Duration::from_secs(20));
    h.cold_start_with_env(&[("BEYOND_AUTH_TEST_SLOW_DRAIN_MS".into(), "12000".into())]);

    let summary = h.handoff();
    assert!(
        summary.committed,
        "slow-drain handoff aborted (heartbeat regression?): {:?}",
        summary.abort_reason
    );
    assert!(
        summary.elapsed >= Duration::from_secs(11),
        "expected drain to actually take >=12s; elapsed={:?}",
        summary.elapsed,
    );
    assert!(
        summary.elapsed <= Duration::from_secs(30),
        "drain took implausibly long; elapsed={:?}",
        summary.elapsed,
    );
}

#[test]
fn tls_handshake_during_drain_window_succeeds() {
    // The TLS path goes through the same accept loop as the plaintext
    // path, so the "kernel absorbs SYNs while paused" invariant is the
    // load-bearing claim. This test:
    // 1. Spawns the binary with mTLS configured.
    // 2. Verifies a TLS request goes through on the incumbent.
    // 3. Triggers a handoff.
    // 4. Verifies a TLS request goes through immediately after the swap.
    let tmp = tempfile::tempdir().expect("tempdir");
    let certs = generate_tls_material(tmp.path());
    let mut h = AuthHarness::new().with_tls(certs);
    h.cold_start();

    let material = h.tls_material().expect("tls material set");
    let client = tls_client(material);
    let pre_url = format!("https://localhost:{}/livez", h.addr().port());
    let pre = client.get(&pre_url).send().expect("pre-handoff TLS GET");
    assert_eq!(pre.status().as_u16(), 200, "pre-handoff TLS /livez");

    let summary = h.handoff();
    assert!(
        summary.committed,
        "TLS handoff aborted: {:?}",
        summary.abort_reason
    );

    let post = client.get(&pre_url).send().expect("post-handoff TLS GET");
    assert_eq!(
        post.status().as_u16(),
        200,
        "post-handoff TLS /livez — successor isn't serving TLS"
    );
}

#[test]
fn unsupervised_cold_start_still_works() {
    // No harness / no supervisor — just spawn `beyond-auth serve` directly
    // with no `LISTEN_FDS`. The binary should take the ColdStart branch
    // with `inherited.empty()`, bind its own listener, and serve.
    use std::process::{Command, Stdio};

    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().join("data");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    drop(listener); // free for the child to re-bind

    let database_url = crate::harness::provision_database_for_unsupervised();
    let child = Command::new(env!("CARGO_BIN_EXE_beyond-auth"))
        .args([
            "serve",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--address",
            &format!("127.0.0.1:{port}"),
        ])
        .env("DATABASE_URL", &database_url)
        .env(
            "SIGNING_KEY_ENCRYPTION_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .env("ADMIN_SECRET", "handoff-test-admin-secret")
        .env("LOG_LEVEL", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(if std::env::var("BEYOND_AUTH_TEST_LOGS").is_ok() {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .spawn()
        .expect("spawn unsupervised auth");

    let mut child = ChildGuard(Some(child));
    let url = format!("http://127.0.0.1:{port}/livez");
    let deadline = Instant::now() + Duration::from_secs(15);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    loop {
        if let Ok(r) = client.get(&url).send()
            && r.status().as_u16() == 200
        {
            child.kill_and_wait();
            return;
        }
        if Instant::now() >= deadline {
            child.kill_and_wait();
            panic!("unsupervised binary never came up");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

struct ChildGuard(Option<std::process::Child>);
impl ChildGuard {
    fn kill_and_wait(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(s)) => return Some(s),
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => return None,
        }
    }
    None
}
