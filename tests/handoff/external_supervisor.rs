//! Tests that exercise the separate-process supervisor deployment shape.
//!
//! Production runs `beyond-auth` under an external supervisor process
//! (the upstream `handoff-supervisor`, or a custom embedder that links the
//! `handoff` library). The supervisor binds the listener once, holds it
//! across child generations, and drives `handoff::Supervisor::perform_handoff`
//! out-of-process.
//!
//! All other tests in this binary drive the supervisor *in-process* from
//! the test thread, which exercises the protocol but not the process
//! model. These tests close that gap by spawning the bundled
//! `handoff-test-supervisor` binary as the parent and triggering handoffs
//! through its Unix-domain trigger socket.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use crate::harness::provision_database_for_unsupervised;

/// Path to the bundled test supervisor binary, set by cargo for the
/// `handoff` integration test target.
const SUPERVISOR_BINARY: &str = env!("CARGO_BIN_EXE_handoff-test-supervisor");
const AUTH_BINARY: &str = env!("CARGO_BIN_EXE_beyond-auth");

const TEST_ENC_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const TEST_ADMIN_SECRET: &str = "handoff-test-admin-secret";

/// One running test supervisor + child. Owns the tempdir so it lives until
/// the test ends.
struct SupervisedAuth {
    _tmp: TempDir,
    _data_dir: PathBuf,
    trigger: PathBuf,
    /// Wrapped in Option so tests can `take()` and SIGKILL out-of-band.
    /// The Drop impl best-effort kills whatever is still there.
    supervisor: Option<Child>,
    addr: SocketAddr,
}

impl SupervisedAuth {
    fn spawn(extra_env: &[(&str, &str)]) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("mkdir data_dir");
        let trigger = tmp.path().join("trigger.sock");
        let journal = tmp.path().join("journal.bin");
        let database_url = provision_database_for_unsupervised();

        let mut cmd = Command::new(SUPERVISOR_BINARY);
        cmd.arg("--binary").arg(AUTH_BINARY);
        cmd.arg("--addr").arg("127.0.0.1:0");
        cmd.arg("--data-dir").arg(&data_dir);
        cmd.arg("--trigger").arg(&trigger);
        cmd.arg("--journal").arg(&journal);
        cmd.arg("--deadline-secs").arg("30");
        cmd.arg("--drain-grace-secs").arg("10");

        for (k, v) in [
            ("DATABASE_URL", database_url.as_str()),
            ("SIGNING_KEY_ENCRYPTION_KEY", TEST_ENC_KEY),
            ("ADMIN_SECRET", TEST_ADMIN_SECRET),
            ("LOG_LEVEL", "info"),
        ]
        .iter()
        .chain(extra_env.iter())
        {
            cmd.arg("--env").arg(format!("{k}={v}"));
        }

        cmd.stdin(Stdio::null()).stdout(Stdio::piped());
        if std::env::var("BEYOND_AUTH_TEST_LOGS").is_ok() {
            cmd.stderr(Stdio::inherit());
        } else {
            cmd.stderr(Stdio::null());
        }

        let mut supervisor = cmd.spawn().expect("spawn test supervisor");

        // The supervisor prints `addr=127.0.0.1:NNNN\n` on stdout once
        // bound. Read it so we know the ephemeral port.
        let stdout = supervisor.stdout.take().expect("supervisor stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read supervisor addr");
        let addr: SocketAddr = line
            .trim()
            .strip_prefix("addr=")
            .expect("supervisor first line is addr=<addr>")
            .parse()
            .expect("parse addr");

        // Bind `data_dir` so it can't be optimized away — the supervisor
        // process holds the same path; we keep it referenced for debugging.
        let _ = data_dir.as_path();
        let me = Self {
            _tmp: tmp,
            _data_dir: data_dir,
            trigger,
            supervisor: Some(supervisor),
            addr,
        };
        me.wait_ready();
        me
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if probe_livez(self.addr) {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "auth never came up under external supervisor at {}",
                    self.addr
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Send `handoff` to the supervisor's trigger socket; return whether
    /// it reported committed.
    fn trigger_handoff(&self) -> Result<bool, String> {
        let response = self.send_command("handoff")?;
        // expected: "ok committed=true" or "ok committed=false" or "err ..."
        if let Some(rest) = response.strip_prefix("ok committed=") {
            Ok(rest.trim() == "true")
        } else if let Some(rest) = response.strip_prefix("err ") {
            Err(rest.to_string())
        } else {
            Err(format!("unexpected supervisor response: {response:?}"))
        }
    }

    fn send_command(&self, cmd: &str) -> Result<String, String> {
        let mut sock = UnixStream::connect(&self.trigger).map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(Duration::from_secs(60))).ok();
        sock.set_write_timeout(Some(Duration::from_secs(5))).ok();
        writeln!(sock, "{cmd}").map_err(|e| e.to_string())?;
        let mut response = String::new();
        sock.read_to_string(&mut response)
            .map_err(|e| e.to_string())?;
        Ok(response.trim().to_string())
    }

    fn shutdown(mut self) {
        // Best-effort. If the supervisor's already dead, the kill is a no-op.
        let _ = self.send_command("shutdown");
        if let Some(mut c) = self.supervisor.take() {
            let _ = c.wait();
        }
    }

    /// Pull the supervisor `Child` out so the test can SIGKILL it directly.
    fn take_supervisor(&mut self) -> Option<Child> {
        self.supervisor.take()
    }
}

impl Drop for SupervisedAuth {
    fn drop(&mut self) {
        if let Some(mut c) = self.supervisor.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn probe_livez(addr: SocketAddr) -> bool {
    let Ok(mut sock) = TcpStream::connect_timeout(&addr, Duration::from_millis(250)) else {
        return false;
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = sock.set_write_timeout(Some(Duration::from_secs(2)));
    let req = format!("GET /livez HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if sock.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = Vec::with_capacity(64);
    let mut tmp = [0u8; 64];
    while buf.len() < 16 {
        match sock.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    std::str::from_utf8(&buf)
        .map(|s| s.starts_with("HTTP/1.1 200"))
        .unwrap_or(false)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[test]
fn external_supervisor_drives_handoff() {
    let sup = SupervisedAuth::spawn(&[]);

    // Sanity: a /livez request goes through.
    assert!(probe_livez(sup.addr), "pre-handoff /livez");

    // Drive a real handoff through the supervisor's trigger socket. The
    // supervisor process — separate from this test thread — runs
    // `handoff::Supervisor::perform_handoff` against the child's control
    // socket. This is the production deployment shape.
    let committed = sup.trigger_handoff().expect("handoff trigger");
    assert!(committed, "supervisor reported handoff aborted");

    // Successor should now be serving.
    assert!(probe_livez(sup.addr), "post-handoff /livez");

    sup.shutdown();
}

#[test]
fn supervisor_sigkill_mid_drain_lets_incumbent_resume() {
    // Slow the drain down so we can reliably SIGKILL the supervisor while
    // the drain is still in flight. Without this, drain runs in
    // milliseconds and we'd race the kill against commit.
    let sup = SupervisedAuth::spawn(&[("BEYOND_AUTH_TEST_SLOW_DRAIN_MS", "3000")]);

    let trigger_path = sup.trigger.clone();
    let handoff_thread = std::thread::spawn(move || {
        // We expect this to fail when the supervisor is killed mid-handoff.
        let mut sock = UnixStream::connect(&trigger_path).ok()?;
        sock.set_read_timeout(Some(Duration::from_secs(30))).ok();
        writeln!(sock, "handoff").ok()?;
        let mut response = String::new();
        sock.read_to_string(&mut response).ok()?;
        Some(response.trim().to_string())
    });

    // Give the handoff time to actually begin draining before we kill.
    std::thread::sleep(Duration::from_millis(500));

    // SIGKILL the supervisor. The auth child detects the disconnect on
    // its control socket, calls `resume_after_abort`, and continues
    // serving on the inherited listener.
    let mut sup = sup;
    let mut supervisor = sup.take_supervisor().expect("supervisor present");
    let _ = supervisor.kill();
    let _ = supervisor.wait();

    // The background handoff trigger call should return Err (EOF from
    // the killed supervisor).
    let outcome = handoff_thread.join().expect("handoff thread");
    assert!(
        outcome.is_none() || outcome.as_deref().is_some_and(|s| s.is_empty()),
        "expected EOF from killed supervisor, got {outcome:?}"
    );

    // Give the incumbent a beat to detect the disconnect and run resume.
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if probe_livez(sup.addr) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "incumbent never resumed serving /livez after supervisor SIGKILL at {}",
        sup.addr
    );
}

#[test]
fn external_supervisor_back_to_back_handoffs() {
    let sup = SupervisedAuth::spawn(&[]);
    for i in 0..3 {
        let committed = sup
            .trigger_handoff()
            .unwrap_or_else(|e| panic!("handoff #{i} failed: {e}"));
        assert!(committed, "handoff #{i} aborted");
        assert!(probe_livez(sup.addr), "post-handoff-{i} /livez");
    }
    sup.shutdown();
}
