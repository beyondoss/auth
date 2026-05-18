//! Minimal supervisor binary for handoff integration tests.
//!
//! Mirrors the shape of the upstream `handoff-supervisor` reference binary
//! but with a stripped-down argv-based config so we don't need a TOML file
//! per test. Uses the same `handoff::Supervisor` library API as production
//! supervisors, so anything tested here exercises the same library code
//! paths a real deployment would.
//!
//! Invocation:
//!
//! ```text
//! handoff-test-supervisor \
//!     --binary <path>           # auth binary path
//!     --addr <ip:port>          # http listener address to bind
//!     --data-dir <path>         # passed to child as --data-dir
//!     --trigger <path>          # Unix socket where the supervisor listens for "handoff" commands
//!     --env KEY=VAL ...         # env vars forwarded to the child
//! ```
//!
//! Once spawned, the supervisor:
//! 1. Binds the http listener on `--addr`.
//! 2. Cold-starts the child binary with that listener inherited as FD 3.
//! 3. Accepts trigger commands on the Unix socket. Supported commands:
//!    - `handoff` — drive `Supervisor::perform_handoff`. Replies
//!      `ok committed=<bool>` or `err <msg>`.
//!    - `pid` — reply with the current child's PID (used by tests that
//!      want to SIGKILL the supervisor independently of the child).
//!    - `addr` — reply with the bound listener's `local_addr`.
//!    - `shutdown` — kill the child and exit. Used at test end.

// `pre_exec` for fd inheritance requires an unsafe block; the closure runs
// post-fork and is documented async-signal-safe.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use handoff::supervisor::{SpawnSpec, Supervisor};

#[derive(Parser, Debug)]
struct Cli {
    /// Path to the auth binary.
    #[arg(long)]
    binary: PathBuf,

    /// `ip:port` to bind the http listener on. Use `127.0.0.1:0` for
    /// ephemeral port; the test reads the bound address via the `addr`
    /// trigger command.
    #[arg(long)]
    addr: String,

    /// Data directory for the child. Passed as `--data-dir` to the auth
    /// binary on cold start and every handoff.
    #[arg(long)]
    data_dir: PathBuf,

    /// Unix socket the supervisor listens on for trigger commands.
    #[arg(long)]
    trigger: PathBuf,

    /// Where to write the supervisor's handoff journal. If unset, no
    /// journal — fine for tests that don't crash-restart the supervisor.
    #[arg(long)]
    journal: Option<PathBuf>,

    /// Per-handoff overall deadline in seconds (handoff lib SpawnSpec).
    #[arg(long, default_value_t = 30)]
    deadline_secs: u64,

    /// Per-handoff drain grace in seconds (handoff lib SpawnSpec).
    #[arg(long, default_value_t = 10)]
    drain_grace_secs: u64,

    /// Environment variables to forward to the child: `KEY=VAL`. Repeat.
    #[arg(long = "env", value_parser = parse_env_pair)]
    env: Vec<(String, String)>,
}

fn parse_env_pair(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("expected KEY=VAL, got {s:?}"))?;
    Ok((k.to_string(), v.to_string()))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Bind the listener. We hold this for the lifetime of the supervisor;
    // every cold-start and successor spawn inherits this FD.
    let listener = TcpListener::bind(&cli.addr)
        .with_context(|| format!("bind http listener on {}", cli.addr))?;
    listener.set_nonblocking(false).ok();
    let bound_addr = listener
        .local_addr()
        .context("listener.local_addr")?
        .to_string();
    let listener_fd = listener.as_raw_fd();

    // Cold-start child.
    let cold = spawn_child(&cli, listener_fd, false).context("cold start spawn")?;
    let current: Arc<Mutex<Child>> = Arc::new(Mutex::new(cold));

    // Build the supervisor object that drives future handoffs.
    let mut sup =
        Supervisor::new(&control_socket_path(&cli.data_dir))?.with_listener("http", listener_fd);
    if let Some(j) = &cli.journal {
        sup = sup.with_journal(j.clone());
    }
    let sup = Arc::new(sup);

    // Best-effort journal recovery: if a prior supervisor crashed mid-
    // handoff, the incumbent self-recovers on disconnect; we just need
    // to drop the on-disk state so the next handoff starts clean.
    if let Ok(Some(prior)) = sup.resume_from_journal() {
        eprintln!(
            "[test-supervisor] resumed from prior journal: handoff_id={} phase={:?}",
            prior.handoff_id, prior.phase
        );
    }

    // Trigger socket.
    let _ = std::fs::remove_file(&cli.trigger);
    if let Some(parent) = cli.trigger.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let trigger = UnixListener::bind(&cli.trigger)
        .with_context(|| format!("bind trigger socket {}", cli.trigger.display()))?;

    // Print the bound address to stdout so the test can read it without
    // having to send an `addr` trigger command. Unbuffered so the test
    // doesn't block waiting for stdio buffering.
    println!("addr={bound_addr}");
    std::io::stdout().flush().ok();

    for client in trigger.incoming() {
        let stream = match client {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut writer = stream.try_clone()?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            continue;
        }
        let reply = match line.trim() {
            "handoff" => match do_handoff(&cli, listener_fd, &sup, &current) {
                Ok(committed) => format!("ok committed={committed}"),
                Err(e) => format!("err {e}"),
            },
            "pid" => match current.lock() {
                Ok(c) => format!("ok pid={}", c.id()),
                Err(_) => "err pid: lock poisoned".into(),
            },
            "addr" => format!("ok addr={bound_addr}"),
            "shutdown" => {
                if let Ok(mut c) = current.lock() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                let _ = writeln!(writer, "ok");
                return Ok(());
            }
            other => format!("err unknown command {other:?}"),
        };
        let _ = writeln!(writer, "{reply}");
    }
    Ok(())
}

fn control_socket_path(data_dir: &std::path::Path) -> PathBuf {
    // Must match what beyond-auth's `cli::serve` derives:
    // `cfg.data_dir.join(".handoff.sock")`.
    data_dir.join(".handoff.sock")
}

fn spawn_child(cli: &Cli, listener_fd: std::os::fd::RawFd, _is_handoff: bool) -> Result<Child> {
    use std::os::unix::process::CommandExt;
    let args = vec![
        "serve".to_string(),
        "--data-dir".to_string(),
        cli.data_dir.to_string_lossy().into_owned(),
        // --address is unused under handoff (listener is inherited) but
        // the binary still parses it.
        "--address".to_string(),
        cli.addr.clone(),
    ];
    let mut cmd = Command::new(&cli.binary);
    cmd.args(&args);
    for (k, v) in &cli.env {
        cmd.env(k, v);
    }
    cmd.env("LISTEN_FDS", "1");
    cmd.env("LISTEN_FDNAMES", "http");
    cmd.stdin(std::process::Stdio::null());
    if std::env::var("BEYOND_AUTH_TEST_LOGS").is_ok() {
        cmd.stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit());
    } else {
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
    }

    // dup2 the inherited listener fd into the child's FD 3.
    let src = listener_fd;
    // SAFETY: pre_exec runs in the forked child between fork and execve.
    // Only async-signal-safe libc calls; no allocations or Rust runtime
    // dependencies.
    unsafe {
        cmd.pre_exec(move || {
            if src == 3 {
                if libc::fcntl(src, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup2(src, 3) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().context("spawn child")
}

fn do_handoff(
    cli: &Cli,
    _listener_fd: std::os::fd::RawFd,
    sup: &Supervisor,
    current: &Arc<Mutex<Child>>,
) -> Result<bool> {
    let args = vec![
        "serve".to_string(),
        "--data-dir".to_string(),
        cli.data_dir.to_string_lossy().into_owned(),
        "--address".to_string(),
        cli.addr.clone(),
    ];
    let spec = SpawnSpec {
        binary: cli.binary.clone(),
        args,
        env: cli.env.clone(),
        deadline: Duration::from_secs(cli.deadline_secs),
        drain_grace: Duration::from_secs(cli.drain_grace_secs),
    };
    let mut outcome = sup.perform_handoff(spec).context("perform_handoff")?;
    let committed = outcome.committed;

    if committed
        && let Some(new_child) = outcome.child.take()
        && let Ok(mut c) = current.lock()
    {
        // Reap the outgoing child (bounded wait — match upstream behavior).
        let _ = wait_with_timeout(&mut c, Duration::from_secs(cli.deadline_secs));
        *c = new_child;
    }
    Ok(committed)
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return Some(s),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return None,
        }
    }
}
