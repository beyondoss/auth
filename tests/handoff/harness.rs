//! End-to-end harness for the `beyond-auth` handoff integration.
//!
//! Owns the postgres testcontainer (singleton across the test binary), the
//! `handoff::Supervisor`, the listener FD that survives across child
//! processes, and the currently-running `Child` handle. Each test method is
//! one phase of the protocol (`cold_start`, `handoff`, `kill_current`,
//! `sigkill_current`, `cold_start_after_crash`, `try_spawn_competitor`).
//!
//! Cribbed from `kv/crates/server/tests/handoff_harness/mod.rs`, trimmed
//! for auth's single-listener, no-on-disk-state shape.

#![allow(dead_code)]

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use handoff::supervisor::{SpawnSpec, Supervisor};
use tempfile::TempDir;
use testcontainers::ContainerAsync;

/// Compiled `beyond-auth` binary path. Cargo sets this for integration
/// tests of the same package.
const AUTH_BINARY: &str = env!("CARGO_BIN_EXE_beyond-auth");

/// Fixed test KEK — 32 zero bytes, base64url. Matches `src/test_server.rs`.
const TEST_ENC_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const TEST_ADMIN_SECRET: &str = "handoff-test-admin-secret";

// ── Shared postgres container ────────────────────────────────────────────

struct PgEnv {
    /// Database URL pointing at the `postgres` superuser DB. Per-test
    /// databases get carved out of this container via `CREATE DATABASE`.
    base_url: String,
    /// Kept alive for the lifetime of the test binary. Dropping stops the
    /// container.
    _container: ContainerAsync<testcontainers_modules::postgres::Postgres>,
    /// Background tokio runtime used for testcontainers + per-DB migration
    /// runs. Kept alive on a dedicated thread.
    rt: tokio::runtime::Handle,
}

static PG_ENV: OnceLock<PgEnv> = OnceLock::new();
static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn pg_env() -> &'static PgEnv {
    PG_ENV.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel();

        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build harness tokio runtime");
            let handle = rt.handle().clone();

            rt.block_on(async move {
                let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
                let (linux_platform, cross_so_prefix) = if cfg!(target_arch = "aarch64") {
                    ("linux/arm64", "aarch64-unknown-linux-gnu")
                } else {
                    ("linux/amd64", "x86_64-unknown-linux-gnu")
                };
                let so_path = find_or_build_extension_so(manifest_dir, cross_so_prefix);

                use testcontainers::CopyTargetOptions;
                use testcontainers::ImageExt;
                use testcontainers::runners::AsyncRunner;
                use testcontainers_modules::postgres::Postgres;

                let pg = Postgres::default()
                    .with_tag("18")
                    .with_platform(linux_platform);
                let container = pg
                    .with_copy_to(
                        CopyTargetOptions::new(
                            "/usr/lib/postgresql/18/lib/beyond_auth_extension.so",
                        )
                        .with_mode(0o755),
                        so_path,
                    )
                    .start()
                    .await
                    .expect("start postgres testcontainer");

                let port = container
                    .get_host_port_ipv4(5432)
                    .await
                    .expect("get postgres port");

                let base_url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

                tx.send((base_url, container, handle))
                    .expect("send PgEnv to caller");

                // Park forever; the receiver owns the container by reference.
                std::future::pending::<()>().await;
            });
        });

        let (base_url, container, rt) = rx.recv().expect("pg env init");
        PgEnv {
            base_url,
            _container: container,
            rt,
        }
    })
}

/// Carve a fresh database out of the shared container, apply migrations,
/// return the connection URL with `search_path=auth,public` set.
pub fn provision_database_for_unsupervised() -> String {
    provision_database()
}

fn provision_database() -> String {
    let env = pg_env();
    let idx = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dbname = format!("handoff_test_{pid}_{idx}");

    let admin_url = env.base_url.clone();
    let port = parse_port(&admin_url);
    // No `search_path` option in the URL — production passes a plain URL
    // (db::connect sets `search_path = auth, public` via `after_connect`),
    // and db::migrate explicitly relies on `_sqlx_migrations` living in
    // the default (public) schema. If we put search_path in the URL,
    // sqlx-migrate creates a fresh tracking table inside `auth` on every
    // successor restart and re-runs all migrations from scratch.
    let db_url = format!("postgres://postgres:postgres@127.0.0.1:{port}/{dbname}");
    let dbname_for_async = dbname.clone();
    env.rt.block_on(async move {
        let pool = sqlx::PgPool::connect(&admin_url)
            .await
            .expect("connect to admin db");
        sqlx::query(&format!("CREATE DATABASE {dbname_for_async}"))
            .execute(&pool)
            .await
            .expect("CREATE DATABASE");
        pool.close().await;
    });
    db_url
}

/// Pull the host port out of `postgres://user:pass@host:PORT/db`. Used to
/// derive per-test DB URLs without naive substring replacement (which mangles
/// the username, since `//postgres:` matches the same prefix as `/postgres`).
fn parse_port(url: &str) -> u16 {
    let after_at = url.rsplit_once('@').expect("admin url has @").1;
    let port_str = after_at
        .rsplit_once(':')
        .and_then(|(_, rest)| rest.split('/').next())
        .expect("admin url has port");
    port_str.parse().expect("parse port")
}

fn find_or_build_extension_so(manifest_dir: &Path, cross_so_prefix: &str) -> PathBuf {
    let candidates = [
        manifest_dir.join(format!(
            "target/{cross_so_prefix}/release/libbeyond_auth_extension.so"
        )),
        manifest_dir.join("target/release/libbeyond_auth_extension.so"),
    ];
    if let Some(p) = candidates.iter().find(|p| p.exists()) {
        return p.clone();
    }
    let task = if cfg!(target_arch = "aarch64") {
        "extension:build:linux:arm64"
    } else {
        "extension:build:linux:amd64"
    };
    eprintln!(
        "[handoff-test] beyond-auth-extension .so not found — building via `mise run {task}`..."
    );
    let status = std::process::Command::new("mise")
        .args(["run", task])
        .status()
        .unwrap_or_else(|e| panic!("invoke mise: {e}"));
    assert!(
        status.success(),
        "`mise run {task}` failed — is Docker running?"
    );
    candidates
        .into_iter()
        .find(|p| p.exists())
        .expect("build succeeded but .so still not found")
}

// ── Harness ───────────────────────────────────────────────────────────────

/// Optional mTLS material for the auth binary. When `Some`, the harness
/// passes `BEYOND_TLS_CERT/KEY/CA` env vars and the readiness probe uses
/// HTTPS instead of plain HTTP.
pub struct TlsMaterial {
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    pub ca_path: PathBuf,
    /// CA cert in PEM form, for the test client's root store.
    pub ca_pem: String,
    /// Client cert+key in PEM form, for the test client's identity.
    pub client_cert_pem: String,
    pub client_key_pem: String,
}

pub struct AuthHarness {
    _tmp: TempDir,
    data_dir: PathBuf,
    control_socket: PathBuf,
    journal_path: PathBuf,
    /// The listener handed in via `LISTEN_FDS`. Held by the harness so the
    /// fd survives across the incumbent and successor child processes.
    listener: TcpListener,
    addr: SocketAddr,
    database_url: String,
    supervisor: Arc<Supervisor>,
    current: Option<Child>,
    extra_env: Vec<(String, String)>,
    tls: Option<TlsMaterial>,
    /// Wall-clock cap on the overall handoff (deadline) — matches the
    /// `SpawnSpec::deadline` field.
    spec_deadline: Duration,
    /// Wall-clock cap on drain specifically.
    spec_drain_grace: Duration,
}

#[derive(Debug)]
pub struct HandoffSummary {
    pub committed: bool,
    pub abort_reason: Option<String>,
    pub handoff_id: handoff::HandoffId,
    pub elapsed: Duration,
}

impl AuthHarness {
    pub fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("mkdir data_dir");
        // Match the path the binary derives in `cli::serve` —
        // `cfg.data_dir.join(".handoff.sock")`. The supervisor and the
        // incumbent must agree, or `connect()` from the harness's
        // `perform_handoff` finds no socket.
        let control_socket = data_dir.join(".handoff.sock");
        let journal_path = tmp.path().join("handoff-journal.bin");

        // Bind 127.0.0.1:0 so we get an unused port. Harness owns the
        // TcpListener so the fd outlives any individual child process.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind http listener");
        listener.set_nonblocking(false).ok();
        let addr = listener.local_addr().expect("local_addr");

        let database_url = provision_database();

        let supervisor = Supervisor::new(&control_socket)
            .expect("Supervisor::new")
            .with_listener("http", listener.as_raw_fd())
            .with_journal(journal_path.clone());
        let supervisor = Arc::new(supervisor);

        Self {
            _tmp: tmp,
            data_dir,
            control_socket,
            journal_path,
            listener,
            addr,
            database_url,
            supervisor,
            current: None,
            extra_env: Vec::new(),
            tls: None,
            spec_deadline: Duration::from_secs(30),
            spec_drain_grace: Duration::from_secs(10),
        }
    }

    pub fn with_spec_deadline(mut self, d: Duration) -> Self {
        self.spec_deadline = d;
        self
    }

    pub fn with_spec_drain_grace(mut self, d: Duration) -> Self {
        self.spec_drain_grace = d;
        self
    }

    pub fn with_env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.extra_env.push((k.into(), v.into()));
        self
    }

    /// Configure the harness to spawn the binary in mTLS mode. The TLS
    /// material is written to disk in the harness's tempdir and the
    /// `BEYOND_TLS_*` env vars are added. The readiness probe automatically
    /// switches to HTTPS with the right CA root.
    pub fn with_tls(mut self, certs: TlsMaterial) -> Self {
        self.extra_env.push((
            "BEYOND_TLS_CERT".into(),
            certs.server_cert_path.to_string_lossy().into_owned(),
        ));
        self.extra_env.push((
            "BEYOND_TLS_KEY".into(),
            certs.server_key_path.to_string_lossy().into_owned(),
        ));
        self.extra_env.push((
            "BEYOND_TLS_CA".into(),
            certs.ca_path.to_string_lossy().into_owned(),
        ));
        self.tls = Some(certs);
        self
    }

    pub fn tls_material(&self) -> Option<&TlsMaterial> {
        self.tls.as_ref()
    }

    // ── Lifecycle ────────────────────────────────────────────────────────

    pub fn cold_start(&mut self) -> &mut Self {
        self.cold_start_with_env(&[])
    }

    pub fn cold_start_with_env(&mut self, extra: &[(String, String)]) -> &mut Self {
        assert!(self.current.is_none(), "auth already running");
        let listener_fds = vec![("http".to_string(), self.listener.as_raw_fd())];
        let args = self.auth_args();
        let env = self.merged_env(extra);
        let child = spawn_inherited(&PathBuf::from(AUTH_BINARY), &args, &listener_fds, &env);
        self.current = Some(child);
        self.wait_ready();
        self
    }

    pub fn handoff(&mut self) -> HandoffSummary {
        self.handoff_with_env(&[])
    }

    pub fn handoff_with_env(&mut self, extra: &[(String, String)]) -> HandoffSummary {
        let started = Instant::now();
        let args = self.auth_args();
        let env = self.merged_env(extra);
        let spec = SpawnSpec {
            binary: PathBuf::from(AUTH_BINARY),
            args,
            env,
            deadline: self.spec_deadline,
            drain_grace: self.spec_drain_grace,
        };
        let mut outcome = self
            .supervisor
            .perform_handoff(spec)
            .expect("perform_handoff");

        if outcome.committed {
            if let Some(mut old) = self.current.take() {
                let _ = old.wait();
            }
            self.current = outcome.child.take();
            self.wait_ready();
        }

        HandoffSummary {
            committed: outcome.committed,
            abort_reason: outcome.abort_reason,
            handoff_id: outcome.handoff_id,
            elapsed: started.elapsed(),
        }
    }

    /// Block until /livez returns 200 on the listener address. Uses HTTPS
    /// (with the configured CA + client cert) when the harness was set up
    /// with TLS; plain HTTP otherwise.
    pub fn wait_ready(&mut self) {
        // Generous timeout: cold start runs db migrate + pool warm-up +
        // signing key load + authz schema compile before /livez starts
        // responding. On CI's shared runner with postgres in a container
        // the sqlx pool acquire alone has been measured at 5–7s per
        // connection, so the whole startup can blow past a tight cap.
        let timeout = Duration::from_secs(90);
        let deadline = Instant::now() + timeout;
        let scheme = if self.tls.is_some() { "https" } else { "http" };
        let url = format!("{scheme}://{}/livez", self.addr);
        loop {
            if let Some(child) = self.current.as_mut()
                && let Ok(Some(status)) = child.try_wait()
            {
                panic!("auth child exited before /livez came up at {url}: {status:?}",);
            }
            let ok = match self.tls.as_ref() {
                Some(certs) => probe_livez_tls(self.addr, certs),
                None => probe_healthz(self.addr),
            };
            if ok {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "wait_ready: /livez never returned 200 within {}s at {url}",
                    timeout.as_secs()
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn kill_current(&mut self) {
        if let Some(child) = self.current.as_mut() {
            // Try SIGTERM first; fall back to SIGKILL after a grace window.
            send_signal(child, libc::SIGTERM);
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if let Ok(Some(_)) = child.try_wait() {
                    self.current = None;
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            }
            let _ = child.kill();
            let _ = child.wait();
            self.current = None;
        }
    }

    pub fn sigkill_current(&mut self) {
        if let Some(mut c) = self.current.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    pub fn cold_start_after_crash(&mut self) -> &mut Self {
        assert!(self.current.is_none(), "kill current child first");
        self.cold_start()
    }

    /// Spawn a second auth process pointed at the same data-dir but a
    /// different ephemeral port and a different control socket — no FD
    /// inheritance, no supervisor coordination. Must fail to start
    /// because the data-dir flock is held.
    pub fn try_spawn_competitor(&self) -> Child {
        let other_listener = TcpListener::bind("127.0.0.1:0").expect("bind competitor");
        let other_addr = other_listener.local_addr().unwrap().to_string();
        drop(other_listener);

        let mut cmd = Command::new(AUTH_BINARY);
        cmd.args([
            "serve",
            "--data-dir",
            self.data_dir.to_str().unwrap(),
            "--address",
            &other_addr,
        ]);
        for (k, v) in self.merged_env(&[]) {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::null()).stdout(Stdio::null());
        if std::env::var("BEYOND_AUTH_TEST_LOGS").is_ok() {
            cmd.stderr(Stdio::inherit());
        } else {
            cmd.stderr(Stdio::null());
        }
        cmd.spawn().expect("spawn competitor")
    }

    // ── Inspection ───────────────────────────────────────────────────────

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn admin_secret(&self) -> &str {
        TEST_ADMIN_SECRET
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn current_pid(&self) -> Option<u32> {
        self.current.as_ref().map(|c| c.id())
    }

    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    // ── Internals ────────────────────────────────────────────────────────

    fn auth_args(&self) -> Vec<String> {
        vec![
            "serve".into(),
            "--data-dir".into(),
            self.data_dir.to_str().unwrap().into(),
            // --address is unused on the supervised path (the listener is
            // inherited) but the binary still requires it to parse.
            "--address".into(),
            self.addr.to_string(),
        ]
    }

    fn merged_env(&self, extra: &[(String, String)]) -> Vec<(String, String)> {
        let mut v = vec![
            ("DATABASE_URL".into(), self.database_url.clone()),
            ("SIGNING_KEY_ENCRYPTION_KEY".into(), TEST_ENC_KEY.into()),
            ("ADMIN_SECRET".into(), TEST_ADMIN_SECRET.into()),
            ("LOG_LEVEL".into(), "info".into()),
            ("OTLP_ENABLED".into(), "false".into()),
        ];
        v.extend(self.extra_env.iter().cloned());
        v.extend(extra.iter().cloned());
        v
    }
}

impl Drop for AuthHarness {
    fn drop(&mut self) {
        if let Some(mut c) = self.current.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn send_signal(child: &Child, sig: libc::c_int) {
    // SAFETY: kill(2) on a valid pid is safe; child.id() returns the pid
    // that std::process::Child tracks, which is alive until we wait().
    unsafe {
        libc::kill(child.id() as libc::pid_t, sig);
    }
}

fn spawn_inherited(
    binary: &Path,
    args: &[String],
    listener_fds: &[(String, RawFd)],
    extra_env: &[(String, String)],
) -> Child {
    let mut cmd = Command::new(binary);
    cmd.args(args);
    let names: Vec<String> = listener_fds.iter().map(|(n, _)| n.clone()).collect();
    cmd.env("LISTEN_FDS", listener_fds.len().to_string());
    cmd.env("LISTEN_FDNAMES", names.join(":"));
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::null());
    if std::env::var("BEYOND_AUTH_TEST_LOGS").is_ok() {
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    } else {
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
    }

    let sources: Vec<RawFd> = listener_fds.iter().map(|(_, f)| *f).collect();
    // SAFETY: `pre_exec` runs in the forked child before `execve`. Only
    // async-signal-safe libc calls; no allocations.
    unsafe {
        cmd.pre_exec(move || {
            for (i, src) in sources.iter().enumerate() {
                let dst = 3 + i as RawFd;
                if *src == dst {
                    if libc::fcntl(*src, libc::F_SETFD, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                } else if libc::dup2(*src, dst) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    cmd.spawn().expect("spawn beyond-auth")
}

/// Generate a fresh CA + server + client cert bundle and write them under
/// `dir`. Returned material includes the in-memory PEM strings so test
/// clients can build their root store + identity without re-reading
/// the files.
pub fn generate_tls_material(dir: &Path) -> TlsMaterial {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        SanType,
    };
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let server_key = KeyPair::generate().unwrap();
    let mut srv_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    srv_params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    srv_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let server_cert = srv_params.signed_by(&server_key, &issuer).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut cli_params = CertificateParams::new(vec!["client".to_string()]).unwrap();
    cli_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = cli_params.signed_by(&client_key, &issuer).unwrap();

    let server_cert_path = dir.join("server.crt");
    let server_key_path = dir.join("server.key");
    let ca_path = dir.join("ca.crt");
    std::fs::write(&server_cert_path, server_cert.pem()).unwrap();
    std::fs::write(&server_key_path, server_key.serialize_pem()).unwrap();
    std::fs::write(&ca_path, ca_cert.pem()).unwrap();

    TlsMaterial {
        server_cert_path,
        server_key_path,
        ca_path,
        ca_pem: ca_cert.pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

/// Build a reqwest blocking client that trusts the harness's CA and
/// presents the harness's client cert for mTLS.
pub fn tls_client(material: &TlsMaterial) -> reqwest::blocking::Client {
    let ca = reqwest::Certificate::from_pem(material.ca_pem.as_bytes()).unwrap();
    let combined = format!("{}{}", material.client_cert_pem, material.client_key_pem);
    let identity = reqwest::Identity::from_pem(combined.as_bytes()).unwrap();
    reqwest::blocking::Client::builder()
        .add_root_certificate(ca)
        .identity(identity)
        .https_only(true)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

/// TLS readiness probe — analog of `probe_healthz` but goes through rustls.
fn probe_livez_tls(addr: SocketAddr, material: &TlsMaterial) -> bool {
    let client = tls_client(material);
    let url = format!("https://localhost:{}/livez", addr.port());
    matches!(client.get(&url).send(), Ok(r) if r.status().as_u16() == 200)
}

/// Send a raw HTTP/1.1 GET /livez to `addr` and return true on a `200`
/// status line. Used by the test harness for the initial readiness probe
/// where reqwest's blocking client doesn't behave well.
fn probe_healthz(addr: SocketAddr) -> bool {
    use std::io::{Read, Write};
    let Ok(mut sock) = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(250))
    else {
        return false;
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(2000)));
    let _ = sock.set_write_timeout(Some(Duration::from_millis(2000)));
    let req = format!(
        "GET /livez HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nUser-Agent: handoff-test\r\nAccept: */*\r\n\r\n"
    );
    if sock.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 256];
    loop {
        match sock.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() >= 16 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let head = std::str::from_utf8(&buf).unwrap_or("");
    head.starts_with("HTTP/1.1 200")
}

pub fn wait_for_path(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(25));
    }
    path.exists()
}

pub fn wait_for_tcp(addr: SocketAddr, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(250)) {
            Ok(_) => return,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                thread::sleep(Duration::from_millis(25));
            }
            Err(e) if e.kind() == ErrorKind::TimedOut => continue,
            Err(e) => panic!("wait_for_tcp({addr}): {e}"),
        }
    }
}

// ── Traffic generator ─────────────────────────────────────────────────────

/// A background HTTP client that hammers /livez on the harness. Counts
/// successful 200s as `acked` and everything else (connect refused, 5xx,
/// timeout) as `errors`. Used by tests that verify request preservation
/// across a handoff.
pub struct HealthzLoop {
    stop: Arc<AtomicBool>,
    acked: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    handles: Vec<thread::JoinHandle<()>>,
}

#[derive(Debug)]
pub struct HealthzStats {
    pub acked: u64,
    pub errors: u64,
}

/// Traffic generator that signs up unique users and then validates their
/// bearer tokens via `GET /v1/users/me`, in a tight loop. Exercises the
/// production DB path (writes + reads against Postgres) and the
/// signing-key path (JWT issued by O must validate on N).
pub struct LoginLoop {
    stop: Arc<AtomicBool>,
    acked: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    handles: Vec<thread::JoinHandle<()>>,
}

#[derive(Debug)]
pub struct LoginStats {
    pub acked: u64,
    pub errors: u64,
}

impl LoginLoop {
    pub fn start(base_url: String, concurrency: usize) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let acked = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::with_capacity(concurrency);
        for worker_id in 0..concurrency {
            let stop = stop.clone();
            let acked = acked.clone();
            let errors = errors.clone();
            let base = base_url.clone();
            handles.push(thread::spawn(move || {
                // 30s per request: signup does Argon2id at OWASP cost. Under
                // 12-way CPU contention on a 2-core CI runner each hash can
                // run 10× slower than local; a tight 5s timeout starves the
                // whole loop into 100% error rate before any signup lands.
                let client = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .expect("LoginLoop client");
                let mut counter: u64 = 0;
                while !stop.load(Ordering::Relaxed) {
                    let email = format!(
                        "loop-{}-{}-{}@example.test",
                        worker_id,
                        counter,
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos()
                    );
                    counter += 1;
                    let bearer = match signup(&client, &base, &email) {
                        Some(b) => b,
                        None => {
                            errors.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };
                    match validate_me(&client, &base, &bearer) {
                        true => {
                            acked.fetch_add(1, Ordering::Relaxed);
                        }
                        false => {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }));
        }
        Self {
            stop,
            acked,
            errors,
            handles,
        }
    }

    pub fn stop(self) -> LoginStats {
        self.stop.store(true, Ordering::Relaxed);
        for h in self.handles {
            let _ = h.join();
        }
        LoginStats {
            acked: self.acked.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

fn signup(client: &reqwest::blocking::Client, base: &str, email: &str) -> Option<String> {
    let res = client
        .post(format!("{base}/v1/users"))
        .json(&serde_json::json!({
            "email": email,
            "password": "correct-horse-battery-staple",
        }))
        .send()
        .ok()?;
    if res.status().as_u16() != 201 {
        return None;
    }
    let body: serde_json::Value = res.json().ok()?;
    body.get("session")
        .and_then(|s| s.get("token"))
        .and_then(|t| t.as_str())
        .map(str::to_owned)
}

fn validate_me(client: &reqwest::blocking::Client, base: &str, bearer: &str) -> bool {
    matches!(
        client
            .get(format!("{base}/v1/users/me"))
            .bearer_auth(bearer)
            .send(),
        Ok(r) if r.status().as_u16() == 200,
    )
}

impl HealthzLoop {
    pub fn start(base_url: String, concurrency: usize) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let acked = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let stop = stop.clone();
            let acked = acked.clone();
            let errors = errors.clone();
            let url = format!("{base_url}/livez");
            handles.push(thread::spawn(move || {
                let client = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()
                    .expect("HealthzLoop client");
                // GET /livez is idempotent. A connection that was keep-alived
                // through the incumbent gets `Connection: close` (or RST) the
                // moment the drain signal fires on graceful_shutdown — a real
                // HTTP client retries idempotent GETs through that. Match
                // that behavior with a single retry so we measure customer-
                // visible availability, not raw socket churn.
                while !stop.load(Ordering::Relaxed) {
                    let outcome = match client.get(&url).send() {
                        Ok(r) if r.status().as_u16() == 200 => Ok(()),
                        Ok(r) => Err(format!("status {}", r.status())),
                        Err(e) => Err(e.to_string()),
                    };
                    let final_outcome = match outcome {
                        Ok(()) => Ok(()),
                        Err(_) => match client.get(&url).send() {
                            Ok(r) if r.status().as_u16() == 200 => Ok(()),
                            Ok(r) => Err(format!("status {}", r.status())),
                            Err(e) => Err(e.to_string()),
                        },
                    };
                    if final_outcome.is_ok() {
                        acked.fetch_add(1, Ordering::Relaxed);
                    } else {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        Self {
            stop,
            acked,
            errors,
            handles,
        }
    }

    pub fn stop(self) -> HealthzStats {
        self.stop.store(true, Ordering::Relaxed);
        for h in self.handles {
            let _ = h.join();
        }
        HealthzStats {
            acked: self.acked.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}
