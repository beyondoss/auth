//! `handoff::Drainable` bridge for `beyond-auth`.
//!
//! Auth has no on-disk state — Postgres is the source of truth — so `seal()`
//! is a no-op. The interesting work is `drain()`: stop accepting new
//! connections (kernel keeps the listener bound; the SYN queue absorbs the
//! gap), then wait for in-flight requests to complete. Connection tracking
//! lives in the accept loop in [`crate::http`] via shared atomics.
//!
//! Topology: the bridge runs on the dedicated handoff control thread
//! (where `handoff::Incumbent::serve` blocks). The accept loop runs on the
//! tokio runtime. They communicate through two atomics:
//!
//! - `accept_paused`: set by `drain()`, cleared by `resume_after_abort()`.
//!   The accept loop checks this before each `accept()` and parks instead
//!   of pulling from the kernel queue when it's true.
//! - `in_flight`: incremented in the accept loop on each new connection,
//!   decremented when its per-connection task finishes. `drain()` polls
//!   this until it hits zero (or the deadline expires).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use handoff::{DrainReport, Drainable, SealReport, StateSnapshot};
use tokio::sync::Notify;

/// One-shot broadcast: `trigger()` flips a flag and wakes everyone currently
/// in `wait()`. Tasks that call `wait()` *after* `trigger()` return
/// immediately. Used to tell every per-connection task that drain has
/// started so they call `graceful_shutdown()` on their hyper Connection.
///
/// `Notify::notify_waiters()` alone isn't enough: it only wakes already-
/// registered waiters, so a connection task that registered its waker
/// *after* `notify_waiters()` fired would block forever and `in_flight`
/// would never reach zero.
pub struct DrainSignal {
    flag: AtomicBool,
    notify: Notify,
}

impl DrainSignal {
    fn new() -> Self {
        Self {
            flag: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn reset(&self) {
        // After an aborted handoff: new connections opened after this
        // point shouldn't fire graceful_shutdown immediately. Existing
        // (pre-trigger) tasks already called graceful_shutdown and have
        // exited; no waiters to lose.
        self.flag.store(false, Ordering::SeqCst);
    }

    pub async fn wait(&self) {
        loop {
            if self.flag.load(Ordering::SeqCst) {
                return;
            }
            // Register the waker before re-checking the flag, otherwise a
            // trigger() racing with our load could be missed.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            if self.flag.load(Ordering::SeqCst) {
                return;
            }
            notified.as_mut().await;
        }
    }
}

/// Shared state wired between [`AuthDrainable`] and the accept loop.
#[derive(Clone)]
pub struct SharedState {
    pub accept_paused: Arc<AtomicBool>,
    pub in_flight: Arc<AtomicUsize>,
    pub drain_signal: Arc<DrainSignal>,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            accept_paused: Arc::new(AtomicBool::new(false)),
            in_flight: Arc::new(AtomicUsize::new(0)),
            drain_signal: Arc::new(DrainSignal::new()),
        }
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AuthDrainable {
    accept_paused: Arc<AtomicBool>,
    in_flight: Arc<AtomicUsize>,
    drain_signal: Arc<DrainSignal>,
}

impl AuthDrainable {
    pub fn new(state: SharedState) -> Self {
        Self {
            accept_paused: state.accept_paused,
            in_flight: state.in_flight,
            drain_signal: state.drain_signal,
        }
    }
}

impl Drainable for AuthDrainable {
    fn drain(&self, deadline: Instant) -> handoff::Result<DrainReport> {
        self.accept_paused.store(true, Ordering::SeqCst);
        // Tell every per-connection task to call `graceful_shutdown` on its
        // hyper Connection. Without this, HTTP/1.1 keep-alive connections
        // sit idle (no request in flight, no data on the wire) but still
        // count toward `in_flight`, and drain times out.
        self.drain_signal.trigger();

        #[cfg(feature = "test-server")]
        {
            if std::env::var("BEYOND_AUTH_TEST_PANIC_DURING_DRAIN").is_ok() {
                panic!("BEYOND_AUTH_TEST_PANIC_DURING_DRAIN tripped");
            }
            if let Ok(ms) = std::env::var("BEYOND_AUTH_TEST_SLOW_DRAIN_MS")
                && let Ok(ms) = ms.parse::<u64>()
            {
                std::thread::sleep(Duration::from_millis(ms));
            }
        }

        while self.in_flight.load(Ordering::Relaxed) > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
        }

        let remaining = self.in_flight.load(Ordering::Relaxed);
        tracing::info!(open_conns_remaining = remaining, "drain complete");
        Ok(DrainReport {
            open_conns_remaining: remaining as u32,
            accept_closed: true,
        })
    }

    fn seal(&self) -> handoff::Result<SealReport> {
        // Auth has no on-disk state. Postgres holds the durable record and
        // its own write guarantees cover us. If `seal` ever grows real work
        // (e.g. flushing an embedded cache), expand the handoff integration
        // tests at the same time — the no-state assumption is load-bearing.
        #[cfg(feature = "test-server")]
        {
            if let Ok(path) = std::env::var("BEYOND_AUTH_TEST_FAIL_SEAL_ONCE_FILE") {
                let p = std::path::Path::new(&path);
                if p.exists() {
                    let _ = std::fs::remove_file(p);
                    return Err(handoff::Error::Protocol(
                        "BEYOND_AUTH_TEST_FAIL_SEAL_ONCE_FILE tripped".into(),
                    ));
                }
            }
        }
        Ok(SealReport::default())
    }

    fn resume_after_abort(&self) -> handoff::Result<()> {
        self.accept_paused.store(false, Ordering::SeqCst);
        self.drain_signal.reset();
        tracing::info!("handoff aborted; accept loop resumed");
        Ok(())
    }

    fn snapshot_state(&self) -> StateSnapshot {
        StateSnapshot {
            shard_count: 0,
            open_conns: self.in_flight.load(Ordering::Relaxed) as u32,
            last_revision_per_shard: Vec::new(),
        }
    }
}
