#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, MatchedPath, Request, State},
    http::header,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use bytes::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperBuilder;
use quick_cache::sync::Cache;
use sqlx::PgPool;
use tokio::sync::RwLock;
use tower::{ServiceBuilder, ServiceExt};
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::{MakeSpan, TraceLayer},
};
use utoipa::OpenApi;
use uuid::Uuid;

use crate::{
    app_config::AppConfig,
    authz::{cache::AuthzCache, schema::CompiledSchema},
    handoff_bridge::{DrainSignal, SharedState},
    metrics::Metrics,
    routes::{self, ApiDoc},
    signing_keys::LoadedKey,
};

/// Wrapper for the admin bearer secret that suppresses accidental `Debug` printing
/// and zeroes memory on drop.
#[derive(Clone)]
pub struct AdminSecret(zeroize::Zeroizing<String>);

impl AdminSecret {
    pub fn new(s: String) -> Self {
        Self(zeroize::Zeroizing::new(s))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for AdminSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Tracks the last cache counter values pushed to Prometheus, so metrics_handler
/// can compute deltas without reading back from Prometheus (which uses f64).
pub struct CacheSyncState {
    pub hits: std::sync::atomic::AtomicU64,
    pub misses: std::sync::atomic::AtomicU64,
    pub invalidations: std::sync::atomic::AtomicU64,
}

impl CacheSyncState {
    pub fn new() -> Self {
        Self {
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
            invalidations: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub jwks: Arc<Bytes>,
    pub signing_key: Arc<LoadedKey>,
    pub app_config: Arc<RwLock<AppConfig>>,
    pub authz_schema: Arc<RwLock<Option<CompiledSchema>>>,
    pub metrics: Arc<Metrics>,
    pub admin_secret: AdminSecret,
    pub http_client: reqwest::Client,
    pub oauth: Arc<RwLock<crate::oauth::OAuthProviders>>,
    pub webauthn: Option<Arc<webauthn_rs::Webauthn>>,
    pub encryptor: std::sync::Arc<dyn crate::crypto::KeyEncryptor>,
    /// Parsed origins (e.g. "https://app.example.com") allowed as OAuth redirect targets.
    /// Empty means no validation is performed — callers should warn at startup.
    pub oauth_redirect_allowlist: Vec<String>,
    /// Public base URL of this service (e.g. "https://auth.example.com"), used to construct
    /// OAuth callback URIs. When None, derived from the incoming request Host header.
    pub public_url: Option<String>,
    pub authz_cache: Arc<AuthzCache>,
    pub partition_cache: Arc<Cache<String, ()>>,
    pub parallel_batch_available: bool,
    pub cache_sync: Arc<CacheSyncState>,
}

#[derive(Clone)]
struct MakeRequestUuid;

impl MakeRequestId for MakeRequestUuid {
    fn make_request_id<B>(&mut self, _: &axum::http::Request<B>) -> Option<RequestId> {
        let id = Uuid::new_v4().to_string().parse().ok()?;
        Some(RequestId::new(id))
    }
}

/// Propagates the caller's W3C trace context (`traceparent`) into the request span.
/// Without this, every request starts a fresh root trace — distributed traces from
/// callers would never connect to spans generated inside this service.
#[derive(Clone)]
struct OtelMakeSpan;

impl<B> MakeSpan<B> for OtelMakeSpan {
    fn make_span(&mut self, request: &axum::http::Request<B>) -> tracing::Span {
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;

        let method = request.method().as_str();
        let uri = request.uri();
        let version = format!("{:?}", request.version());

        let span = tracing::info_span!(
            "http.request",
            otel.kind = "server",
            http.method = method,
            http.target = %uri,
            http.flavor = version,
            http.route = tracing::field::Empty,
            http.status_code = tracing::field::Empty,
        );
        let _ = span.set_parent(crate::telemetry::extract_trace_context(request.headers()));
        span
    }
}

/// Grace window for in-flight connections to finish after the accept loop
/// exits via a SIGINT/SIGTERM (full shutdown). On a committed handoff,
/// `AuthDrainable::drain` has already waited for in-flight to reach zero,
/// so this is effectively a no-op on that path.
const SHUTDOWN_DRAIN_GRACE: Duration = Duration::from_secs(30);

/// Main entry point used by `cli::serve`. Owns the bound listener (which
/// may have been inherited from a handoff supervisor), the optional TLS
/// acceptor, and the shared atomics that the handoff control thread reads
/// to coordinate drain.
///
/// The accept loop never closes the listener — when `shared.accept_paused`
/// is true it parks instead, so the kernel's SYN backlog absorbs the gap
/// between O draining and N starting accept. This is the invariant that
/// makes zero-downtime restart possible.
pub async fn serve(
    listener: tokio::net::TcpListener,
    tls: Option<(String, String, String)>,
    state: AppState,
    shared: SharedState,
    handoff_shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let tls_acceptor = match tls.as_ref() {
        Some((cert, key, ca)) => Some(build_tls_acceptor(cert, key, ca)?),
        None => None,
    };

    let app = router(state);

    let stop_reason = accept_loop(
        listener,
        tls_acceptor,
        app,
        shared.clone(),
        handoff_shutdown.clone(),
    )
    .await;

    match stop_reason {
        StopReason::HandoffCommitted => {
            tracing::info!("handoff committed — accept loop exited; pending tasks already drained");
        }
        StopReason::Signal => {
            tracing::info!(
                grace_ms = SHUTDOWN_DRAIN_GRACE.as_millis() as u64,
                "shutdown signal received; waiting for in-flight requests to complete"
            );
            let deadline = Instant::now() + SHUTDOWN_DRAIN_GRACE;
            while shared.in_flight.load(Ordering::Relaxed) > 0 && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let remaining = shared.in_flight.load(Ordering::Relaxed);
            if remaining > 0 {
                tracing::warn!(remaining, "shutdown grace expired with open connections");
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum StopReason {
    Signal,
    HandoffCommitted,
}

async fn accept_loop(
    listener: tokio::net::TcpListener,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    app: Router,
    shared: SharedState,
    handoff_shutdown: Arc<AtomicBool>,
) -> StopReason {
    let signal_fut = shutdown_signal();
    tokio::pin!(signal_fut);

    loop {
        if handoff_shutdown.load(Ordering::Relaxed) {
            return StopReason::HandoffCommitted;
        }

        let paused = shared.accept_paused.load(Ordering::Relaxed);

        tokio::select! {
            biased;

            _ = &mut signal_fut => {
                tracing::info!("shutdown signal received, draining connections");
                return StopReason::Signal;
            }

            res = listener.accept(), if !paused => {
                match res {
                    Ok((tcp, peer)) => {
                        shared.in_flight.fetch_add(1, Ordering::Relaxed);
                        let in_flight = shared.in_flight.clone();
                        let acceptor = tls_acceptor.clone();
                        let app = app.clone();
                        let drain_signal = shared.drain_signal.clone();
                        tokio::spawn(async move {
                            serve_one_connection(tcp, peer, acceptor, app, drain_signal).await;
                            in_flight.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "accept error");
                    }
                }
            }

            // Paused: park the accept arm so the kernel's listen backlog
            // absorbs incoming SYNs. We keep the loop alive (and the
            // listener bound) for the entire drain → seal → commit window;
            // on abort we'll resume accepting from this same fd.
            _ = tokio::time::sleep(Duration::from_millis(25)), if paused => {}

            // Idle wake to check handoff_shutdown when traffic is quiet.
            // 100ms cap on commit-to-exit latency is fine — the handoff
            // protocol's own deadline is measured in seconds.
            _ = tokio::time::sleep(Duration::from_millis(100)), if !paused => {}
        }
    }
}

async fn serve_one_connection(
    tcp: tokio::net::TcpStream,
    _peer: std::net::SocketAddr,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    app: Router,
    drain_signal: Arc<DrainSignal>,
) {
    let svc = hyper::service::service_fn(move |req: axum::http::Request<hyper::body::Incoming>| {
        app.clone().oneshot(req)
    });
    // Bind the Builder so the connection future can borrow from it for its
    // entire lifetime — without this, `HyperBuilder::new(...)` is a
    // temporary that drops while the pinned future still borrows it.
    let builder = HyperBuilder::new(TokioExecutor::new());

    match tls_acceptor {
        Some(acceptor) => match acceptor.accept(tcp).await {
            Ok(tls_stream) => {
                let io = TokioIo::new(tls_stream);
                let conn = builder.serve_connection_with_upgrades(io, svc);
                tokio::pin!(conn);
                tokio::select! {
                    biased;
                    res = conn.as_mut() => {
                        if let Err(e) = res {
                            tracing::debug!(error = %e, "TLS connection serve error");
                        }
                    }
                    _ = drain_signal.wait() => {
                        conn.as_mut().graceful_shutdown();
                        if let Err(e) = conn.await {
                            tracing::debug!(error = %e, "TLS connection drained with error");
                        }
                    }
                }
            }
            Err(e) => tracing::debug!(error = %e, "TLS handshake failed"),
        },
        None => {
            let io = TokioIo::new(tcp);
            let conn = builder.serve_connection_with_upgrades(io, svc);
            tokio::pin!(conn);
            tokio::select! {
                biased;
                res = conn.as_mut() => {
                    if let Err(e) = res {
                        tracing::debug!(error = %e, "connection serve error");
                    }
                }
                _ = drain_signal.wait() => {
                    conn.as_mut().graceful_shutdown();
                    if let Err(e) = conn.await {
                        tracing::debug!(error = %e, "connection drained with error");
                    }
                }
            }
        }
    }
}

fn build_tls_acceptor(
    cert_path: &str,
    key_path: &str,
    ca_path: &str,
) -> Result<tokio_rustls::TlsAcceptor> {
    use rustls::RootCertStore;
    use rustls::ServerConfig;
    use rustls::server::WebPkiClientVerifier;
    use tokio_rustls::TlsAcceptor;

    let server_certs = tls_load_certs(cert_path)?;
    let server_key = tls_load_key(key_path)?;
    let ca_certs = tls_load_certs(ca_path)?;

    let mut ca_store = RootCertStore::empty();
    for cert in ca_certs {
        ca_store.add(cert)?;
    }

    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(
        std::sync::Arc::new(ca_store),
        provider.clone(),
    )
    .build()?;

    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(std::sync::Arc::new(cfg)))
}

fn tls_load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let f = std::fs::File::open(path)?;
    rustls_pemfile::certs(&mut std::io::BufReader::new(f))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn tls_load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let f = std::fs::File::open(path)?;
    rustls_pemfile::private_key(&mut std::io::BufReader::new(f))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {path}"))
}

/// Convenience entry for in-process test servers that don't participate in
/// the handoff protocol. Constructs throwaway shared state and a
/// never-fires handoff-shutdown flag.
pub async fn serve_with_listener(
    listener: tokio::net::TcpListener,
    tls: Option<(String, String, String)>,
    state: AppState,
) -> Result<()> {
    serve(
        listener,
        tls,
        state,
        SharedState::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await
}

fn router(state: AppState) -> Router {
    let openapi = ApiDoc::openapi();

    routes::router(state.clone())
        .route("/openapi.json", get(move || async move { Json(openapi) }))
        .route("/metrics", get(metrics_handler))
        .with_state(state.clone())
        .route_layer(middleware::from_fn_with_state(state, record_metrics))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
                .layer(PropagateRequestIdLayer::x_request_id())
                .layer(TraceLayer::new_for_http().make_span_with(OtelMakeSpan))
                .layer(TimeoutLayer::with_status_code(
                    axum::http::StatusCode::REQUEST_TIMEOUT,
                    Duration::from_secs(30),
                ))
                .layer(CatchPanicLayer::new()),
        )
}

async fn record_metrics(State(state): State<AppState>, req: Request, next: Next) -> Response {
    state.metrics.http_connections_active.inc();
    let method = req.method().as_str().to_string();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "<unmatched>".to_string());
    tracing::Span::current().record("http.route", &path);
    let timer = state
        .metrics
        .http_request_duration_seconds
        .with_label_values(&[&method, &path]);
    let start = Instant::now();

    let response = next.run(req).await;
    state.metrics.http_connections_active.dec();

    let status = response.status().as_u16();
    state
        .metrics
        .http_requests_total
        .with_label_values(&[&method, &path, &status.to_string()])
        .inc();
    timer.observe(start.elapsed().as_secs_f64());

    if let Some(code) = response.extensions().get::<crate::error::AuthErrorCode>() {
        state
            .metrics
            .auth_errors_total
            .with_label_values(&[code.0])
            .inc();
    }

    if response
        .extensions()
        .get::<crate::error::DbPoolTimeout>()
        .is_some()
    {
        state.metrics.db_pool_acquire_timeouts_total.inc();
    }

    let size = state.pool.size() as usize;
    let idle = state.pool.num_idle();
    state.metrics.db_pool_size.set(size as f64);
    state.metrics.db_pool_idle.set(idle as f64);
    state.metrics.db_pool_active.set((size - idle) as f64);

    tracing::Span::current().record("http.status_code", status);

    response
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    // Authz cache counters — sync deltas from the atomics in AuthzCache.
    let cc = state.authz_cache.counters();
    let prev_hits = state
        .cache_sync
        .hits
        .swap(cc.hits, std::sync::atomic::Ordering::Relaxed);
    let prev_misses = state
        .cache_sync
        .misses
        .swap(cc.misses, std::sync::atomic::Ordering::Relaxed);
    let prev_inv = state
        .cache_sync
        .invalidations
        .swap(cc.invalidations, std::sync::atomic::Ordering::Relaxed);
    if cc.hits > prev_hits {
        state
            .metrics
            .authz_cache_hits_total
            .inc_by((cc.hits - prev_hits) as f64);
    }
    if cc.misses > prev_misses {
        state
            .metrics
            .authz_cache_misses_total
            .inc_by((cc.misses - prev_misses) as f64);
    }
    if cc.invalidations > prev_inv {
        state
            .metrics
            .authz_cache_invalidations_total
            .inc_by((cc.invalidations - prev_inv) as f64);
    }

    (
        axum::http::StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.encode(),
    )
        .into_response()
}

/// Background task that refreshes the `auth_active_sessions_total` gauge every 60 s.
/// Running this as a task keeps the DB query off the scrape hot path.
pub async fn active_sessions_gauge(pool: sqlx::PgPool, metrics: Arc<Metrics>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        if let Ok(Some(n)) = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM auth.sessions s
         INNER JOIN auth.tokens t ON t.id = s.token_id
         WHERE t.expires_at > now()"
        )
        .fetch_one(&pool)
        .await
        {
            metrics.active_sessions_total.set(n as f64);
        }
    }
}

async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            tracing::error!(error = %e, "Ctrl+C handler failed");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => tracing::error!(error = %e, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
