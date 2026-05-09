#![allow(dead_code)]

use std::sync::Arc;
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
use quick_cache::sync::Cache;
use sqlx::PgPool;
use tokio::sync::RwLock;
use tower::ServiceBuilder;
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

pub async fn serve(bind_addr: &str, state: AppState) -> Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    tracing::info!(addr = bind_addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

pub async fn serve_with_listener(listener: tokio::net::TcpListener, state: AppState) -> Result<()> {
    let app = router(state);
    axum::serve(listener, app).await?;
    Ok(())
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

    tracing::info!("shutdown signal received, draining connections");
}
