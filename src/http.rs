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
use sqlx::PgPool;
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use utoipa::OpenApi;
use uuid::Uuid;

use crate::{
    app_config::AppConfig,
    authz::{cache::AuthzCache, schema::CompiledSchema},
    keys::LoadedKey,
    metrics::Metrics,
    routes::{self, ApiDoc},
};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub jwks: Arc<Bytes>,
    pub signing_key: Arc<LoadedKey>,
    pub app_config: Arc<RwLock<AppConfig>>,
    pub authz_schema: Arc<RwLock<Option<CompiledSchema>>>,
    pub metrics: Arc<Metrics>,
    pub admin_secret: String,
    pub http_client: reqwest::Client,
    pub oauth: Arc<RwLock<crate::oauth::OAuthProviders>>,
    pub webauthn: Arc<webauthn_rs::Webauthn>,
    pub encryptor: std::sync::Arc<dyn crate::crypto::KeyEncryptor>,
    /// Parsed origins (e.g. "https://app.example.com") allowed as OAuth redirect targets.
    /// Empty means no validation is performed — callers should warn at startup.
    pub oauth_redirect_allowlist: Vec<String>,
    /// Public base URL of this service (e.g. "https://auth.example.com"), used to construct
    /// OAuth callback URIs. When None, derived from the incoming request Host header.
    pub public_url: Option<String>,
    pub authz_cache: Arc<AuthzCache>,
}

#[derive(Clone)]
struct MakeRequestUuid;

impl MakeRequestId for MakeRequestUuid {
    fn make_request_id<B>(&mut self, _: &axum::http::Request<B>) -> Option<RequestId> {
        let id = Uuid::new_v4().to_string().parse().ok()?;
        Some(RequestId::new(id))
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
                .layer(TraceLayer::new_for_http())
                .layer(TimeoutLayer::with_status_code(
                    axum::http::StatusCode::REQUEST_TIMEOUT,
                    Duration::from_secs(30),
                ))
                .layer(CatchPanicLayer::new()),
        )
}

async fn record_metrics(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let method = req.method().as_str().to_string();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let timer = state
        .metrics
        .http_request_duration_seconds
        .with_label_values(&[&method, &path]);
    let start = Instant::now();

    let response = next.run(req).await;

    let status = response.status().as_u16().to_string();
    state
        .metrics
        .http_requests_total
        .with_label_values(&[&method, &path, &status])
        .inc();
    timer.observe(start.elapsed().as_secs_f64());

    response
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    match state.metrics.render() {
        Ok(body) => (
            axum::http::StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            body,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "failed to encode metrics");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received, draining connections");
}
