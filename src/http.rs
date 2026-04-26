use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Request, State},
    http::header,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use bytes::Bytes;
use sqlx::PgPool;
use tower::ServiceBuilder;
use tower_helmet::HelmetLayer;
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use utoipa::OpenApi;
use uuid::Uuid;

use crate::{
    metrics::Metrics,
    routes::{self, ApiDoc},
};

#[derive(Clone)]
pub struct AppState {
    #[allow(dead_code)]
    pub pool: PgPool,
    pub jwks: Arc<Bytes>,
    pub metrics: Arc<Metrics>,
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

fn router(state: AppState) -> Router {
    let openapi = ApiDoc::openapi();

    routes::router()
        .route("/openapi.json", get(move || async move { Json(openapi) }))
        .route("/metrics", get(metrics_handler))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, record_metrics))
        .layer(
            ServiceBuilder::new()
                .layer(HelmetLayer::with_defaults())
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

async fn record_metrics(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
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
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
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
