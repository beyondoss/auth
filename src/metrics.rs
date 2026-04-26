use std::sync::Arc;

use prometheus::{CounterVec, HistogramVec, Opts, Registry, histogram_opts};

pub struct Metrics {
    pub http_requests_total: CounterVec,
    pub http_request_duration_seconds: HistogramVec,
    pub registry: Registry,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        let registry = Registry::new();

        let http_requests_total = CounterVec::new(
            Opts::new("http_requests_total", "Total HTTP requests"),
            &["method", "path", "status"],
        )
        .expect("valid metric");

        let http_request_duration_seconds = HistogramVec::new(
            histogram_opts!(
                "http_request_duration_seconds",
                "HTTP request duration in seconds",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]
            ),
            &["method", "path"],
        )
        .expect("valid metric");

        registry
            .register(Box::new(http_requests_total.clone()))
            .expect("unique metric");
        registry
            .register(Box::new(http_request_duration_seconds.clone()))
            .expect("unique metric");

        Arc::new(Self {
            http_requests_total,
            http_request_duration_seconds,
            registry,
        })
    }

    pub fn render(&self) -> Result<String, prometheus::Error> {
        use prometheus::{Encoder, TextEncoder};
        let mut buf = Vec::new();
        TextEncoder::new().encode(&self.registry.gather(), &mut buf)?;
        match String::from_utf8(buf) {
            Ok(s) => Ok(s),
            Err(e) => {
                tracing::error!(error = %e, "metrics render produced invalid UTF-8");
                Ok(String::new())
            }
        }
    }
}
