#[allow(unused_imports)]
use prometheus::{
    Counter, CounterVec, Encoder as _, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec,
    Opts, Registry, TextEncoder,
};

macro_rules! define_metrics {
    (
        $(#[$struct_meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $metric_type:ident $field:ident($metric_name:literal)
                $([$($label:literal),+ $(,)?])?
                $(buckets = $buckets:expr)?
                => $help:literal
            ),* $(,)?
        }
    ) => {
        $(#[$struct_meta])*
        $vis struct $name {
            pub registry: Registry,
            $(pub $field: define_metrics!(@field_type $metric_type $([$($label),+])?),)*
        }

        impl $name {
            pub fn new() -> Self {
                let registry = Registry::new();
                $(
                    let $field = define_metrics!(
                        @create $metric_type $metric_name $help
                        $([$($label),+])?
                        $(buckets = $buckets)?
                    );
                    registry.register(Box::new($field.clone())).expect("metric not yet registered");
                )*
                Self { registry, $($field,)* }
            }

            #[allow(dead_code)]
            pub fn registry(&self) -> &Registry { &self.registry }

            pub fn encode(&self) -> String {
                let mut buf = Vec::new();
                TextEncoder::new().encode(&self.registry.gather(), &mut buf)
                    .expect("encoding to vec never fails");
                String::from_utf8(buf).expect("prometheus outputs valid utf-8")
            }
        }

        impl Default for $name {
            fn default() -> Self { Self::new() }
        }
    };

    (@field_type counter) => { Counter };
    (@field_type counter [$($label:literal),+]) => { CounterVec };
    (@field_type counter_vec) => { CounterVec };
    (@field_type counter_vec [$($label:literal),+]) => { CounterVec };
    (@field_type gauge) => { Gauge };
    (@field_type gauge [$($label:literal),+]) => { GaugeVec };
    (@field_type gauge_vec) => { GaugeVec };
    (@field_type gauge_vec [$($label:literal),+]) => { GaugeVec };
    (@field_type histogram) => { Histogram };
    (@field_type histogram [$($label:literal),+]) => { HistogramVec };
    (@field_type histogram_vec) => { HistogramVec };
    (@field_type histogram_vec [$($label:literal),+]) => { HistogramVec };

    (@create counter $name:literal $help:literal) => {
        Counter::new($name, $help).expect("valid metric")
    };
    (@create counter $name:literal $help:literal [$($label:literal),+]) => {
        CounterVec::new(Opts::new($name, $help), &[$($label),+]).expect("valid metric")
    };
    (@create counter_vec $name:literal $help:literal [$($label:literal),+]) => {
        CounterVec::new(Opts::new($name, $help), &[$($label),+]).expect("valid metric")
    };
    (@create gauge $name:literal $help:literal) => {
        Gauge::new($name, $help).expect("valid metric")
    };
    (@create gauge $name:literal $help:literal [$($label:literal),+]) => {
        GaugeVec::new(Opts::new($name, $help), &[$($label),+]).expect("valid metric")
    };
    (@create gauge_vec $name:literal $help:literal [$($label:literal),+]) => {
        GaugeVec::new(Opts::new($name, $help), &[$($label),+]).expect("valid metric")
    };
    (@create histogram $name:literal $help:literal) => {
        Histogram::with_opts(HistogramOpts::new($name, $help)).expect("valid metric")
    };
    (@create histogram $name:literal $help:literal buckets = $buckets:expr) => {
        Histogram::with_opts(
            HistogramOpts::new($name, $help).buckets($buckets.to_vec())
        ).expect("valid metric")
    };
    (@create histogram $name:literal $help:literal [$($label:literal),+]) => {
        HistogramVec::new(HistogramOpts::new($name, $help), &[$($label),+]).expect("valid metric")
    };
    (@create histogram $name:literal $help:literal [$($label:literal),+] buckets = $buckets:expr) => {
        HistogramVec::new(
            HistogramOpts::new($name, $help).buckets($buckets.to_vec()),
            &[$($label),+],
        ).expect("valid metric")
    };
    (@create histogram_vec $name:literal $help:literal [$($label:literal),+]) => {
        HistogramVec::new(HistogramOpts::new($name, $help), &[$($label),+]).expect("valid metric")
    };
    (@create histogram_vec $name:literal $help:literal [$($label:literal),+] buckets = $buckets:expr) => {
        HistogramVec::new(
            HistogramOpts::new($name, $help).buckets($buckets.to_vec()),
            &[$($label),+],
        ).expect("valid metric")
    };
}

// Bucket sets grouped by operation latency profile.
// Each tier covers the expected p50–p99 range for that class of operation.

/// HTTP request latency — from 5ms fast-path to 2.5s slow requests.
const HTTP_BUCKETS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5];
/// Database-backed operations — 1ms fast-path through 1s slow queries.
const DB_OP_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0];
/// In-memory fast operations (cache lookups, authz checks) — sub-ms to ~250ms.
const FAST_OP_BUCKETS: &[f64] = &[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25];
/// Password hashing (Argon2id) — 50ms–2s depending on cost parameter.
const CRYPTO_BUCKETS: &[f64] = &[0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0, 2.0];

define_metrics! {
    pub struct Metrics {
        counter_vec http_requests_total("http_requests_total")["method", "path", "status"]
            => "Total HTTP requests",
        histogram_vec http_request_duration_seconds("http_request_duration_seconds")["method", "path"]
            buckets = HTTP_BUCKETS
            => "HTTP request duration in seconds",
        gauge http_connections_active("http_connections_active")
            => "HTTP requests currently in flight",

        // Auth error breakdown — useful for distinguishing user errors from service errors.
        counter_vec auth_errors_total("auth_errors_total")["code"]
            => "Auth errors by machine-readable code",

        // DB connection pool saturation — pool exhaustion shows up here before latency spikes.
        gauge db_pool_size("db_pool_size")
            => "Total connections in the pool (active + idle)",
        gauge db_pool_idle("db_pool_idle")
            => "Idle connections in the pool",
        gauge db_pool_active("db_pool_active")
            => "Active (checked-out) connections in the pool",
        counter db_pool_acquire_timeouts_total("db_pool_acquire_timeouts_total")
            => "Total database pool acquire timeout errors (pool exhausted)",

        // Authz cache effectiveness.
        counter authz_cache_hits_total("authz_cache_hits_total")
            => "Authz cache hits",
        counter authz_cache_misses_total("authz_cache_misses_total")
            => "Authz cache misses (expired, version-invalidated, or cold)",
        counter authz_cache_invalidations_total("authz_cache_invalidations_total")
            => "Authz cache version bumps from relation writes",

        // Token GC health.
        counter_vec token_gc_deleted_total("token_gc_deleted_total")["kind"]
            => "Tokens deleted by GC, by kind (one_time, session, idle_session)",
        counter token_gc_errors_total("token_gc_errors_total")
            => "Token GC failures — repeated non-zero values indicate table bloat risk",

        // Authz check outcomes — allowed/denied/invalid_token.
        counter_vec authz_checks_total("authz_checks_total")["result"]
            => "Authz decisions by outcome (allowed, denied, invalid_token)",

        // Per-operation latency histograms.
        histogram authz_check_duration_seconds("authz_check_duration_seconds")
            buckets = FAST_OP_BUCKETS
            => "Duration of authz check DB queries in seconds",
        histogram session_validation_duration_seconds("auth_session_validation_duration_seconds")
            buckets = DB_OP_BUCKETS
            => "Session validation duration in seconds (require_auth middleware)",
        histogram password_hash_duration_seconds("auth_password_hash_duration_seconds")
            buckets = CRYPTO_BUCKETS
            => "Password hash/verify duration in seconds (Argon2id)",

        // Token GC liveness.
        gauge token_gc_last_run_timestamp_seconds("token_gc_last_run_timestamp_seconds")
            => "Unix timestamp of the last successful GC pass",

        // Signing key lifecycle events.
        counter signing_key_rotations_total("auth_signing_key_rotations_total")
            => "Signing keys generated (new active key created)",
        counter signing_key_reencryptions_total("auth_signing_key_reencryptions_total")
            => "Signing keys re-encrypted with current KEK",
    }
}
