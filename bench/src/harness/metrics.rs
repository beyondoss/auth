use std::time::Duration;

use anyhow::Result;
use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub name: String,
    pub value: f64,
    pub unit: String,
}

impl Metric {
    pub fn new(name: impl Into<String>, value: f64, unit: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value,
            unit: unit.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub mean_us: f64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub p999_us: u64,
    pub max_us: u64,
    pub count: u64,
}

impl LatencyStats {
    pub fn from_histogram(h: &Histogram<u64>) -> Self {
        Self {
            mean_us: h.mean(),
            p50_us: h.value_at_quantile(0.50),
            p95_us: h.value_at_quantile(0.95),
            p99_us: h.value_at_quantile(0.99),
            p999_us: h.value_at_quantile(0.999),
            max_us: h.max(),
            count: h.len(),
        }
    }
}

pub fn new_histogram() -> Histogram<u64> {
    // 1µs..60s, 3 sig figs.
    Histogram::new_with_bounds(1, 60_000_000, 3).expect("valid histogram bounds")
}

pub fn record_duration(h: &mut Histogram<u64>, d: Duration) {
    let micros = d.as_micros().min(u64::MAX as u128) as u64;
    let _ = h.record(micros.max(1));
}

/// Snapshot of `pg_stat_database` + `pg_stat_wal` for the current database.
/// Used by taking before/after snapshots and computing the delta.
#[derive(Debug, Clone)]
pub struct PgStatSnapshot {
    pub xact_commit: i64,
    pub xact_rollback: i64,
    pub tup_returned: i64,
    pub tup_fetched: i64,
    pub tup_inserted: i64,
    pub tup_updated: i64,
    pub tup_deleted: i64,
    pub blks_hit: i64,
    pub blks_read: i64,
    pub wal_bytes: i64,
}

impl PgStatSnapshot {
    pub async fn capture(pool: &PgPool) -> Result<Self> {
        let row = sqlx::query(
            r#"
            SELECT
                COALESCE(d.xact_commit, 0)   AS xact_commit,
                COALESCE(d.xact_rollback, 0) AS xact_rollback,
                COALESCE(d.tup_returned, 0)  AS tup_returned,
                COALESCE(d.tup_fetched, 0)   AS tup_fetched,
                COALESCE(d.tup_inserted, 0)  AS tup_inserted,
                COALESCE(d.tup_updated, 0)   AS tup_updated,
                COALESCE(d.tup_deleted, 0)   AS tup_deleted,
                COALESCE(d.blks_hit, 0)      AS blks_hit,
                COALESCE(d.blks_read, 0)     AS blks_read,
                COALESCE((SELECT wal_bytes::bigint FROM pg_stat_wal), 0) AS wal_bytes
            FROM pg_stat_database d
            WHERE d.datname = current_database()
            "#,
        )
        .fetch_one(pool)
        .await?;
        Ok(Self {
            xact_commit: row.try_get("xact_commit")?,
            xact_rollback: row.try_get("xact_rollback")?,
            tup_returned: row.try_get("tup_returned")?,
            tup_fetched: row.try_get("tup_fetched")?,
            tup_inserted: row.try_get("tup_inserted")?,
            tup_updated: row.try_get("tup_updated")?,
            tup_deleted: row.try_get("tup_deleted")?,
            blks_hit: row.try_get("blks_hit")?,
            blks_read: row.try_get("blks_read")?,
            wal_bytes: row.try_get("wal_bytes")?,
        })
    }

    pub fn delta(&self, prev: &Self) -> Vec<Metric> {
        let d_commit = self.xact_commit - prev.xact_commit;
        let d_rollback = self.xact_rollback - prev.xact_rollback;
        let d_returned = self.tup_returned - prev.tup_returned;
        let d_fetched = self.tup_fetched - prev.tup_fetched;
        let d_inserted = self.tup_inserted - prev.tup_inserted;
        let d_updated = self.tup_updated - prev.tup_updated;
        let d_deleted = self.tup_deleted - prev.tup_deleted;
        let d_hit = self.blks_hit - prev.blks_hit;
        let d_read = self.blks_read - prev.blks_read;
        let d_wal = self.wal_bytes - prev.wal_bytes;
        let cache_hit_ratio = if d_hit + d_read > 0 {
            d_hit as f64 / (d_hit + d_read) as f64
        } else {
            0.0
        };
        vec![
            Metric::new("xact_commit", d_commit as f64, "txns"),
            Metric::new("xact_rollback", d_rollback as f64, "txns"),
            Metric::new("tup_returned", d_returned as f64, "rows"),
            Metric::new("tup_fetched", d_fetched as f64, "rows"),
            Metric::new("tup_inserted", d_inserted as f64, "rows"),
            Metric::new("tup_updated", d_updated as f64, "rows"),
            Metric::new("tup_deleted", d_deleted as f64, "rows"),
            Metric::new("buffer_cache_hit_ratio", cache_hit_ratio, "ratio"),
            Metric::new("wal_bytes", d_wal as f64, "bytes"),
        ]
    }
}
