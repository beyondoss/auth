use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use sqlx::PgPool;
use tokio::sync::OnceCell;

use beyond_auth::test_server::{BenchServer, create_session};

use crate::harness::{Scenario, WorkerCtx, ZipfSampler};

const SCHEMA: &str = r#"{"version":1,"resources":[{"name":"doc","roles":["viewer"],"permissions":{"view":["viewer"]}}]}"#;
const N_OBJECTS: usize = 10_000;

pub struct ColdCheck {
    url: String,
    admin_secret: &'static str,
    client: Client,
    bearer: OnceCell<String>,
    sampler: ZipfSampler,
}

impl ColdCheck {
    pub fn new(server: &BenchServer) -> Self {
        Self {
            url: server.url.clone(),
            admin_secret: server.admin_secret,
            client: Client::new(),
            bearer: OnceCell::new(),
            sampler: ZipfSampler::new(N_OBJECTS, 1.0),
        }
    }
}

#[async_trait]
impl Scenario for ColdCheck {
    fn name(&self) -> &str {
        "http::cold_check"
    }

    fn question(&self) -> &str {
        "Full-stack authz check throughput with Zipf-sampled resource set (realistic cache hit mix)"
    }

    async fn setup(&self, pool: &PgPool) -> Result<()> {
        self.client
            .put(format!("{}/v1/authz/schema", self.url))
            .header("Authorization", format!("Bearer {}", self.admin_secret))
            .header("Content-Type", "application/json")
            .body(SCHEMA)
            .send()
            .await?
            .error_for_status()?;

        let session = create_session(pool).await?;
        let user_id = session.user_id.to_string();

        // Bulk-insert N relations directly in DB
        let mut qb = sqlx::QueryBuilder::new(
            "INSERT INTO auth.authz_relations \
             (object_type, object_id, relation, subject_id) ",
        );
        qb.push_values(0..N_OBJECTS, |mut b, i| {
            b.push_bind("doc")
                .push_bind(format!("bench-cold-{i:06}"))
                .push_bind("viewer")
                .push_bind(user_id.clone());
        });
        qb.push(" ON CONFLICT DO NOTHING");
        qb.build().execute(pool).await?;

        self.bearer.set(session.bearer).ok();
        Ok(())
    }

    async fn run(&self, ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let bearer = self.bearer.get().expect("setup not called");
        let i = self.sampler.sample(&mut ctx.rng);
        let resource_id = format!("bench-cold-{i:06}");
        let resp = self
            .client
            .get(format!("{}/v1/authz/decisions", self.url))
            .query(&[
                ("permission", "view"),
                ("resource_type", "doc"),
                ("resource_id", &resource_id),
            ])
            .header("Authorization", bearer)
            .send()
            .await?
            .error_for_status()?;
        let _: serde_json::Value = resp.json().await?;
        Ok(())
    }
}
