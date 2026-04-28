use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use sqlx::PgPool;
use tokio::sync::OnceCell;

use beyond_auth::test_server::{BenchServer, create_session};

use crate::harness::{Scenario, WorkerCtx};

const SCHEMA: &str = r#"{"version":1,"resources":[{"name":"doc","roles":["viewer"],"permissions":{"view":["viewer"]}}]}"#;
const RESOURCE_ID: &str = "bench-warm-doc";

pub struct WarmCheck {
    url: String,
    admin_secret: &'static str,
    client: Client,
    bearer: OnceCell<String>,
    user_id: OnceCell<String>,
}

impl WarmCheck {
    pub fn new(server: &BenchServer) -> Self {
        Self {
            url: server.url.clone(),
            admin_secret: server.admin_secret,
            client: Client::new(),
            bearer: OnceCell::new(),
            user_id: OnceCell::new(),
        }
    }
}

#[async_trait]
impl Scenario for WarmCheck {
    fn name(&self) -> &str {
        "http::warm_check"
    }

    fn question(&self) -> &str {
        "Full-stack authz check throughput with a hot in-process cache (0 DB calls on repeat checks)"
    }

    async fn setup(&self, pool: &PgPool) -> Result<()> {
        // Set authz schema in service (updates in-memory compiled schema)
        self.client
            .put(format!("{}/v1/authz/schema", self.url))
            .header("Authorization", format!("Bearer {}", self.admin_secret))
            .header("Content-Type", "application/json")
            .body(SCHEMA)
            .send()
            .await?
            .error_for_status()?;

        // Create a real user + session in DB
        let session = create_session(pool).await?;
        let user_id = session.user_id.to_string();

        // Write one relation directly in DB
        sqlx::query(
            "INSERT INTO auth.authz_relations \
             (object_type, object_id, relation, subject_id) \
             VALUES ('doc', $1, 'viewer', $2) ON CONFLICT DO NOTHING",
        )
        .bind(RESOURCE_ID)
        .bind(&user_id)
        .execute(pool)
        .await?;

        self.bearer.set(session.bearer).ok();
        self.user_id.set(user_id).ok();
        Ok(())
    }

    async fn run(&self, _ctx: &mut WorkerCtx<'_>) -> Result<()> {
        let bearer = self.bearer.get().expect("setup not called");
        let resp = self
            .client
            .get(format!("{}/v1/authz/decisions", self.url))
            .query(&[
                ("permission", "view"),
                ("resource_type", "doc"),
                ("resource_id", RESOURCE_ID),
            ])
            .header("Authorization", bearer)
            .send()
            .await?
            .error_for_status()?;
        let _: serde_json::Value = resp.json().await?;
        Ok(())
    }
}
