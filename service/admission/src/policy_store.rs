//! Policy store abstraction and PostgreSQL implementation for OPA policies.
//!
//! The `PolicyStore` trait allows swapping backends (e.g. filesystem) later
//! without touching admission logic.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{error, info};

/// A single OPA policy row loaded from the store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaPolicy {
    pub policy_id: String,
    pub version: i64,
    pub capability: String,
    pub tenant: Option<String>,
    pub priority: i32,
    pub entrypoint: String,
    pub module: String,
    pub data: Option<Value>,
    pub limits: Option<Value>,
    pub scope: Option<Value>,
    pub metadata: Option<Value>,
    pub active: bool,
}

/// Abstraction over policy storage backends.
#[async_trait]
pub trait PolicyStore: Send + Sync {
    /// Load all active policies, ordered by priority then policy_id.
    async fn load_policies(&self) -> anyhow::Result<Vec<OpaPolicy>>;
}

/// PostgreSQL-backed policy store using `deadpool-postgres`.
pub struct PostgresPolicyStore {
    pool: deadpool_postgres::Pool,
}

impl PostgresPolicyStore {
    /// Create a new store from a connection string.
    ///
    /// The URL should be a standard PostgreSQL connection string, e.g.
    /// `postgres://user:pass@host:5432/dbname`.
    pub fn new(pg_url: &str) -> anyhow::Result<Self> {
        let pg_config: tokio_postgres::Config = pg_url.parse()?;

        let mgr_config = deadpool_postgres::ManagerConfig {
            recycling_method: deadpool_postgres::RecyclingMethod::Fast,
        };
        let mgr =
            deadpool_postgres::Manager::from_config(pg_config, tokio_postgres::NoTls, mgr_config);

        let pool = deadpool_postgres::Pool::builder(mgr)
            .max_size(4)
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build PG pool: {}", e))?;

        info!("PostgreSQL policy store initialised");
        Ok(Self { pool })
    }
}

#[async_trait]
impl PolicyStore for PostgresPolicyStore {
    async fn load_policies(&self) -> anyhow::Result<Vec<OpaPolicy>> {
        let client = self.pool.get().await.map_err(|e| {
            error!("failed to acquire PG connection: {}", e);
            anyhow::anyhow!("PG pool error: {}", e)
        })?;

        let rows = client
            .query(
                "SELECT policy_id, version, capability, tenant, priority, \
                        entrypoint, module, data, limits, scope, metadata, active \
                 FROM opa_policies \
                 WHERE active = true \
                 ORDER BY priority, policy_id",
                &[],
            )
            .await?;

        let policies = rows
            .iter()
            .map(|row| OpaPolicy {
                policy_id: row.get("policy_id"),
                version: row.get("version"),
                capability: row.get("capability"),
                tenant: row.get("tenant"),
                priority: row.get("priority"),
                entrypoint: row.get("entrypoint"),
                module: row.get("module"),
                data: row.get("data"),
                limits: row.get("limits"),
                scope: row.get("scope"),
                metadata: row.get("metadata"),
                active: row.get("active"),
            })
            .collect::<Vec<_>>();

        info!(
            "loaded {} active OPA policies from PostgreSQL",
            policies.len()
        );
        Ok(policies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opa_policy_serde_round_trip() {
        let policy = OpaPolicy {
            policy_id: "test-policy".into(),
            version: 1,
            capability: "fs.read.v1".into(),
            tenant: None,
            priority: 0,
            entrypoint: "data.smith.deny".into(),
            module: "package smith\ndeny[msg] { msg := \"no\" }".into(),
            data: Some(serde_json::json!({"key": "value"})),
            limits: None,
            scope: None,
            metadata: None,
            active: true,
        };

        let json = serde_json::to_string(&policy).unwrap();
        let deser: OpaPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.policy_id, "test-policy");
        assert_eq!(deser.capability, "fs.read.v1");
        assert_eq!(deser.entrypoint, "data.smith.deny");
    }
}
