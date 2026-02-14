//! Policy sync service: periodically loads policies from PostgreSQL
//! and pushes them to the OPA management server REST API.

use std::time::Duration;

use anyhow::Result;
use tokio::{select, signal};
use tracing::{error, info};

use crate::config::AdmissionConfig;
use crate::metrics::MetricsServer;
use crate::policy_store::{OpaPolicy, PolicyStore, PostgresPolicyStore};

/// Periodically syncs OPA policies from PostgreSQL to the OPA server.
pub struct PolicySyncService {
    policy_store: PostgresPolicyStore,
    opa_url: String,
    metrics_server: MetricsServer,
}

impl PolicySyncService {
    pub async fn new(config: AdmissionConfig) -> Result<Self> {
        let policy_store = PostgresPolicyStore::new(&config.pg_url)?;
        let metrics_server = MetricsServer::new(config.metrics_addr);
        Ok(Self {
            policy_store,
            opa_url: config.opa_url,
            metrics_server,
        })
    }

    pub async fn run(self) -> Result<()> {
        info!("Starting policy sync service");
        let metrics_handle = self.metrics_server.start().await?;

        // Initial sync
        self.sync().await;

        // Periodic reconciliation (60s)
        loop {
            select! {
                _ = tokio::time::sleep(Duration::from_secs(60)) => {
                    self.sync().await;
                }
                _ = signal::ctrl_c() => {
                    info!("Received shutdown signal");
                    break;
                }
            }
        }

        metrics_handle.abort();
        info!("Policy sync service stopped");
        Ok(())
    }

    async fn sync(&self) {
        match self.policy_store.load_policies().await {
            Ok(policies) => {
                sync_policies_to_opa(&policies, &self.opa_url).await;
                crate::metrics::set_policies_loaded(policies.len());
                crate::metrics::record_sync("success");
            }
            Err(e) => {
                error!("Failed to load policies from PostgreSQL: {}", e);
                crate::metrics::record_sync("error");
            }
        }
    }
}

/// Sync policies to the OPA management server REST API.
///
/// Pushes each active policy's Rego module via `PUT /v1/policies/{id}`
/// and optional data document via `PUT /v1/data` (merge).
async fn sync_policies_to_opa(policies: &[OpaPolicy], opa_url: &str) {
    let client = reqwest::Client::new();

    for policy in policies {
        if !policy.active {
            continue;
        }

        // PUT module: /v1/policies/{policy_id}
        let policy_url = format!("{}/v1/policies/{}", opa_url, policy.policy_id);
        match client
            .put(&policy_url)
            .header("Content-Type", "text/plain")
            .body(policy.module.clone())
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                info!("Synced policy '{}' module to OPA", policy.policy_id);
            }
            Ok(resp) => {
                tracing::warn!(
                    "OPA rejected policy '{}': {}",
                    policy.policy_id,
                    resp.status()
                );
            }
            Err(e) => {
                tracing::warn!("Failed to sync policy '{}' to OPA: {}", policy.policy_id, e);
            }
        }

        // PUT data: /v1/data (merge entire data document)
        if let Some(ref data) = policy.data {
            let data_url = format!("{}/v1/data", opa_url);
            match client.put(&data_url).json(data).send().await {
                Ok(resp) if resp.status().is_success() => {
                    info!("Synced policy '{}' data to OPA", policy.policy_id);
                }
                Ok(resp) => {
                    tracing::warn!(
                        "OPA rejected data for '{}': {}",
                        policy.policy_id,
                        resp.status()
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to sync data for '{}' to OPA: {}",
                        policy.policy_id,
                        e
                    );
                }
            }
        }
    }
}
