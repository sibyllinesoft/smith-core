//! Configuration for the Smith Policy Sync Service

use std::net::SocketAddr;

/// Policy sync service configuration
#[derive(Debug, Clone)]
pub struct AdmissionConfig {
    /// PostgreSQL URL for OPA policy storage
    pub pg_url: String,
    /// OPA management server URL for policy sync
    pub opa_url: String,
    /// Metrics HTTP bind address
    pub metrics_addr: SocketAddr,
}
