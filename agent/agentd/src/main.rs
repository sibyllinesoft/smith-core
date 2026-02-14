#![allow(dead_code, missing_docs)]

use anyhow::Result;

#[cfg(feature = "grpc")]
mod adapters;
mod admission_pipeline;
mod attestation_utils;
mod audit;
mod bootstrap;
mod capabilities;
mod capability;
mod commands;
mod config;
#[cfg(feature = "grpc")]
mod core;
#[cfg(feature = "grpc")]
mod desktop;
mod health;
mod idempotency;
mod intent;
#[cfg(feature = "grpc")]
mod isolation;
mod isolation_tests;
mod metrics;
mod nats;
mod policy;
mod runners;
mod schema;
mod security;
mod trace;
mod util;
mod vm;
mod worker;

#[cfg(test)]
mod test_policy_enforcement;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    bootstrap::run().await
}
