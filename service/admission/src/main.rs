//! Smith Policy Sync Service
//!
//! Periodically loads OPA policies from PostgreSQL and pushes them
//! to the OPA management server REST API.

use anyhow::{Context, Result};
use clap::{Arg, Command};
use tracing::info;

use smith_admission::{config::AdmissionConfig, service::PolicySyncService};

/// Initialize tracing with structured logging
fn init_tracing() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing()?;
    info!("Starting Smith Policy Sync Service");

    let matches = Command::new("smith-policy-sync")
        .version("0.2.0")
        .about("Smith Policy Sync - PostgreSQL to OPA policy synchronization")
        .arg(
            Arg::new("pg-url")
                .long("pg-url")
                .required(true)
                .env("SMITH_ADMISSION_PG_URL")
                .help("PostgreSQL connection URL"),
        )
        .arg(
            Arg::new("opa-url")
                .long("opa-url")
                .required(true)
                .env("SMITH_ADMISSION_OPA_URL")
                .help("OPA management server URL"),
        )
        .arg(
            Arg::new("metrics-addr")
                .long("metrics-addr")
                .default_value("0.0.0.0:9091")
                .help("Metrics HTTP bind address"),
        )
        .get_matches();

    let config = AdmissionConfig {
        pg_url: matches.get_one::<String>("pg-url").unwrap().clone(),
        opa_url: matches.get_one::<String>("opa-url").unwrap().clone(),
        metrics_addr: matches
            .get_one::<String>("metrics-addr")
            .unwrap()
            .parse()
            .with_context(|| "Invalid metrics address")?,
    };

    info!("  PostgreSQL: {}", config.pg_url);
    info!("  OPA server: {}", config.opa_url);
    info!("  Metrics:    {}", config.metrics_addr);

    PolicySyncService::new(config).await?.run().await
}
