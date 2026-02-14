//! Smith Policy Sync Service
//!
//! Periodically synchronizes OPA policies from PostgreSQL to the OPA
//! management server REST API.

pub mod config;
pub mod metrics;
pub mod policy_store;
pub mod service;
