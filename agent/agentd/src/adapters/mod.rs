//! Ingest adapter implementations
//!
//! This module provides concrete implementations of the `IngestAdapter` trait
//! for various transport protocols:
//!
//! - `grpc`: gRPC adapter using tonic (primary direct mode)
//! - `nats`: NATS JetStream adapter (for distributed deployments)
//! - Additional adapters: http, unix, stdio (planned)

#[cfg(feature = "grpc")]
pub mod grpc;

#[cfg(feature = "grpc")]
pub use grpc::GrpcAdapter;

// Re-export core traits for convenience
pub use crate::core::ingest::{
    AdapterConfigInfo, AdapterStats, CapabilityInfo, HealthStatus, IngestAdapter, IntentHandler,
    OutputChunk, RequestContext,
};
