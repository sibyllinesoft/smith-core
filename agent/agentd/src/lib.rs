//! Agentd - Agent Daemon Library
//!
//! This library provides a general-purpose agent execution daemon with:
//! - Pluggable isolation backends (Linux native, macOS, containers, none)
//! - Pluggable ingest adapters (gRPC, NATS, HTTP, Unix socket, stdio)
//! - Pluggable authentication (mTLS, JWT, API keys, peer credentials)
//! - Output multiplexing and routing
//! - Sandbox lifecycle management
//!
//! # Architecture
//!
//! The core traits in the `core` module define abstractions that allow
//! swapping implementations at runtime based on configuration:
//!
//! - [`core::IsolationBackend`]: Creates and manages sandboxes
//! - [`core::IngestAdapter`]: Receives execution requests
//! - [`core::AuthProvider`]: Authenticates and authorizes requests
//! - [`core::OutputSink`]: Routes execution results
//! - [`core::SandboxManager`]: Manages sandbox lifecycle
//!
//! # Execution Modes
//!
//! - **Workstation Mode**: Direct host execution with policy guards (no sandbox overhead)
//! - **Server Mode**: Full sandbox isolation for untrusted workloads
//! - **Custom**: Mix and match backends for specific requirements

// Ingest adapters for receiving requests
#[cfg(feature = "grpc")]
pub mod adapters;

pub mod admission_pipeline;
pub mod audit;
pub mod auth;
pub mod bootstrap;
pub mod capabilities;
pub mod capability;
pub mod commands;
pub mod config;
pub mod core;
#[cfg(feature = "grpc")]
pub mod desktop;
pub mod health;
pub mod idempotency;
pub mod intent;
pub mod isolation;
pub mod isolation_tests;
pub mod metrics;
pub mod nats;
#[cfg(test)]
pub mod nats_testing;
pub mod policy;
pub mod runners;
pub mod schema;
pub mod security;
pub mod trace;
pub mod util;
pub mod vm;
pub mod worker;

// Planner module for AI-powered execution orchestration
pub mod planner;

// Runtime orchestration
pub mod runtime;

// Comprehensive test modules
#[cfg(test)]
pub mod security_validation_tests;

// Re-export commonly used types
pub use runners::{
    create_exec_context, ExecContext, ExecutionContext, ExecutionResult, MemoryOutputSink,
    OutputSink, Runner, Scope,
};
pub use smith_protocol::ExecutionLimits;
