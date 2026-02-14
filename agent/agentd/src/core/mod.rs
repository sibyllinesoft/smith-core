//! Core traits and abstractions for agentd
//!
//! This module defines the foundational traits that enable pluggable:
//! - Isolation backends (Linux native, macOS, containers, none)
//! - Ingest adapters (gRPC, NATS, HTTP, Unix socket, stdio)
//! - Authentication providers (mTLS, JWT, API keys, peer credentials)
//! - Output sinks and multiplexing
//! - Sandbox lifecycle management

pub mod auth;
pub mod ingest;
pub mod intent;
pub mod isolation;
pub mod output;
pub mod sandbox;

// Re-export core types for convenience
pub use auth::{AuthProvider, AuthzDecision, Credentials, Identity};
pub use ingest::{IngestAdapter, IntentHandler};
pub use intent::{Command, IntentRequest, IntentResponse, IntentStatus};
pub use isolation::{
    BackendCapabilities, IsolationBackend, Sandbox, SandboxCapabilities, SandboxSpec, StreamOutput,
};
pub use output::{EmitContext, OutputMultiplexer, OutputSink, RoutingRule};
pub use sandbox::{
    RequiredCapabilities, SandboxId, SandboxManager, SandboxSelectionOptions, SandboxSession,
};
