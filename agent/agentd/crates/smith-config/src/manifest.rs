//! Centralized list of environment variables used across Smith services.
//! This helps keep dev/prod parity and avoids drift between crates.

/// Environment variables the executor respects.
pub const EXECUTOR_ENV_VARS: &[&str] = &[
    "SMITH_EXECUTOR_CONFIG",
    "SMITH_NATS_URL",
    "SMITH_CLICKHOUSE_URL",
    "SMITH_JAEGER_ENDPOINT",
    "SMITH_LOG_LEVEL",
];

/// Environment variables used by the client (Vite)
pub const CLIENT_ENV_VARS: &[&str] = &[
    "VITE_SMITH_BASE_URL",
    "VITE_SMITH_WS_URL",
    "VITE_SMITH_AUTH_TOKEN",
    "VITE_CLICKHOUSE_URL",
    "VITE_SMITH_GRAPH_ADAPTER",
    "VITE_SMITH_OFFLINE",
];

/// Environment variables shared utilities may look for
pub const SHARED_ENV_VARS: &[&str] = &["SMITH_LOG_FORMAT", "SMITH_LOG_LEVEL"];
