//! HTTP server configuration

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// HTTP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Server bind address
    pub bind_address: String,

    /// Server port
    pub port: u16,

    /// Smith service connection URL
    pub smith_service_url: String,

    /// JWT secret for authentication
    pub jwt_secret: String,

    /// Enable CORS
    pub cors_enabled: bool,

    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,

    /// WebSocket configuration
    pub websocket: WebSocketConfig,

    /// Security configuration
    pub security: SecurityConfig,

    /// Performance configuration
    pub performance: PerformanceConfig,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per minute per client
    pub requests_per_minute: u32,

    /// Burst allowance
    pub burst_size: u32,

    /// WebSocket messages per minute per connection
    pub websocket_messages_per_minute: u32,

    /// Maximum concurrent WebSocket connections per IP
    pub max_connections_per_ip: u32,
}

/// WebSocket configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    /// Maximum message size in bytes
    pub max_message_size: usize,

    /// Ping interval in seconds
    #[serde(with = "duration_serde")]
    pub ping_interval: Duration,

    /// Connection timeout in seconds
    #[serde(with = "duration_serde")]
    pub connection_timeout: Duration,

    /// Maximum concurrent connections
    pub max_connections: usize,

    /// Event buffer size per connection
    pub event_buffer_size: usize,

    /// Heartbeat interval in seconds
    #[serde(with = "duration_serde")]
    pub heartbeat_interval: Duration,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// JWT token expiration in seconds
    #[serde(with = "duration_serde")]
    pub jwt_expiration: Duration,

    /// Require authentication for WebSocket connections
    pub require_auth_websocket: bool,

    /// Require authentication for API endpoints
    pub require_auth_api: bool,

    /// HTTPS only (for production)
    pub https_only: bool,

    /// Trusted proxy headers for rate limiting
    pub trusted_proxies: Vec<String>,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Event batching size for WebSocket
    pub event_batch_size: usize,

    /// Event batching timeout in milliseconds
    #[serde(with = "duration_serde")]
    pub event_batch_timeout: Duration,

    /// Connection pool size for Smith service
    pub smith_connection_pool_size: usize,

    /// Request timeout in seconds
    #[serde(with = "duration_serde")]
    pub request_timeout: Duration,

    /// Enable Gzip compression
    pub enable_compression: bool,

    /// Maximum request size in bytes
    pub max_request_size: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port: 3000,
            smith_service_url: "tcp://127.0.0.1:7878".to_string(),
            jwt_secret: "dev-secret-change-in-production-secure-key".to_string(),
            cors_enabled: false,
            rate_limit: RateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            security: SecurityConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 1000,
            burst_size: 100,
            websocket_messages_per_minute: 6000, // 100/second
            max_connections_per_ip: 10,
        }
    }
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_message_size: 64 * 1024, // 64KB
            ping_interval: Duration::from_secs(30),
            connection_timeout: Duration::from_secs(300), // 5 minutes
            max_connections: 1000,
            event_buffer_size: 1000,
            heartbeat_interval: Duration::from_secs(10),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            jwt_expiration: Duration::from_secs(24 * 60 * 60), // 24 hours
            require_auth_websocket: false,                     // Development default
            require_auth_api: false,                           // Development default
            https_only: false,                                 // Development default
            trusted_proxies: vec![],
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            event_batch_size: 50,
            event_batch_timeout: Duration::from_millis(10), // Sub-100ms requirement
            smith_connection_pool_size: 10,
            request_timeout: Duration::from_secs(30),
            enable_compression: true,
            max_request_size: 16 * 1024 * 1024, // 16MB
        }
    }
}

impl HttpConfig {
    pub fn validate(&self) -> Result<()> {
        // Validate bind address
        if self.bind_address.is_empty() {
            return Err(anyhow::anyhow!("Bind address cannot be empty"));
        }

        // Validate port range (note: u16 cannot exceed 65535, so just check minimum)
        if self.port < 1024 {
            return Err(anyhow::anyhow!(
                "Port must be between 1024 and 65535, got: {}",
                self.port
            ));
        }

        // Validate Smith service URL
        if self.smith_service_url.is_empty() {
            return Err(anyhow::anyhow!("Smith service URL cannot be empty"));
        }

        // Warn about default JWT secret
        if self.jwt_secret.contains("dev-secret-change-in-production") {
            tracing::warn!("⚠️  Using default JWT secret - change this in production!");
        }

        if self.jwt_secret.len() < 32 {
            return Err(anyhow::anyhow!("JWT secret must be at least 32 characters"));
        }

        // Validate sub-configurations
        self.rate_limit.validate()?;
        self.websocket.validate()?;
        self.security.validate()?;
        self.performance.validate()?;

        Ok(())
    }

    pub fn development() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port: 3000,
            cors_enabled: true, // Allow CORS for development
            security: SecurityConfig {
                require_auth_websocket: false,
                require_auth_api: false,
                https_only: false,
                ..Default::default()
            },
            performance: PerformanceConfig {
                event_batch_timeout: Duration::from_millis(50), // Relaxed for development
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub fn production() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            port: 3000,
            cors_enabled: false, // Strict CORS in production
            security: SecurityConfig {
                require_auth_websocket: true,
                require_auth_api: true,
                https_only: true,
                jwt_expiration: Duration::from_secs(8 * 60 * 60), // 8 hours
                trusted_proxies: vec!["127.0.0.1".to_string(), "::1".to_string()],
            },
            rate_limit: RateLimitConfig {
                requests_per_minute: 2000,
                burst_size: 200,
                websocket_messages_per_minute: 12000, // 200/second
                max_connections_per_ip: 20,
            },
            performance: PerformanceConfig {
                event_batch_size: 100,                         // Larger batches
                event_batch_timeout: Duration::from_millis(5), // Aggressive batching
                smith_connection_pool_size: 20,
                request_timeout: Duration::from_secs(15), // Shorter timeout
                enable_compression: true,
                max_request_size: 8 * 1024 * 1024, // 8MB (smaller for production)
            },
            ..Default::default()
        }
    }

    pub fn testing() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port: 0, // Let OS assign port for tests
            cors_enabled: true,
            rate_limit: RateLimitConfig {
                requests_per_minute: 100, // Lower limits for tests
                burst_size: 50,
                websocket_messages_per_minute: 600,
                max_connections_per_ip: 5,
            },
            websocket: WebSocketConfig {
                max_connections: 10, // Few connections for tests
                event_buffer_size: 100,
                connection_timeout: Duration::from_secs(10), // Shorter timeout
                ..Default::default()
            },
            performance: PerformanceConfig {
                request_timeout: Duration::from_secs(5), // Shorter for tests
                max_request_size: 1024 * 1024,           // 1MB for tests
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

impl RateLimitConfig {
    pub fn validate(&self) -> Result<()> {
        if self.requests_per_minute == 0 {
            return Err(anyhow::anyhow!(
                "Rate limit requests_per_minute must be > 0"
            ));
        }

        if self.burst_size == 0 {
            return Err(anyhow::anyhow!("Rate limit burst_size must be > 0"));
        }

        if self.websocket_messages_per_minute == 0 {
            return Err(anyhow::anyhow!("WebSocket rate limit must be > 0"));
        }

        if self.max_connections_per_ip == 0 {
            return Err(anyhow::anyhow!("Max connections per IP must be > 0"));
        }

        Ok(())
    }
}

impl WebSocketConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_message_size < 1024 {
            return Err(anyhow::anyhow!("WebSocket max message size must be >= 1KB"));
        }

        if self.max_message_size > 100 * 1024 * 1024 {
            return Err(anyhow::anyhow!(
                "WebSocket max message size must be <= 100MB"
            ));
        }

        if self.ping_interval.as_secs() == 0 {
            return Err(anyhow::anyhow!("WebSocket ping interval must be > 0"));
        }

        if self.connection_timeout.as_secs() == 0 {
            return Err(anyhow::anyhow!("WebSocket connection timeout must be > 0"));
        }

        if self.max_connections == 0 {
            return Err(anyhow::anyhow!("WebSocket max_connections must be > 0"));
        }

        if self.event_buffer_size == 0 {
            return Err(anyhow::anyhow!("WebSocket event buffer size must be > 0"));
        }

        if self.heartbeat_interval.as_secs() == 0 {
            return Err(anyhow::anyhow!("WebSocket heartbeat interval must be > 0"));
        }

        Ok(())
    }
}

impl SecurityConfig {
    pub fn validate(&self) -> Result<()> {
        if self.jwt_expiration.as_secs() == 0 {
            return Err(anyhow::anyhow!("JWT expiration must be > 0"));
        }

        if self.jwt_expiration.as_secs() > 7 * 24 * 60 * 60 {
            tracing::warn!("JWT expiration > 7 days may be a security risk");
        }

        // Validate trusted proxy IPs
        for proxy in &self.trusted_proxies {
            if proxy.parse::<std::net::IpAddr>().is_err() && proxy != "localhost" {
                return Err(anyhow::anyhow!("Invalid trusted proxy address: {}", proxy));
            }
        }

        Ok(())
    }
}

impl PerformanceConfig {
    pub fn validate(&self) -> Result<()> {
        if self.event_batch_size == 0 {
            return Err(anyhow::anyhow!("Event batch size must be > 0"));
        }

        if self.event_batch_timeout.as_millis() == 0 {
            return Err(anyhow::anyhow!("Event batch timeout must be > 0"));
        }

        if self.event_batch_timeout.as_millis() > 100 {
            tracing::warn!(
                "⚠️  Event batch timeout > 100ms may not meet sub-100ms latency requirement"
            );
        }

        if self.smith_connection_pool_size == 0 {
            return Err(anyhow::anyhow!("Smith connection pool size must be > 0"));
        }

        if self.request_timeout.as_secs() == 0 {
            return Err(anyhow::anyhow!("Request timeout must be > 0"));
        }

        if self.max_request_size < 1024 {
            return Err(anyhow::anyhow!("Max request size must be >= 1KB"));
        }

        Ok(())
    }
}

// Helper module for Duration serialization
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_millis() as u64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}
