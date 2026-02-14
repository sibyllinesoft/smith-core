//! MCP (Model Context Protocol) configuration for Smith

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// MCP configuration for Smith platform
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Whether MCP adapter is enabled
    pub enabled: bool,

    /// Global timeout for MCP operations (default: 30s)
    pub default_timeout_ms: u64,

    /// Maximum number of concurrent MCP servers
    pub max_servers: usize,

    /// Maximum number of retries for failed operations
    pub max_retries: u32,

    /// Retry delay in milliseconds
    pub retry_delay_ms: u64,

    /// Configured MCP servers
    pub servers: Vec<McpServerConfig>,

    /// Global environment variables to pass to all MCP servers
    pub global_env: HashMap<String, String>,

    /// Working directory for MCP server processes
    pub work_dir: Option<PathBuf>,

    /// Enable detailed MCP protocol logging
    pub debug_logging: bool,
}

/// Individual MCP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    /// Unique identifier for this server
    pub name: String,

    /// Human-readable description
    pub description: Option<String>,

    /// Command to execute for stdio transport
    pub command: String,

    /// Command arguments
    pub args: Vec<String>,

    /// Working directory for this server
    pub cwd: Option<PathBuf>,

    /// Whether this server is enabled
    pub enabled: bool,

    /// Specific timeout for this server (overrides global)
    pub timeout_ms: Option<u64>,

    /// Environment variables specific to this server
    pub env: HashMap<String, String>,

    /// Auto-start this server on manager initialization
    pub auto_start: bool,

    /// Tags for server categorization and discovery
    pub tags: Vec<String>,

    /// Server priority (higher = more preferred for tool conflicts)
    pub priority: i32,

    /// Allow filesystem access for this server
    pub allow_filesystem: bool,

    /// Allow network access for this server
    pub allow_network: bool,

    /// Maximum execution time per tool call
    pub max_execution_time_ms: u64,

    /// Trust level (1-5, 5 = highest trust)
    pub trust_level: u8,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_timeout_ms: 30_000,
            max_servers: 10,
            max_retries: 3,
            retry_delay_ms: 1_000,
            servers: vec![],
            global_env: HashMap::new(),
            work_dir: None,
            debug_logging: false,
        }
    }
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: None,
            command: String::new(),
            args: vec![],
            cwd: None,
            enabled: true,
            timeout_ms: None,
            env: HashMap::new(),
            auto_start: true,
            tags: vec![],
            priority: 0,
            allow_filesystem: false,
            allow_network: false,
            max_execution_time_ms: 30_000,
            trust_level: 1,
        }
    }
}

impl McpConfig {
    /// Create a development configuration with lenient security
    pub fn development() -> Self {
        Self {
            enabled: true,
            default_timeout_ms: 30_000,
            max_servers: 10,
            max_retries: 3,
            retry_delay_ms: 1_000,
            servers: vec![],
            global_env: HashMap::new(),
            work_dir: Some(std::env::temp_dir()),
            debug_logging: true,
        }
    }

    /// Create a production configuration with strict security
    pub fn production() -> Self {
        Self {
            enabled: true,
            default_timeout_ms: 15_000,
            max_servers: 5,
            max_retries: 2,
            retry_delay_ms: 2_000,
            servers: vec![],
            global_env: HashMap::new(),
            work_dir: None,
            debug_logging: false,
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.max_servers == 0 {
            return Err("max_servers must be greater than 0".to_string());
        }

        if self.default_timeout_ms == 0 {
            return Err("default_timeout_ms must be greater than 0".to_string());
        }

        // Validate server configurations
        for server in &self.servers {
            server.validate()?;
        }

        // Check for duplicate server names
        let mut names = std::collections::HashSet::new();
        for server in &self.servers {
            if !names.insert(&server.name) {
                return Err(format!("Duplicate server name: '{}'", server.name));
            }
        }

        Ok(())
    }

    /// Find server configuration by name
    pub fn find_server(&self, name: &str) -> Option<&McpServerConfig> {
        self.servers.iter().find(|s| s.name == name)
    }

    /// Get enabled servers
    pub fn enabled_servers(&self) -> impl Iterator<Item = &McpServerConfig> {
        self.servers.iter().filter(|s| s.enabled)
    }
}

impl McpServerConfig {
    /// Validate this server configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Server name cannot be empty".to_string());
        }

        if self.command.is_empty() {
            return Err(format!("Server '{}' command cannot be empty", self.name));
        }

        if let Some(timeout) = self.timeout_ms {
            if timeout == 0 {
                return Err(format!(
                    "Server '{}' timeout must be greater than 0",
                    self.name
                ));
            }
        }

        if self.trust_level == 0 || self.trust_level > 5 {
            return Err(format!(
                "Server '{}' trust_level must be between 1 and 5",
                self.name
            ));
        }

        Ok(())
    }

    /// Check if server has a specific tag
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.contains(&tag.to_string())
    }

    /// Get display name for this server
    pub fn display_name(&self) -> &str {
        self.description.as_deref().unwrap_or(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = McpConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_servers, 10);

        let dev_config = McpConfig::development();
        assert!(dev_config.enabled);
        assert!(dev_config.debug_logging);

        let prod_config = McpConfig::production();
        assert!(prod_config.enabled);
        assert!(!prod_config.debug_logging);
        assert_eq!(prod_config.default_timeout_ms, 15_000);
    }

    #[test]
    fn test_server_config_validation() {
        let mut server = McpServerConfig {
            name: "test".to_string(),
            command: "python".to_string(),
            args: vec!["-m".to_string(), "mcp_server".to_string()],
            ..Default::default()
        };

        assert!(server.validate().is_ok());

        // Test empty name
        server.name.clear();
        assert!(server.validate().is_err());

        // Test empty command
        server.name = "test".to_string();
        server.command.clear();
        assert!(server.validate().is_err());

        // Test invalid trust level
        server.command = "python".to_string();
        server.trust_level = 0;
        assert!(server.validate().is_err());

        server.trust_level = 6;
        assert!(server.validate().is_err());

        server.trust_level = 3;
        assert!(server.validate().is_ok());
    }

    #[test]
    fn test_config_validation() {
        let mut config = McpConfig::development();
        assert!(config.validate().is_ok());

        // Test invalid max_servers
        config.max_servers = 0;
        assert!(config.validate().is_err());

        // Test duplicate server names
        config.max_servers = 10;
        config.servers = vec![
            McpServerConfig {
                name: "duplicate".to_string(),
                command: "python".to_string(),
                ..Default::default()
            },
            McpServerConfig {
                name: "duplicate".to_string(),
                command: "node".to_string(),
                ..Default::default()
            },
        ];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_server_helpers() {
        let server = McpServerConfig {
            name: "test".to_string(),
            description: Some("Test Server".to_string()),
            command: "python".to_string(),
            tags: vec!["development".to_string(), "testing".to_string()],
            trust_level: 3,
            ..Default::default()
        };

        assert!(server.has_tag("development"));
        assert!(server.has_tag("testing"));
        assert!(!server.has_tag("production"));
        assert_eq!(server.display_name(), "Test Server");
    }

    #[test]
    fn test_config_server_finding() {
        let mut config = McpConfig::development();
        config.servers = vec![
            McpServerConfig {
                name: "server1".to_string(),
                command: "python".to_string(),
                enabled: true,
                ..Default::default()
            },
            McpServerConfig {
                name: "server2".to_string(),
                command: "node".to_string(),
                enabled: false,
                ..Default::default()
            },
        ];

        assert!(config.find_server("server1").is_some());
        assert!(config.find_server("server2").is_some());
        assert!(config.find_server("nonexistent").is_none());

        let enabled_servers: Vec<_> = config.enabled_servers().collect();
        assert_eq!(enabled_servers.len(), 1);
        assert_eq!(enabled_servers[0].name, "server1");
    }
}
