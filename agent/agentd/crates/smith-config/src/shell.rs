//! Shell execution configuration

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Shell execution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellConfig {
    /// Default shell to use when none specified
    pub default_shell: String,

    /// Default timeout for commands
    #[serde(with = "duration_serde")]
    pub default_timeout: Duration,

    /// Maximum output buffer size before truncation
    pub max_output_size: usize,

    /// PTY configuration
    pub pty: PtyConfig,

    /// ANSI escape sequence handling
    pub strip_ansi_codes: bool,

    /// Environment variable handling
    pub environment: EnvironmentConfig,

    /// Security settings
    pub security: ShellSecurityConfig,

    /// Shell-specific configurations
    pub shell_specific: HashMap<String, ShellSpecificConfig>,

    /// Working directory settings
    pub working_directory: WorkingDirectoryConfig,

    /// Logging and debugging
    pub logging: ShellLoggingConfig,
}

/// PTY (pseudo-terminal) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtyConfig {
    /// Number of rows
    pub rows: Option<u16>,

    /// Number of columns
    pub cols: Option<u16>,

    /// Terminal type (e.g., "xterm-256color")
    pub terminal_type: Option<String>,
}

/// Environment variable handling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    /// Capture environment changes after command execution
    pub capture_changes: bool,

    /// Maximum number of environment variables to capture
    pub snapshot_size_limit: usize,

    /// Environment variables to always preserve
    pub preserve_vars: Vec<String>,

    /// Environment variables to always remove
    pub remove_vars: Vec<String>,
}

/// Shell security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellSecurityConfig {
    /// Allow interactive commands (with stdin)
    pub allow_interactive_commands: bool,

    /// Enable sandbox mode (restricted command set)
    pub sandbox_mode: bool,

    /// Allowed commands in sandbox mode (None = allow all)
    pub allowed_commands: Option<Vec<String>>,

    /// Always blocked commands
    pub blocked_commands: Vec<String>,

    /// Maximum command line length
    pub max_command_length: usize,

    /// Block commands with dangerous patterns
    pub block_dangerous_patterns: bool,
}

/// Shell-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShellSpecificConfig {
    /// Shell-specific timeout override
    #[serde(with = "duration_serde_opt")]
    pub timeout: Option<Duration>,

    /// Shell-specific environment variables
    pub environment: HashMap<String, String>,

    /// Shell initialization commands
    pub init_commands: Vec<String>,

    /// Login shell arguments
    pub login_args: Option<Vec<String>>,

    /// Non-login shell arguments
    pub non_login_args: Option<Vec<String>>,

    /// Feature support flags
    pub features: ShellFeatures,
}

/// Shell feature support configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellFeatures {
    /// Supports job control
    pub job_control: bool,

    /// Supports command history
    pub history: bool,

    /// Supports tab completion
    pub completion: bool,

    /// Supports colored output
    pub color: bool,
}

/// Working directory configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkingDirectoryConfig {
    /// Preserve current working directory across commands
    pub preserve_cwd: bool,

    /// Default working directory if none specified
    pub default_cwd: Option<PathBuf>,

    /// Allowed working directories (None = allow all)
    pub allowed_directories: Option<Vec<PathBuf>>,
}

/// Shell logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellLoggingConfig {
    /// Log executed commands
    pub log_commands: bool,

    /// Log command output
    pub log_output: bool,

    /// Log environment changes
    pub log_environment_changes: bool,

    /// Enable PTY debugging
    pub debug_pty: bool,

    /// Maximum log line length before truncation
    pub max_log_line_length: usize,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            default_shell: "/bin/sh".to_string(), // Will be detected at runtime
            default_timeout: Duration::from_secs(120), // 2 minutes
            max_output_size: 2 * 1024 * 1024,     // 2MB
            pty: PtyConfig::default(),
            strip_ansi_codes: false,
            environment: EnvironmentConfig::default(),
            security: ShellSecurityConfig::default(),
            shell_specific: HashMap::new(),
            working_directory: WorkingDirectoryConfig::default(),
            logging: ShellLoggingConfig::default(),
        }
    }
}

impl Default for PtyConfig {
    fn default() -> Self {
        Self {
            rows: Some(24),
            cols: Some(80),
            terminal_type: Some("xterm-256color".to_string()),
        }
    }
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            capture_changes: true,
            snapshot_size_limit: 1000,
            preserve_vars: vec![
                "PATH".to_string(),
                "HOME".to_string(),
                "USER".to_string(),
                "SHELL".to_string(),
                "TERM".to_string(),
                "LANG".to_string(),
                "LC_ALL".to_string(),
            ],
            remove_vars: vec![
                "SSH_AUTH_SOCK".to_string(),
                "SSH_AGENT_PID".to_string(),
                "GPG_AGENT_INFO".to_string(),
            ],
        }
    }
}

impl Default for ShellSecurityConfig {
    fn default() -> Self {
        Self {
            allow_interactive_commands: true,
            sandbox_mode: false,
            allowed_commands: None,
            blocked_commands: vec![
                // Fork bombs and resource exhaustion
                ":(){ :|:& };:".to_string(),
                "fork() { fork|fork& }; fork".to_string(),
                // Dangerous deletions
                "rm -rf /".to_string(),
                "sudo rm -rf".to_string(),
                "> /dev/sda".to_string(),
                // System manipulation
                "mkfs".to_string(),
                "fdisk".to_string(),
                "dd if=/dev/zero".to_string(),
                "dd if=/dev/urandom".to_string(),
                // Network attacks
                "ping -f".to_string(),
                "hping".to_string(),
                "nmap".to_string(),
                // Process manipulation
                "kill -9 -1".to_string(),
                "killall -9".to_string(),
                "pkill -9".to_string(),
            ],
            max_command_length: 8192, // 8KB
            block_dangerous_patterns: true,
        }
    }
}

impl Default for ShellFeatures {
    fn default() -> Self {
        Self {
            job_control: true,
            history: true,
            completion: true,
            color: true,
        }
    }
}

impl Default for WorkingDirectoryConfig {
    fn default() -> Self {
        Self {
            preserve_cwd: true,
            default_cwd: None,
            allowed_directories: None, // Allow all by default
        }
    }
}

impl Default for ShellLoggingConfig {
    fn default() -> Self {
        Self {
            log_commands: true,
            log_output: false, // Can be very verbose
            log_environment_changes: false,
            debug_pty: false,
            max_log_line_length: 1024,
        }
    }
}

impl ShellConfig {
    pub fn validate(&self) -> Result<()> {
        // Validate shell exists (simple check)
        if self.default_shell.is_empty() {
            return Err(anyhow::anyhow!("Default shell cannot be empty"));
        }

        // Validate timeout
        if self.default_timeout.as_millis() == 0 {
            return Err(anyhow::anyhow!("Default timeout cannot be zero"));
        }

        if self.default_timeout.as_secs() > 10 * 60 {
            tracing::warn!("Default timeout > 10 minutes may cause resource issues");
        }

        // Validate output size
        if self.max_output_size == 0 {
            return Err(anyhow::anyhow!("Max output size cannot be zero"));
        }

        if self.max_output_size > 100 * 1024 * 1024 {
            return Err(anyhow::anyhow!("Max output size too large (max 100MB)"));
        }

        // Validate sub-configurations
        self.pty.validate()?;
        self.environment.validate()?;
        self.security.validate()?;
        self.working_directory.validate()?;
        self.logging.validate()?;

        // Validate shell-specific configurations
        for (shell_name, shell_config) in &self.shell_specific {
            shell_config.validate().map_err(|e| {
                anyhow::anyhow!(
                    "Shell-specific config for '{}' validation failed: {}",
                    shell_name,
                    e
                )
            })?;
        }

        Ok(())
    }

    pub fn development() -> Self {
        Self {
            default_timeout: Duration::from_secs(300), // 5 minutes for development
            security: ShellSecurityConfig {
                sandbox_mode: false,
                allow_interactive_commands: true,
                block_dangerous_patterns: false, // More permissive
                ..Default::default()
            },
            logging: ShellLoggingConfig {
                log_commands: true,
                log_output: true, // Verbose for development
                debug_pty: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub fn production() -> Self {
        Self {
            default_timeout: Duration::from_secs(30), // Strict timeout for production
            strip_ansi_codes: true,                   // Clean output for logging
            security: ShellSecurityConfig {
                sandbox_mode: true,
                allow_interactive_commands: false,
                allowed_commands: Some(vec![
                    // Core utilities
                    "ls".to_string(),
                    "cat".to_string(),
                    "grep".to_string(),
                    "awk".to_string(),
                    "sed".to_string(),
                    "sort".to_string(),
                    "uniq".to_string(),
                    "cut".to_string(),
                    "head".to_string(),
                    "tail".to_string(),
                    "wc".to_string(),
                    // File operations
                    "find".to_string(),
                    "mkdir".to_string(),
                    "touch".to_string(),
                    "cp".to_string(),
                    "mv".to_string(),
                    // System info
                    "ps".to_string(),
                    "top".to_string(),
                    "df".to_string(),
                    "du".to_string(),
                    "free".to_string(),
                    "uptime".to_string(),
                    "uname".to_string(),
                    // Network utilities (limited)
                    "ping".to_string(),
                    "dig".to_string(),
                    "host".to_string(),
                    "nslookup".to_string(),
                    // Text processing
                    "tr".to_string(),
                    "expand".to_string(),
                    "unexpand".to_string(),
                    "fold".to_string(),
                    // Archiving
                    "tar".to_string(),
                    "gzip".to_string(),
                    "gunzip".to_string(),
                    "zip".to_string(),
                    "unzip".to_string(),
                ]),
                block_dangerous_patterns: true,
                max_command_length: 2048, // Stricter limit
                ..Default::default()
            },
            environment: EnvironmentConfig {
                capture_changes: false,   // Don't capture in production
                snapshot_size_limit: 100, // Small snapshot
                ..Default::default()
            },
            logging: ShellLoggingConfig {
                log_commands: true,
                log_output: false, // Too verbose for production
                log_environment_changes: false,
                debug_pty: false,
                max_log_line_length: 512, // Shorter lines
            },
            ..Default::default()
        }
    }

    pub fn testing() -> Self {
        Self {
            default_timeout: Duration::from_secs(5), // Quick timeout for tests
            max_output_size: 64 * 1024,              // 64KB for tests
            security: ShellSecurityConfig {
                sandbox_mode: false,               // Permissive for tests
                allow_interactive_commands: false, // No interaction in tests
                block_dangerous_patterns: false,
                ..Default::default()
            },
            environment: EnvironmentConfig {
                capture_changes: false,
                snapshot_size_limit: 10,
                ..Default::default()
            },
            logging: ShellLoggingConfig {
                log_commands: false,
                log_output: false,
                log_environment_changes: false,
                debug_pty: false,
                max_log_line_length: 256,
            },
            ..Default::default()
        }
    }

    /// Check if a command is allowed based on security configuration
    pub fn is_command_allowed(&self, command: &str) -> bool {
        if command.len() > self.security.max_command_length {
            return false;
        }

        // Check blocked commands first
        for blocked in &self.security.blocked_commands {
            if command.contains(blocked) {
                return false;
            }
        }

        // Check dangerous patterns if enabled
        if self.security.block_dangerous_patterns && self.contains_dangerous_pattern(command) {
            return false;
        }

        // If allow list is specified, check it
        if let Some(ref allowed) = self.security.allowed_commands {
            let command_name = command.split_whitespace().next().unwrap_or(command);
            return allowed.iter().any(|allowed_cmd| {
                command_name == allowed_cmd || command.starts_with(&format!("{} ", allowed_cmd))
            });
        }

        true
    }

    fn contains_dangerous_pattern(&self, command: &str) -> bool {
        let dangerous_patterns = [
            // Redirection to devices
            ">/dev/",
            ">>/dev/",
            // Recursive operations on root
            "rm -rf /",
            "chmod -R /",
            "chown -R /",
            // Pipe to shell
            "| sh",
            "| bash",
            "| zsh",
            // Dangerous combinations
            "sudo rm",
            "sudo dd",
            "sudo mkfs",
            // Network flood attacks
            "ping -f",
            "ping -i 0",
            // Resource exhaustion
            "while true",
            "for i in $(seq 1 1000000)",
            "> /dev/null &",
        ];

        dangerous_patterns
            .iter()
            .any(|pattern| command.contains(pattern))
    }
}

impl PtyConfig {
    pub fn validate(&self) -> Result<()> {
        if let Some(rows) = self.rows {
            if rows == 0 || rows > 1000 {
                return Err(anyhow::anyhow!(
                    "Invalid PTY rows: {}. Must be between 1 and 1000",
                    rows
                ));
            }
        }

        if let Some(cols) = self.cols {
            if cols == 0 || cols > 1000 {
                return Err(anyhow::anyhow!(
                    "Invalid PTY cols: {}. Must be between 1 and 1000",
                    cols
                ));
            }
        }

        Ok(())
    }
}

impl EnvironmentConfig {
    pub fn validate(&self) -> Result<()> {
        if self.snapshot_size_limit == 0 {
            return Err(anyhow::anyhow!(
                "Environment snapshot size limit must be > 0"
            ));
        }

        if self.snapshot_size_limit > 10_000 {
            return Err(anyhow::anyhow!(
                "Environment snapshot size limit too large (max 10,000)"
            ));
        }

        Ok(())
    }
}

impl ShellSecurityConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_command_length == 0 {
            return Err(anyhow::anyhow!("Max command length must be > 0"));
        }

        if self.max_command_length > 1024 * 1024 {
            return Err(anyhow::anyhow!("Max command length too large (max 1MB)"));
        }

        Ok(())
    }
}

impl ShellSpecificConfig {
    pub fn validate(&self) -> Result<()> {
        if let Some(timeout) = self.timeout {
            if timeout.as_millis() == 0 {
                return Err(anyhow::anyhow!("Shell-specific timeout cannot be zero"));
            }
        }

        Ok(())
    }
}

impl WorkingDirectoryConfig {
    pub fn validate(&self) -> Result<()> {
        if let Some(ref default_cwd) = self.default_cwd {
            if !default_cwd.is_absolute() {
                return Err(anyhow::anyhow!("Default CWD must be an absolute path"));
            }
        }

        if let Some(ref allowed_dirs) = self.allowed_directories {
            for dir in allowed_dirs {
                if !dir.is_absolute() {
                    return Err(anyhow::anyhow!(
                        "Allowed directories must be absolute paths"
                    ));
                }
            }
        }

        Ok(())
    }
}

impl ShellLoggingConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_log_line_length == 0 {
            return Err(anyhow::anyhow!("Max log line length must be > 0"));
        }

        if self.max_log_line_length > 64 * 1024 {
            return Err(anyhow::anyhow!("Max log line length too large (max 64KB)"));
        }

        Ok(())
    }
}

// Helper modules for Duration serialization
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

mod duration_serde_opt {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(d) => serializer.serialize_some(&(d.as_millis() as u64)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<u64>::deserialize(deserializer)? {
            Some(millis) => Ok(Some(Duration::from_millis(millis))),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Duration;

    #[test]
    fn test_shell_config_default() {
        let config = ShellConfig::default();

        assert_eq!(config.default_shell, "/bin/sh");
        assert_eq!(config.default_timeout, Duration::from_secs(120));
        assert_eq!(config.max_output_size, 2 * 1024 * 1024);
        assert!(!config.strip_ansi_codes);
        assert!(config.shell_specific.is_empty());
    }

    #[test]
    fn test_shell_config_validation() {
        let mut config = ShellConfig::default();
        assert!(config.validate().is_ok());

        // Test empty shell path
        config.default_shell = "".to_string();
        assert!(config.validate().is_err());

        config.default_shell = "/bin/bash".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_shell_security_config() {
        let security = ShellSecurityConfig::default();
        assert!(security.allow_interactive_commands);
        assert!(!security.sandbox_mode);
        assert!(security.allowed_commands.is_none());
        assert_eq!(security.max_command_length, 8192);
        assert!(security.block_dangerous_patterns); // Default is true

        assert!(security.validate().is_ok());
    }

    #[test]
    fn test_shell_security_config_validation() {
        let invalid_security = ShellSecurityConfig {
            max_command_length: 0,
            ..ShellSecurityConfig::default()
        };
        assert!(invalid_security.validate().is_err());

        let valid_security = ShellSecurityConfig {
            max_command_length: 1024,
            ..ShellSecurityConfig::default()
        };
        assert!(valid_security.validate().is_ok());
    }

    #[test]
    fn test_pty_config() {
        let pty = PtyConfig::default();
        assert_eq!(pty.rows, Some(24));
        assert_eq!(pty.cols, Some(80));
        assert_eq!(pty.terminal_type, Some("xterm-256color".to_string())); // Fixed field name
    }

    #[test]
    fn test_environment_config() {
        let env = EnvironmentConfig::default();
        assert!(env.capture_changes); // Fixed field name
        assert_eq!(env.snapshot_size_limit, 1000); // Fixed field name
        assert!(env.preserve_vars.contains(&"PATH".to_string())); // Fixed field name
        assert!(env.preserve_vars.contains(&"HOME".to_string()));
        assert!(env.preserve_vars.contains(&"USER".to_string()));
        assert!(env.remove_vars.contains(&"SSH_AUTH_SOCK".to_string())); // Fixed field name
    }

    #[test]
    fn test_working_directory_config() {
        let wd = WorkingDirectoryConfig::default();
        assert!(wd.preserve_cwd); // Fixed field name
        assert!(wd.default_cwd.is_none()); // Fixed field name
        assert!(wd.allowed_directories.is_none()); // Fixed field name
    }

    #[test]
    fn test_shell_features() {
        let features = ShellFeatures::default();
        assert!(features.job_control);
        assert!(features.history);
        assert!(features.completion);
        assert!(features.color); // Only these 4 fields exist
    }

    #[test]
    fn test_shell_specific_config_validation() {
        let mut shell_config = ShellSpecificConfig {
            timeout: Some(Duration::from_secs(60)),
            environment: HashMap::new(),           // Fixed field name
            init_commands: vec!["-i".to_string()], // Fixed field name
            login_args: Some(vec!["--login".to_string()]),
            non_login_args: Some(vec!["--norc".to_string()]),
            features: ShellFeatures::default(), // Not optional
        };

        assert!(shell_config.validate().is_ok());

        // Test zero timeout
        shell_config.timeout = Some(Duration::from_millis(0));
        assert!(shell_config.validate().is_err());
    }

    #[test]
    fn test_shell_logging_config() {
        let logging = ShellLoggingConfig::default();
        assert!(logging.log_commands);
        assert!(!logging.log_output);
        assert!(!logging.log_environment_changes);
        assert!(!logging.debug_pty); // Fixed field name
        assert_eq!(logging.max_log_line_length, 1024);

        assert!(logging.validate().is_ok());
    }

    #[test]
    fn test_shell_logging_config_validation() {
        let zero_len_logging = ShellLoggingConfig {
            max_log_line_length: 0,
            ..ShellLoggingConfig::default()
        };
        assert!(zero_len_logging.validate().is_err());

        let too_large_logging = ShellLoggingConfig {
            max_log_line_length: 128 * 1024, // > 64KB
            ..ShellLoggingConfig::default()
        };
        assert!(too_large_logging.validate().is_err());

        let valid_logging = ShellLoggingConfig {
            max_log_line_length: 2048,
            ..ShellLoggingConfig::default()
        };
        assert!(valid_logging.validate().is_ok());
    }

    #[test]
    fn test_duration_serialization() {
        let config = ShellConfig {
            default_timeout: Duration::from_millis(5000),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&config).unwrap();
        assert!(serialized.contains("5000"));

        let deserialized: ShellConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.default_timeout, Duration::from_millis(5000));
    }

    #[test]
    fn test_shell_config_serialization_roundtrip() {
        let original_config = ShellConfig::default();

        let json = serde_json::to_string(&original_config).unwrap();
        let deserialized_config: ShellConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(
            original_config.default_shell,
            deserialized_config.default_shell
        );
        assert_eq!(
            original_config.default_timeout,
            deserialized_config.default_timeout
        );
        assert_eq!(
            original_config.max_output_size,
            deserialized_config.max_output_size
        );
        assert_eq!(
            original_config.strip_ansi_codes,
            deserialized_config.strip_ansi_codes
        );
    }

    #[test]
    fn test_security_config_with_allowed_commands() {
        let security = ShellSecurityConfig {
            allow_interactive_commands: false,
            sandbox_mode: true,
            allowed_commands: Some(vec![
                "ls".to_string(),
                "cat".to_string(),
                "grep".to_string(),
                "find".to_string(),
            ]),
            blocked_commands: vec!["rm".to_string(), "sudo".to_string()], // Fixed field name
            max_command_length: 2048,
            block_dangerous_patterns: true, // Fixed field name
        };

        assert!(security.validate().is_ok());
        assert!(security.allowed_commands.is_some());
        assert_eq!(security.allowed_commands.as_ref().unwrap().len(), 4);
        assert!(!security.allow_interactive_commands);
        assert!(security.sandbox_mode);
        assert_eq!(security.blocked_commands.len(), 2);
    }

    #[test]
    fn test_working_directory_config_with_restrictions() {
        let wd_config = WorkingDirectoryConfig {
            preserve_cwd: false, // Fixed field names
            default_cwd: Some(PathBuf::from("/home/user")),
            allowed_directories: Some(vec![
                PathBuf::from("/home"),
                PathBuf::from("/tmp"),
                PathBuf::from("/var/log"),
            ]),
        };

        assert_eq!(wd_config.default_cwd, Some(PathBuf::from("/home/user")));
        assert!(!wd_config.preserve_cwd);
        assert!(wd_config.allowed_directories.is_some());
        assert_eq!(wd_config.allowed_directories.as_ref().unwrap().len(), 3);
    }

    #[test]
    fn test_pty_config_custom() {
        let pty = PtyConfig {
            rows: Some(50),
            cols: Some(150),
            terminal_type: Some("screen-256color".to_string()), // Fixed field name
        };

        assert_eq!(pty.rows, Some(50));
        assert_eq!(pty.cols, Some(150));
        assert_eq!(pty.terminal_type, Some("screen-256color".to_string()));
    }

    #[test]
    fn test_environment_config_with_custom_settings() {
        let env_config = EnvironmentConfig {
            capture_changes: true, // Fixed field names
            snapshot_size_limit: 2000,
            preserve_vars: vec![
                "PATH".to_string(),
                "HOME".to_string(),
                "USER".to_string(),
                "SHELL".to_string(),
            ],
            remove_vars: vec!["TEMP_VAR".to_string(), "OLD_VAR".to_string()],
        };

        assert!(env_config.capture_changes);
        assert_eq!(env_config.snapshot_size_limit, 2000);
        assert_eq!(env_config.preserve_vars.len(), 4);
        assert_eq!(env_config.remove_vars.len(), 2);
        assert!(env_config.preserve_vars.contains(&"PATH".to_string()));
        assert!(env_config.remove_vars.contains(&"TEMP_VAR".to_string()));
    }
}
