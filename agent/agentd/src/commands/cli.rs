use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// CLI definition for the Smith executor binary.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, name = "executor")]
pub struct Cli {
    #[command(subcommand)]
    pub command: ExecutorCommand,
}

/// Supported subcommands for the executor binary.
#[derive(Subcommand, Debug)]
pub enum ExecutorCommand {
    /// Run the executor daemon
    Run {
        /// Path to configuration file
        #[arg(short, long, default_value = "/etc/executor/config.toml")]
        config: PathBuf,
        /// Run in demo mode (reduced security for development)
        #[arg(long)]
        demo: bool,
        /// Automatically bootstrap JetStream streams if missing
        #[arg(long)]
        autobootstrap: bool,
        /// Required capability digest (hex64) for bundle enforcement
        #[arg(long, required = true)]
        capability_digest: String,
        /// Isolation backend to use (landlock, container, host)
        #[arg(long, default_value = "landlock")]
        isolation: String,
    },
    /// Check configuration and system compatibility
    CheckConfig {
        /// Path to configuration file
        #[arg(short, long, default_value = "/etc/executor/config.toml")]
        config: PathBuf,
    },
    /// Run comprehensive self-test with isolation validation
    SelfTest {
        /// Path to configuration file
        #[arg(short, long, default_value = "/etc/executor/config.toml")]
        config: PathBuf,
        /// Run comprehensive isolation tests (may take longer)
        #[arg(long)]
        comprehensive: bool,
    },
    /// Print seccomp allowlist for capability
    PrintSeccomp {
        /// Capability to print seccomp rules for
        #[arg(short, long)]
        capability: String,
    },
    /// Reload policy configuration (sends SIGHUP to running daemon)
    ReloadPolicy {
        /// PID of running executor daemon
        #[arg(short, long)]
        pid: Option<u32>,
    },
}
