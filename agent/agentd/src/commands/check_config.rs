/*!
 * Configuration check command implementation
 *
 * Extracted from main.rs to reduce complexity and improve maintainability.
 * Handles system configuration validation and compatibility checks.
 */

use anyhow::Result;
use std::path::PathBuf;

use crate::config::{self, Config};

/// Handles the check-config command
pub struct CheckConfigCommand;

impl CheckConfigCommand {
    /// Run all configuration validations and print the consolidated report.
    pub async fn execute(config_path: PathBuf) -> Result<()> {
        println!("🔍 Smith Executor Configuration Check");
        println!("=====================================");

        match config::load_config(&config_path) {
            Ok(config) => {
                println!("✅ Configuration loaded successfully");

                // Check OS and security capabilities
                let security_status = check_security_capabilities(&config);
                print_security_status(&security_status);

                // Check directories
                let dir_status = check_directories(&config);
                print_directory_status(&dir_status);

                // Check NATS connectivity (optional)
                let nats_status = check_nats_connectivity(&config).await;
                print_nats_status(&nats_status);

                // Check JetStream streams
                let streams_status = if nats_status.connected {
                    let status = check_jetstream_streams(&config).await;
                    print_streams_status(&status);
                    status
                } else {
                    StreamsStatus::default()
                };

                // Summary
                print_summary(&security_status, &dir_status, &nats_status, &streams_status);

                Ok(())
            }
            Err(e) => {
                println!("❌ Configuration failed to load: {}", e);
                std::process::exit(1);
            }
        }
    }
}

// Configuration check status structures
/// Snapshot of host security features relevant to the executor.
#[derive(Debug)]
pub struct SecurityStatus {
    pub is_linux: bool,
    pub landlock_available: bool,
    pub seccomp_available: bool,
    pub cgroups_available: bool,
    pub is_root: bool,
    pub kernel_version: String,
}

impl SecurityStatus {
    /// Returns true when all mandatory security features are available.
    pub fn production_ready(&self) -> bool {
        self.is_linux
            && self.landlock_available
            && self.seccomp_available
            && self.cgroups_available
            && !self.is_root
    }
}

/// Tracks whether required executor directories can be accessed or created.
#[derive(Debug)]
pub struct DirectoryStatus {
    pub work_root: bool,
    pub state_dir: bool,
    pub audit_dir: bool,
    pub all_valid: bool,
}

/// Captures high-level NATS connectivity health.
#[derive(Debug)]
pub struct NatsStatus {
    pub connected: bool,
    pub error: Option<String>,
    pub jetstream_available: bool,
}

/// Presence checks for JetStream streams the executor depends on.
#[derive(Debug, Default)]
pub struct StreamsStatus {
    pub intents: bool,
    pub results: bool,
    pub audit: bool,
    pub system: bool,
    pub all_exist: bool,
}

/// Inspect kernel/OS features and executor toggles to build a security report.
pub fn check_security_capabilities(config: &Config) -> SecurityStatus {
    let is_linux = cfg!(target_os = "linux");
    let is_root = unsafe { libc::getuid() == 0 };

    // Check kernel version (simplified)
    let kernel_version = std::fs::read_to_string("/proc/version")
        .map(|v| v.lines().next().unwrap_or("unknown").to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // For now, assume these are available on Linux (proper detection would check kernel features)
    let landlock_available = is_linux && config.executor.landlock_enabled;
    let seccomp_available = is_linux;
    let cgroups_available = is_linux && std::path::Path::new("/sys/fs/cgroup").exists();

    SecurityStatus {
        is_linux,
        landlock_available,
        seccomp_available,
        cgroups_available,
        is_root,
        kernel_version,
    }
}

/// Validate the executor’s working/state/audit directories are writable.
pub fn check_directories(config: &Config) -> DirectoryStatus {
    let work_root =
        config.executor.work_root.exists() || can_create_dir(&config.executor.work_root);
    let state_dir =
        config.executor.state_dir.exists() || can_create_dir(&config.executor.state_dir);
    let audit_dir =
        config.executor.audit_dir.exists() || can_create_dir(&config.executor.audit_dir);

    DirectoryStatus {
        work_root,
        state_dir,
        audit_dir,
        all_valid: work_root && state_dir && audit_dir,
    }
}

fn can_create_dir(path: &std::path::Path) -> bool {
    if let Some(parent) = path.parent() {
        parent.exists()
            && parent
                .metadata()
                .map(|m| !m.permissions().readonly())
                .unwrap_or(false)
    } else {
        false
    }
}

/// Attempt to connect to NATS and run a lightweight health check.
pub async fn check_nats_connectivity(config: &Config) -> NatsStatus {
    let nats_url = &config.nats.url;
    match smith_bus::SmithBus::connect(nats_url).await {
        Ok(bus) => {
            let health = bus.health_check().await.unwrap_or(smith_bus::HealthStatus {
                nats_connected: false,
                jetstream_available: false,
            });

            NatsStatus {
                connected: health.nats_connected,
                error: None,
                jetstream_available: health.jetstream_available,
            }
        }
        Err(e) => NatsStatus {
            connected: false,
            error: Some(e.to_string()),
            jetstream_available: false,
        },
    }
}

/// Confirm that critical JetStream streams exist and are reported as healthy.
pub async fn check_jetstream_streams(config: &Config) -> StreamsStatus {
    match smith_bus::SmithBus::connect(&config.nats.url).await {
        Ok(bus) => {
            let stream_manager = bus.stream_manager();
            match stream_manager.get_streams_info().await {
                Ok(streams) => {
                    let intents = streams.iter().any(|s| s.name == "INTENTS" && s.exists);
                    let results = streams
                        .iter()
                        .any(|s| s.name == "INTENT_RESULTS" && s.exists);
                    let audit = streams.iter().any(|s| s.name == "AUDIT_LOGS" && s.exists);
                    let system = streams
                        .iter()
                        .any(|s| s.name == "SYSTEM_EVENTS" && s.exists);

                    StreamsStatus {
                        intents,
                        results,
                        audit,
                        system,
                        all_exist: intents && results && audit && system,
                    }
                }
                Err(_) => StreamsStatus::default(),
            }
        }
        Err(_) => StreamsStatus::default(),
    }
}

/// Pretty-print the security report with emoji markers.
pub fn print_security_status(status: &SecurityStatus) {
    println!("\n🔒 Security Features:");
    println!(
        "├─ OS: {}",
        if status.is_linux {
            "✅ Linux"
        } else {
            "❌ Non-Linux (demo only)"
        }
    );
    println!(
        "├─ Landlock LSM: {}",
        if status.landlock_available {
            "✅ Available"
        } else {
            "❌ Not Available"
        }
    );
    println!(
        "├─ Seccomp-BPF: {}",
        if status.seccomp_available {
            "✅ Available"
        } else {
            "❌ Not Available"
        }
    );
    println!(
        "├─ Cgroups v2: {}",
        if status.cgroups_available {
            "✅ Available"
        } else {
            "❌ Not Available"
        }
    );
    println!(
        "├─ User: {}",
        if status.is_root {
            "⚠️  Root (not recommended)"
        } else {
            "✅ Non-root"
        }
    );
    println!(
        "└─ Kernel: {}",
        status.kernel_version.lines().next().unwrap_or("unknown")
    );
}

/// Pretty-print directory access results.
pub fn print_directory_status(status: &DirectoryStatus) {
    println!("\n📁 Directory Status:");
    println!(
        "├─ Work Root: {}",
        if status.work_root {
            "✅ OK"
        } else {
            "❌ Inaccessible"
        }
    );
    println!(
        "├─ State Dir: {}",
        if status.state_dir {
            "✅ OK"
        } else {
            "❌ Inaccessible"
        }
    );
    println!(
        "└─ Audit Dir: {}",
        if status.audit_dir {
            "✅ OK"
        } else {
            "❌ Inaccessible"
        }
    );
}

/// Pretty-print NATS connectivity and JetStream availability.
pub fn print_nats_status(status: &NatsStatus) {
    println!("\n🔌 NATS Connectivity:");
    if status.connected {
        println!("├─ Connection: ✅ Connected");
        println!(
            "└─ JetStream: {}",
            if status.jetstream_available {
                "✅ Available"
            } else {
                "❌ Not Available"
            }
        );
    } else {
        println!("├─ Connection: ❌ Failed");
        if let Some(ref error) = status.error {
            println!("└─ Error: {}", error);
        }
    }
}

/// Pretty-print JetStream stream checks.
pub fn print_streams_status(status: &StreamsStatus) {
    println!("\n🌊 JetStream Streams:");
    println!(
        "├─ INTENTS: {}",
        if status.intents {
            "✅ Exists"
        } else {
            "❌ Missing"
        }
    );
    println!(
        "├─ INTENT_RESULTS: {}",
        if status.results {
            "✅ Exists"
        } else {
            "❌ Missing"
        }
    );
    println!(
        "├─ AUDIT_LOGS: {}",
        if status.audit {
            "✅ Exists"
        } else {
            "❌ Missing"
        }
    );
    println!(
        "└─ SYSTEM_EVENTS: {}",
        if status.system {
            "✅ Exists"
        } else {
            "❌ Missing"
        }
    );
}

fn print_summary(
    security_status: &SecurityStatus,
    dir_status: &DirectoryStatus,
    nats_status: &NatsStatus,
    streams_status: &StreamsStatus,
) {
    println!("\n📊 Summary:");
    println!(
        "├─ Security Features: {}",
        if security_status.landlock_available && security_status.seccomp_available {
            "✅ Full"
        } else if security_status.is_linux {
            "⚠️  Partial"
        } else {
            "❌ Demo Only"
        }
    );
    println!(
        "├─ Directories: {}",
        if dir_status.all_valid {
            "✅ Valid"
        } else {
            "⚠️  Issues"
        }
    );
    println!(
        "├─ NATS: {}",
        if nats_status.connected {
            "✅ Connected"
        } else {
            "❌ Failed"
        }
    );
    println!(
        "└─ JetStream: {}",
        if nats_status.connected && streams_status.all_exist {
            "✅ Ready"
        } else {
            "❌ Not Ready"
        }
    );

    println!(
        "\n🚀 Executor Status: {}",
        if security_status.production_ready() && dir_status.all_valid && nats_status.connected {
            "READY FOR PRODUCTION"
        } else if security_status.is_linux {
            "READY FOR DEVELOPMENT (use --demo for unsafe mode)"
        } else {
            "DEMO MODE ONLY (unsupported OS)"
        }
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ==================== SecurityStatus Tests ====================

    #[test]
    fn test_security_status_production_ready_all_features() {
        let status = SecurityStatus {
            is_linux: true,
            landlock_available: true,
            seccomp_available: true,
            cgroups_available: true,
            is_root: false,
            kernel_version: "Linux 6.0.0".to_string(),
        };
        assert!(status.production_ready());
    }

    #[test]
    fn test_security_status_production_ready_not_linux() {
        let status = SecurityStatus {
            is_linux: false,
            landlock_available: true,
            seccomp_available: true,
            cgroups_available: true,
            is_root: false,
            kernel_version: "Darwin 21.0.0".to_string(),
        };
        assert!(!status.production_ready());
    }

    #[test]
    fn test_security_status_production_ready_no_landlock() {
        let status = SecurityStatus {
            is_linux: true,
            landlock_available: false,
            seccomp_available: true,
            cgroups_available: true,
            is_root: false,
            kernel_version: "Linux 5.10.0".to_string(),
        };
        assert!(!status.production_ready());
    }

    #[test]
    fn test_security_status_production_ready_root_user() {
        let status = SecurityStatus {
            is_linux: true,
            landlock_available: true,
            seccomp_available: true,
            cgroups_available: true,
            is_root: true, // Running as root
            kernel_version: "Linux 6.0.0".to_string(),
        };
        assert!(!status.production_ready());
    }

    #[test]
    fn test_security_status_debug() {
        let status = SecurityStatus {
            is_linux: true,
            landlock_available: true,
            seccomp_available: true,
            cgroups_available: true,
            is_root: false,
            kernel_version: "Linux 6.0.0".to_string(),
        };
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("is_linux"));
        assert!(debug_str.contains("landlock_available"));
    }

    // ==================== DirectoryStatus Tests ====================

    #[test]
    fn test_directory_status_all_valid() {
        let status = DirectoryStatus {
            work_root: true,
            state_dir: true,
            audit_dir: true,
            all_valid: true,
        };
        assert!(status.all_valid);
    }

    #[test]
    fn test_directory_status_partial() {
        let status = DirectoryStatus {
            work_root: true,
            state_dir: false,
            audit_dir: true,
            all_valid: false,
        };
        assert!(!status.all_valid);
        assert!(status.work_root);
        assert!(!status.state_dir);
    }

    #[test]
    fn test_directory_status_debug() {
        let status = DirectoryStatus {
            work_root: true,
            state_dir: true,
            audit_dir: true,
            all_valid: true,
        };
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("work_root"));
        assert!(debug_str.contains("state_dir"));
        assert!(debug_str.contains("audit_dir"));
    }

    // ==================== NatsStatus Tests ====================

    #[test]
    fn test_nats_status_connected() {
        let status = NatsStatus {
            connected: true,
            error: None,
            jetstream_available: true,
        };
        assert!(status.connected);
        assert!(status.jetstream_available);
        assert!(status.error.is_none());
    }

    #[test]
    fn test_nats_status_disconnected_with_error() {
        let status = NatsStatus {
            connected: false,
            error: Some("Connection refused".to_string()),
            jetstream_available: false,
        };
        assert!(!status.connected);
        assert!(status.error.is_some());
        assert_eq!(status.error.unwrap(), "Connection refused");
    }

    #[test]
    fn test_nats_status_debug() {
        let status = NatsStatus {
            connected: true,
            error: None,
            jetstream_available: true,
        };
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("connected"));
        assert!(debug_str.contains("jetstream_available"));
    }

    // ==================== StreamsStatus Tests ====================

    #[test]
    fn test_streams_status_default() {
        let status = StreamsStatus::default();
        assert!(!status.intents);
        assert!(!status.results);
        assert!(!status.audit);
        assert!(!status.system);
        assert!(!status.all_exist);
    }

    #[test]
    fn test_streams_status_all_exist() {
        let status = StreamsStatus {
            intents: true,
            results: true,
            audit: true,
            system: true,
            all_exist: true,
        };
        assert!(status.all_exist);
    }

    #[test]
    fn test_streams_status_partial() {
        let status = StreamsStatus {
            intents: true,
            results: false,
            audit: true,
            system: false,
            all_exist: false,
        };
        assert!(!status.all_exist);
        assert!(status.intents);
        assert!(!status.results);
    }

    #[test]
    fn test_streams_status_debug() {
        let status = StreamsStatus::default();
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("intents"));
        assert!(debug_str.contains("results"));
        assert!(debug_str.contains("audit"));
    }

    // ==================== can_create_dir Tests ====================

    #[test]
    fn test_can_create_dir_existing_parent() {
        let temp_dir = TempDir::new().unwrap();
        let new_path = temp_dir.path().join("new_dir");
        assert!(can_create_dir(&new_path));
    }

    #[test]
    fn test_can_create_dir_no_parent() {
        let path = PathBuf::from("/nonexistent/parent/dir");
        assert!(!can_create_dir(&path));
    }

    #[test]
    fn test_can_create_dir_root() {
        let path = PathBuf::from("/");
        // Root has no parent, so should return false
        let parent = path.parent();
        assert!(parent.is_none());
        assert!(!can_create_dir(&path));
    }

    // ==================== Print Functions Tests (don't panic) ====================

    #[test]
    fn test_print_security_status_linux_ready() {
        let status = SecurityStatus {
            is_linux: true,
            landlock_available: true,
            seccomp_available: true,
            cgroups_available: true,
            is_root: false,
            kernel_version: "Linux version 6.0.0-generic".to_string(),
        };
        // Just ensure it doesn't panic
        print_security_status(&status);
    }

    #[test]
    fn test_print_security_status_non_linux() {
        let status = SecurityStatus {
            is_linux: false,
            landlock_available: false,
            seccomp_available: false,
            cgroups_available: false,
            is_root: false,
            kernel_version: "Darwin Kernel Version 21.0.0".to_string(),
        };
        // Just ensure it doesn't panic
        print_security_status(&status);
    }

    #[test]
    fn test_print_security_status_root_user() {
        let status = SecurityStatus {
            is_linux: true,
            landlock_available: true,
            seccomp_available: true,
            cgroups_available: true,
            is_root: true,
            kernel_version: "Linux version 6.0.0".to_string(),
        };
        // Just ensure it doesn't panic
        print_security_status(&status);
    }

    #[test]
    fn test_print_directory_status_all_ok() {
        let status = DirectoryStatus {
            work_root: true,
            state_dir: true,
            audit_dir: true,
            all_valid: true,
        };
        // Just ensure it doesn't panic
        print_directory_status(&status);
    }

    #[test]
    fn test_print_directory_status_issues() {
        let status = DirectoryStatus {
            work_root: true,
            state_dir: false,
            audit_dir: false,
            all_valid: false,
        };
        // Just ensure it doesn't panic
        print_directory_status(&status);
    }

    #[test]
    fn test_print_nats_status_connected() {
        let status = NatsStatus {
            connected: true,
            error: None,
            jetstream_available: true,
        };
        // Just ensure it doesn't panic
        print_nats_status(&status);
    }

    #[test]
    fn test_print_nats_status_disconnected() {
        let status = NatsStatus {
            connected: false,
            error: Some("Connection timed out".to_string()),
            jetstream_available: false,
        };
        // Just ensure it doesn't panic
        print_nats_status(&status);
    }

    #[test]
    fn test_print_streams_status_all_exist() {
        let status = StreamsStatus {
            intents: true,
            results: true,
            audit: true,
            system: true,
            all_exist: true,
        };
        // Just ensure it doesn't panic
        print_streams_status(&status);
    }

    #[test]
    fn test_print_streams_status_missing() {
        let status = StreamsStatus::default();
        // Just ensure it doesn't panic
        print_streams_status(&status);
    }

    #[test]
    fn test_print_summary_production_ready() {
        let security = SecurityStatus {
            is_linux: true,
            landlock_available: true,
            seccomp_available: true,
            cgroups_available: true,
            is_root: false,
            kernel_version: "Linux 6.0.0".to_string(),
        };
        let dir = DirectoryStatus {
            work_root: true,
            state_dir: true,
            audit_dir: true,
            all_valid: true,
        };
        let nats = NatsStatus {
            connected: true,
            error: None,
            jetstream_available: true,
        };
        let streams = StreamsStatus {
            intents: true,
            results: true,
            audit: true,
            system: true,
            all_exist: true,
        };
        // Just ensure it doesn't panic
        print_summary(&security, &dir, &nats, &streams);
    }

    #[test]
    fn test_print_summary_dev_mode() {
        let security = SecurityStatus {
            is_linux: true,
            landlock_available: false,
            seccomp_available: true,
            cgroups_available: true,
            is_root: false,
            kernel_version: "Linux 5.10.0".to_string(),
        };
        let dir = DirectoryStatus {
            work_root: true,
            state_dir: true,
            audit_dir: true,
            all_valid: true,
        };
        let nats = NatsStatus {
            connected: false,
            error: Some("Connection refused".to_string()),
            jetstream_available: false,
        };
        let streams = StreamsStatus::default();
        // Just ensure it doesn't panic
        print_summary(&security, &dir, &nats, &streams);
    }

    #[test]
    fn test_print_summary_demo_mode() {
        let security = SecurityStatus {
            is_linux: false,
            landlock_available: false,
            seccomp_available: false,
            cgroups_available: false,
            is_root: false,
            kernel_version: "Darwin 21.0.0".to_string(),
        };
        let dir = DirectoryStatus {
            work_root: true,
            state_dir: true,
            audit_dir: true,
            all_valid: true,
        };
        let nats = NatsStatus {
            connected: true,
            error: None,
            jetstream_available: true,
        };
        let streams = StreamsStatus::default();
        // Just ensure it doesn't panic
        print_summary(&security, &dir, &nats, &streams);
    }
}
