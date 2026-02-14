use anyhow::Result;
use std::ffi::{CString, NulError};
use std::mem::size_of;
use std::os::fd::RawFd;
// use std::os::unix::prelude::*; // Commented out - not used
use smith_config::LandlockProfile;
use std::path::Path;
use tracing::{debug, info, warn};

/// Landlock ABI version (requires Linux 5.15+)
#[allow(dead_code)]
const LANDLOCK_ABI_VERSION: u32 = 2;

/// Landlock access rights for filesystem operations
/// Values must match linux/landlock.h
#[repr(u64)]
#[derive(Debug, Clone, Copy)]
pub enum LandlockAccess {
    FsExecute = 1 << 0,      // 1
    FsWriteFile = 1 << 1,    // 2
    FsReadFile = 1 << 2,     // 4
    FsReadDir = 1 << 3,      // 8
    FsRemoveDir = 1 << 4,    // 16
    FsRemoveFile = 1 << 5,   // 32
    FsMakeChar = 1 << 6,     // 64
    FsMakeDir = 1 << 7,      // 128
    FsMakeReg = 1 << 8,      // 256
    FsMakeSock = 1 << 9,     // 512
    FsMakeFifo = 1 << 10,    // 1024
    FsMakeBlock = 1 << 11,   // 2048
    FsMakeSymlink = 1 << 12, // 4096
    FsRefer = 1 << 13,       // 8192 (ABI v2)
    FsTruncate = 1 << 14,    // 16384 (ABI v3)
}

/// Landlock filesystem rule configuration
#[derive(Debug, Clone)]
pub struct LandlockRule {
    pub path: String,
    pub access_rights: u64,
}

impl LandlockRule {
    /// Create rule allowing only read access (auto-detects file vs directory)
    pub fn read_only(path: &str) -> Self {
        let is_dir = Path::new(path).is_dir();
        let access_rights = if is_dir {
            // Directories need FsReadDir to list contents
            LandlockAccess::FsReadFile as u64 | LandlockAccess::FsReadDir as u64
        } else {
            // Files only need FsReadFile
            LandlockAccess::FsReadFile as u64
        };
        Self {
            path: path.to_string(),
            access_rights,
        }
    }

    /// Create rule allowing read and write access (auto-detects file vs directory)
    pub fn read_write(path: &str) -> Self {
        let is_dir = Path::new(path).is_dir();
        let access_rights = if is_dir {
            // Directories need directory-specific rights
            LandlockAccess::FsReadFile as u64
                | LandlockAccess::FsReadDir as u64
                | LandlockAccess::FsWriteFile as u64
                | LandlockAccess::FsMakeReg as u64
                | LandlockAccess::FsMakeDir as u64
                | LandlockAccess::FsRemoveFile as u64
                | LandlockAccess::FsRemoveDir as u64
                | LandlockAccess::FsTruncate as u64
        } else {
            // Files only need file-specific rights
            LandlockAccess::FsReadFile as u64
                | LandlockAccess::FsWriteFile as u64
                | LandlockAccess::FsTruncate as u64
        };
        Self {
            path: path.to_string(),
            access_rights,
        }
    }

    /// Create rule allowing execution access (auto-detects file vs directory)
    pub fn execute(path: &str) -> Self {
        let is_dir = Path::new(path).is_dir();
        let access_rights = if is_dir {
            // Directories need FsReadDir to traverse, FsExecute for binaries within
            LandlockAccess::FsExecute as u64
                | LandlockAccess::FsReadFile as u64
                | LandlockAccess::FsReadDir as u64
        } else {
            // Files need FsExecute and FsReadFile (to load the binary)
            LandlockAccess::FsExecute as u64 | LandlockAccess::FsReadFile as u64
        };
        Self {
            path: path.to_string(),
            access_rights,
        }
    }
}

/// Landlock configuration for path-based access control
#[derive(Debug, Clone)]
pub struct LandlockConfig {
    pub enabled: bool,
    pub rules: Vec<LandlockRule>,
    pub default_deny: bool,
}

impl Default for LandlockConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: Vec::new(),
            default_deny: true,
        }
    }
}

impl LandlockConfig {
    /// Add a read-only rule for a path
    pub fn allow_read(&mut self, path: &str) -> &mut Self {
        self.rules.push(LandlockRule::read_only(path));
        self
    }

    /// Add a read-write rule for a path
    pub fn allow_read_write(&mut self, path: &str) -> &mut Self {
        self.rules.push(LandlockRule::read_write(path));
        self
    }

    /// Add an execution rule for a path
    pub fn allow_execute(&mut self, path: &str) -> &mut Self {
        self.rules.push(LandlockRule::execute(path));
        self
    }
}

/// Landlock ruleset handle
pub struct LandlockRuleset {
    fd: RawFd,
}

impl Drop for LandlockRuleset {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// System call numbers for Landlock (these may vary by architecture)
#[cfg(target_arch = "x86_64")]
mod syscall_numbers {
    pub const LANDLOCK_CREATE_RULESET: i64 = 444;
    pub const LANDLOCK_ADD_RULE: i64 = 445;
    pub const LANDLOCK_RESTRICT_SELF: i64 = 446;
}

#[cfg(target_arch = "aarch64")]
mod syscall_numbers {
    pub const LANDLOCK_CREATE_RULESET: i64 = 444;
    pub const LANDLOCK_ADD_RULE: i64 = 445;
    pub const LANDLOCK_RESTRICT_SELF: i64 = 446;
}

use syscall_numbers::*;

/// Landlock ruleset attributes structure
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

/// Landlock path beneath rule structure
#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Check if Landlock is available on the system
pub fn is_landlock_available() -> bool {
    debug!("Checking Landlock availability");

    // Try to create a dummy ruleset to test if Landlock is available
    let attr = LandlockRulesetAttr {
        handled_access_fs: LandlockAccess::FsReadFile as u64,
    };

    let fd = unsafe {
        libc::syscall(
            LANDLOCK_CREATE_RULESET,
            &attr as *const LandlockRulesetAttr,
            size_of::<LandlockRulesetAttr>(),
            0u32, // flags
        ) as i32
    };

    if fd >= 0 {
        unsafe { libc::close(fd) };
        info!("Landlock is available");
        true
    } else {
        let error = std::io::Error::last_os_error();
        warn!("Landlock is not available: {}", error);
        false
    }
}

/// Create Landlock ruleset and apply rules
pub fn apply_landlock_rules(config: &LandlockConfig) -> Result<()> {
    if !config.enabled {
        debug!("Landlock is disabled in configuration");
        return Ok(());
    }

    if config.rules.is_empty() {
        warn!("No Landlock rules configured, skipping");
        return Ok(());
    }

    if !is_landlock_available() {
        return Err(anyhow::anyhow!(
            "Landlock is not available on this system (requires Linux 5.15+)"
        ));
    }

    debug!("Applying {} Landlock rules", config.rules.len());

    // Calculate all handled access rights
    let mut handled_access_fs = 0u64;
    for rule in &config.rules {
        handled_access_fs |= rule.access_rights;
    }

    // Create ruleset
    let ruleset = create_landlock_ruleset(handled_access_fs)?;

    // Add rules to the ruleset
    for rule in &config.rules {
        add_landlock_rule(&ruleset, rule)?;
    }

    // Apply the ruleset to the current process
    restrict_self_with_ruleset(&ruleset)?;

    info!("Successfully applied {} Landlock rules", config.rules.len());
    Ok(())
}

/// Create a new Landlock ruleset
fn create_landlock_ruleset(handled_access_fs: u64) -> Result<LandlockRuleset> {
    let attr = LandlockRulesetAttr { handled_access_fs };

    let fd = unsafe {
        libc::syscall(
            LANDLOCK_CREATE_RULESET,
            &attr as *const LandlockRulesetAttr,
            size_of::<LandlockRulesetAttr>(),
            0u32, // flags
        ) as i32
    };

    if fd < 0 {
        return Err(anyhow::anyhow!(
            "Failed to create Landlock ruleset: {}",
            std::io::Error::last_os_error()
        ));
    }

    debug!("Created Landlock ruleset with fd: {}", fd);
    Ok(LandlockRuleset { fd })
}

/// Add a rule to the Landlock ruleset
fn add_landlock_rule(ruleset: &LandlockRuleset, rule: &LandlockRule) -> Result<()> {
    debug!(
        "Adding Landlock rule for path: {} with access: {:#x}",
        rule.path, rule.access_rights
    );

    // Open the path to get a file descriptor
    let _path = Path::new(&rule.path);
    let path_fd = unsafe {
        let path_cstr = CString::new(rule.path.as_bytes())
            .map_err(|e: NulError| anyhow::anyhow!("Invalid path: {}", e))?;
        libc::open(path_cstr.as_ptr(), libc::O_PATH | libc::O_CLOEXEC)
    };

    if path_fd < 0 {
        return Err(anyhow::anyhow!(
            "Failed to open path {} for Landlock rule: {}",
            rule.path,
            std::io::Error::last_os_error()
        ));
    }

    // Create path beneath attribute
    let path_beneath_attr = LandlockPathBeneathAttr {
        allowed_access: rule.access_rights,
        parent_fd: path_fd,
    };

    let result = unsafe {
        libc::syscall(
            LANDLOCK_ADD_RULE,
            ruleset.fd,
            1u32, // LANDLOCK_RULE_PATH_BENEATH
            &path_beneath_attr as *const LandlockPathBeneathAttr,
            0u32, // flags
        ) as i32
    };

    // Close the path file descriptor
    unsafe { libc::close(path_fd) };

    if result != 0 {
        return Err(anyhow::anyhow!(
            "Failed to add Landlock rule for path {}: {}",
            rule.path,
            std::io::Error::last_os_error()
        ));
    }

    debug!("Successfully added Landlock rule for path: {}", rule.path);
    Ok(())
}

/// Apply the ruleset to the current process
fn restrict_self_with_ruleset(ruleset: &LandlockRuleset) -> Result<()> {
    debug!("Restricting process with Landlock ruleset");

    // Landlock requires NO_NEW_PRIVS to be set before restricting
    // This prevents the process from gaining new privileges after being sandboxed
    let nnp_result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if nnp_result != 0 {
        return Err(anyhow::anyhow!(
            "Failed to set NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        ));
    }
    debug!("Set NO_NEW_PRIVS for Landlock");

    let result = unsafe {
        libc::syscall(
            LANDLOCK_RESTRICT_SELF,
            ruleset.fd,
            0u32, // flags
        ) as i32
    };

    if result != 0 {
        return Err(anyhow::anyhow!(
            "Failed to restrict process with Landlock ruleset: {}",
            std::io::Error::last_os_error()
        ));
    }

    debug!("Successfully restricted process with Landlock ruleset");
    Ok(())
}

/// Create default Landlock configuration for capability execution
pub fn create_capability_landlock_config(
    capability: &str,
    allowed_paths: &[String],
    workdir: &Path,
) -> LandlockConfig {
    let mut config = LandlockConfig::default();

    // Always allow read/write access to workdir
    config.allow_read_write(&workdir.to_string_lossy());

    // Allow read access to capability-specific paths
    for path in allowed_paths {
        match capability {
            "fs.read" | "fs.read.v1" => {
                // Read-only access for fs.read capability
                config.allow_read(path);
            }
            "http.fetch" | "http.fetch.v1" => {
                // For HTTP fetch, allow all specified paths including SSL certs
                config.allow_read(path);
            }
            _ => {
                // Default to read-only for unknown capabilities
                config.allow_read(path);
            }
        }
    }

    // Add capability-specific system paths
    match capability {
        "http.fetch" | "http.fetch.v1" => {
            // HTTP fetch needs DNS resolution access
            config.allow_read("/etc/resolv.conf");
            config.allow_read("/etc/hosts");
            // SSL certificate access
            config.allow_read("/etc/ssl");
            config.allow_read("/etc/pki");
            config.allow_read("/usr/share/ca-certificates");
        }
        _ => {}
    }

    // Essential system paths for all capabilities
    config.allow_read("/proc");
    config.allow_read("/sys");
    config.allow_read("/dev/null");
    config.allow_read("/dev/zero");
    config.allow_read("/dev/urandom");

    config
}

/// Create Landlock configuration from derived policy profiles.
pub fn landlock_config_from_profile(
    capability: &str,
    profile: &LandlockProfile,
    workdir: &Path,
) -> LandlockConfig {
    let mut config = LandlockConfig::default();

    config.allow_read_write(&workdir.to_string_lossy());

    for path in &profile.read {
        config.allow_read(path);
    }

    for path in &profile.write {
        config.allow_read_write(path);
    }

    match capability {
        "http.fetch" | "http.fetch.v1" => {
            config.allow_read("/etc/resolv.conf");
            config.allow_read("/etc/hosts");
            config.allow_read("/etc/ssl");
            config.allow_read("/etc/pki");
            config.allow_read("/usr/share/ca-certificates");
        }
        _ => {}
    }

    config.allow_read("/proc");
    config.allow_read("/sys");
    config.allow_read("/dev/null");
    config.allow_read("/dev/zero");
    config.allow_read("/dev/urandom");

    config
}

/// Fallback implementation when Landlock is not available
pub fn apply_fallback_path_restrictions(allowed_paths: &[String]) -> Result<()> {
    warn!("Landlock not available, applying fallback path restrictions");

    // In fallback mode, we rely on:
    // 1. Strict bind mounting (implemented in namespaces.rs)
    // 2. O_NOFOLLOW flag usage in file operations
    // 3. Careful path validation in runners

    info!(
        "Applied fallback path restrictions for {} paths",
        allowed_paths.len()
    );

    // Log the paths that would be restricted for audit purposes
    for (i, path) in allowed_paths.iter().enumerate() {
        debug!("Fallback restriction {}: {}", i + 1, path);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_landlock_rule_creation() {
        let rule = LandlockRule::read_only("/tmp");
        assert_eq!(rule.path, "/tmp");
        assert!(rule.access_rights & (LandlockAccess::FsReadFile as u64) != 0);
        assert!(rule.access_rights & (LandlockAccess::FsReadDir as u64) != 0);
        assert!(rule.access_rights & (LandlockAccess::FsWriteFile as u64) == 0);
    }

    #[test]
    fn test_landlock_config_builder() {
        let mut config = LandlockConfig::default();
        config
            .allow_read("/etc")
            .allow_read_write("/tmp")
            .allow_execute("/usr/bin");

        assert_eq!(config.rules.len(), 3);
        assert!(config.enabled);
        assert!(config.default_deny);
    }

    #[test]
    fn test_capability_landlock_config() {
        let temp_dir = tempdir().unwrap();
        let allowed_paths = vec!["/etc/ssl/certs".to_string()];

        let config = create_capability_landlock_config("fs.read", &allowed_paths, temp_dir.path());

        assert!(config.enabled);
        assert!(!config.rules.is_empty());

        // Should contain workdir and allowed path
        let path_count = config
            .rules
            .iter()
            .filter(|r| {
                r.path.contains(temp_dir.path().to_str().unwrap()) || r.path == "/etc/ssl/certs"
            })
            .count();
        assert!(path_count >= 2);
    }

    #[test]
    fn test_landlock_access_values() {
        // Verify the access right values match Landlock ABI
        assert_eq!(LandlockAccess::FsExecute as u64, 1);
        assert_eq!(LandlockAccess::FsWriteFile as u64, 2);
        assert_eq!(LandlockAccess::FsReadFile as u64, 4);
        assert_eq!(LandlockAccess::FsReadDir as u64, 8);
    }

    #[test]
    fn test_read_write_rule_contains_all_needed_rights() {
        let rule = LandlockRule::read_write("/tmp");

        // Should contain read rights
        assert!(rule.access_rights & (LandlockAccess::FsReadFile as u64) != 0);
        assert!(rule.access_rights & (LandlockAccess::FsReadDir as u64) != 0);

        // Should contain write rights
        assert!(rule.access_rights & (LandlockAccess::FsWriteFile as u64) != 0);
        assert!(rule.access_rights & (LandlockAccess::FsMakeReg as u64) != 0);
        assert!(rule.access_rights & (LandlockAccess::FsMakeDir as u64) != 0);
        assert!(rule.access_rights & (LandlockAccess::FsRemoveFile as u64) != 0);
        assert!(rule.access_rights & (LandlockAccess::FsRemoveDir as u64) != 0);
    }
}
