use anyhow::{Context, Result};
use std::ffi::{CString, NulError};
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::prelude::*;
use std::time::Instant;
use tracing::{debug, error, info, warn};

/// Linux namespace types
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum NamespaceType {
    User = libc::CLONE_NEWUSER as u32,
    Mount = libc::CLONE_NEWNS as u32,
    Pid = libc::CLONE_NEWPID as u32,
    Net = libc::CLONE_NEWNET as u32,
    Uts = libc::CLONE_NEWUTS as u32,
    Ipc = libc::CLONE_NEWIPC as u32,
}

/// Namespace configuration for sandboxed execution
#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    pub uid_map: Vec<(u32, u32, u32)>, // (container_uid, host_uid, count)
    pub gid_map: Vec<(u32, u32, u32)>, // (container_gid, host_gid, count)
    pub mount_proc: bool,
    pub mount_tmpfs: bool,
    pub bind_mounts: Vec<BindMount>,
}

/// Bind mount configuration
#[derive(Debug, Clone)]
pub struct BindMount {
    pub source: String,
    pub target: String,
    pub readonly: bool,
    pub options: Vec<String>,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        let host_uid = unsafe { libc::geteuid() as u32 };
        let host_gid = unsafe { libc::getegid() as u32 };
        Self {
            // Map sandbox root to the invoking host user so workspace access
            // continues to work under user namespaces.
            uid_map: vec![(0, host_uid, 1)],
            gid_map: vec![(0, host_gid, 1)],
            mount_proc: true,
            mount_tmpfs: true,
            bind_mounts: vec![
                // Essential system files for SSL/TLS
                BindMount {
                    source: "/etc/ssl/certs".to_string(),
                    target: "/etc/ssl/certs".to_string(),
                    readonly: true,
                    options: vec!["nosuid".to_string(), "nodev".to_string()],
                },
                // Essential system files for DNS resolution
                BindMount {
                    source: "/etc/resolv.conf".to_string(),
                    target: "/etc/resolv.conf".to_string(),
                    readonly: true,
                    options: vec!["nosuid".to_string(), "nodev".to_string()],
                },
            ],
        }
    }
}

/// Handle to created namespaces
pub struct NamespaceHandle {
    pub pid: libc::pid_t,
    pub user_ns_fd: Option<RawFd>,
    pub mount_ns_fd: Option<RawFd>,
    pub pid_ns_fd: Option<RawFd>,
    pub net_ns_fd: Option<RawFd>,
    pub uts_ns_fd: Option<RawFd>,
    pub ipc_ns_fd: Option<RawFd>,
}

impl Drop for NamespaceHandle {
    fn drop(&mut self) {
        // Close namespace file descriptors
        if let Some(fd) = self.user_ns_fd.take() {
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.mount_ns_fd.take() {
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.pid_ns_fd.take() {
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.net_ns_fd.take() {
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.uts_ns_fd.take() {
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.ipc_ns_fd.take() {
            unsafe { libc::close(fd) };
        }
    }
}

/// Create namespaces for sandboxed execution
pub fn create_namespaces(config: &NamespaceConfig) -> Result<NamespaceHandle> {
    debug!("Creating namespaces for sandboxed execution");

    // Attempt to create namespaces individually so we can degrade gracefully on
    // hosts that disable specific isolation features (common in local dev
    // environments).
    let user_created = ensure_namespace(NamespaceType::User, "user", false)?;
    if user_created {
        if let Err(error) = configure_uid_gid_mapping(config) {
            warn!(
                %error,
                "Failed to configure UID/GID mapping inside user namespace; continuing without remap"
            );
        }
    } else {
        warn!("User namespace unavailable; continuing without UID/GID remapping");
    }

    let mount_created = ensure_namespace(NamespaceType::Mount, "mount", false)?;
    let pid_created = ensure_namespace(NamespaceType::Pid, "pid", false)?;
    let net_created = ensure_namespace(NamespaceType::Net, "network", false)?;
    let uts_created = ensure_namespace(NamespaceType::Uts, "uts", false)?;
    let ipc_created = ensure_namespace(NamespaceType::Ipc, "ipc", false)?;

    let pid = unsafe { libc::getpid() };

    let user_ns_fd = if user_created {
        Some(open_namespace_fd(pid, "user")?)
    } else {
        None
    };
    let mount_ns_fd = if mount_created {
        Some(open_namespace_fd(pid, "mnt")?)
    } else {
        None
    };
    let pid_ns_fd = if pid_created {
        Some(open_namespace_fd(pid, "pid")?)
    } else {
        None
    };
    let net_ns_fd = if net_created {
        Some(open_namespace_fd(pid, "net")?)
    } else {
        None
    };
    let uts_ns_fd = if uts_created {
        Some(open_namespace_fd(pid, "uts")?)
    } else {
        None
    };
    let ipc_ns_fd = if ipc_created {
        Some(open_namespace_fd(pid, "ipc")?)
    } else {
        None
    };

    info!(
        user = user_created,
        mount = mount_created,
        pid = pid_created,
        net = net_created,
        uts = uts_created,
        ipc = ipc_created,
        "Namespace isolation configured"
    );

    Ok(NamespaceHandle {
        pid,
        user_ns_fd,
        mount_ns_fd,
        pid_ns_fd,
        net_ns_fd,
        uts_ns_fd,
        ipc_ns_fd,
    })
}

fn ensure_namespace(ns_type: NamespaceType, label: &str, required: bool) -> Result<bool> {
    let flag = ns_type as i32;
    debug!(namespace = label, "Attempting to create namespace");
    let start = Instant::now();
    let result = unsafe { libc::unshare(flag) };
    let elapsed_ms = start.elapsed().as_millis() as u64;
    if result == 0 {
        info!(
            namespace = label,
            elapsed_ms, "Successfully created namespace"
        );
        return Ok(true);
    }

    let error = io::Error::last_os_error();
    let errno = error.raw_os_error();

    match errno {
        Some(libc::EPERM) | Some(libc::EACCES) => {
            if required {
                error!(
                    namespace = label,
                    %error,
                    elapsed_ms,
                    "Permission denied while creating namespace"
                );
                Err(anyhow::anyhow!(
                    "Failed to create {} namespace (permission denied): {}",
                    label,
                    error
                ))
            } else {
                warn!(
                    namespace = label,
                    %error,
                    elapsed_ms,
                    "Namespace unavailable (permission denied); continuing without isolation"
                );
                Ok(false)
            }
        }
        Some(libc::EINVAL) => {
            if required {
                error!(
                    namespace = label,
                    %error,
                    elapsed_ms,
                    "Namespace unsupported by kernel"
                );
                Err(anyhow::anyhow!(
                    "Failed to create {} namespace (unsupported by kernel): {}",
                    label,
                    error
                ))
            } else {
                warn!(
                    namespace = label,
                    %error,
                    elapsed_ms,
                    "Namespace unsupported by kernel; continuing without isolation"
                );
                Ok(false)
            }
        }
        Some(libc::EUSERS) => {
            // Too many user namespaces created; treat as fatal for required namespaces.
            if required {
                error!(
                    namespace = label,
                    %error,
                    elapsed_ms,
                    "Namespace quota reached"
                );
                Err(anyhow::anyhow!(
                    "Failed to create {} namespace (namespace quota reached): {}",
                    label,
                    error
                ))
            } else {
                warn!(
                    namespace = label,
                    %error,
                    elapsed_ms,
                    "Namespace quota reached; continuing without isolation"
                );
                Ok(false)
            }
        }
        _ => {
            if required {
                error!(
                    namespace = label,
                    %error,
                    elapsed_ms,
                    "Namespace creation failed"
                );
                Err(anyhow::anyhow!(
                    "Failed to create {} namespace: {}",
                    label,
                    error
                ))
            } else {
                warn!(
                    namespace = label,
                    %error,
                    elapsed_ms,
                    "Namespace creation failed; continuing without isolation"
                );
                Ok(false)
            }
        }
    }
}

/// Open namespace file descriptor
fn open_namespace_fd(pid: libc::pid_t, ns_type: &str) -> Result<RawFd> {
    let ns_path = format!("/proc/{}/ns/{}", pid, ns_type);
    let fd = unsafe {
        let path_cstr = CString::new(ns_path.clone())
            .map_err(|e: NulError| anyhow::anyhow!("Invalid namespace path: {}", e))?;
        libc::open(path_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
    };

    if fd < 0 {
        return Err(anyhow::anyhow!(
            "Failed to open namespace {}: {}",
            ns_path,
            std::io::Error::last_os_error()
        ));
    }

    debug!("Opened namespace fd {} for {}", fd, ns_type);
    Ok(fd)
}

/// Configure UID and GID mapping in user namespace
fn configure_uid_gid_mapping(config: &NamespaceConfig) -> Result<()> {
    debug!("Configuring UID/GID mapping");

    // Deny setgroups to enable gid_map writing
    write_to_file("/proc/self/setgroups", "deny").context("Failed to deny setgroups")?;

    // Write UID mapping
    let uid_map_content = format_id_map(&config.uid_map);
    write_to_file("/proc/self/uid_map", &uid_map_content).context("Failed to write UID mapping")?;

    // Write GID mapping
    let gid_map_content = format_id_map(&config.gid_map);
    write_to_file("/proc/self/gid_map", &gid_map_content).context("Failed to write GID mapping")?;

    info!("Successfully configured UID/GID mapping");
    Ok(())
}

/// Format ID mapping for writing to uid_map/gid_map
fn format_id_map(mappings: &[(u32, u32, u32)]) -> String {
    mappings
        .iter()
        .map(|(container_id, host_id, count)| format!("{} {} {}", container_id, host_id, count))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Write content to a file (used for proc filesystem configuration)
fn write_to_file(path: &str, content: &str) -> Result<()> {
    debug!("Writing to {}: {}", path, content);
    let mut file =
        File::create(path).with_context(|| format!("Failed to create file: {}", path))?;
    file.write_all(content.as_bytes())
        .with_context(|| format!("Failed to write to file: {}", path))?;
    file.sync_all()
        .with_context(|| format!("Failed to sync file: {}", path))?;
    Ok(())
}

/// Setup mount namespace with proc, tmpfs, and bind mounts
pub fn setup_mount_namespace(config: &NamespaceConfig, workdir: &std::path::Path) -> Result<()> {
    debug!(
        "Setting up mount namespace in workdir: {}",
        workdir.display()
    );

    // Make root filesystem private to avoid propagating changes
    let result = unsafe {
        libc::mount(
            std::ptr::null(),
            b"/\0".as_ptr() as *const libc::c_char,
            std::ptr::null(),
            libc::MS_PRIVATE | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if result != 0 {
        return Err(anyhow::anyhow!(
            "Failed to make root filesystem private: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Mount proc filesystem if requested
    if config.mount_proc {
        mount_proc_filesystem(workdir)?;
    }

    // Mount tmpfs for /tmp if requested
    if config.mount_tmpfs {
        mount_tmpfs_filesystem(workdir)?;
    }

    // Apply bind mounts
    for bind_mount in &config.bind_mounts {
        apply_bind_mount(bind_mount, workdir)?;
    }

    info!("Successfully setup mount namespace");
    Ok(())
}

/// Mount proc filesystem in the namespace
fn mount_proc_filesystem(workdir: &std::path::Path) -> Result<()> {
    let proc_dir = workdir.join("proc");
    std::fs::create_dir_all(&proc_dir)
        .with_context(|| format!("Failed to create proc directory: {}", proc_dir.display()))?;

    let result = unsafe {
        let source = b"proc\0".as_ptr() as *const libc::c_char;
        let target =
            CString::new(proc_dir.as_os_str().as_bytes()).context("Invalid proc directory path")?;
        let fstype = b"proc\0".as_ptr() as *const libc::c_char;
        let flags = libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV;

        libc::mount(source, target.as_ptr(), fstype, flags, std::ptr::null())
    };

    if result != 0 {
        return Err(anyhow::anyhow!(
            "Failed to mount proc filesystem: {}",
            std::io::Error::last_os_error()
        ));
    }

    debug!("Successfully mounted proc filesystem");
    Ok(())
}

/// Mount tmpfs filesystem for /tmp
fn mount_tmpfs_filesystem(workdir: &std::path::Path) -> Result<()> {
    let tmp_dir = workdir.join("tmp");
    std::fs::create_dir_all(&tmp_dir)
        .with_context(|| format!("Failed to create tmp directory: {}", tmp_dir.display()))?;

    let result = unsafe {
        let source = b"tmpfs\0".as_ptr() as *const libc::c_char;
        let target =
            CString::new(tmp_dir.as_os_str().as_bytes()).context("Invalid tmp directory path")?;
        let fstype = b"tmpfs\0".as_ptr() as *const libc::c_char;
        let flags = libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV;
        // Limit tmpfs size to 64MB by default
        let data = b"size=67108864,mode=1777\0".as_ptr() as *const libc::c_void;

        libc::mount(source, target.as_ptr(), fstype, flags, data)
    };

    if result != 0 {
        return Err(anyhow::anyhow!(
            "Failed to mount tmpfs filesystem: {}",
            std::io::Error::last_os_error()
        ));
    }

    debug!("Successfully mounted tmpfs filesystem");
    Ok(())
}

/// Apply a bind mount
fn apply_bind_mount(bind_mount: &BindMount, workdir: &std::path::Path) -> Result<()> {
    let target_path = if bind_mount.target.starts_with('/') {
        workdir.join(&bind_mount.target[1..]) // Remove leading slash for relative to workdir
    } else {
        workdir.join(&bind_mount.target)
    };

    // Create target directory if it doesn't exist
    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create bind mount target parent: {}",
                parent.display()
            )
        })?;
    }

    // Create the target file/directory
    if std::path::Path::new(&bind_mount.source).is_dir() {
        std::fs::create_dir_all(&target_path).with_context(|| {
            format!(
                "Failed to create bind mount target directory: {}",
                target_path.display()
            )
        })?;
    } else {
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create bind mount target parent: {}",
                    parent.display()
                )
            })?;
        }
        File::create(&target_path).with_context(|| {
            format!(
                "Failed to create bind mount target file: {}",
                target_path.display()
            )
        })?;
    }

    let mut flags = libc::MS_BIND;
    if bind_mount.readonly {
        flags |= libc::MS_RDONLY;
    }

    // Apply additional mount options
    for option in &bind_mount.options {
        match option.as_str() {
            "nosuid" => flags |= libc::MS_NOSUID,
            "nodev" => flags |= libc::MS_NODEV,
            "noexec" => flags |= libc::MS_NOEXEC,
            _ => warn!("Unknown mount option: {}", option),
        }
    }

    let result = unsafe {
        let source =
            CString::new(bind_mount.source.as_bytes()).context("Invalid bind mount source path")?;
        let target = CString::new(target_path.as_os_str().as_bytes())
            .context("Invalid bind mount target path")?;

        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };

    if result != 0 {
        return Err(anyhow::anyhow!(
            "Failed to apply bind mount from {} to {}: {}",
            bind_mount.source,
            target_path.display(),
            std::io::Error::last_os_error()
        ));
    }

    debug!(
        "Successfully applied bind mount: {} -> {} (readonly: {})",
        bind_mount.source,
        target_path.display(),
        bind_mount.readonly
    );
    Ok(())
}

/// Pivot root to the new root directory
pub fn pivot_root_to_workdir(workdir: &std::path::Path) -> Result<()> {
    debug!("Pivoting root to workdir: {}", workdir.display());

    // Create old_root directory in the new root
    let old_root = workdir.join("old_root");
    std::fs::create_dir_all(&old_root).with_context(|| {
        format!(
            "Failed to create old_root directory: {}",
            old_root.display()
        )
    })?;

    let result = unsafe {
        let new_root =
            CString::new(workdir.as_os_str().as_bytes()).context("Invalid workdir path")?;
        let old_root_cstr =
            CString::new(old_root.as_os_str().as_bytes()).context("Invalid old_root path")?;

        libc::syscall(
            libc::SYS_pivot_root,
            new_root.as_ptr(),
            old_root_cstr.as_ptr(),
        ) as i32
    };

    if result != 0 {
        return Err(anyhow::anyhow!(
            "Failed to pivot root: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Change to the new root directory
    std::env::set_current_dir("/").context("Failed to change to new root directory")?;

    // Unmount the old root (lazy unmount)
    let result = unsafe {
        let old_root = b"/old_root\0".as_ptr() as *const libc::c_char;
        libc::umount2(old_root, libc::MNT_DETACH)
    };

    if result != 0 {
        warn!(
            "Failed to unmount old root: {}",
            std::io::Error::last_os_error()
        );
    }

    // Remove the old_root directory
    if let Err(e) = std::fs::remove_dir("/old_root") {
        warn!("Failed to remove old_root directory: {}", e);
    }

    info!("Successfully pivoted root to workdir");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_config_default() {
        let config = NamespaceConfig::default();
        let host_uid = unsafe { libc::geteuid() as u32 };
        let host_gid = unsafe { libc::getegid() as u32 };
        assert_eq!(config.uid_map, vec![(0, host_uid, 1)]);
        assert_eq!(config.gid_map, vec![(0, host_gid, 1)]);
        assert!(config.mount_proc);
        assert!(config.mount_tmpfs);
        assert!(!config.bind_mounts.is_empty());
    }

    #[test]
    fn test_format_id_map() {
        let mappings = vec![(0, 1000, 1), (1, 2000, 100)];
        let result = format_id_map(&mappings);
        assert_eq!(result, "0 1000 1\n1 2000 100");
    }

    #[test]
    #[cfg(unix)]
    fn test_namespace_type_values() {
        assert_eq!(NamespaceType::User as u32, libc::CLONE_NEWUSER as u32);
        assert_eq!(NamespaceType::Mount as u32, libc::CLONE_NEWNS as u32);
        assert_eq!(NamespaceType::Pid as u32, libc::CLONE_NEWPID as u32);
        assert_eq!(NamespaceType::Net as u32, libc::CLONE_NEWNET as u32);
        assert_eq!(NamespaceType::Uts as u32, libc::CLONE_NEWUTS as u32);
        assert_eq!(NamespaceType::Ipc as u32, libc::CLONE_NEWIPC as u32);
    }
}
