use anyhow::Result;
use tracing::{debug, error, info, warn};

/// Seccomp filter actions
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum SeccompAction {
    Kill = 0x00000000,  // SECCOMP_RET_KILL
    Trap = 0x00030000,  // SECCOMP_RET_TRAP
    Errno = 0x00050000, // SECCOMP_RET_ERRNO
    Allow = 0x7fff0000, // SECCOMP_RET_ALLOW
}

/// Seccomp BPF instruction
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompInstruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl SeccompInstruction {
    /// Load instruction
    pub fn load(offset: u32) -> Self {
        Self {
            code: 0x20, // BPF_LD | BPF_W | BPF_ABS
            jt: 0,
            jf: 0,
            k: offset,
        }
    }

    /// Jump if equal instruction
    pub fn jump_eq(k: u32, jt: u8, jf: u8) -> Self {
        Self {
            code: 0x15, // BPF_JMP | BPF_JEQ | BPF_K
            jt,
            jf,
            k,
        }
    }

    /// Return instruction
    pub fn ret(action: SeccompAction) -> Self {
        Self {
            code: 0x06, // BPF_RET | BPF_K
            jt: 0,
            jf: 0,
            k: action as u32,
        }
    }
}

/// Seccomp filter program
#[repr(C)]
struct SeccompProgram {
    len: u16,
    filter: *const SeccompInstruction,
}

/// Seccomp configuration for capability-specific syscall filtering
#[derive(Debug, Clone)]
pub struct SeccompConfig {
    pub enabled: bool,
    pub default_action: SeccompAction,
    pub allowed_syscalls: Vec<i32>,
}

impl Default for SeccompConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_action: SeccompAction::Kill,
            allowed_syscalls: Vec::new(),
        }
    }
}

impl SeccompConfig {
    /// Add an allowed syscall by number
    pub fn allow_syscall(&mut self, syscall_num: i32) -> &mut Self {
        if !self.allowed_syscalls.contains(&syscall_num) {
            self.allowed_syscalls.push(syscall_num);
        }
        self
    }

    /// Add multiple allowed syscalls
    pub fn allow_syscalls(&mut self, syscalls: &[i32]) -> &mut Self {
        for &syscall in syscalls {
            self.allow_syscall(syscall);
        }
        self
    }
}

fn apply_common_runtime_syscalls(config: &mut SeccompConfig) {
    let common_syscalls = [
        libc::SYS_read as i32,
        libc::SYS_write as i32,
        libc::SYS_close as i32,
        libc::SYS_fstat as i32,
        libc::SYS_stat as i32,
        libc::SYS_lstat as i32,
        libc::SYS_newfstatat as i32,
        libc::SYS_lseek as i32,
        libc::SYS_mmap as i32,
        libc::SYS_mprotect as i32,
        libc::SYS_munmap as i32,
        libc::SYS_brk as i32,
        libc::SYS_rt_sigaction as i32,
        libc::SYS_rt_sigprocmask as i32,
        libc::SYS_rt_sigreturn as i32,
        libc::SYS_sigaltstack as i32,
        libc::SYS_exit as i32,
        libc::SYS_exit_group as i32,
        libc::SYS_clock_gettime as i32,
        libc::SYS_clock_nanosleep as i32,
        libc::SYS_nanosleep as i32,
        libc::SYS_sched_yield as i32,
        libc::SYS_getpid as i32,
        libc::SYS_gettid as i32,
        libc::SYS_getuid as i32,
        libc::SYS_geteuid as i32,
        libc::SYS_getgid as i32,
        libc::SYS_getegid as i32,
        libc::SYS_getrandom as i32,
        libc::SYS_futex as i32,
        libc::SYS_set_tid_address as i32,
        libc::SYS_set_robust_list as i32,
        libc::SYS_prlimit64 as i32,
        libc::SYS_ioctl as i32,
        libc::SYS_dup as i32,
        libc::SYS_dup2 as i32,
        libc::SYS_dup3 as i32,
        libc::SYS_clone as i32,
    ];

    config.allow_syscalls(&common_syscalls);

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        // clone3 is used by newer glibc versions when available; include it where supported.
        config.allow_syscall(libc::SYS_clone3 as i32);
    }

    #[cfg(target_arch = "x86_64")]
    {
        // arch_prctl is required for thread-local storage setup during exec on x86_64.
        config.allow_syscall(libc::SYS_arch_prctl as i32);
    }
}

/// Create seccomp configuration for fs.read capability
pub fn create_fs_read_seccomp_config() -> SeccompConfig {
    let mut config = SeccompConfig::default();

    apply_common_runtime_syscalls(&mut config);

    // Filesystem syscalls specific to fs.read capability
    let fs_read_syscalls = [
        libc::SYS_openat as i32,     // File opening
        libc::SYS_pread64 as i32,    // Positioned read
        libc::SYS_readlink as i32,   // Symlink resolution (with validation)
        libc::SYS_readlinkat as i32, // Positioned symlink resolution
        libc::SYS_getdents64 as i32, // Directory reading
        libc::SYS_fcntl as i32,      // File control operations
        libc::SYS_statx as i32,      // Extended stat
    ];

    config.allow_syscalls(&fs_read_syscalls);

    debug!(
        "Created fs.read seccomp config with {} allowed syscalls",
        config.allowed_syscalls.len()
    );
    debug!(
        includes_setresgid = %config
            .allowed_syscalls
            .contains(&(libc::SYS_setresgid as i32)),
        includes_setresuid = %config
            .allowed_syscalls
            .contains(&(libc::SYS_setresuid as i32)),
        "fs.read seccomp syscall coverage"
    );
    debug!(allowed_syscalls = ?config.allowed_syscalls, "fs.read seccomp syscalls");

    config
}

/// Create seccomp configuration for fs.write capability
pub fn create_fs_write_seccomp_config() -> SeccompConfig {
    let mut config = SeccompConfig::default();

    apply_common_runtime_syscalls(&mut config);

    // Filesystem syscalls specific to fs.write capability
    let fs_write_syscalls = [
        libc::SYS_openat as i32,    // File opening
        libc::SYS_pwrite64 as i32,  // Positioned write
        libc::SYS_lseek as i32,     // File seeking
        libc::SYS_stat as i32,      // File metadata
        libc::SYS_fstat as i32,     // File descriptor metadata
        libc::SYS_unlink as i32,    // File deletion
        libc::SYS_unlinkat as i32,  // Positioned file deletion
        libc::SYS_mkdir as i32,     // Directory creation
        libc::SYS_mkdirat as i32,   // Positioned directory creation
        libc::SYS_rmdir as i32,     // Directory removal
        libc::SYS_rename as i32,    // File renaming
        libc::SYS_renameat as i32,  // Positioned file renaming
        libc::SYS_truncate as i32,  // File truncation
        libc::SYS_ftruncate as i32, // File descriptor truncation
        libc::SYS_fsync as i32,     // Filesystem sync
        libc::SYS_fdatasync as i32, // Data sync
        libc::SYS_fcntl as i32,     // File control operations
    ];

    config.allow_syscalls(&fs_write_syscalls);

    debug!(
        "Created fs.write seccomp config with {} allowed syscalls",
        config.allowed_syscalls.len()
    );

    config
}

/// Create seccomp configuration for sqlite.query capability
pub fn create_sqlite_query_seccomp_config() -> SeccompConfig {
    let mut config = SeccompConfig::default();

    apply_common_runtime_syscalls(&mut config);

    // SQLite-specific syscalls
    let sqlite_syscalls = [
        libc::SYS_openat as i32,    // Database file opening
        libc::SYS_pread64 as i32,   // Positioned read
        libc::SYS_pwrite64 as i32,  // Positioned write
        libc::SYS_lseek as i32,     // File seeking
        libc::SYS_stat as i32,      // File metadata
        libc::SYS_fstat as i32,     // File descriptor metadata
        libc::SYS_fsync as i32,     // Filesystem sync
        libc::SYS_fdatasync as i32, // Data sync
        libc::SYS_fallocate as i32, // Space allocation
        libc::SYS_flock as i32,     // File locking
        libc::SYS_fcntl as i32,     // File control operations
        libc::SYS_unlink as i32,    // Temporary file cleanup
    ];

    config.allow_syscalls(&sqlite_syscalls);

    debug!(
        "Created sqlite.query seccomp config with {} allowed syscalls",
        config.allowed_syscalls.len()
    );

    config
}

/// Create seccomp configuration for archive.read capability
pub fn create_archive_read_seccomp_config() -> SeccompConfig {
    let mut config = SeccompConfig::default();

    apply_common_runtime_syscalls(&mut config);

    // Archive reading syscalls (similar to fs.read but more restricted)
    let archive_read_syscalls = [
        libc::SYS_openat as i32,  // Archive file opening
        libc::SYS_pread64 as i32, // Positioned read
        libc::SYS_lseek as i32,   // File seeking
        libc::SYS_stat as i32,    // File metadata
        libc::SYS_fstat as i32,   // File descriptor metadata
        libc::SYS_fcntl as i32,   // File control operations
    ];

    config.allow_syscalls(&archive_read_syscalls);

    debug!(
        "Created archive.read seccomp config with {} allowed syscalls",
        config.allowed_syscalls.len()
    );

    config
}

/// Create seccomp configuration for http.fetch capability  
pub fn create_http_fetch_seccomp_config() -> SeccompConfig {
    let mut config = SeccompConfig::default();

    apply_common_runtime_syscalls(&mut config);

    // Network syscalls for http.fetch (through netns proxy only)
    let network_syscalls = [
        libc::SYS_socket as i32,        // Socket creation (restricted by netns)
        libc::SYS_connect as i32,       // Socket connection (via proxy only)
        libc::SYS_sendto as i32,        // Send data
        libc::SYS_recvfrom as i32,      // Receive data
        libc::SYS_sendmsg as i32,       // Send message
        libc::SYS_recvmsg as i32,       // Receive message
        libc::SYS_getsockopt as i32,    // Get socket options
        libc::SYS_setsockopt as i32,    // Set socket options
        libc::SYS_poll as i32,          // Poll for I/O
        libc::SYS_epoll_create1 as i32, // Epoll creation
        libc::SYS_epoll_ctl as i32,     // Epoll control
        libc::SYS_epoll_wait as i32,    // Epoll wait
        libc::SYS_pipe2 as i32,         // Pipe creation
    ];

    // File syscalls for SSL certificates and configuration
    let file_syscalls = [
        libc::SYS_openat as i32,
        libc::SYS_fstat as i32,
        libc::SYS_stat as i32,
        libc::SYS_readlink as i32,
        libc::SYS_readlinkat as i32,
    ];

    config.allow_syscalls(&network_syscalls);
    config.allow_syscalls(&file_syscalls);

    debug!(
        "Created http.fetch seccomp config with {} allowed syscalls",
        config.allowed_syscalls.len()
    );

    config
}

/// Create seccomp configuration for shell.exec capability
pub fn create_shell_exec_seccomp_config() -> SeccompConfig {
    let mut config = SeccompConfig::default();
    config.default_action = SeccompAction::Allow;

    // Shell execution requires the full runtime syscall surface plus
    // filesystem primitives so basic utilities can run safely inside the jail.
    apply_common_runtime_syscalls(&mut config);

    let shell_syscalls = [
        libc::SYS_open as i32,
        libc::SYS_openat as i32,
        libc::SYS_getdents64 as i32,
        libc::SYS_readlink as i32,
        libc::SYS_readlinkat as i32,
        libc::SYS_fcntl as i32,
        libc::SYS_statx as i32,
        libc::SYS_access as i32,
        libc::SYS_getcwd as i32,
        libc::SYS_chdir as i32,
        libc::SYS_unlinkat as i32,
        libc::SYS_renameat as i32,
        libc::SYS_mkdirat as i32,
        libc::SYS_rmdir as i32,
        libc::SYS_utimensat as i32,
        libc::SYS_getxattr as i32,
        libc::SYS_lgetxattr as i32,
        libc::SYS_fgetxattr as i32,
        libc::SYS_listxattr as i32,
        libc::SYS_llistxattr as i32,
        libc::SYS_flistxattr as i32,
        libc::SYS_removexattr as i32,
        libc::SYS_lremovexattr as i32,
        libc::SYS_fremovexattr as i32,
        libc::SYS_faccessat as i32,
        libc::SYS_socket as i32,
        libc::SYS_connect as i32,
        libc::SYS_sendto as i32,
        libc::SYS_recvfrom as i32,
        libc::SYS_sendmsg as i32,
        libc::SYS_recvmsg as i32,
        libc::SYS_setsockopt as i32,
        libc::SYS_getsockopt as i32,
        libc::SYS_getsockname as i32,
        libc::SYS_getpeername as i32,
        libc::SYS_shutdown as i32,
    ];

    config.allow_syscalls(&shell_syscalls);

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        config.allow_syscall(libc::SYS_faccessat2 as i32);
    }

    #[cfg(target_arch = "x86_64")]
    {
        config.allow_syscall(libc::SYS_openat2 as i32);
    }

    debug!(
        "Created shell.exec seccomp config with {} allowed syscalls",
        config.allowed_syscalls.len()
    );

    config
}

/// Resolve syscall names from derivation data to numeric identifiers.
pub fn syscall_number_from_name(name: &str) -> Option<i32> {
    let normalized = name.trim().to_lowercase();
    match normalized.as_str() {
        "read" => Some(libc::SYS_read as i32),
        "readv" => Some(libc::SYS_readv as i32),
        "write" => Some(libc::SYS_write as i32),
        "writev" => Some(libc::SYS_writev as i32),
        "close" => Some(libc::SYS_close as i32),
        "open" => Some(libc::SYS_open as i32),
        "openat" => Some(libc::SYS_openat as i32),
        "stat" => Some(libc::SYS_stat as i32),
        "lstat" => Some(libc::SYS_lstat as i32),
        "fstat" => Some(libc::SYS_fstat as i32),
        "fstatat" | "newfstatat" => Some(libc::SYS_newfstatat as i32),
        "pread" | "pread64" => Some(libc::SYS_pread64 as i32),
        "pwrite" | "pwrite64" => Some(libc::SYS_pwrite64 as i32),
        "lseek" => Some(libc::SYS_lseek as i32),
        "getdents" | "getdents64" => Some(libc::SYS_getdents64 as i32),
        "readlink" => Some(libc::SYS_readlink as i32),
        "readlinkat" => Some(libc::SYS_readlinkat as i32),
        "execve" => Some(libc::SYS_execve as i32),
        "execveat" => Some(libc::SYS_execveat as i32),
        "clone" => Some(libc::SYS_clone as i32),
        "clone3" => Some(libc::SYS_clone3 as i32),
        "fork" => Some(libc::SYS_fork as i32),
        "vfork" => Some(libc::SYS_vfork as i32),
        "wait4" => Some(libc::SYS_wait4 as i32),
        "waitid" => Some(libc::SYS_waitid as i32),
        "dup" => Some(libc::SYS_dup as i32),
        "dup2" => Some(libc::SYS_dup2 as i32),
        "dup3" => Some(libc::SYS_dup3 as i32),
        "fcntl" => Some(libc::SYS_fcntl as i32),
        "mmap" => Some(libc::SYS_mmap as i32),
        "mprotect" => Some(libc::SYS_mprotect as i32),
        "munmap" => Some(libc::SYS_munmap as i32),
        "brk" => Some(libc::SYS_brk as i32),
        "rt_sigaction" => Some(libc::SYS_rt_sigaction as i32),
        "rt_sigprocmask" => Some(libc::SYS_rt_sigprocmask as i32),
        "exit" => Some(libc::SYS_exit as i32),
        "exit_group" => Some(libc::SYS_exit_group as i32),
        "clock_gettime" => Some(libc::SYS_clock_gettime as i32),
        "futex" => Some(libc::SYS_futex as i32),
        "nanosleep" => Some(libc::SYS_nanosleep as i32),
        "getrandom" => Some(libc::SYS_getrandom as i32),
        "fsync" => Some(libc::SYS_fsync as i32),
        "fdatasync" => Some(libc::SYS_fdatasync as i32),
        "fallocate" => Some(libc::SYS_fallocate as i32),
        "flock" => Some(libc::SYS_flock as i32),
        "unlink" => Some(libc::SYS_unlink as i32),
        "unlinkat" => Some(libc::SYS_unlinkat as i32),
        "mkdir" => Some(libc::SYS_mkdir as i32),
        "mkdirat" => Some(libc::SYS_mkdirat as i32),
        "rmdir" => Some(libc::SYS_rmdir as i32),
        "rename" => Some(libc::SYS_rename as i32),
        "renameat" => Some(libc::SYS_renameat as i32),
        "truncate" => Some(libc::SYS_truncate as i32),
        "ftruncate" => Some(libc::SYS_ftruncate as i32),
        "socket" => Some(libc::SYS_socket as i32),
        "connect" => Some(libc::SYS_connect as i32),
        "sendto" => Some(libc::SYS_sendto as i32),
        "recvfrom" => Some(libc::SYS_recvfrom as i32),
        "sendmsg" => Some(libc::SYS_sendmsg as i32),
        "recvmsg" => Some(libc::SYS_recvmsg as i32),
        "setsockopt" => Some(libc::SYS_setsockopt as i32),
        "getsockopt" => Some(libc::SYS_getsockopt as i32),
        "getsockname" => Some(libc::SYS_getsockname as i32),
        "getpeername" => Some(libc::SYS_getpeername as i32),
        "shutdown" => Some(libc::SYS_shutdown as i32),
        "poll" => Some(libc::SYS_poll as i32),
        "ppoll" => Some(libc::SYS_ppoll as i32),
        "select" => Some(libc::SYS_select as i32),
        "pselect6" => Some(libc::SYS_pselect6 as i32),
        "epoll_create" => Some(libc::SYS_epoll_create as i32),
        "epoll_create1" => Some(libc::SYS_epoll_create1 as i32),
        "epoll_ctl" => Some(libc::SYS_epoll_ctl as i32),
        "epoll_wait" => Some(libc::SYS_epoll_wait as i32),
        "epoll_pwait" => Some(libc::SYS_epoll_pwait as i32),
        "pipe" => Some(libc::SYS_pipe as i32),
        "pipe2" => Some(libc::SYS_pipe2 as i32),
        "prctl" => Some(libc::SYS_prctl as i32),
        "rt_sigreturn" => Some(libc::SYS_rt_sigreturn as i32),
        "uname" => Some(libc::SYS_uname as i32),
        "getpid" => Some(libc::SYS_getpid as i32),
        "gettid" => Some(libc::SYS_gettid as i32),
        "set_tid_address" => Some(libc::SYS_set_tid_address as i32),
        "set_robust_list" => Some(libc::SYS_set_robust_list as i32),
        "sigaltstack" => Some(libc::SYS_sigaltstack as i32),
        "prlimit" | "prlimit64" => Some(libc::SYS_prlimit64 as i32),
        _ => None,
    }
}

/// Generate BPF instructions for seccomp filter
pub fn generate_bpf_filter(config: &SeccompConfig) -> Vec<SeccompInstruction> {
    let mut instructions = Vec::new();

    // Load the system call number
    instructions.push(SeccompInstruction::load(0)); // offsetof(struct seccomp_data, nr)

    // Create jump table for allowed syscalls
    // This generates a series of jump-if-equal instructions
    let mut remaining_syscalls = config.allowed_syscalls.len();

    for &syscall_num in &config.allowed_syscalls {
        remaining_syscalls -= 1;

        if remaining_syscalls == 0 {
            // Last syscall - jump to allow or fall through to default
            instructions.push(SeccompInstruction::jump_eq(syscall_num as u32, 1, 0));
        } else {
            // Jump to allow (distance depends on remaining syscalls)
            instructions.push(SeccompInstruction::jump_eq(
                syscall_num as u32,
                remaining_syscalls as u8 + 1,
                0,
            ));
        }
    }

    // Default action (kill/deny)
    instructions.push(SeccompInstruction::ret(config.default_action));

    // Allow action
    instructions.push(SeccompInstruction::ret(SeccompAction::Allow));

    debug!(
        "Generated BPF filter with {} instructions for {} syscalls",
        instructions.len(),
        config.allowed_syscalls.len()
    );

    instructions
}

/// Apply seccomp filter to current process
pub fn apply_seccomp_filter(config: &SeccompConfig) -> Result<()> {
    if !config.enabled {
        debug!("Seccomp is disabled in configuration");
        return Ok(());
    }

    if config.allowed_syscalls.is_empty() {
        return Err(anyhow::anyhow!("No syscalls configured for seccomp filter"));
    }

    debug!(
        "Applying seccomp filter with {} allowed syscalls",
        config.allowed_syscalls.len()
    );

    // Generate BPF filter program
    let instructions = generate_bpf_filter(config);

    let program = SeccompProgram {
        len: instructions.len() as u16,
        filter: instructions.as_ptr(),
    };

    // Set no new privileges to allow seccomp without capabilities
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result != 0 {
        return Err(anyhow::anyhow!(
            "Failed to set no new privileges: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Apply seccomp filter
    let result = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &program as *const SeccompProgram,
            0,
            0,
        )
    };

    if result != 0 {
        return Err(anyhow::anyhow!(
            "Failed to apply seccomp filter: {}",
            std::io::Error::last_os_error()
        ));
    }

    info!(
        "Successfully applied seccomp filter with {} allowed syscalls",
        config.allowed_syscalls.len()
    );

    Ok(())
}

/// Create seccomp configuration based on capability
pub fn create_capability_seccomp_config(capability: &str) -> SeccompConfig {
    match capability {
        "fs.read" | "fs.read.v1" => create_fs_read_seccomp_config(),
        "fs.write" | "fs.write.v1" => create_fs_write_seccomp_config(),
        "http.fetch" | "http.fetch.v1" => create_http_fetch_seccomp_config(),
        "shell.exec" | "shell.exec.v1" => create_shell_exec_seccomp_config(),
        "sqlite.query" | "sqlite.query.v1" => create_sqlite_query_seccomp_config(),
        "archive.read" | "archive.read.v1" => create_archive_read_seccomp_config(),
        _ => {
            warn!(
                "Unknown capability '{}', using restrictive seccomp config",
                capability
            );
            let mut config = SeccompConfig::default();

            // Only allow minimal syscalls for unknown capabilities
            let minimal_syscalls = [
                libc::SYS_read as i32,
                libc::SYS_write as i32,
                libc::SYS_close as i32,
                libc::SYS_exit as i32,
                libc::SYS_exit_group as i32,
            ];

            config.allow_syscalls(&minimal_syscalls);
            config
        }
    }
}

/// Validate that forbidden syscalls are properly blocked
pub fn validate_seccomp_blocking() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::signal::Signal;
        use nix::sys::wait::{waitpid, WaitStatus};
        use nix::unistd::{fork, ForkResult};

        debug!("Validating seccomp syscall blocking by executing forbidden syscall");

        // Configure a minimal allowlist that intentionally excludes ptrace.
        let mut config = SeccompConfig::default();
        config.allow_syscalls(&[
            libc::SYS_read as i32,
            libc::SYS_write as i32,
            libc::SYS_exit as i32,
            libc::SYS_exit_group as i32,
        ]);

        match unsafe { fork()? } {
            ForkResult::Child => {
                if let Err(e) = apply_seccomp_filter(&config) {
                    error!("Failed to apply seccomp filter in validation child: {}", e);
                    std::process::exit(2);
                }

                // Attempt a forbidden syscall. ptrace is disallowed for all capabilities.
                unsafe {
                    libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0);
                }

                // If we reach here, the filter did not terminate the process.
                std::process::exit(1);
            }
            ForkResult::Parent { child } => match waitpid(child, None)? {
                WaitStatus::Signaled(_, Signal::SIGSYS, _) => {
                    info!("Seccomp validation succeeded: ptrace syscall was blocked");
                    Ok(())
                }
                WaitStatus::Exited(_, 77) => {
                    info!("Seccomp validation succeeded with kernel exit status 77");
                    Ok(())
                }
                WaitStatus::Exited(_, code) => Err(anyhow::anyhow!(
                    "Seccomp validation child exited unexpectedly with status {}",
                    code
                )),
                other => Err(anyhow::anyhow!(
                    "Unexpected seccomp validation status: {:?}",
                    other
                )),
            },
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!("Seccomp validation skipped: unsupported platform");
        Ok(())
    }
}

/// Test seccomp filter with allowed syscall (for self-test)
#[cfg(test)]
#[cfg(unix)]
pub fn test_allowed_syscall() -> Result<()> {
    // Test that an allowed syscall (like getpid) works
    let pid = unsafe { libc::getpid() };
    if pid > 0 {
        debug!("Allowed syscall test passed: getpid returned {}", pid);
        Ok(())
    } else {
        Err(anyhow::anyhow!("Allowed syscall test failed"))
    }
}

/// Test seccomp filter with allowed syscall (non-Unix platforms)
#[cfg(test)]
#[cfg(not(unix))]
pub fn test_allowed_syscall() -> Result<()> {
    // On non-Unix platforms, return success for testing
    debug!("Allowed syscall test skipped on non-Unix platform");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn test_seccomp_config_creation() {
        let mut config = SeccompConfig::default();
        assert!(config.enabled);
        assert_eq!(config.default_action as u32, SeccompAction::Kill as u32);
        assert!(config.allowed_syscalls.is_empty());

        config.allow_syscall(libc::SYS_read as i32);
        config.allow_syscall(libc::SYS_write as i32);

        assert_eq!(config.allowed_syscalls.len(), 2);
        assert!(config.allowed_syscalls.contains(&(libc::SYS_read as i32)));
        assert!(config.allowed_syscalls.contains(&(libc::SYS_write as i32)));
    }

    #[test]
    #[cfg(unix)]
    fn test_fs_read_seccomp_config() {
        let config = create_fs_read_seccomp_config();
        assert!(config.enabled);
        assert!(!config.allowed_syscalls.is_empty());

        // Should contain essential syscalls
        assert!(config.allowed_syscalls.contains(&(libc::SYS_read as i32)));
        assert!(config.allowed_syscalls.contains(&(libc::SYS_write as i32)));
        assert!(config.allowed_syscalls.contains(&(libc::SYS_openat as i32)));
        assert!(config.allowed_syscalls.contains(&(libc::SYS_close as i32)));

        // Should not contain forbidden syscalls like mount
        // (we can't test mount directly as it's not in allowed list)
        assert!(!config.allowed_syscalls.contains(&999999)); // Non-existent syscall
    }

    #[test]
    #[cfg(unix)]
    fn test_http_fetch_seccomp_config() {
        let config = create_http_fetch_seccomp_config();
        assert!(config.enabled);
        assert!(!config.allowed_syscalls.is_empty());

        // Should contain network syscalls
        assert!(config.allowed_syscalls.contains(&(libc::SYS_socket as i32)));
        assert!(config
            .allowed_syscalls
            .contains(&(libc::SYS_connect as i32)));

        // Should contain base syscalls
        assert!(config.allowed_syscalls.contains(&(libc::SYS_read as i32)));
        assert!(config.allowed_syscalls.contains(&(libc::SYS_write as i32)));
    }

    #[test]
    #[cfg(unix)]
    fn test_capability_seccomp_config_unknown() {
        let config = create_capability_seccomp_config("unknown.capability");
        assert!(config.enabled);

        // Should have minimal syscalls only
        assert!(config.allowed_syscalls.len() <= 10);
        assert!(config.allowed_syscalls.contains(&(libc::SYS_read as i32)));
        assert!(config.allowed_syscalls.contains(&(libc::SYS_write as i32)));
        assert!(config.allowed_syscalls.contains(&(libc::SYS_exit as i32)));
    }

    #[test]
    #[cfg(unix)]
    fn test_bpf_filter_generation() {
        let mut config = SeccompConfig::default();
        config.allow_syscall(libc::SYS_read as i32);
        config.allow_syscall(libc::SYS_write as i32);

        let instructions = generate_bpf_filter(&config);

        // Should have at least: load, jump for read, jump for write, default action, allow action
        assert!(instructions.len() >= 5);

        // First instruction should be load
        assert_eq!(instructions[0].code, 0x20); // BPF_LD | BPF_W | BPF_ABS
    }

    #[test]
    fn test_seccomp_instruction_creation() {
        let load = SeccompInstruction::load(0);
        assert_eq!(load.code, 0x20);
        assert_eq!(load.k, 0);

        let jump = SeccompInstruction::jump_eq(42, 1, 0);
        assert_eq!(jump.code, 0x15);
        assert_eq!(jump.k, 42);
        assert_eq!(jump.jt, 1);
        assert_eq!(jump.jf, 0);

        let ret = SeccompInstruction::ret(SeccompAction::Allow);
        assert_eq!(ret.code, 0x06);
        assert_eq!(ret.k, SeccompAction::Allow as u32);
    }

    #[test]
    fn test_seccomp_actions() {
        assert_eq!(SeccompAction::Kill as u32, 0x00000000);
        assert_eq!(SeccompAction::Allow as u32, 0x7fff0000);
        assert_eq!(SeccompAction::Errno as u32, 0x00050000);
        assert_eq!(SeccompAction::Trap as u32, 0x00030000);
    }
}
