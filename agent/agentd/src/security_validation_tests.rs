//! Targeted integration tests that exercise the most critical sandbox layers.
//!
//! These tests intentionally run heavy-weight isolation primitives (Landlock,
//! seccomp, network namespaces) inside short-lived forked children so the
//! parent test process remains unaffected.

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use anyhow::Result;
    use nix::sched::{unshare, CloneFlags};
    use nix::sys::signal::Signal;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult};
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    use smith_jailer::landlock::{self, LandlockConfig};
    use smith_jailer::seccomp::{self, SeccompConfig};

    /// Helper to run closure inside a forked child and wait for the outcome.
    ///
    /// The closure returns `Ok(())` to indicate success or `Err(code)` to
    /// request a specific exit code from the child process.
    fn run_in_subprocess<F>(f: F) -> Result<WaitStatus>
    where
        F: FnOnce() -> Result<(), i32>,
    {
        match unsafe { fork()? } {
            ForkResult::Child => {
                let exit_code = match f() {
                    Ok(()) => 0,
                    Err(code) => code,
                };
                std::process::exit(exit_code);
            }
            ForkResult::Parent { child } => Ok(waitpid(child, None)?),
        }
    }

    fn require_root(reason: &str) -> bool {
        if unsafe { libc::geteuid() == 0 } {
            true
        } else {
            eprintln!("Skipping test ({reason}): requires root privileges");
            false
        }
    }

    #[test]
    fn landlock_blocks_forbidden_paths() -> Result<()> {
        if !landlock::is_landlock_available() {
            eprintln!("Skipping Landlock test: kernel does not support Landlock");
            return Ok(());
        }
        if !require_root("Landlock needs CAP_SYS_ADMIN for path setup") {
            return Ok(());
        }

        let allowed = tempdir()?;
        let forbidden = tempdir()?;
        let allowed_file = allowed.path().join("allowed.txt");
        let forbidden_file = forbidden.path().join("forbidden.txt");
        File::create(&allowed_file)?.write_all(b"allowed")?;
        File::create(&forbidden_file)?.write_all(b"forbidden")?;

        let status = run_in_subprocess(|| {
            let mut config = LandlockConfig::default();
            let allowed_path = allowed
                .path()
                .to_str()
                .expect("tempdir path should be UTF-8");
            config.allow_read(allowed_path);
            config.allow_read("/proc");
            config.allow_read("/etc");
            config.allow_read("/run");
            config.allow_read("/tmp");

            landlock::apply_landlock_rules(&config).expect("apply landlock");

            // Allowed file succeeds
            if std::fs::read(&allowed_file).is_err() {
                eprintln!("Landlock unexpectedly denied allowed read");
                return Err(3);
            }

            // Forbidden file should be denied with EPERM
            match std::fs::read(&forbidden_file) {
                Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
                Ok(_) => {
                    eprintln!("Landlock unexpectedly allowed forbidden read");
                    Err(1)
                }
                Err(err) => {
                    eprintln!("Unexpected error reading forbidden file: {err}");
                    Err(2)
                }
            }
        })?;

        match status {
            WaitStatus::Exited(_, code) => assert_eq!(code, 0, "Landlock child exited with {code}"),
            other => panic!("Unexpected child status: {other:?}"),
        }

        Ok(())
    }

    #[test]
    fn seccomp_traps_disallowed_syscalls() -> Result<()> {
        // Seccomp filters can be applied without root as long as NO_NEW_PRIVS is set.
        let status = run_in_subprocess(|| {
            let mut config = SeccompConfig::default();
            config.allow_syscalls(&[
                libc::SYS_read as i32,
                libc::SYS_write as i32,
                libc::SYS_exit as i32,
                libc::SYS_exit_group as i32,
            ]);

            seccomp::apply_seccomp_filter(&config).expect("apply seccomp");

            // This syscall is not on the allowlist and should terminate the process.
            unsafe {
                libc::syscall(libc::SYS_getpid);
            }

            // If the process is still alive, the filter did not work.
            Err(1)
        })?;

        match status {
            WaitStatus::Signaled(_, Signal::SIGSYS, _) => Ok(()),
            WaitStatus::Exited(_, code) if code == 77 => {
                // Some kernels translate SECCOMP_RET_KILL to exit status 77.
                Ok(())
            }
            other => panic!("Seccomp filter did not trigger as expected: {other:?}"),
        }
    }

    #[test]
    fn network_namespace_blocks_outbound_connections() -> Result<()> {
        if !require_root("creating a network namespace") {
            return Ok(());
        }

        let status = run_in_subprocess(|| {
            unshare(CloneFlags::CLONE_NEWNET).expect("unshare network namespace");

            match std::net::TcpStream::connect("127.0.0.1:80") {
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::NetworkUnreachable
                            | std::io::ErrorKind::AddrNotAvailable
                    ) =>
                {
                    Ok(())
                }
                Err(err) => {
                    eprintln!("Unexpected network error: {err}");
                    Err(1)
                }
                Ok(_) => {
                    eprintln!("Connection succeeded unexpectedly inside isolated namespace");
                    Err(2)
                }
            }
        })?;

        match status {
            WaitStatus::Exited(_, code) => {
                assert_eq!(code, 0, "Network namespace child exited with {code}")
            }
            other => panic!("Unexpected child status: {other:?}"),
        }

        Ok(())
    }
}
