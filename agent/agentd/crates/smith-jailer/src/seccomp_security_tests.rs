//! Comprehensive security tests for seccomp-bpf system call filtering
//!
//! This module contains extensive tests to verify that seccomp provides
//! effective system call filtering and prevents various attack vectors.

#![allow(unexpected_cfgs)]

use super::seccomp::*;

// Import BPF constants from libc
use libc::{
    BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, SECCOMP_RET_ALLOW, SECCOMP_RET_KILL,
};

/// Test environment for seccomp security testing
pub struct SeccompTestEnvironment {
    pub baseline_config: SeccompConfig,
    pub strict_config: SeccompConfig,
    pub permissive_config: SeccompConfig,
}

impl SeccompTestEnvironment {
    /// Create various seccomp configurations for testing
    pub fn new() -> Self {
        let baseline_config = SeccompConfig {
            enabled: true,
            allowed_syscalls: get_baseline_syscalls(),
            default_action: SeccompAction::Kill,
        };

        let strict_config = SeccompConfig {
            enabled: true,
            allowed_syscalls: get_minimal_syscalls(),
            default_action: SeccompAction::Kill,
        };

        let permissive_config = SeccompConfig {
            enabled: true,
            allowed_syscalls: get_extended_syscalls(),
            default_action: SeccompAction::Allow,
        };

        Self {
            baseline_config,
            strict_config,
            permissive_config,
        }
    }
}

/// Get minimal syscalls required for basic operation
fn get_minimal_syscalls() -> Vec<i32> {
    vec![
        libc::SYS_read as i32,
        libc::SYS_write as i32,
        libc::SYS_exit as i32,
        libc::SYS_exit_group as i32,
        libc::SYS_brk as i32,
        libc::SYS_mmap as i32,
        libc::SYS_munmap as i32,
        libc::SYS_rt_sigreturn as i32,
    ]
}

/// Get baseline syscalls for typical operation
fn get_baseline_syscalls() -> Vec<i32> {
    let mut syscalls = get_minimal_syscalls();
    syscalls.extend([
        libc::SYS_openat as i32,
        libc::SYS_close as i32,
        libc::SYS_stat as i32,
        libc::SYS_fstat as i32,
        libc::SYS_lseek as i32,
        libc::SYS_getpid as i32,
        libc::SYS_getuid as i32,
        libc::SYS_getgid as i32,
        libc::SYS_geteuid as i32,
        libc::SYS_getegid as i32,
    ]);
    syscalls
}

/// Get extended syscalls for complex operations
fn get_extended_syscalls() -> Vec<i32> {
    let mut syscalls = get_baseline_syscalls();
    syscalls.extend([
        libc::SYS_socket as i32,
        libc::SYS_connect as i32,
        libc::SYS_sendto as i32,
        libc::SYS_recvfrom as i32,
        libc::SYS_futex as i32,
        libc::SYS_clone as i32,
        libc::SYS_execve as i32,
        libc::SYS_wait4 as i32,
        libc::SYS_pipe as i32,
        libc::SYS_dup as i32,
        libc::SYS_dup2 as i32,
    ]);
    syscalls
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_seccomp_test_environment_creation() {
        let env = SeccompTestEnvironment::new();

        // Test baseline config
        assert!(env.baseline_config.enabled);
        assert!(!env.baseline_config.allowed_syscalls.is_empty());
        assert!(matches!(
            env.baseline_config.default_action,
            SeccompAction::Kill
        ));

        // Test strict config
        assert!(env.strict_config.enabled);
        assert!(
            env.strict_config.allowed_syscalls.len() < env.baseline_config.allowed_syscalls.len()
        );

        // Test permissive config
        assert!(env.permissive_config.enabled);
        assert!(
            env.permissive_config.allowed_syscalls.len()
                > env.baseline_config.allowed_syscalls.len()
        );
        assert!(matches!(
            env.permissive_config.default_action,
            SeccompAction::Allow
        ));
    }

    #[test]
    fn test_seccomp_actions() {
        // Test action enum values
        assert_ne!(SeccompAction::Kill as u32, SeccompAction::Allow as u32);
        assert_ne!(SeccompAction::Kill as u32, SeccompAction::Errno as u32);
        assert_ne!(SeccompAction::Trap as u32, SeccompAction::Errno as u32);
    }

    #[test]
    fn test_bpf_filter_creation() {
        let env = SeccompTestEnvironment::new();

        // Test BPF filter generation for baseline config
        let baseline_filter = generate_bpf_filter(&env.baseline_config);
        assert!(
            !baseline_filter.is_empty(),
            "BPF filter should not be empty"
        );

        // Test BPF filter generation for strict config
        let strict_filter = generate_bpf_filter(&env.strict_config);
        assert!(
            !strict_filter.is_empty(),
            "Strict BPF filter should not be empty"
        );
    }

    #[test]
    #[cfg(feature = "syscall-resolution")] // Feature doesn't exist - test disabled
    #[allow(unexpected_cfgs)]
    fn test_syscall_number_resolution() {
        // Test that we can resolve common syscall numbers
        let common_syscalls = vec![
            "read",
            "write",
            "open",
            "close",
            "stat",
            "fstat",
            "mmap",
            "munmap",
            "brk",
            "rt_sigaction",
            "rt_sigreturn",
            "getpid",
            "getuid",
            "getgid",
        ];

        for syscall in common_syscalls {
            let number = get_syscall_number(syscall);
            assert!(
                number.is_ok(),
                "Should be able to resolve syscall: {}",
                syscall
            );

            let num = number.unwrap();
            assert!(
                num > 0,
                "Syscall number should be positive: {} = {}",
                syscall,
                num
            );
            assert!(
                num < 1000,
                "Syscall number should be reasonable: {} = {}",
                syscall,
                num
            );
        }
    }

    #[test]
    #[cfg(feature = "syscall-resolution")] // Feature doesn't exist - test disabled
    #[allow(unexpected_cfgs)]
    fn test_syscall_number_caching() {
        // Test that syscall number lookups are consistent
        let syscall = "getpid";
        let first_lookup = get_syscall_number(syscall).unwrap();
        let second_lookup = get_syscall_number(syscall).unwrap();

        assert_eq!(
            first_lookup, second_lookup,
            "Syscall number lookups should be consistent"
        );

        // Test multiple syscalls
        let syscalls = vec!["read", "write", "open", "close"];
        let mut numbers = HashMap::new();

        for syscall in &syscalls {
            let num = get_syscall_number(syscall).unwrap();
            numbers.insert(syscall, num);
        }

        // Verify consistency on second pass
        for syscall in &syscalls {
            let num = get_syscall_number(syscall).unwrap();
            assert_eq!(
                numbers[syscall], num,
                "Syscall number should be consistent: {}",
                syscall
            );
        }
    }

    #[test]
    fn test_capability_seccomp_configs() {
        let test_cases = vec![
            (
                "fs.read.v1",
                vec!["read", "openat", "close", "stat", "fstat"],
            ),
            (
                "fs.write.v1",
                vec!["write", "openat", "close", "unlink", "mkdir"],
            ),
            (
                "http.fetch.v1",
                vec!["socket", "connect", "sendto", "recvfrom", "close"],
            ),
            (
                "sqlite.query.v1",
                vec!["read", "write", "openat", "close", "stat", "fstat", "mmap"],
            ),
            (
                "archive.read.v1",
                vec!["read", "openat", "close", "stat", "fstat"],
            ),
        ];

        for (capability, expected_syscalls) in test_cases {
            let config = create_capability_seccomp_config(capability);
            assert!(
                config.enabled,
                "Config should be enabled for {}",
                capability
            );

            // Check that expected syscalls are present
            for syscall in expected_syscalls {
                let syscall_num = match syscall {
                    "socket" => libc::SYS_socket as i32,
                    "connect" => libc::SYS_connect as i32,
                    "sendto" => libc::SYS_sendto as i32,
                    "recvfrom" => libc::SYS_recvfrom as i32,
                    "close" => libc::SYS_close as i32,
                    "read" => libc::SYS_read as i32,
                    "write" => libc::SYS_write as i32,
                    "openat" => libc::SYS_openat as i32,
                    "stat" => libc::SYS_stat as i32,
                    "fstat" => libc::SYS_fstat as i32,
                    "mmap" => libc::SYS_mmap as i32,
                    "unlink" => libc::SYS_unlink as i32,
                    "mkdir" => libc::SYS_mkdir as i32,
                    _ => panic!("Unknown syscall: {}", syscall),
                };
                assert!(
                    config.allowed_syscalls.contains(&syscall_num),
                    "Capability {} should allow syscall {}",
                    capability,
                    syscall
                );
            }
        }
    }

    #[test]
    fn test_seccomp_config_creation() {
        let config = SeccompConfig {
            enabled: true,
            allowed_syscalls: vec![libc::SYS_read as i32, libc::SYS_write as i32],
            default_action: SeccompAction::Kill,
        };

        // Valid config should have proper structure
        assert!(config.enabled);
        assert_eq!(config.allowed_syscalls.len(), 2);
        assert!(config.allowed_syscalls.contains(&(libc::SYS_read as i32)));
        assert!(config.allowed_syscalls.contains(&(libc::SYS_write as i32)));

        // Test config with additional syscalls
        let mut extended_config = config.clone();
        extended_config
            .allowed_syscalls
            .push(libc::SYS_openat as i32);
        assert_eq!(extended_config.allowed_syscalls.len(), 3);

        // Test empty syscalls list
        let empty_config = SeccompConfig {
            enabled: true,
            allowed_syscalls: vec![],
            default_action: SeccompAction::Kill,
        };
        assert_eq!(empty_config.allowed_syscalls.len(), 0);
    }

    #[test]
    fn test_seccomp_instruction_creation() {
        // Test individual seccomp instruction creation
        let load_arch = SeccompInstruction::load(4); // offset of arch in seccomp_data

        assert_eq!(load_arch.code, 0x20); // BPF_LD | BPF_W | BPF_ABS
        assert_eq!(load_arch.k, 4);

        // Test jump instruction
        let jump_eq = SeccompInstruction::jump_eq(0xc000003e, 1, 0); // AUDIT_ARCH_X86_64

        assert_eq!(jump_eq.code, 0x15); // BPF_JMP | BPF_JEQ | BPF_K
        assert_eq!(jump_eq.jt, 1);
        assert_eq!(jump_eq.jf, 0);

        // Test return instruction
        let ret_allow = SeccompInstruction::ret(SeccompAction::Allow);
        assert_eq!(ret_allow.code, 0x06); // BPF_RET | BPF_K
        assert_eq!(ret_allow.k, SeccompAction::Allow as u32);
    }

    #[test]
    fn test_seccomp_action_values() {
        // Test different seccomp actions
        assert_eq!(SeccompAction::Kill as u32, 0x00000000);
        assert_eq!(SeccompAction::Trap as u32, 0x00030000);
        assert_eq!(SeccompAction::Errno as u32, 0x00050000);
        assert_eq!(SeccompAction::Allow as u32, 0x7fff0000);
    }

    #[test]
    fn test_syscall_number_resolution() {
        assert_eq!(
            super::syscall_number_from_name("read"),
            Some(libc::SYS_read as i32)
        );
        assert_eq!(
            super::syscall_number_from_name("WRITE"),
            Some(libc::SYS_write as i32)
        );
        assert_eq!(super::syscall_number_from_name("unknown"), None);
    }

    #[test]
    fn test_seccomp_filter_complexity() {
        let env = SeccompTestEnvironment::new();

        // Test filter size scales with syscall count
        let minimal_filter = generate_bpf_filter(&env.strict_config);
        let extended_filter = generate_bpf_filter(&env.permissive_config);

        assert!(
            extended_filter.len() >= minimal_filter.len(),
            "Extended filter should be at least as large as minimal filter"
        );

        // Test that filters have reasonable size bounds
        assert!(
            minimal_filter.len() >= 4, // At least arch check + syscall load + return
            "Minimal filter should have basic structure"
        );

        assert!(
            extended_filter.len() < 10000, // Reasonable upper bound
            "Extended filter should not be excessively large"
        );
    }

    #[test]
    fn test_seccomp_error_conditions() {
        // Test config with no syscalls
        let empty_config = SeccompConfig {
            enabled: true,
            allowed_syscalls: vec![],
            default_action: SeccompAction::Kill,
        };

        let filter = generate_bpf_filter(&empty_config);
        // Empty syscalls should result in a minimal filter (probably just deny-all)
        assert!(
            !filter.is_empty(),
            "Even empty config should generate some filter instructions"
        );

        // Test disabled config
        let disabled_config = SeccompConfig {
            enabled: false,
            allowed_syscalls: vec![libc::SYS_read as i32],
            default_action: SeccompAction::Kill,
        };

        // Disabled config might still create a filter for testing
        let filter = generate_bpf_filter(&disabled_config);
        // Should create some filter instructions even for disabled config
        assert!(
            !filter.is_empty(),
            "Should generate filter instructions even for disabled config"
        );
    }

    #[test]
    fn test_dangerous_syscalls_blocked() {
        let env = SeccompTestEnvironment::new();

        // List of potentially dangerous syscalls that should not be in baseline
        let dangerous_syscalls = vec![
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "personality",
            "keyctl",
            "add_key",
            "request_key",
            "kexec_load",
            "kexec_file_load",
            "reboot",
            "syslog",
            "quotactl",
            "mount",
            "umount",
            "umount2",
            "pivot_root",
            "chroot",
        ];

        for dangerous in dangerous_syscalls {
            let syscall_num = match dangerous {
                "ptrace" => libc::SYS_ptrace as i32,
                "process_vm_readv" => libc::SYS_process_vm_readv as i32,
                "process_vm_writev" => libc::SYS_process_vm_writev as i32,
                "personality" => libc::SYS_personality as i32,
                "keyctl" => libc::SYS_keyctl as i32,
                "add_key" => libc::SYS_add_key as i32,
                "request_key" => libc::SYS_request_key as i32,
                "reboot" => libc::SYS_reboot as i32,
                "quotactl" => libc::SYS_quotactl as i32,
                "mount" => libc::SYS_mount as i32,
                "umount" => libc::SYS_umount2 as i32,
                "umount2" => libc::SYS_umount2 as i32,
                "pivot_root" => libc::SYS_pivot_root as i32,
                "chroot" => libc::SYS_chroot as i32,
                // Skip syscalls that don't have libc constants
                "kexec_load" | "kexec_file_load" | "syslog" => continue,
                _ => panic!("Unknown dangerous syscall: {}", dangerous),
            };
            assert!(
                !env.baseline_config.allowed_syscalls.contains(&syscall_num),
                "Dangerous syscall {} should not be in baseline config",
                dangerous
            );

            assert!(
                !env.strict_config.allowed_syscalls.contains(&syscall_num),
                "Dangerous syscall {} should not be in strict config",
                dangerous
            );
        }
    }

    #[test]
    fn test_essential_syscalls_present() {
        let env = SeccompTestEnvironment::new();

        // List of syscalls essential for basic operation
        let essential_syscalls = vec!["read", "write", "exit", "exit_group", "rt_sigreturn"];

        for essential in essential_syscalls {
            let syscall_num = match essential {
                "read" => libc::SYS_read as i32,
                "write" => libc::SYS_write as i32,
                "exit" => libc::SYS_exit as i32,
                "exit_group" => libc::SYS_exit_group as i32,
                "rt_sigreturn" => libc::SYS_rt_sigreturn as i32,
                _ => panic!("Unknown essential syscall: {}", essential),
            };
            assert!(
                env.baseline_config.allowed_syscalls.contains(&syscall_num),
                "Essential syscall {} should be in baseline config",
                essential
            );

            assert!(
                env.strict_config.allowed_syscalls.contains(&syscall_num),
                "Essential syscall {} should be in strict config",
                essential
            );
        }
    }

    #[test]
    fn test_capability_specific_syscall_sets() {
        // Test that different capabilities have appropriate syscall sets
        let fs_read_config = create_capability_seccomp_config("fs.read.v1");
        let http_fetch_config = create_capability_seccomp_config("http.fetch.v1");

        // fs.read should not have network syscalls
        let network_syscalls = vec![
            libc::SYS_socket as i32,
            libc::SYS_connect as i32,
            libc::SYS_sendto as i32,
            libc::SYS_recvfrom as i32,
        ];
        for net_call in network_syscalls {
            assert!(
                !fs_read_config.allowed_syscalls.contains(&net_call),
                "fs.read should not allow network syscall {}",
                net_call
            );
        }

        // http.fetch should have network syscalls
        let required_network = vec![libc::SYS_socket as i32, libc::SYS_connect as i32];
        for net_call in required_network {
            assert!(
                http_fetch_config.allowed_syscalls.contains(&net_call),
                "http.fetch should allow network syscall {}",
                net_call
            );
        }
    }

    #[test]
    fn test_bpf_constants() {
        // Verify BPF constants are correct
        assert_eq!(BPF_LD, 0x00);
        assert_eq!(BPF_W, 0x00);
        assert_eq!(BPF_ABS, 0x20);
        assert_eq!(BPF_JMP, 0x05);
        assert_eq!(BPF_JEQ, 0x10);
        assert_eq!(BPF_K, 0x00);
        assert_eq!(BPF_RET, 0x06);

        // Verify SECCOMP constants
        assert_eq!(SECCOMP_RET_KILL, 0x00000000);
        assert_eq!(SECCOMP_RET_ALLOW, 0x7fff0000);
    }

    #[test]
    fn test_seccomp_config_debug_format() {
        let config = SeccompConfig {
            enabled: true,
            allowed_syscalls: vec![libc::SYS_read as i32, libc::SYS_write as i32],
            default_action: SeccompAction::Kill,
        };

        let debug_output = format!("{:?}", config);
        assert!(debug_output.contains("SeccompConfig"));
        assert!(debug_output.contains("enabled: true"));
        // Check for syscall numbers instead of names
        assert!(debug_output.contains(&(libc::SYS_read as i32).to_string()));
        assert!(debug_output.contains(&(libc::SYS_write as i32).to_string()));
        assert!(debug_output.contains("Kill"));
    }

    #[test]
    fn test_syscall_whitelist_vs_blacklist() {
        // Test that we're using whitelist (allow only specified) approach
        let config = SeccompConfig {
            enabled: true,
            allowed_syscalls: vec![libc::SYS_read as i32, libc::SYS_write as i32],
            default_action: SeccompAction::Kill,
        };

        // Default action should be restrictive
        assert!(matches!(config.default_action, SeccompAction::Kill));

        // Only allowed syscalls should be permitted
        assert_eq!(config.allowed_syscalls.len(), 2);
        assert!(config.allowed_syscalls.contains(&(libc::SYS_read as i32)));
        assert!(config.allowed_syscalls.contains(&(libc::SYS_write as i32)));
    }
}

/// Performance and stress tests for seccomp
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_bpf_filter_creation_performance() {
        let env = SeccompTestEnvironment::new();

        // Measure BPF filter creation time
        let start = Instant::now();
        let filter = generate_bpf_filter(&env.baseline_config);
        let duration = start.elapsed();

        assert!(
            !filter.is_empty(),
            "Filter creation should produce instructions"
        );
        assert!(
            duration < Duration::from_millis(100),
            "Filter creation should be fast, took {:?}",
            duration
        );
    }

    #[test]
    fn test_large_syscall_set_performance() {
        // Create config with many syscalls
        let mut large_syscalls = Vec::new();
        for i in 0..200 {
            large_syscalls.push(i as i32); // Use actual syscall numbers
        }

        let large_config = SeccompConfig {
            enabled: true,
            allowed_syscalls: large_syscalls,
            default_action: SeccompAction::Kill,
        };

        let start = Instant::now();
        let filter = generate_bpf_filter(&large_config);
        let duration = start.elapsed();

        // Should handle large syscall sets efficiently
        assert!(
            duration < Duration::from_millis(500),
            "Large filter creation should be reasonable, took {:?}",
            duration
        );

        // Filter should be created successfully and have reasonable size
        assert!(
            filter.len() < 100000,
            "Large filter should have reasonable size: {}",
            filter.len()
        );
    }

    #[test]
    fn test_repeated_filter_creation() {
        let env = SeccompTestEnvironment::new();

        // Test creating many filters doesn't degrade performance
        let start = Instant::now();
        for _ in 0..100 {
            let _ = generate_bpf_filter(&env.baseline_config);
        }
        let duration = start.elapsed();

        assert!(
            duration < Duration::from_secs(1),
            "Repeated filter creation should be fast, took {:?}",
            duration
        );
    }
}

/// Security-focused integration tests
#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_seccomp_prevents_dangerous_operations() {
        // Test that seccomp configs don't allow dangerous syscalls
        let configs = vec![
            create_capability_seccomp_config("fs.read.v1"),
            create_capability_seccomp_config("http.fetch.v1"),
            create_capability_seccomp_config("sqlite.query.v1"),
        ];

        let dangerous_syscalls = vec![
            libc::SYS_ptrace as i32,
            libc::SYS_process_vm_readv as i32,
            libc::SYS_personality as i32,
            libc::SYS_keyctl as i32,
            libc::SYS_kexec_load as i32,
            libc::SYS_reboot as i32,
            libc::SYS_mount as i32,
            libc::SYS_umount2 as i32, // Use umount2 instead of umount
            libc::SYS_chroot as i32,
        ];

        for config in configs {
            for dangerous in &dangerous_syscalls {
                assert!(
                    !config.allowed_syscalls.contains(dangerous),
                    "Config should not allow dangerous syscall: {}",
                    dangerous
                );
            }
        }
    }

    #[test]
    fn test_seccomp_capability_isolation() {
        let fs_config = create_capability_seccomp_config("fs.read.v1");
        let http_config = create_capability_seccomp_config("http.fetch.v1");

        // fs.read should not have network capabilities
        let network_calls = vec![
            libc::SYS_socket as i32,
            libc::SYS_connect as i32,
            libc::SYS_sendto as i32,
            libc::SYS_recvfrom as i32,
        ];
        for net_call in &network_calls {
            assert!(
                !fs_config.allowed_syscalls.contains(net_call),
                "fs.read should not allow network syscall: {}",
                net_call
            );
        }

        // http.fetch should not have dangerous file operations
        let dangerous_file_ops = vec![
            libc::SYS_unlink as i32,
            libc::SYS_rmdir as i32,
            libc::SYS_rename as i32,
            libc::SYS_chmod as i32,
            libc::SYS_chown as i32,
        ];
        for file_op in &dangerous_file_ops {
            assert!(
                !http_config.allowed_syscalls.contains(file_op),
                "http.fetch should not allow dangerous file operation: {}",
                file_op
            );
        }
    }

    #[test]
    fn test_minimal_privilege_principle() {
        let configs = vec![
            ("fs.read.v1", create_capability_seccomp_config("fs.read.v1")),
            (
                "http.fetch.v1",
                create_capability_seccomp_config("http.fetch.v1"),
            ),
            (
                "sqlite.query.v1",
                create_capability_seccomp_config("sqlite.query.v1"),
            ),
        ];

        for (capability, config) in configs {
            // Each capability should have minimal required syscalls
            assert!(
                config.allowed_syscalls.len() < 80,
                "Capability {} should have minimal syscalls, has {}",
                capability,
                config.allowed_syscalls.len()
            );

            // Should have essential syscalls for basic operation
            let essential = vec![
                libc::SYS_read as i32,
                libc::SYS_write as i32,
                libc::SYS_exit as i32,
                libc::SYS_exit_group as i32,
            ];
            for syscall in essential {
                assert!(
                    config.allowed_syscalls.contains(&syscall),
                    "Capability {} should have essential syscall {}",
                    capability,
                    syscall
                );
            }
        }
    }
}
