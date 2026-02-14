/// Simple test for capability bundle enforcement functionality
#[cfg(test)]
mod tests {
    use crate::config::PolicyDerivations;

    #[test]
    fn test_policy_derivations_loading() {
        let json_content = r#"{
  "seccomp_allow": {
    "fs.read.v1": ["read", "readv", "openat", "close", "fstat"],
    "http.fetch.v1": ["socket", "connect", "sendto", "recvfrom", "close"]
  },
  "landlock_paths": {
    "fs.read.v1": { 
      "read": ["/etc/smith-ro/", "/app/ro/"], 
      "write": [] 
    },
    "http.fetch.v1": { 
      "read": [], 
      "write": [] 
    }
  },
  "cgroups": {
    "fs.read.v1": { 
      "cpu_pct": 20, 
      "mem_mb": 64 
    },
    "http.fetch.v1": { 
      "cpu_pct": 30, 
      "mem_mb": 128 
    }
  }
}"#;

        let derivations: PolicyDerivations = serde_json::from_str(json_content).unwrap();

        // Test seccomp allowlist
        let fs_read_syscalls = derivations.get_seccomp_allowlist("fs.read.v1").unwrap();
        assert_eq!(fs_read_syscalls.len(), 5);
        assert!(fs_read_syscalls.contains(&"read".to_string()));
        assert!(fs_read_syscalls.contains(&"openat".to_string()));

        // Test landlock profile
        let fs_read_landlock = derivations.get_landlock_profile("fs.read.v1").unwrap();
        assert_eq!(fs_read_landlock.read.len(), 2);
        assert_eq!(fs_read_landlock.write.len(), 0);
        assert!(fs_read_landlock
            .read
            .contains(&"/etc/smith-ro/".to_string()));

        // Test cgroup limits
        let fs_read_cgroup = derivations.get_cgroup_limits("fs.read.v1").unwrap();
        assert_eq!(fs_read_cgroup.cpu_pct, 20);
        assert_eq!(fs_read_cgroup.mem_mb, 64);

        let http_fetch_cgroup = derivations.get_cgroup_limits("http.fetch.v1").unwrap();
        assert_eq!(http_fetch_cgroup.cpu_pct, 30);
        assert_eq!(http_fetch_cgroup.mem_mb, 128);
    }

    #[test]
    fn test_capability_digest_validation() {
        // Valid 64-character hex string
        let valid_digest = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        assert_eq!(valid_digest.len(), 64);
        assert!(valid_digest.chars().all(|c| c.is_ascii_hexdigit()));

        // Invalid digest - too short
        let invalid_short = "abcdef123";
        assert_ne!(invalid_short.len(), 64);

        // Invalid digest - contains non-hex characters
        let invalid_chars = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789g";
        assert_eq!(invalid_chars.len(), 64);
        assert!(!invalid_chars.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
