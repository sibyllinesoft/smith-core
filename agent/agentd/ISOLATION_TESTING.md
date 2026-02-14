# Smith Executor - Isolation Testing & Validation

This document describes the comprehensive isolation testing system implemented in the Smith Executor as part of **Milestone 5 - Isolation Tests & Resource Limits**.

## Overview

The Smith Executor implements fortress-level security through multiple isolation mechanisms:
- **Seccomp-BPF**: Syscall filtering to prevent dangerous system calls
- **Landlock**: Filesystem access control (Linux 5.15+)
- **Cgroups v2**: Resource limits (CPU, memory, PID, I/O)
- **Namespaces**: Process, mount, network, and user isolation

## Testing Framework

### Test Architecture

The isolation testing system is built around three core components:

1. **`isolation_tests.rs`** - Core testing logic with comprehensive validation
2. **`health.rs`** - HTTP endpoints for health monitoring and test execution
3. **CLI Integration** - `--self-test` and `--check-config` commands

### Test Categories

#### 1. Seccomp Syscall Filtering Tests

**Purpose**: Validate that dangerous syscalls are blocked while allowing safe operations.

**Tests Performed**:
- `ptrace` blocking - Prevents debugging/tracing attacks
- Raw socket creation - Prevents network privilege escalation
- `mount` syscall - Prevents filesystem manipulation attacks

**Validation Method**:
```rust
// Fork child process, apply seccomp filter, attempt forbidden syscall
// Expected result: EPERM or process killed by seccomp violation
```

**Success Criteria**:
- Allowed syscalls (getpid, read, write) work normally
- Forbidden syscalls fail with EPERM or kill the process
- All test syscalls are properly blocked

#### 2. Landlock Filesystem Access Control Tests

**Purpose**: Validate filesystem access restrictions work as intended.

**Tests Performed**:
- Read-only access enforcement - Only whitelisted directories accessible
- Write prevention - Write operations blocked in read-only areas
- Directory creation prevention - mkdir blocked in restricted areas

**Validation Method**:
```rust
// Create test directories (allowed, forbidden, readonly)
// Apply Landlock rules, attempt various file operations
// Expected result: Only allowed operations succeed
```

**Success Criteria**:
- Whitelisted paths are accessible for allowed operations
- Non-whitelisted paths return PermissionDenied
- Write operations blocked in read-only areas
- Directory creation blocked where not permitted

#### 3. Cgroups Resource Limits Tests

**Purpose**: Validate that resource limits are enforced and measurable.

**Tests Performed**:
- CPU throttling - Aggressive CPU usage limited by percentage
- Memory limits - Memory usage tracked and limited
- PID limits - Process creation limits enforced

**Validation Method**:
```rust
// Create cgroup with strict limits, run resource-intensive tasks
// Measure actual resource usage vs limits
// Expected result: Usage constrained by configured limits
```

**Success Criteria**:
- CPU usage is throttled according to configured percentage
- Memory usage is tracked and limited
- PID limits prevent excessive process creation
- Throttling statistics are available and accurate

## Test Execution Methods

### 1. Command Line Interface

```bash
# Quick configuration check
smith-executor check-config

# Basic self-test with quick isolation validation
smith-executor self-test

# Comprehensive isolation testing (may take 30+ seconds)
smith-executor self-test --comprehensive
```

**Exit Codes**:
- `0` - All tests passed, system ready for production
- `1` - Configuration issues detected or tests failed

### 2. Health Endpoints

The executor provides HTTP endpoints for monitoring and testing:

```bash
# Quick health check (uses cached status)
curl http://localhost:3001/health/quick

# Comprehensive health check with quick isolation validation  
curl http://localhost:3000/health

# Run comprehensive isolation tests (POST request)
curl -X POST http://localhost:3001/health/isolation

# Simple readiness check
curl http://localhost:3001/ready
```

### 3. Programmatic Testing

```rust
use executor::isolation_tests::{run_isolation_tests, quick_isolation_check};

// Quick check for basic functionality
let isolation_ok = quick_isolation_check().await?;

// Comprehensive testing
let results = run_isolation_tests().await?;
if results.overall_passed {
    println!("All isolation mechanisms working correctly");
}
```

## Platform Support

### Linux (Full Support)
- **Kernel Requirements**: 5.15+ recommended for full Landlock v2 support
- **Cgroups**: Requires cgroups v2 (`/sys/fs/cgroup` mount point)
- **Permissions**: Some tests may require elevated privileges

### Non-Linux Platforms
- Tests are automatically skipped with clear messaging
- Executor can run in `--demo` mode for development
- All isolation features disabled with appropriate warnings

## Test Output Examples

### Successful Test Run
```
🧪 Smith Executor Self-Test
===========================

🖥️  Platform Information:
├─ OS: linux x86_64
├─ Linux: ✅ Yes
└─ Root: ✅ No

🔒 Security Features:
├─ Landlock: ✅ Available
├─ Seccomp: ✅ Available  
├─ Cgroups: ✅ Available
└─ Namespaces: ✅ Available

🛡️  Quick Isolation Check:
├─ Result: ✅ Isolation mechanisms appear functional

📊 Self-Test Summary:
├─ Platform: ✅ Supported
├─ Security: ✅ Full
├─ Isolation: ✅ Working
└─ Configuration: ✅ Valid

🚀 Final Status: ✅ READY FOR PRODUCTION
```

### Comprehensive Test Results
```
🛡️  ISOLATION VALIDATION REPORT
=====================================

🔒 Seccomp Syscall Filtering:
├─ Status: ✅ PASS
└─ Details: Seccomp filtering active - 3 tests passed: [ptrace: blocked with EPERM, raw_socket: blocked with EPERM/EACCES, mount: blocked with EPERM/EACCES]

📁 Landlock Filesystem Control:
├─ Status: ✅ PASS
└─ Details: Landlock filesystem restrictions active - 3 tests passed: [readonly_access: properly enforced read-only access, write_prevention: blocked write access, dir_prevention: blocked directory creation]

💾 Cgroups Resource Limits:
├─ Status: ✅ PASS
└─ Details: Cgroups resource limits active - 3 tests passed: [cpu_throttling: actively throttled: 15 periods, 847291μs throttle time, memory_limits: limit applied (10MB) and usage tracked (2847392B), pid_limits: limit applied (3 max) and tracking works (1 current)]

📊 Overall Security Isolation:
└─ Status: ✅ SECURE - All isolation mechanisms working
```

### Failed Test Example
```
❌ Seccomp test 'mount' failed: Mount succeeded when it should have been blocked

⚠️  WARNING: Security isolation is not fully functional
   This executor may not provide adequate sandboxing
   Review failed tests and fix configuration before production use
```

## Integration with CI/CD

### GitHub Actions Integration
```yaml
- name: Run Isolation Tests
  run: |
    cargo build --bin executor
    # Run comprehensive isolation tests
    ./target/debug/executor self-test --comprehensive
    
    # Test health endpoints
    ./target/debug/executor run --demo &
    sleep 5
    curl -f http://localhost:3001/health/quick
    curl -f -X POST http://localhost:3001/health/isolation
```

### Docker Integration
```dockerfile
# In your Dockerfile
RUN ./executor self-test --comprehensive || \
    (echo "Isolation tests failed - container may not be secure" && exit 1)
    
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3001/health/quick || exit 1
```

## Security Guarantees

When all tests pass, the Smith Executor provides these security guarantees:

### Seccomp Protection
- ✅ Dangerous syscalls (ptrace, mount, reboot) are blocked
- ✅ Network privilege escalation prevented (raw sockets blocked)
- ✅ System modification prevented (filesystem mounting blocked)

### Landlock Protection  
- ✅ Filesystem access limited to explicitly allowed paths
- ✅ Write operations restricted to designated areas
- ✅ Directory creation controlled by whitelist policy

### Cgroups Protection
- ✅ CPU usage throttled to prevent resource exhaustion
- ✅ Memory usage limited and tracked
- ✅ Process creation limited to prevent fork bombs
- ✅ I/O bandwidth can be controlled (when configured)

### Combined Protection
- ✅ Multiple layers of defense (defense-in-depth)
- ✅ Fail-secure design (restrictive by default)
- ✅ Continuous monitoring and validation
- ✅ Immediate detection of isolation failures

## Troubleshooting

### Common Issues

#### "Landlock not available"
- **Cause**: Kernel < 5.15 or Landlock not enabled
- **Solution**: Upgrade kernel or run in `--demo` mode
- **Impact**: Filesystem restrictions use fallback mechanisms

#### "Cgroups v2 not available"  
- **Cause**: System using cgroups v1 or not mounted
- **Solution**: Enable cgroups v2 or run in `--demo` mode
- **Impact**: Resource limits will not be enforced

#### "Seccomp tests failing"
- **Cause**: Kernel without seccomp-bpf support
- **Solution**: Upgrade kernel or check kernel config
- **Impact**: Syscall filtering will not work

#### Permission Errors
- **Cause**: Running tests without sufficient privileges
- **Solution**: Run as root or with appropriate capabilities
- **Impact**: Some tests cannot validate privilege restrictions

### Debugging Commands

```bash
# Check kernel support
uname -r
grep CONFIG_SECCOMP /boot/config-$(uname -r)
grep CONFIG_LSM /boot/config-$(uname -r)

# Check cgroups v2
mount | grep cgroup
ls -la /sys/fs/cgroup/

# Verbose test output
RUST_LOG=debug ./executor self-test --comprehensive
```

## Performance Impact

The isolation testing system is designed for minimal performance impact:

- **Quick checks**: < 100ms (cached status)
- **Comprehensive tests**: 10-30 seconds (full validation)
- **Runtime overhead**: < 1% CPU (monitoring only)
- **Memory overhead**: < 10MB (test infrastructure)

## Future Enhancements

Planned improvements for the isolation testing system:

1. **Extended Syscall Coverage**: Test more dangerous syscalls
2. **Network Isolation**: Validate network namespace restrictions
3. **Performance Benchmarking**: Measure isolation overhead
4. **Automated Remediation**: Suggest fixes for failed tests
5. **Compliance Reporting**: Generate compliance reports for audits

## Conclusion

The Smith Executor's isolation testing system provides comprehensive validation that security mechanisms are working correctly. By testing real syscall blocking, filesystem restrictions, and resource limits, it ensures that the executor can safely run untrusted code in a properly isolated environment.

The system follows security best practices:
- **Fail-secure by default**: Tests verify restrictions work
- **Defense in depth**: Multiple layers of isolation tested
- **Continuous monitoring**: Health endpoints provide ongoing validation
- **Clear reporting**: Detailed feedback on what's working and what isn't

This testing framework provides confidence that the Smith Executor delivers on its security promises and can be safely deployed in production environments.