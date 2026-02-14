use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use warp::{Filter, Reply};

use crate::isolation_tests::{quick_isolation_check, run_isolation_tests, IsolationTestResults};
use smith_jailer::landlock::is_landlock_available;

/// Overall health status of the executor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub timestamp: u64,
    pub version: String,
    pub platform: PlatformInfo,
    pub security: SecurityStatus,
    pub isolation: IsolationStatus,
    pub services: ServiceStatus,
}

/// Platform information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub os: String,
    pub arch: String,
    pub kernel_version: Option<String>,
    pub is_linux: bool,
    pub is_root: bool,
}

/// Security feature status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatus {
    pub landlock_available: bool,
    pub seccomp_available: bool,
    pub cgroups_available: bool,
    pub namespaces_available: bool,
    pub overall_secure: bool,
}

/// Isolation test status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationStatus {
    pub last_test_timestamp: Option<u64>,
    pub seccomp_working: bool,
    pub landlock_working: bool,
    pub cgroups_working: bool,
    pub isolation_effective: bool,
    pub test_details: Option<IsolationTestResults>,
}

/// Service health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub nats_connected: bool,
    pub jetstream_available: bool,
    pub worker_pools: HashMap<String, WorkerPoolStatus>,
}

/// Worker pool status for a capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerPoolStatus {
    pub capability: String,
    pub workers: u32,
    pub active: u32,
    pub queue_depth: u32,
}

/// Health check service
pub struct HealthService {
    health_status: Arc<RwLock<HealthStatus>>,
}

impl HealthService {
    /// Create new health service
    pub fn new() -> Result<Self> {
        let platform = PlatformInfo::detect();
        let security = SecurityStatus::detect();

        let initial_status = HealthStatus {
            status: "starting".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            platform,
            security,
            isolation: IsolationStatus::default(),
            services: ServiceStatus::default(),
        };

        Ok(Self {
            health_status: Arc::new(RwLock::new(initial_status)),
        })
    }

    /// Start HTTP health server
    pub async fn start_server(&self, port: u16) -> Result<()> {
        let health_status = self.health_status.clone();

        // Health check endpoint (comprehensive)
        let health = warp::path("health")
            .and(warp::get())
            .and(warp::any().map(move || health_status.clone()))
            .and_then(Self::handle_health_check);

        // Quick health check endpoint (minimal isolation validation)
        let health_status_quick = self.health_status.clone();
        let quick_health = warp::path("health")
            .and(warp::path("quick"))
            .and(warp::get())
            .and(warp::any().map(move || health_status_quick.clone()))
            .and_then(Self::handle_quick_health_check);

        // Isolation test endpoint (comprehensive testing)
        let health_status_test = self.health_status.clone();
        let isolation_test = warp::path("health")
            .and(warp::path("isolation"))
            .and(warp::post())
            .and(warp::any().map(move || health_status_test.clone()))
            .and_then(Self::handle_isolation_test);

        // Ready check endpoint (simpler than health)
        let health_status_ready = self.health_status.clone();
        let ready = warp::path("ready")
            .and(warp::get())
            .and(warp::any().map(move || health_status_ready.clone()))
            .and_then(Self::handle_ready_check);

        let routes = health
            .or(quick_health)
            .or(isolation_test)
            .or(ready)
            .with(warp::cors().allow_any_origin());

        info!("🏥 Health server starting on port {} with endpoints:", port);
        info!(
            "  - GET  /health          - Comprehensive health check with quick isolation validation"
        );
        info!("  - GET  /health/quick     - Fast health check with cached isolation status");
        info!("  - POST /health/isolation - Run comprehensive isolation tests");
        info!("  - GET  /ready            - Simple readiness check");

        warp::serve(routes).run(([0, 0, 0, 0], port)).await;

        Ok(())
    }

    /// Handle health check request
    async fn handle_health_check(
        health_status: Arc<RwLock<HealthStatus>>,
    ) -> Result<impl Reply, warp::Rejection> {
        debug!("Health check requested");

        let mut status = health_status.write().await;

        // Update timestamp
        status.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Run quick isolation check
        match quick_isolation_check().await {
            Ok(isolation_ok) => {
                status.isolation.isolation_effective = isolation_ok;
                if isolation_ok {
                    status.status = "healthy".to_string();
                } else {
                    status.status = "degraded".to_string();
                }
            }
            Err(e) => {
                warn!("Quick isolation check failed: {}", e);
                status.status = "unhealthy".to_string();
                status.isolation.isolation_effective = false;
            }
        }

        let response_status = if status.status == "healthy" {
            warp::http::StatusCode::OK
        } else if status.status == "degraded" {
            warp::http::StatusCode::OK // Still return 200 but with degraded status
        } else {
            warp::http::StatusCode::SERVICE_UNAVAILABLE
        };

        Ok(warp::reply::with_status(
            warp::reply::json(&*status),
            response_status,
        ))
    }

    /// Handle quick health check request (uses cached isolation status)
    async fn handle_quick_health_check(
        health_status: Arc<RwLock<HealthStatus>>,
    ) -> Result<impl Reply, warp::Rejection> {
        debug!("Quick health check requested");

        let status = health_status.read().await;

        // Quick response with cached data
        let quick_response = serde_json::json!({
            "status": status.status,
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "platform": {
                "os": status.platform.os,
                "is_linux": status.platform.is_linux
            },
            "security_features": {
                "landlock_available": status.security.landlock_available,
                "seccomp_available": status.security.seccomp_available,
                "cgroups_available": status.security.cgroups_available,
                "overall_secure": status.security.overall_secure
            },
            "isolation_status": {
                "last_test": status.isolation.last_test_timestamp.map(|ts| ts.to_string()),
                "effective": status.isolation.isolation_effective,
                "details": if status.isolation.isolation_effective {
                    "Isolation mechanisms were validated in last test"
                } else {
                    "Some isolation mechanisms may not be working - run comprehensive test"
                }
            },
            "services": {
                "nats_connected": status.services.nats_connected,
                "jetstream_available": status.services.jetstream_available
            }
        });

        let response_status = match status.status.as_str() {
            "healthy" => warp::http::StatusCode::OK,
            "degraded" => warp::http::StatusCode::OK, // Still OK but with warnings
            _ => warp::http::StatusCode::SERVICE_UNAVAILABLE,
        };

        Ok(warp::reply::with_status(
            warp::reply::json(&quick_response),
            response_status,
        ))
    }

    /// Handle comprehensive isolation test request
    async fn handle_isolation_test(
        health_status: Arc<RwLock<HealthStatus>>,
    ) -> Result<impl Reply, warp::Rejection> {
        info!("Comprehensive isolation test requested");

        let test_results = match run_isolation_tests().await {
            Ok(results) => results,
            Err(e) => {
                warn!("Isolation tests failed: {}", e);

                // Create detailed error response
                let error_response = serde_json::json!({
                    "error": "Isolation test execution failed",
                    "details": e.to_string(),
                    "timestamp": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    "test_status": {
                        "seccomp": "failed_to_execute",
                        "landlock": "failed_to_execute",
                        "cgroups": "failed_to_execute"
                    },
                    "recommendations": [
                        "Check if running on supported Linux system",
                        "Verify cgroups v2 is available",
                        "Ensure executor has necessary permissions",
                        "Review system logs for detailed error information"
                    ]
                });

                return Ok(warp::reply::with_status(
                    warp::reply::json(&error_response),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                ));
            }
        };

        // Create comprehensive response with detailed analysis
        let detailed_response = serde_json::json!({
            "test_results": test_results,
            "summary": {
                "overall_status": if test_results.overall_passed() { "secure" } else { "compromised" },
                "tests_passed": format!("{}/{}",
                    [test_results.seccomp_passed, test_results.landlock_passed, test_results.cgroups_passed]
                        .iter().filter(|&&x| x).count(),
                    3),
                "critical_issues": if !test_results.overall_passed() {
                    let mut issues = Vec::new();
                    if !test_results.seccomp_passed {
                        issues.push("Seccomp syscall filtering not working properly".to_string());
                    }
                    if !test_results.landlock_passed {
                        issues.push("Landlock filesystem restrictions not working properly".to_string());
                    }
                    if !test_results.cgroups_passed {
                        issues.push("Cgroups resource limits not working properly".to_string());
                    }
                    issues
                } else {
                    Vec::<String>::new()
                }
            },
            "detailed_results": {
                "seccomp": {
                    "status": if test_results.seccomp_passed { "pass" } else { "fail" },
                    "details": test_results.seccomp_details,
                    "impact": if test_results.seccomp_passed {
                        "Syscall filtering is protecting against dangerous system calls"
                    } else {
                        "WARNING: Processes may be able to execute dangerous system calls"
                    }
                },
                "landlock": {
                    "status": if test_results.landlock_passed { "pass" } else { "fail" },
                    "details": test_results.landlock_details,
                    "impact": if test_results.landlock_passed {
                        "Filesystem access is properly restricted"
                    } else {
                        "WARNING: Processes may be able to access unauthorized files"
                    }
                },
                "cgroups": {
                    "status": if test_results.cgroups_passed { "pass" } else { "fail" },
                    "details": test_results.cgroups_details,
                    "impact": if test_results.cgroups_passed {
                        "Resource limits are being enforced"
                    } else {
                        "WARNING: Processes may consume unlimited system resources"
                    }
                }
            },
            "recommendations": if !test_results.overall_passed() {
                vec![
                    "Review failed isolation mechanisms",
                    "Check system requirements (Linux kernel >= 5.15 for full Landlock support)",
                    "Verify cgroups v2 is properly configured",
                    "Consider running in --demo mode for development only",
                    "Contact system administrator for production deployments"
                ]
            } else {
                vec![
                    "Isolation mechanisms are working correctly",
                    "System is ready for production workloads",
                    "Continue with regular health monitoring"
                ]
            },
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        // Update health status with test results
        {
            let mut status = health_status.write().await;
            status.isolation = IsolationStatus {
                last_test_timestamp: Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                ),
                seccomp_working: test_results.seccomp_passed,
                landlock_working: test_results.landlock_passed,
                cgroups_working: test_results.cgroups_passed,
                isolation_effective: test_results.overall_passed(),
                test_details: Some(test_results.clone()),
            };

            status.status = if test_results.overall_passed() {
                "healthy".to_string()
            } else {
                "compromised".to_string()
            };

            status.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
        }

        let response_status = if test_results.overall_passed() {
            warp::http::StatusCode::OK
        } else {
            warp::http::StatusCode::SERVICE_UNAVAILABLE
        };

        Ok(warp::reply::with_status(
            warp::reply::json(&detailed_response),
            response_status,
        ))
    }

    /// Handle ready check (simpler health check)
    async fn handle_ready_check(
        health_status: Arc<RwLock<HealthStatus>>,
    ) -> Result<impl Reply, warp::Rejection> {
        let status = health_status.read().await;

        let is_ready = status.status == "healthy" || status.status == "degraded";
        let response = serde_json::json!({
            "ready": is_ready,
            "status": status.status,
            "timestamp": status.timestamp
        });

        let response_status = if is_ready {
            warp::http::StatusCode::OK
        } else {
            warp::http::StatusCode::SERVICE_UNAVAILABLE
        };

        Ok(warp::reply::with_status(
            warp::reply::json(&response),
            response_status,
        ))
    }

    /// Update service status
    pub async fn update_service_status(&self, services: ServiceStatus) {
        let mut status = self.health_status.write().await;
        status.services = services;
        status.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Get current health status
    pub async fn get_status(&self) -> HealthStatus {
        self.health_status.read().await.clone()
    }
}

impl PlatformInfo {
    /// Detect platform information
    pub fn detect() -> Self {
        let is_linux = cfg!(target_os = "linux");
        let is_root = unsafe { libc::getuid() == 0 };

        let kernel_version = if is_linux {
            std::fs::read_to_string("/proc/version")
                .ok()
                .and_then(|v| v.lines().next().map(|s| s.to_string()))
        } else {
            None
        };

        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            kernel_version,
            is_linux,
            is_root,
        }
    }
}

impl SecurityStatus {
    /// Detect security feature availability
    pub fn detect() -> Self {
        let is_linux = cfg!(target_os = "linux");

        let landlock_available = is_linux && is_landlock_available();
        let seccomp_available = is_linux; // Assume seccomp is available on Linux
        let cgroups_available =
            is_linux && std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
        let namespaces_available = is_linux; // Assume namespaces are available on Linux

        let overall_secure =
            landlock_available && seccomp_available && cgroups_available && namespaces_available;

        Self {
            landlock_available,
            seccomp_available,
            cgroups_available,
            namespaces_available,
            overall_secure,
        }
    }
}

impl Default for IsolationStatus {
    fn default() -> Self {
        Self {
            last_test_timestamp: None,
            seccomp_working: false,
            landlock_working: false,
            cgroups_working: false,
            isolation_effective: false,
            test_details: None,
        }
    }
}

impl Default for ServiceStatus {
    fn default() -> Self {
        Self {
            nats_connected: false,
            jetstream_available: false,
            worker_pools: HashMap::new(),
        }
    }
}

/// Create health service and start background health monitoring
pub async fn setup_health_service(port: Option<u16>) -> Result<Arc<HealthService>> {
    let health_service = Arc::new(HealthService::new()?);

    if let Some(port) = port {
        let health_clone = health_service.clone();
        tokio::spawn(async move {
            if let Err(e) = health_clone.start_server(port).await {
                warn!("Health server failed: {}", e);
            }
        });
    }

    Ok(health_service)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== PlatformInfo Tests ====================

    #[test]
    fn test_platform_detection() {
        let platform = PlatformInfo::detect();
        assert!(!platform.os.is_empty());
        assert!(!platform.arch.is_empty());
        // On Linux, kernel version should be available
        if cfg!(target_os = "linux") {
            assert!(platform.is_linux);
            assert!(platform.kernel_version.is_some());
        }
    }

    #[test]
    fn test_platform_info_clone() {
        let platform = PlatformInfo::detect();
        let cloned = platform.clone();
        assert_eq!(platform.os, cloned.os);
        assert_eq!(platform.arch, cloned.arch);
        assert_eq!(platform.is_linux, cloned.is_linux);
    }

    #[test]
    fn test_platform_info_debug() {
        let platform = PlatformInfo::detect();
        let debug_str = format!("{:?}", platform);
        assert!(debug_str.contains("os"));
        assert!(debug_str.contains("arch"));
    }

    #[test]
    fn test_platform_info_serialize() {
        let platform = PlatformInfo::detect();
        let json = serde_json::to_string(&platform).unwrap();
        assert!(json.contains("\"os\""));
        assert!(json.contains("\"arch\""));
        assert!(json.contains("\"is_linux\""));
    }

    // ==================== SecurityStatus Tests ====================

    #[test]
    fn test_security_detection() {
        let security = SecurityStatus::detect();
        // Verify detection completes without panic
        if cfg!(target_os = "linux") {
            assert!(security.seccomp_available);
            assert!(security.namespaces_available);
        }
    }

    #[test]
    fn test_security_status_clone() {
        let security = SecurityStatus::detect();
        let cloned = security.clone();
        assert_eq!(security.landlock_available, cloned.landlock_available);
        assert_eq!(security.seccomp_available, cloned.seccomp_available);
        assert_eq!(security.cgroups_available, cloned.cgroups_available);
        assert_eq!(security.overall_secure, cloned.overall_secure);
    }

    #[test]
    fn test_security_status_debug() {
        let security = SecurityStatus::detect();
        let debug_str = format!("{:?}", security);
        assert!(debug_str.contains("landlock_available"));
        assert!(debug_str.contains("seccomp_available"));
    }

    #[test]
    fn test_security_status_serialize() {
        let security = SecurityStatus::detect();
        let json = serde_json::to_string(&security).unwrap();
        assert!(json.contains("landlock_available"));
        assert!(json.contains("seccomp_available"));
        assert!(json.contains("cgroups_available"));
        assert!(json.contains("overall_secure"));
    }

    // ==================== IsolationStatus Tests ====================

    #[test]
    fn test_isolation_status_default() {
        let isolation = IsolationStatus::default();
        assert!(isolation.last_test_timestamp.is_none());
        assert!(!isolation.seccomp_working);
        assert!(!isolation.landlock_working);
        assert!(!isolation.cgroups_working);
        assert!(!isolation.isolation_effective);
        assert!(isolation.test_details.is_none());
    }

    #[test]
    fn test_isolation_status_clone() {
        let isolation = IsolationStatus {
            last_test_timestamp: Some(123456),
            seccomp_working: true,
            landlock_working: false,
            cgroups_working: true,
            isolation_effective: false,
            test_details: None,
        };
        let cloned = isolation.clone();
        assert_eq!(isolation.last_test_timestamp, cloned.last_test_timestamp);
        assert_eq!(isolation.seccomp_working, cloned.seccomp_working);
        assert_eq!(isolation.landlock_working, cloned.landlock_working);
        assert_eq!(isolation.cgroups_working, cloned.cgroups_working);
    }

    #[test]
    fn test_isolation_status_debug() {
        let isolation = IsolationStatus::default();
        let debug_str = format!("{:?}", isolation);
        assert!(debug_str.contains("seccomp_working"));
        assert!(debug_str.contains("landlock_working"));
    }

    #[test]
    fn test_isolation_status_serialize() {
        let isolation = IsolationStatus::default();
        let json = serde_json::to_string(&isolation).unwrap();
        assert!(json.contains("seccomp_working"));
        assert!(json.contains("landlock_working"));
        assert!(json.contains("isolation_effective"));
    }

    // ==================== ServiceStatus Tests ====================

    #[test]
    fn test_service_status_default() {
        let services = ServiceStatus::default();
        assert!(!services.nats_connected);
        assert!(!services.jetstream_available);
        assert!(services.worker_pools.is_empty());
    }

    #[test]
    fn test_service_status_with_worker_pools() {
        let mut services = ServiceStatus::default();
        services.nats_connected = true;
        services.jetstream_available = true;
        services.worker_pools.insert(
            "fs.read.v1".to_string(),
            WorkerPoolStatus {
                capability: "fs.read.v1".to_string(),
                workers: 4,
                active: 2,
                queue_depth: 10,
            },
        );

        assert_eq!(services.worker_pools.len(), 1);
        let pool = services.worker_pools.get("fs.read.v1").unwrap();
        assert_eq!(pool.workers, 4);
        assert_eq!(pool.active, 2);
    }

    #[test]
    fn test_service_status_clone() {
        let mut services = ServiceStatus::default();
        services.nats_connected = true;
        let cloned = services.clone();
        assert_eq!(services.nats_connected, cloned.nats_connected);
    }

    #[test]
    fn test_service_status_serialize() {
        let services = ServiceStatus::default();
        let json = serde_json::to_string(&services).unwrap();
        assert!(json.contains("nats_connected"));
        assert!(json.contains("jetstream_available"));
        assert!(json.contains("worker_pools"));
    }

    // ==================== WorkerPoolStatus Tests ====================

    #[test]
    fn test_worker_pool_status_creation() {
        let pool = WorkerPoolStatus {
            capability: "http.fetch.v1".to_string(),
            workers: 8,
            active: 3,
            queue_depth: 25,
        };

        assert_eq!(pool.capability, "http.fetch.v1");
        assert_eq!(pool.workers, 8);
        assert_eq!(pool.active, 3);
        assert_eq!(pool.queue_depth, 25);
    }

    #[test]
    fn test_worker_pool_status_clone() {
        let pool = WorkerPoolStatus {
            capability: "shell.exec.v1".to_string(),
            workers: 2,
            active: 1,
            queue_depth: 5,
        };
        let cloned = pool.clone();
        assert_eq!(pool.capability, cloned.capability);
        assert_eq!(pool.workers, cloned.workers);
    }

    #[test]
    fn test_worker_pool_status_serialize() {
        let pool = WorkerPoolStatus {
            capability: "test".to_string(),
            workers: 1,
            active: 0,
            queue_depth: 0,
        };
        let json = serde_json::to_string(&pool).unwrap();
        assert!(json.contains("\"capability\""));
        assert!(json.contains("\"workers\""));
        assert!(json.contains("\"active\""));
        assert!(json.contains("\"queue_depth\""));
    }

    // ==================== HealthStatus Tests ====================

    #[test]
    fn test_health_status_creation() {
        let status = HealthStatus {
            status: "healthy".to_string(),
            timestamp: 1234567890,
            version: "1.0.0".to_string(),
            platform: PlatformInfo::detect(),
            security: SecurityStatus::detect(),
            isolation: IsolationStatus::default(),
            services: ServiceStatus::default(),
        };

        assert_eq!(status.status, "healthy");
        assert_eq!(status.timestamp, 1234567890);
        assert_eq!(status.version, "1.0.0");
    }

    #[test]
    fn test_health_status_clone() {
        let status = HealthStatus {
            status: "starting".to_string(),
            timestamp: 1000,
            version: "0.1.0".to_string(),
            platform: PlatformInfo::detect(),
            security: SecurityStatus::detect(),
            isolation: IsolationStatus::default(),
            services: ServiceStatus::default(),
        };
        let cloned = status.clone();
        assert_eq!(status.status, cloned.status);
        assert_eq!(status.timestamp, cloned.timestamp);
        assert_eq!(status.version, cloned.version);
    }

    #[test]
    fn test_health_status_serialize() {
        let status = HealthStatus {
            status: "healthy".to_string(),
            timestamp: 1234567890,
            version: "1.0.0".to_string(),
            platform: PlatformInfo::detect(),
            security: SecurityStatus::detect(),
            isolation: IsolationStatus::default(),
            services: ServiceStatus::default(),
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"status\""));
        assert!(json.contains("\"timestamp\""));
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"platform\""));
        assert!(json.contains("\"security\""));
        assert!(json.contains("\"isolation\""));
        assert!(json.contains("\"services\""));
    }

    #[test]
    fn test_health_status_deserialize() {
        let json = r#"{
            "status": "healthy",
            "timestamp": 1234567890,
            "version": "1.0.0",
            "platform": {
                "os": "linux",
                "arch": "x86_64",
                "kernel_version": null,
                "is_linux": true,
                "is_root": false
            },
            "security": {
                "landlock_available": true,
                "seccomp_available": true,
                "cgroups_available": true,
                "namespaces_available": true,
                "overall_secure": true
            },
            "isolation": {
                "last_test_timestamp": null,
                "seccomp_working": false,
                "landlock_working": false,
                "cgroups_working": false,
                "isolation_effective": false,
                "test_details": null
            },
            "services": {
                "nats_connected": false,
                "jetstream_available": false,
                "worker_pools": {}
            }
        }"#;

        let status: HealthStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.status, "healthy");
        assert_eq!(status.timestamp, 1234567890);
        assert_eq!(status.version, "1.0.0");
        assert!(status.security.overall_secure);
    }

    // ==================== HealthService Tests ====================

    #[tokio::test]
    async fn test_health_service_creation() {
        let health_service = HealthService::new();
        assert!(health_service.is_ok());

        if let Ok(service) = health_service {
            let status = service.get_status().await;
            assert_eq!(status.status, "starting");
            assert!(!status.version.is_empty());
        }
    }

    #[tokio::test]
    async fn test_health_service_get_status() {
        let service = HealthService::new().unwrap();
        let status = service.get_status().await;

        assert_eq!(status.status, "starting");
        assert!(!status.platform.os.is_empty());
        assert!(status.timestamp > 0);
    }

    #[tokio::test]
    async fn test_health_service_update_service_status() {
        let service = HealthService::new().unwrap();

        let mut new_services = ServiceStatus::default();
        new_services.nats_connected = true;
        new_services.jetstream_available = true;

        service.update_service_status(new_services.clone()).await;

        let status = service.get_status().await;
        assert!(status.services.nats_connected);
        assert!(status.services.jetstream_available);
    }

    #[tokio::test]
    async fn test_health_service_update_updates_timestamp() {
        let service = HealthService::new().unwrap();
        let initial_status = service.get_status().await;
        let initial_timestamp = initial_status.timestamp;

        // Small delay to ensure timestamp changes
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let new_services = ServiceStatus::default();
        service.update_service_status(new_services).await;

        let updated_status = service.get_status().await;
        assert!(updated_status.timestamp >= initial_timestamp);
    }

    #[tokio::test]
    async fn test_health_service_concurrent_access() {
        let service = Arc::new(HealthService::new().unwrap());
        let service_clone = service.clone();

        // Simulate concurrent reads and writes
        let read_handle = tokio::spawn(async move {
            for _ in 0..5 {
                let _ = service.get_status().await;
            }
        });

        let write_handle = tokio::spawn(async move {
            for _ in 0..5 {
                let services = ServiceStatus::default();
                service_clone.update_service_status(services).await;
            }
        });

        // Both should complete without deadlock
        let _ = tokio::join!(read_handle, write_handle);
    }

    // ==================== setup_health_service Tests ====================

    #[tokio::test]
    async fn test_setup_health_service_without_port() {
        let result = setup_health_service(None).await;
        assert!(result.is_ok());

        let service = result.unwrap();
        let status = service.get_status().await;
        assert_eq!(status.status, "starting");
    }

    // ==================== Warp HTTP Handler Tests ====================

    #[tokio::test]
    async fn test_handle_ready_check_starting_status() {
        let health_status = Arc::new(RwLock::new(HealthStatus {
            status: "starting".to_string(),
            timestamp: 1234567890,
            version: "1.0.0".to_string(),
            platform: PlatformInfo {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                kernel_version: None,
                is_linux: true,
                is_root: false,
            },
            security: SecurityStatus {
                landlock_available: true,
                seccomp_available: true,
                cgroups_available: true,
                namespaces_available: true,
                overall_secure: true,
            },
            isolation: IsolationStatus::default(),
            services: ServiceStatus::default(),
        }));

        let ready_filter = warp::path("ready")
            .and(warp::get())
            .and(warp::any().map(move || health_status.clone()))
            .and_then(HealthService::handle_ready_check);

        let response = warp::test::request()
            .method("GET")
            .path("/ready")
            .reply(&ready_filter)
            .await;

        // "starting" status should return SERVICE_UNAVAILABLE
        assert_eq!(response.status(), 503);

        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["ready"], false);
        assert_eq!(body["status"], "starting");
    }

    #[tokio::test]
    async fn test_handle_ready_check_healthy_status() {
        let health_status = Arc::new(RwLock::new(HealthStatus {
            status: "healthy".to_string(),
            timestamp: 1234567890,
            version: "1.0.0".to_string(),
            platform: PlatformInfo {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                kernel_version: None,
                is_linux: true,
                is_root: false,
            },
            security: SecurityStatus {
                landlock_available: true,
                seccomp_available: true,
                cgroups_available: true,
                namespaces_available: true,
                overall_secure: true,
            },
            isolation: IsolationStatus::default(),
            services: ServiceStatus::default(),
        }));

        let ready_filter = warp::path("ready")
            .and(warp::get())
            .and(warp::any().map(move || health_status.clone()))
            .and_then(HealthService::handle_ready_check);

        let response = warp::test::request()
            .method("GET")
            .path("/ready")
            .reply(&ready_filter)
            .await;

        assert_eq!(response.status(), 200);

        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["ready"], true);
        assert_eq!(body["status"], "healthy");
    }

    #[tokio::test]
    async fn test_handle_ready_check_degraded_status() {
        let health_status = Arc::new(RwLock::new(HealthStatus {
            status: "degraded".to_string(),
            timestamp: 1234567890,
            version: "1.0.0".to_string(),
            platform: PlatformInfo {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                kernel_version: None,
                is_linux: true,
                is_root: false,
            },
            security: SecurityStatus {
                landlock_available: true,
                seccomp_available: true,
                cgroups_available: false,
                namespaces_available: true,
                overall_secure: false,
            },
            isolation: IsolationStatus::default(),
            services: ServiceStatus::default(),
        }));

        let ready_filter = warp::path("ready")
            .and(warp::get())
            .and(warp::any().map(move || health_status.clone()))
            .and_then(HealthService::handle_ready_check);

        let response = warp::test::request()
            .method("GET")
            .path("/ready")
            .reply(&ready_filter)
            .await;

        // "degraded" status should still return OK (200)
        assert_eq!(response.status(), 200);

        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["ready"], true);
        assert_eq!(body["status"], "degraded");
    }

    #[tokio::test]
    async fn test_handle_quick_health_check() {
        let health_status = Arc::new(RwLock::new(HealthStatus {
            status: "healthy".to_string(),
            timestamp: 1234567890,
            version: "1.0.0".to_string(),
            platform: PlatformInfo {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                kernel_version: Some("5.15.0".to_string()),
                is_linux: true,
                is_root: false,
            },
            security: SecurityStatus {
                landlock_available: true,
                seccomp_available: true,
                cgroups_available: true,
                namespaces_available: true,
                overall_secure: true,
            },
            isolation: IsolationStatus {
                last_test_timestamp: Some(1234567800),
                seccomp_working: true,
                landlock_working: true,
                cgroups_working: true,
                isolation_effective: true,
                test_details: None,
            },
            services: ServiceStatus {
                nats_connected: true,
                jetstream_available: true,
                worker_pools: HashMap::new(),
            },
        }));

        let quick_health_filter = warp::path!("health" / "quick")
            .and(warp::get())
            .and(warp::any().map(move || health_status.clone()))
            .and_then(HealthService::handle_quick_health_check);

        let response = warp::test::request()
            .method("GET")
            .path("/health/quick")
            .reply(&quick_health_filter)
            .await;

        assert_eq!(response.status(), 200);

        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["status"], "healthy");
        assert!(body["platform"]["is_linux"].as_bool().unwrap());
        assert!(body["security_features"]["overall_secure"]
            .as_bool()
            .unwrap());
        assert!(body["isolation_status"]["effective"].as_bool().unwrap());
        assert!(body["services"]["nats_connected"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_handle_quick_health_check_unhealthy() {
        let health_status = Arc::new(RwLock::new(HealthStatus {
            status: "unhealthy".to_string(),
            timestamp: 1234567890,
            version: "1.0.0".to_string(),
            platform: PlatformInfo {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                kernel_version: None,
                is_linux: true,
                is_root: false,
            },
            security: SecurityStatus {
                landlock_available: false,
                seccomp_available: false,
                cgroups_available: false,
                namespaces_available: false,
                overall_secure: false,
            },
            isolation: IsolationStatus::default(),
            services: ServiceStatus::default(),
        }));

        let quick_health_filter = warp::path!("health" / "quick")
            .and(warp::get())
            .and(warp::any().map(move || health_status.clone()))
            .and_then(HealthService::handle_quick_health_check);

        let response = warp::test::request()
            .method("GET")
            .path("/health/quick")
            .reply(&quick_health_filter)
            .await;

        assert_eq!(response.status(), 503);

        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["status"], "unhealthy");
        assert!(!body["security_features"]["overall_secure"]
            .as_bool()
            .unwrap());
    }

    #[tokio::test]
    async fn test_handle_quick_health_check_isolation_not_effective() {
        let health_status = Arc::new(RwLock::new(HealthStatus {
            status: "degraded".to_string(),
            timestamp: 1234567890,
            version: "1.0.0".to_string(),
            platform: PlatformInfo {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                kernel_version: None,
                is_linux: true,
                is_root: false,
            },
            security: SecurityStatus {
                landlock_available: true,
                seccomp_available: true,
                cgroups_available: true,
                namespaces_available: true,
                overall_secure: true,
            },
            isolation: IsolationStatus {
                last_test_timestamp: None,
                seccomp_working: false,
                landlock_working: false,
                cgroups_working: false,
                isolation_effective: false,
                test_details: None,
            },
            services: ServiceStatus::default(),
        }));

        let quick_health_filter = warp::path!("health" / "quick")
            .and(warp::get())
            .and(warp::any().map(move || health_status.clone()))
            .and_then(HealthService::handle_quick_health_check);

        let response = warp::test::request()
            .method("GET")
            .path("/health/quick")
            .reply(&quick_health_filter)
            .await;

        // Degraded returns 200
        assert_eq!(response.status(), 200);

        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert!(!body["isolation_status"]["effective"].as_bool().unwrap());
        assert!(body["isolation_status"]["details"]
            .as_str()
            .unwrap()
            .contains("run comprehensive test"));
    }
}
