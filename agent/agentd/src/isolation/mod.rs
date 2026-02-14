//! Isolation backend implementations
//!
//! This module contains concrete implementations of the `IsolationBackend` trait:
//! - `LinuxNativeBackend`: Uses Landlock LSM for filesystem access control (no mount isolation)
//! - `ContainerBackend`: Uses mount namespaces for true filesystem isolation
//! - `FirecrackerBackend`: Uses Firecracker microVMs for full hardware isolation
//! - `HostDirectBackend`: No isolation, just policy guards (workstation mode)
//!
//! Future implementations:
//! - `MacosNativeBackend`: Uses sandbox-exec (seatbelt)

#[cfg(target_os = "linux")]
pub mod container;
#[cfg(target_os = "linux")]
pub mod firecracker;
pub mod host_direct;
pub mod linux;

#[cfg(target_os = "linux")]
pub use container::ContainerBackend;
#[cfg(target_os = "linux")]
pub use firecracker::{FirecrackerBackend, FirecrackerConfig};
pub use host_direct::HostDirectBackend;
pub use linux::LinuxNativeBackend;

use crate::core::isolation::{BackendCapabilities, IsolationBackend};
use anyhow::Context;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, RwLock};

type BackendFactory = dyn Fn(&Path) -> anyhow::Result<Arc<dyn IsolationBackend>> + Send + Sync;

#[derive(Clone)]
struct RegisteredBackend {
    factory: Arc<BackendFactory>,
}

#[derive(Default)]
struct BackendRegistry {
    backends: HashMap<String, RegisteredBackend>,
    aliases: HashMap<String, String>,
    insertion_order: Vec<String>,
}

impl BackendRegistry {
    fn register_backend(
        &mut self,
        canonical_name: &str,
        aliases: &[&str],
        factory: Arc<BackendFactory>,
    ) -> anyhow::Result<()> {
        let canonical = normalize_backend_name(canonical_name);
        if canonical.is_empty() {
            anyhow::bail!("Isolation backend canonical name cannot be empty");
        }

        if self.backends.contains_key(&canonical) {
            anyhow::bail!("Isolation backend '{}' is already registered", canonical);
        }

        let mut alias_set = HashSet::new();
        alias_set.insert(canonical.clone());
        alias_set.insert(canonical.replace('-', "_"));

        for alias in aliases {
            let normalized = normalize_backend_name(alias);
            if normalized.is_empty() {
                continue;
            }

            alias_set.insert(normalized.clone());
            alias_set.insert(normalized.replace('-', "_"));
        }

        for alias in &alias_set {
            if let Some(existing) = self.aliases.get(alias) {
                anyhow::bail!(
                    "Isolation backend alias '{}' is already registered for '{}'",
                    alias,
                    existing
                );
            }
        }

        self.backends
            .insert(canonical.clone(), RegisteredBackend { factory });
        self.insertion_order.push(canonical.clone());

        for alias in alias_set {
            self.aliases.insert(alias, canonical.clone());
        }

        Ok(())
    }

    fn resolve_canonical(&self, name: &str) -> Option<String> {
        let normalized = normalize_backend_name(name);
        if normalized.is_empty() {
            return None;
        }

        self.aliases.get(&normalized).cloned()
    }

    fn backend_factory(&self, name: &str) -> Option<Arc<BackendFactory>> {
        let canonical = self.resolve_canonical(name)?;
        self.backends
            .get(&canonical)
            .map(|entry| entry.factory.clone())
    }

    fn available_backend_names(&self) -> Vec<String> {
        self.insertion_order.clone()
    }
}

fn normalize_backend_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('_', "-")
}

fn build_registry() -> BackendRegistry {
    let mut registry = BackendRegistry::default();
    register_builtin_backends(&mut registry)
        .expect("builtin isolation backend registration failed");
    registry
}

static BACKEND_REGISTRY: Lazy<RwLock<BackendRegistry>> =
    Lazy::new(|| RwLock::new(build_registry()));

fn register_builtin_backends(registry: &mut BackendRegistry) -> anyhow::Result<()> {
    registry.register_backend(
        "host-direct",
        &["none", "host", "workstation", "host_direct"],
        Arc::new(|work_root| Ok(Arc::new(HostDirectBackend::new(work_root)))),
    )?;

    registry.register_backend(
        "linux-native",
        &["linux", "native", "landlock", "linux_native"],
        Arc::new(|work_root| {
            #[cfg(target_os = "linux")]
            {
                Ok(Arc::new(LinuxNativeBackend::new(work_root)?))
            }
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("LinuxNativeBackend is only available on Linux")
            }
        }),
    )?;

    registry.register_backend(
        "container",
        &["namespace", "mount-ns", "mount_ns"],
        Arc::new(|work_root| {
            #[cfg(target_os = "linux")]
            {
                Ok(Arc::new(ContainerBackend::new(work_root, None)?))
            }
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("ContainerBackend is only available on Linux")
            }
        }),
    )?;

    registry.register_backend(
        "firecracker",
        &["microvm", "vm"],
        Arc::new(|work_root| {
            #[cfg(target_os = "linux")]
            {
                let config = FirecrackerConfig {
                    work_root: work_root.to_path_buf(),
                    ..Default::default()
                };
                Ok(Arc::new(FirecrackerBackend::new(config)?))
            }
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("FirecrackerBackend is only available on Linux")
            }
        }),
    )?;

    Ok(())
}

/// Register a custom isolation backend factory.
///
/// This allows modular provider integration (for example, a Gondolin-backed
/// provider) without modifying backend selection code paths.
pub fn register_backend_factory<F>(
    canonical_name: &str,
    aliases: &[&str],
    factory: F,
) -> anyhow::Result<()>
where
    F: Fn(&Path) -> anyhow::Result<Arc<dyn IsolationBackend>> + Send + Sync + 'static,
{
    let mut registry = BACKEND_REGISTRY.write().expect("backend registry poisoned");
    registry.register_backend(canonical_name, aliases, Arc::new(factory))
}

/// Resolve an alias to its canonical backend name.
pub fn canonical_backend_name(name: &str) -> Option<String> {
    let registry = BACKEND_REGISTRY.read().expect("backend registry poisoned");
    registry.resolve_canonical(name)
}

/// List registered canonical backend names.
pub fn available_backends() -> Vec<String> {
    let registry = BACKEND_REGISTRY.read().expect("backend registry poisoned");
    registry.available_backend_names()
}

fn backend_score(caps: &BackendCapabilities) -> u8 {
    let mut score = 0u8;
    if caps.filesystem_isolation {
        score += 4;
    }
    if caps.process_isolation {
        score += 2;
    }
    if caps.network_isolation {
        score += 2;
    }
    if caps.syscall_filtering {
        score += 2;
    }
    if caps.resource_limits {
        score += 1;
    }
    score
}

/// Probe the system and return the best available isolation backend
pub async fn detect_best_backend(work_root: &Path) -> Arc<dyn IsolationBackend> {
    let mut best_candidate: Option<(u8, Arc<dyn IsolationBackend>)> = None;

    for name in available_backends() {
        let backend = match create_backend(&name, work_root) {
            Ok(backend) => backend,
            Err(err) => {
                tracing::debug!(
                    backend = %name,
                    error = %err,
                    "Skipping unavailable backend candidate"
                );
                continue;
            }
        };

        match backend.probe().await {
            Ok(caps) => {
                let score = backend_score(&caps);
                tracing::debug!(
                    backend = %caps.name,
                    score,
                    filesystem_isolation = caps.filesystem_isolation,
                    network_isolation = caps.network_isolation,
                    process_isolation = caps.process_isolation,
                    syscall_filtering = caps.syscall_filtering,
                    "Scored backend candidate"
                );

                let should_replace = best_candidate
                    .as_ref()
                    .map(|(existing_score, _)| score > *existing_score)
                    .unwrap_or(true);

                if should_replace {
                    best_candidate = Some((score, backend));
                }
            }
            Err(err) => {
                tracing::warn!(
                    backend = %name,
                    error = %err,
                    "Backend probe failed; skipping candidate"
                );
            }
        }
    }

    if let Some((score, backend)) = best_candidate {
        tracing::info!(backend = %backend.name(), score, "Using detected best isolation backend");
        return backend;
    }

    tracing::warn!(
        "No registered isolation backend could be initialized; falling back to host-direct"
    );
    Arc::new(HostDirectBackend::new(work_root))
}

/// Create a backend by name
pub fn create_backend(name: &str, work_root: &Path) -> anyhow::Result<Arc<dyn IsolationBackend>> {
    let factory = {
        let registry = BACKEND_REGISTRY.read().expect("backend registry poisoned");
        registry.backend_factory(name).ok_or_else(|| {
            let available = registry.available_backend_names().join(", ");
            anyhow::anyhow!(
                "Unknown isolation backend '{}'. Available backends: {}",
                name,
                available
            )
        })?
    };

    factory(work_root).with_context(|| format!("Failed to initialize isolation backend '{}'", name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use uuid::Uuid;

    #[test]
    fn test_create_backend_host_direct() {
        let temp_dir = TempDir::new().unwrap();

        // All host-direct aliases should work
        let aliases = ["none", "host", "host-direct", "host_direct", "workstation"];
        for alias in aliases {
            let backend = create_backend(alias, temp_dir.path());
            assert!(backend.is_ok(), "Failed for alias: {}", alias);
            assert_eq!(backend.unwrap().name(), "host-direct");
        }
    }

    #[test]
    fn test_create_backend_unknown() {
        let temp_dir = TempDir::new().unwrap();
        let result = create_backend("unknown-backend", temp_dir.path());
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("Unknown isolation backend"));
        assert!(err.contains("host-direct"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_create_backend_linux() {
        let temp_dir = TempDir::new().unwrap();

        let aliases = ["linux", "native", "linux-native", "linux_native"];
        for alias in aliases {
            let result = create_backend(alias, temp_dir.path());
            // On Linux, this should succeed (or fail only due to permissions)
            // We just check it doesn't panic
            let _ = result;
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_create_backend_linux_not_available() {
        let temp_dir = TempDir::new().unwrap();

        let aliases = ["linux", "native", "linux-native", "linux_native"];
        for alias in aliases {
            let result = create_backend(alias, temp_dir.path());
            assert!(result.is_err());
            let err = result.err().unwrap().to_string();
            assert!(err.contains("only available on Linux"));
        }
    }

    #[test]
    fn test_canonical_backend_name_resolves_aliases() {
        assert_eq!(
            canonical_backend_name("host_direct").as_deref(),
            Some("host-direct")
        );
        assert_eq!(
            canonical_backend_name("LANDLOCK").as_deref(),
            Some("linux-native")
        );
    }

    #[test]
    fn test_available_backends_contains_core_backends() {
        let names = available_backends();
        assert!(names.contains(&"host-direct".to_string()));
        assert!(names.contains(&"linux-native".to_string()));
        assert!(names.contains(&"container".to_string()));
        assert!(names.contains(&"firecracker".to_string()));
    }

    #[test]
    fn test_register_backend_factory_allows_custom_provider() {
        let temp_dir = TempDir::new().unwrap();
        let backend_name = format!("test-provider-{}", Uuid::new_v4().simple());
        let alias = format!("{}-alias", backend_name);

        register_backend_factory(&backend_name, &[&alias], |work_root| {
            Ok(Arc::new(HostDirectBackend::new(work_root)))
        })
        .expect("custom backend registration should succeed");

        let canonical = canonical_backend_name(&alias);
        assert_eq!(canonical.as_deref(), Some(backend_name.as_str()));

        let backend =
            create_backend(&alias, temp_dir.path()).expect("custom backend should create");
        assert_eq!(backend.name(), "host-direct");
    }

    #[test]
    fn test_register_backend_factory_rejects_alias_collision() {
        let backend_name = format!("test-collision-{}", Uuid::new_v4().simple());
        let result = register_backend_factory(&backend_name, &["host"], |work_root| {
            Ok(Arc::new(HostDirectBackend::new(work_root)))
        });
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("already registered"));
    }

    #[tokio::test]
    async fn test_detect_best_backend() {
        let temp_dir = TempDir::new().unwrap();
        let backend = detect_best_backend(temp_dir.path()).await;

        // Should return a valid backend
        let name = backend.name();
        assert!(
            name == "host-direct"
                || name == "linux-native"
                || name == "container"
                || name == "firecracker",
            "Unexpected backend: {}",
            name
        );
    }

    #[tokio::test]
    async fn test_backend_probe() {
        let temp_dir = TempDir::new().unwrap();
        let backend = create_backend("host-direct", temp_dir.path()).unwrap();

        let caps = backend.probe().await.unwrap();
        assert_eq!(caps.name, "host-direct");
        // Host-direct has no kernel isolation
        assert!(!caps.filesystem_isolation);
        assert!(!caps.network_isolation);
        assert!(!caps.process_isolation);
        assert!(!caps.syscall_filtering);
        // But supports persistent sandboxes
        assert!(caps.persistent_sandboxes);
    }
}
