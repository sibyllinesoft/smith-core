use crate::capability::CapabilityRegistry;

pub mod shell_exec_v1;

/// Initialize and register all built-in capabilities
pub fn register_builtin_capabilities() -> CapabilityRegistry {
    let mut registry = CapabilityRegistry::new();

    registry.register(Box::new(shell_exec_v1::ShellExecV1Capability::new()));

    tracing::info!("Registered {} built-in capabilities", registry.list().len());
    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_builtin_capabilities() {
        let registry = register_builtin_capabilities();
        let capability_names = registry.list();

        assert_eq!(capability_names.len(), 1);
        assert!(capability_names.contains(&"shell.exec.v1".to_string()));
    }

    #[test]
    fn test_capability_registry_security_properties() {
        let registry = register_builtin_capabilities();
        let capability_names = registry.list();

        for name in capability_names {
            // All capability names must follow versioned pattern
            assert!(
                name.contains(".v"),
                "Capability '{}' must have version suffix",
                name
            );

            // Names must be lowercase with dots and underscores only
            assert!(
                name.chars()
                    .all(|c| c.is_lowercase() || c.is_numeric() || c == '.' || c == '_'),
                "Capability '{}' must use only lowercase, numbers, dots, and underscores",
                name
            );
        }
    }

    #[test]
    fn test_specific_capability_presence() {
        let registry = register_builtin_capabilities();

        assert!(
            registry.get("shell.exec.v1").is_some(),
            "Should be able to retrieve shell.exec.v1 capability"
        );

        // Test that removed capabilities return None
        assert!(registry.get("fs.read.v1").is_none());
        assert!(registry.get("http.fetch.v1").is_none());
        assert!(registry.get("sqlite.query.v1").is_none());
    }
}
