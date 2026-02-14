//! Path Permission and Validation Module
//!
//! Handles path validation, actor isolation, and scope checking for fs.write operations.

use anyhow::Result;
use std::path::{Path, PathBuf};
use tracing::debug;

/// Path validator for fs.write operations with actor isolation
pub struct PathValidator {
    smith_root: PathBuf,
}

impl PathValidator {
    /// Create new path validator
    pub fn new() -> Self {
        Self {
            smith_root: PathBuf::from("/tmp/smith"),
        }
    }

    /// Create path validator with custom smith root
    pub fn with_smith_root(smith_root: PathBuf) -> Self {
        Self { smith_root }
    }

    /// Validate write path is within allowed scope and follows ACTOR isolation
    pub fn validate_write_path(
        &self,
        path: &Path,
        scope_paths: &[String],
        actor: &str,
    ) -> Result<PathBuf> {
        let abs_path = self.resolve_absolute_path(path, actor)?;
        let canonical_path = self.canonicalize_path(&abs_path)?;

        self.validate_scope_permission(&canonical_path, scope_paths)?;
        self.validate_actor_isolation(&canonical_path, actor)?;

        debug!(
            "Validated write path: {} for actor: {}",
            canonical_path.display(),
            actor
        );
        Ok(canonical_path)
    }

    /// Resolve relative paths to absolute paths within actor namespace
    fn resolve_absolute_path(&self, path: &Path, actor: &str) -> Result<PathBuf> {
        let abs_path = if path.is_relative() {
            // For relative paths, construct within the actor's namespace
            let actor_base = self.smith_root.join(actor);
            actor_base.join(path)
        } else {
            path.to_path_buf()
        };

        Ok(abs_path)
    }

    /// Canonicalize path to prevent path traversal attacks
    fn canonicalize_path(&self, path: &Path) -> Result<PathBuf> {
        // Try to canonicalize, fallback to parent canonicalization if path doesn't exist
        let canonical_path = path.canonicalize().unwrap_or_else(|_| {
            // If canonicalization fails (e.g., path doesn't exist), validate the parent
            if let Some(parent) = path.parent() {
                if let Ok(canonical_parent) = parent.canonicalize() {
                    canonical_parent.join(path.file_name().unwrap_or_default())
                } else {
                    path.to_path_buf()
                }
            } else {
                path.to_path_buf()
            }
        });

        Ok(canonical_path)
    }

    /// Check path against allowed scope paths
    fn validate_scope_permission(
        &self,
        canonical_path: &Path,
        scope_paths: &[String],
    ) -> Result<()> {
        let mut allowed = false;
        for allowed_prefix in scope_paths {
            let allowed_path = PathBuf::from(allowed_prefix);
            if canonical_path.starts_with(&allowed_path) {
                allowed = true;
                break;
            }
        }

        if !allowed {
            return Err(anyhow::anyhow!(
                "Path {} is not within any allowed scope prefix",
                canonical_path.display()
            ));
        }

        Ok(())
    }

    /// Enforce ACTOR isolation: path must be within /tmp/smith/{actor}/
    fn validate_actor_isolation(&self, canonical_path: &Path, actor: &str) -> Result<()> {
        let expected_actor_prefix = self.smith_root.join(actor);
        if !canonical_path.starts_with(&expected_actor_prefix) {
            return Err(anyhow::anyhow!(
                "Path {} violates actor isolation - must be within {}",
                canonical_path.display(),
                expected_actor_prefix.display()
            ));
        }

        Ok(())
    }
}

impl Default for PathValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_path_validator_creation() {
        let validator = PathValidator::new();
        assert_eq!(validator.smith_root, PathBuf::from("/tmp/smith"));

        let custom_root = PathBuf::from("/custom/root");
        let custom_validator = PathValidator::with_smith_root(custom_root.clone());
        assert_eq!(custom_validator.smith_root, custom_root);
    }

    #[test]
    fn test_resolve_absolute_path() {
        let validator = PathValidator::new();

        // Relative path resolution
        let relative_path = Path::new("test.txt");
        let resolved = validator
            .resolve_absolute_path(relative_path, "test-actor")
            .unwrap();
        assert_eq!(resolved, PathBuf::from("/tmp/smith/test-actor/test.txt"));

        // Absolute path passthrough
        let absolute_path = Path::new("/tmp/smith/actor/file.txt");
        let resolved = validator
            .resolve_absolute_path(absolute_path, "actor")
            .unwrap();
        assert_eq!(resolved, absolute_path);
    }

    #[test]
    fn test_scope_validation() {
        let validator = PathValidator::new();
        let scope_paths = vec!["/tmp/smith".to_string(), "/opt/allowed".to_string()];

        // Valid path within scope
        let allowed_path = PathBuf::from("/tmp/smith/actor/file.txt");
        assert!(validator
            .validate_scope_permission(&allowed_path, &scope_paths)
            .is_ok());

        // Invalid path outside scope
        let forbidden_path = PathBuf::from("/etc/passwd");
        assert!(validator
            .validate_scope_permission(&forbidden_path, &scope_paths)
            .is_err());
    }

    #[test]
    fn test_actor_isolation() {
        let validator = PathValidator::new();

        // Valid path within actor namespace
        let actor_path = PathBuf::from("/tmp/smith/test-actor/file.txt");
        assert!(validator
            .validate_actor_isolation(&actor_path, "test-actor")
            .is_ok());

        // Invalid path in different actor namespace
        let other_actor_path = PathBuf::from("/tmp/smith/other-actor/file.txt");
        assert!(validator
            .validate_actor_isolation(&other_actor_path, "test-actor")
            .is_err());

        // Invalid path outside smith root
        let outside_path = PathBuf::from("/tmp/other/file.txt");
        assert!(validator
            .validate_actor_isolation(&outside_path, "test-actor")
            .is_err());
    }

    #[test]
    fn test_full_validation_workflow() {
        let _temp_dir = tempdir().unwrap();
        let validator = PathValidator::new();
        let scope_paths = vec!["/tmp/smith".to_string()];

        // Valid relative path
        let relative_path = Path::new("test.txt");
        let result = validator.validate_write_path(relative_path, &scope_paths, "test-actor");
        assert!(result.is_ok());

        // Invalid path violating actor isolation
        let bad_absolute_path = Path::new("/tmp/smith/other-actor/test.txt");
        let result = validator.validate_write_path(bad_absolute_path, &scope_paths, "test-actor");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("violates actor isolation"));
    }
}
