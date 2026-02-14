//! Git Clone Validation Module
//!
//! Contains all validation logic for git clone operations including URL validation,
//! path security checks, and branch name validation.

use anyhow::{Context, Result};
use regex::Regex;
use std::path::{Path, PathBuf};
use tracing::debug;
use url::Url;

/// Git repository validation utilities
pub struct GitValidator {
    allowed_hosts: Vec<String>,
}

impl GitValidator {
    /// Create new validator with allowed hosts
    pub fn new(allowed_hosts: Vec<String>) -> Self {
        Self { allowed_hosts }
    }

    /// Validate repository URL is from an allowed host and uses safe protocol
    pub fn validate_repository_url(&self, repo_url: &str) -> Result<()> {
        let url = Url::parse(repo_url).context("Failed to parse repository URL")?;

        self.validate_protocol(&url)?;
        self.validate_host(&url)?;
        self.validate_path(&url, repo_url)?;

        debug!("Validated repository URL: {}", repo_url);
        Ok(())
    }

    /// Validate destination path is within allowed scope and follows ACTOR isolation
    pub fn validate_destination_path(
        &self,
        path: &Path,
        scope_paths: &[String],
        actor: &str,
    ) -> Result<PathBuf> {
        let abs_path = self.resolve_absolute_path(path, actor)?;
        self.validate_scope_permissions(&abs_path, scope_paths)?;
        self.validate_actor_isolation(&abs_path, actor)?;
        self.validate_path_safety(&abs_path)?;

        debug!(
            "Validated destination path: {} for actor: {}",
            abs_path.display(),
            actor
        );
        Ok(abs_path)
    }

    /// Validate branch or tag name for safety
    pub fn validate_branch_name(&self, branch: &str) -> Result<()> {
        if branch.is_empty() {
            return Err(anyhow::anyhow!("Branch name cannot be empty"));
        }

        // Check for command injection and unsafe characters
        let unsafe_chars = Regex::new(r"[;&|`$()]").unwrap();
        if unsafe_chars.is_match(branch) {
            return Err(anyhow::anyhow!(
                "Branch name '{}' contains unsafe characters",
                branch
            ));
        }

        // Additional Git-specific validations
        if branch.starts_with('-') || branch.contains("..") || branch.contains("//") {
            return Err(anyhow::anyhow!(
                "Branch name '{}' violates Git naming rules",
                branch
            ));
        }

        Ok(())
    }

    /// Validate protocol is allowed
    fn validate_protocol(&self, url: &Url) -> Result<()> {
        match url.scheme() {
            "https" | "git" => {
                // Allow standard protocols
                Ok(())
            }
            "ssh" => {
                // SSH is allowed but should use git@ user
                if url.username() != "git" {
                    Err(anyhow::anyhow!("SSH URLs must use 'git' user"))
                } else {
                    Ok(())
                }
            }
            _ => Err(anyhow::anyhow!("Unsupported protocol: {}", url.scheme())),
        }
    }

    /// Validate host is in allowlist
    fn validate_host(&self, url: &Url) -> Result<()> {
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("Repository URL must have a valid host"))?;

        if !self.allowed_hosts.iter().any(|allowed| host == allowed) {
            return Err(anyhow::anyhow!(
                "Host '{}' is not in the allowed hosts list: {:?}",
                host,
                self.allowed_hosts
            ));
        }

        Ok(())
    }

    /// Validate URL path for security issues
    fn validate_path(&self, url: &Url, repo_url: &str) -> Result<()> {
        let path = url.path();
        
        // Check for directory traversal in both normalized and original URL
        let original_path_contains_traversal = repo_url.contains("/..");
        let normalized_path_contains_traversal = path.contains("..");
        
        if original_path_contains_traversal || normalized_path_contains_traversal || path.contains("//") {
            return Err(anyhow::anyhow!(
                "Repository URL path contains unsafe characters"
            ));
        }

        Ok(())
    }

    /// Resolve relative path to absolute path within actor's namespace
    fn resolve_absolute_path(&self, path: &Path, actor: &str) -> Result<PathBuf> {
        let abs_path = if path.is_relative() {
            let actor_base = PathBuf::from("/tmp/smith").join(actor);
            actor_base.join(path)
        } else {
            path.to_path_buf()
        };

        Ok(abs_path)
    }

    /// Validate path is within allowed scope
    fn validate_scope_permissions(&self, abs_path: &Path, scope_paths: &[String]) -> Result<()> {
        let mut allowed = false;
        for allowed_prefix in scope_paths {
            let allowed_path = PathBuf::from(allowed_prefix);
            if abs_path.starts_with(&allowed_path) {
                allowed = true;
                break;
            }
        }

        if !allowed {
            return Err(anyhow::anyhow!(
                "Destination path {} is not within any allowed scope prefix",
                abs_path.display()
            ));
        }

        Ok(())
    }

    /// Validate actor isolation constraints
    fn validate_actor_isolation(&self, abs_path: &Path, actor: &str) -> Result<()> {
        // Enforce ACTOR isolation: path must be within /tmp/smith/{actor}/
        let expected_actor_prefix = PathBuf::from("/tmp/smith").join(actor);
        if !abs_path.starts_with(&expected_actor_prefix) {
            return Err(anyhow::anyhow!(
                "Destination path {} violates actor isolation - must be within {}",
                abs_path.display(),
                expected_actor_prefix.display()
            ));
        }

        Ok(())
    }

    /// Validate path safety (no traversal attacks)
    fn validate_path_safety(&self, abs_path: &Path) -> Result<()> {
        let path_str = abs_path.to_string_lossy();
        if path_str.contains("..") || path_str.contains("//") {
            return Err(anyhow::anyhow!("Destination path contains unsafe elements"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_validator() -> GitValidator {
        GitValidator::new(vec![
            "github.com".to_string(),
            "gitlab.com".to_string(),
        ])
    }

    #[test]
    fn test_validate_repository_url_https() {
        let validator = create_test_validator();
        assert!(validator.validate_repository_url("https://github.com/user/repo.git").is_ok());
    }

    #[test]
    fn test_validate_repository_url_ssh() {
        let validator = create_test_validator();
        assert!(validator.validate_repository_url("ssh://git@github.com/user/repo.git").is_ok());
    }

    #[test]
    fn test_validate_repository_url_unsafe_protocol() {
        let validator = create_test_validator();
        assert!(validator.validate_repository_url("ftp://github.com/user/repo.git").is_err());
    }

    #[test]
    fn test_validate_repository_url_unauthorized_host() {
        let validator = create_test_validator();
        assert!(validator.validate_repository_url("https://evil.com/user/repo.git").is_err());
    }

    #[test]
    fn test_validate_branch_name_valid() {
        let validator = create_test_validator();
        assert!(validator.validate_branch_name("main").is_ok());
        assert!(validator.validate_branch_name("feature/new-feature").is_ok());
    }

    #[test]
    fn test_validate_branch_name_unsafe() {
        let validator = create_test_validator();
        assert!(validator.validate_branch_name("branch; rm -rf /").is_err());
        assert!(validator.validate_branch_name("branch$(evil)").is_err());
        assert!(validator.validate_branch_name("../evil").is_err());
    }
}