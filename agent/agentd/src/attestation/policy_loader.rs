//! Policy Loader Module
//!
//! Handles loading capability bundles, signatures, and provenance from various locations.

use anyhow::Result;
use smith_attestation::{Signature, SlsaProvenance};
use std::path::{Path, PathBuf};
use tracing::debug;

/// Policy loader for attestation files
pub struct PolicyLoader {
    signature_search_paths: Vec<PathBuf>,
    provenance_search_paths: Vec<PathBuf>,
}

impl PolicyLoader {
    /// Create new policy loader with default search paths
    pub fn new() -> Self {
        Self {
            signature_search_paths: vec![
                PathBuf::from("build/attestation/policy_signature.json"),
                PathBuf::from("policy_signature.json"),
                PathBuf::from(".attestation/policy_signature.json"),
            ],
            provenance_search_paths: vec![
                PathBuf::from("build/attestation/build-provenance.json"),
                PathBuf::from("build-provenance.json"),
                PathBuf::from(".attestation/build-provenance.json"),
            ],
        }
    }

    /// Create policy loader with custom search paths
    pub fn with_custom_paths(
        signature_paths: Vec<PathBuf>,
        provenance_paths: Vec<PathBuf>,
    ) -> Self {
        Self {
            signature_search_paths: signature_paths,
            provenance_search_paths: provenance_paths,
        }
    }

    /// Load capability bundle from path
    pub async fn load_capability_bundle(&self, path: &Path) -> Result<Vec<u8>> {
        if !path.exists() {
            return Err(anyhow::anyhow!(
                "Capability bundle does not exist: {}",
                path.display()
            ));
        }

        let bundle_bytes = tokio::fs::read(path).await?;
        debug!("Loaded capability bundle from: {}", path.display());
        Ok(bundle_bytes)
    }

    /// Load policy signature from search paths
    pub async fn load_policy_signature(&self) -> Result<Signature> {
        for path in &self.signature_search_paths {
            match self.try_load_signature(path).await {
                Ok(signature) => {
                    debug!("Loaded policy signature from: {}", path.display());
                    return Ok(signature);
                }
                Err(_) => continue,
            }
        }

        Err(anyhow::anyhow!("Policy signature not found in any search path"))
    }

    /// Load policy provenance from search paths
    pub async fn load_policy_provenance(&self) -> Result<SlsaProvenance> {
        for path in &self.provenance_search_paths {
            match self.try_load_provenance(path).await {
                Ok(provenance) => {
                    debug!("Loaded policy provenance from: {}", path.display());
                    return Ok(provenance);
                }
                Err(_) => continue,
            }
        }

        Err(anyhow::anyhow!("Policy provenance not found in any search path"))
    }

    /// Try to load signature from a specific path
    async fn try_load_signature(&self, path: &Path) -> Result<Signature> {
        let signature_bytes = tokio::fs::read(path).await?;
        let signature: Signature = serde_json::from_slice(&signature_bytes)?;
        Ok(signature)
    }

    /// Try to load provenance from a specific path
    async fn try_load_provenance(&self, path: &Path) -> Result<SlsaProvenance> {
        let provenance_bytes = tokio::fs::read(path).await?;
        let provenance: SlsaProvenance = serde_json::from_slice(&provenance_bytes)?;
        Ok(provenance)
    }

    /// Check if capability bundle exists and is readable
    pub fn validate_capability_bundle_path(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(anyhow::anyhow!(
                "Capability bundle does not exist: {}",
                path.display()
            ));
        }

        if !path.is_file() {
            return Err(anyhow::anyhow!(
                "Capability bundle path is not a file: {}",
                path.display()
            ));
        }

        // Check if file is readable (basic permission check)
        match std::fs::metadata(path) {
            Ok(metadata) => {
                if metadata.len() == 0 {
                    return Err(anyhow::anyhow!(
                        "Capability bundle is empty: {}",
                        path.display()
                    ));
                }
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Cannot read capability bundle metadata: {}: {}",
                    path.display(),
                    e
                ));
            }
        }

        Ok(())
    }

    /// Get signature search paths
    pub fn get_signature_search_paths(&self) -> &[PathBuf] {
        &self.signature_search_paths
    }

    /// Get provenance search paths
    pub fn get_provenance_search_paths(&self) -> &[PathBuf] {
        &self.provenance_search_paths
    }
}

impl Default for PolicyLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, NamedTempFile};
    use std::io::Write;

    #[test]
    fn test_policy_loader_creation() {
        let loader = PolicyLoader::new();
        
        assert!(!loader.signature_search_paths.is_empty());
        assert!(!loader.provenance_search_paths.is_empty());
        
        // Check default paths are present
        assert!(loader.signature_search_paths.iter()
            .any(|p| p.to_string_lossy().contains("policy_signature.json")));
        assert!(loader.provenance_search_paths.iter()
            .any(|p| p.to_string_lossy().contains("build-provenance.json")));
    }

    #[test]
    fn test_policy_loader_with_custom_paths() {
        let custom_sig_paths = vec![PathBuf::from("/custom/signature.json")];
        let custom_prov_paths = vec![PathBuf::from("/custom/provenance.json")];

        let loader = PolicyLoader::with_custom_paths(
            custom_sig_paths.clone(),
            custom_prov_paths.clone(),
        );

        assert_eq!(loader.get_signature_search_paths(), &custom_sig_paths);
        assert_eq!(loader.get_provenance_search_paths(), &custom_prov_paths);
    }

    #[tokio::test]
    async fn test_load_capability_bundle_success() {
        let temp_dir = tempdir().unwrap();
        let bundle_path = temp_dir.path().join("capability_bundle.json");
        
        let test_content = b"{\"policies\": []}";
        tokio::fs::write(&bundle_path, test_content).await.unwrap();

        let loader = PolicyLoader::new();
        let result = loader.load_capability_bundle(&bundle_path).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_content);
    }

    #[tokio::test]
    async fn test_load_capability_bundle_not_found() {
        let loader = PolicyLoader::new();
        let non_existent_path = PathBuf::from("/non/existent/path.json");
        
        let result = loader.load_capability_bundle(&non_existent_path).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[test]
    fn test_validate_capability_bundle_path_success() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "{{\"test\": \"content\"}}").unwrap();

        let loader = PolicyLoader::new();
        let result = loader.validate_capability_bundle_path(temp_file.path());
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_capability_bundle_path_not_found() {
        let loader = PolicyLoader::new();
        let non_existent_path = PathBuf::from("/non/existent/path.json");
        
        let result = loader.validate_capability_bundle_path(&non_existent_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[test]
    fn test_validate_capability_bundle_path_empty_file() {
        let temp_file = NamedTempFile::new().unwrap();
        // Don't write anything, file remains empty

        let loader = PolicyLoader::new();
        let result = loader.validate_capability_bundle_path(temp_file.path());
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("is empty"));
    }

    #[test]
    fn test_validate_capability_bundle_path_directory() {
        let temp_dir = tempdir().unwrap();
        
        let loader = PolicyLoader::new();
        let result = loader.validate_capability_bundle_path(temp_dir.path());
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a file"));
    }

    #[tokio::test]
    async fn test_load_policy_signature_not_found() {
        // Create loader with non-existent paths
        let custom_paths = vec![PathBuf::from("/non/existent/signature.json")];
        let loader = PolicyLoader::with_custom_paths(custom_paths, vec![]);
        
        let result = loader.load_policy_signature().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found in any search path"));
    }

    #[tokio::test]
    async fn test_load_policy_provenance_not_found() {
        // Create loader with non-existent paths
        let custom_paths = vec![PathBuf::from("/non/existent/provenance.json")];
        let loader = PolicyLoader::with_custom_paths(vec![], custom_paths);
        
        let result = loader.load_policy_provenance().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found in any search path"));
    }
}