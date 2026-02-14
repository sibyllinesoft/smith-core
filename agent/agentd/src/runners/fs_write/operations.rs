//! File Operations Module
//!
//! Handles actual file writing operations with different modes and permission management.

use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::fs::{create_dir_all, File};
use tokio::io::AsyncWriteExt;
use tracing::info;

/// File writer with mode and permission handling
pub struct FileWriter;

impl FileWriter {
    /// Parse Unix permissions from string (e.g., "644", "755")
    pub fn parse_permissions(perm_str: &str) -> Result<u32> {
        u32::from_str_radix(perm_str, 8)
            .context("Invalid permissions format - must be octal (e.g., '644', '755')")
    }

    /// Write content to file with specified mode and permissions
    pub async fn write_file(
        path: &Path,
        content: &[u8],
        mode: &str,
        permissions: u32,
    ) -> Result<()> {
        Self::ensure_parent_directory(path).await?;

        let mut file = Self::open_file_with_mode(path, mode).await?;
        Self::write_and_sync_content(&mut file, content, path).await?;
        Self::set_file_permissions(&file, path, permissions).await?;

        info!(
            "Successfully wrote {} bytes to {} with mode '{}' and permissions '{:o}'",
            content.len(),
            path.display(),
            mode,
            permissions
        );

        Ok(())
    }

    /// Ensure parent directory exists
    async fn ensure_parent_directory(path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            create_dir_all(parent).await.with_context(|| {
                format!("Failed to create parent directory: {}", parent.display())
            })?;
        }
        Ok(())
    }

    /// Open file with specified mode
    async fn open_file_with_mode(path: &Path, mode: &str) -> Result<File> {
        let file = match mode {
            "create" => {
                // Create new file, fail if exists
                File::create_new(path).await.with_context(|| {
                    format!(
                        "Failed to create new file (file may already exist): {}",
                        path.display()
                    )
                })?
            }
            "write" => {
                // Create or overwrite file
                File::create(path).await.with_context(|| {
                    format!("Failed to create/overwrite file: {}", path.display())
                })?
            }
            "append" => {
                // Open for append, create if doesn't exist
                tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .await
                    .with_context(|| {
                        format!("Failed to open file for append: {}", path.display())
                    })?
            }
            _ => return Err(anyhow::anyhow!("Invalid write mode: {}", mode)),
        };

        Ok(file)
    }

    /// Write content and sync to disk
    async fn write_and_sync_content(file: &mut File, content: &[u8], path: &Path) -> Result<()> {
        file.write_all(content)
            .await
            .with_context(|| format!("Failed to write content to file: {}", path.display()))?;

        file.sync_all()
            .await
            .with_context(|| format!("Failed to sync file: {}", path.display()))?;

        Ok(())
    }

    /// Set file permissions (Unix-like systems only)
    async fn set_file_permissions(file: &File, path: &Path, permissions: u32) -> Result<()> {
        #[cfg(unix)]
        {
            let metadata = file
                .metadata()
                .await
                .with_context(|| format!("Failed to get file metadata: {}", path.display()))?;
            let mut current_permissions = metadata.permissions();
            current_permissions.set_mode(permissions);
            std::fs::set_permissions(path, current_permissions)
                .with_context(|| format!("Failed to set file permissions: {}", path.display()))?;
        }

        #[cfg(not(unix))]
        {
            // On non-Unix systems, log that permissions are not set
            tracing::warn!("File permissions not supported on this platform");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs;

    #[test]
    fn test_parse_permissions() {
        assert_eq!(FileWriter::parse_permissions("644").unwrap(), 0o644);
        assert_eq!(FileWriter::parse_permissions("755").unwrap(), 0o755);
        assert_eq!(FileWriter::parse_permissions("600").unwrap(), 0o600);

        // Invalid permissions
        assert!(FileWriter::parse_permissions("888").is_err());
        assert!(FileWriter::parse_permissions("abc").is_err());
        assert!(FileWriter::parse_permissions("").is_err());
    }

    #[tokio::test]
    async fn test_write_file_create_mode() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_create.txt");
        let content = b"Hello, create mode!";

        let result = FileWriter::write_file(&file_path, content, "create", 0o644).await;
        assert!(result.is_ok());

        // Verify file exists and has correct content
        assert!(file_path.exists());
        let read_content = fs::read(&file_path).await.unwrap();
        assert_eq!(read_content, content);

        // Try to create again - should fail
        let result = FileWriter::write_file(&file_path, content, "create", 0o644).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("may already exist"));
    }

    #[tokio::test]
    async fn test_write_file_write_mode() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_write.txt");
        let content1 = b"First content";
        let content2 = b"Second content";

        // First write
        let result = FileWriter::write_file(&file_path, content1, "write", 0o644).await;
        assert!(result.is_ok());

        let read_content = fs::read(&file_path).await.unwrap();
        assert_eq!(read_content, content1);

        // Second write (should overwrite)
        let result = FileWriter::write_file(&file_path, content2, "write", 0o644).await;
        assert!(result.is_ok());

        let read_content = fs::read(&file_path).await.unwrap();
        assert_eq!(read_content, content2);
    }

    #[tokio::test]
    async fn test_write_file_append_mode() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_append.txt");
        let content1 = b"First line\n";
        let content2 = b"Second line\n";

        // First write
        let result = FileWriter::write_file(&file_path, content1, "append", 0o644).await;
        assert!(result.is_ok());

        // Second write (should append)
        let result = FileWriter::write_file(&file_path, content2, "append", 0o644).await;
        assert!(result.is_ok());

        // Verify both contents are present
        let read_content = fs::read(&file_path).await.unwrap();
        let expected_content = [&content1[..], &content2[..]].concat();
        assert_eq!(read_content, expected_content);
    }

    #[tokio::test]
    async fn test_invalid_write_mode() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_invalid.txt");
        let content = b"test content";

        let result = FileWriter::write_file(&file_path, content, "invalid_mode", 0o644).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid write mode"));
    }

    #[tokio::test]
    async fn test_ensure_parent_directory() {
        let temp_dir = tempdir().unwrap();
        let nested_path = temp_dir.path().join("nested").join("deep").join("test.txt");

        // Parent directories don't exist yet
        assert!(!nested_path.parent().unwrap().exists());

        let result = FileWriter::write_file(&nested_path, b"test", "create", 0o644).await;
        assert!(result.is_ok());

        // Verify parent directories were created
        assert!(nested_path.parent().unwrap().exists());
        assert!(nested_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_perms.txt");
        let content = b"permission test";

        let result = FileWriter::write_file(&file_path, content, "create", 0o755).await;
        assert!(result.is_ok());

        // Check file permissions
        let metadata = fs::metadata(&file_path).await.unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o755);
    }
}
