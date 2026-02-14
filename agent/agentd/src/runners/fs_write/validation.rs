//! Content and Filename Validation Module
//!
//! Handles content parsing, filename validation, and security checks for fs.write operations.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::Value;
use std::path::Path;

/// Content validator for fs.write operations
pub struct ContentValidator;

impl ContentValidator {
    /// Parse content from JSON (string or base64-encoded object)
    pub fn parse_content(content_value: &Value) -> Result<Vec<u8>> {
        match content_value {
            Value::String(s) => Ok(s.as_bytes().to_vec()),
            Value::Object(obj) => Self::parse_encoded_content(obj),
            _ => Err(anyhow::anyhow!(
                "Content must be a string or base64-encoded object"
            )),
        }
    }

    /// Parse encoded content from object format
    fn parse_encoded_content(obj: &serde_json::Map<String, Value>) -> Result<Vec<u8>> {
        let data = obj
            .get("data")
            .ok_or_else(|| anyhow::anyhow!("Object content must have 'data' field"))?;

        let encoding = obj
            .get("encoding")
            .ok_or_else(|| anyhow::anyhow!("Object content must have 'encoding' field"))?;

        match encoding.as_str() {
            Some("base64") => {
                let data_str = data
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Base64 data must be a string"))?;

                BASE64
                    .decode(data_str.as_bytes())
                    .context("Failed to decode base64 content")
            }
            Some(enc) => Err(anyhow::anyhow!("Unsupported encoding: {}", enc)),
            None => Err(anyhow::anyhow!("Encoding must be a string")),
        }
    }

    /// Check if filename is safe (no path traversal, reserved names, etc.)
    pub fn validate_filename(filename: &str) -> Result<()> {
        Self::check_path_traversal(filename)?;
        Self::check_reserved_names(filename)?;
        Self::check_filename_length(filename)?;
        Self::check_unsafe_characters(filename)?;

        Ok(())
    }

    /// Check for path traversal attempts
    fn check_path_traversal(filename: &str) -> Result<()> {
        if filename.contains("..") || filename.contains("/") || filename.contains("\\") {
            return Err(anyhow::anyhow!(
                "Filename cannot contain path separators or '..'"
            ));
        }
        Ok(())
    }

    /// Check for reserved names (Windows compatibility)
    fn check_reserved_names(filename: &str) -> Result<()> {
        let reserved_names = [
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];

        let name_upper = filename.to_uppercase();
        for reserved in &reserved_names {
            if name_upper == *reserved || name_upper.starts_with(&format!("{}.", reserved)) {
                return Err(anyhow::anyhow!("Filename '{}' is reserved", filename));
            }
        }

        Ok(())
    }

    /// Check filename length
    fn check_filename_length(filename: &str) -> Result<()> {
        if filename.len() > 255 {
            return Err(anyhow::anyhow!("Filename too long (max 255 characters)"));
        }
        Ok(())
    }

    /// Check for unsafe characters
    fn check_unsafe_characters(filename: &str) -> Result<()> {
        if !filename
            .chars()
            .all(|c| c.is_alphanumeric() || "._-".contains(c))
        {
            return Err(anyhow::anyhow!("Filename contains unsafe characters"));
        }
        Ok(())
    }

    /// Validate parameter structure and content size
    pub fn validate_params(params: &Value) -> Result<()> {
        Self::validate_path_parameter(params)?;
        Self::validate_content_parameter(params)?;
        Self::validate_mode_parameter(params)?;
        Self::validate_permissions_parameter(params)?;

        Ok(())
    }

    /// Validate path parameter
    fn validate_path_parameter(params: &Value) -> Result<()> {
        let path_val = params
            .get("path")
            .ok_or_else(|| anyhow::anyhow!("path parameter is required"))?;

        if !path_val.is_string() {
            return Err(anyhow::anyhow!("path must be a string"));
        }

        let path_str = path_val.as_str().unwrap();
        if path_str.is_empty() {
            return Err(anyhow::anyhow!("path cannot be empty"));
        }

        // Validate filename if it's a relative path
        let path = Path::new(path_str);
        if let Some(filename) = path.file_name() {
            if let Some(filename_str) = filename.to_str() {
                Self::validate_filename(filename_str)?;
            }
        }

        Ok(())
    }

    /// Validate content parameter
    fn validate_content_parameter(params: &Value) -> Result<()> {
        let content_val = params
            .get("content")
            .ok_or_else(|| anyhow::anyhow!("content parameter is required"))?;

        // Validate content can be parsed
        let content = Self::parse_content(content_val)?;
        if content.len() > 1_048_576 {
            return Err(anyhow::anyhow!("Content size exceeds 1MB limit"));
        }

        Ok(())
    }

    /// Validate mode parameter
    fn validate_mode_parameter(params: &Value) -> Result<()> {
        if let Some(mode) = params.get("mode") {
            if let Some(mode_str) = mode.as_str() {
                if !["create", "write", "append"].contains(&mode_str) {
                    return Err(anyhow::anyhow!(
                        "mode must be 'create', 'write', or 'append'"
                    ));
                }
            } else {
                return Err(anyhow::anyhow!("mode must be a string"));
            }
        }
        Ok(())
    }

    /// Validate permissions parameter
    fn validate_permissions_parameter(params: &Value) -> Result<()> {
        if let Some(permissions) = params.get("permissions") {
            if let Some(perm_str) = permissions.as_str() {
                // Validate permissions format
                u32::from_str_radix(perm_str, 8)
                    .context("Invalid permissions format - must be octal (e.g., '644', '755')")?;
            } else {
                return Err(anyhow::anyhow!("permissions must be a string"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_content_string() {
        let string_content = json!("Hello, World!");
        let parsed = ContentValidator::parse_content(&string_content).unwrap();
        assert_eq!(parsed, b"Hello, World!");
    }

    #[test]
    fn test_parse_content_base64() {
        let base64_content = json!({
            "data": "SGVsbG8sIFdvcmxkIQ==", // "Hello, World!" in base64
            "encoding": "base64"
        });
        let parsed = ContentValidator::parse_content(&base64_content).unwrap();
        assert_eq!(parsed, b"Hello, World!");
    }

    #[test]
    fn test_parse_content_invalid() {
        // Invalid type
        let invalid_content = json!(123);
        assert!(ContentValidator::parse_content(&invalid_content).is_err());

        // Missing encoding
        let incomplete_content = json!({"data": "test"});
        assert!(ContentValidator::parse_content(&incomplete_content).is_err());

        // Invalid encoding
        let invalid_encoding = json!({
            "data": "test",
            "encoding": "invalid"
        });
        assert!(ContentValidator::parse_content(&invalid_encoding).is_err());

        // Invalid base64
        let invalid_base64 = json!({
            "data": "invalid-base64!@#",
            "encoding": "base64"
        });
        assert!(ContentValidator::parse_content(&invalid_base64).is_err());
    }

    #[test]
    fn test_validate_filename_valid() {
        assert!(ContentValidator::validate_filename("test.txt").is_ok());
        assert!(ContentValidator::validate_filename("my_file-1.json").is_ok());
        assert!(ContentValidator::validate_filename("file.tar.gz").is_ok());
        assert!(ContentValidator::validate_filename("123").is_ok());
    }

    #[test]
    fn test_validate_filename_path_traversal() {
        assert!(ContentValidator::validate_filename("../test.txt").is_err());
        assert!(ContentValidator::validate_filename("test/file.txt").is_err());
        assert!(ContentValidator::validate_filename("test\\file.txt").is_err());
        assert!(ContentValidator::validate_filename("dir/../file.txt").is_err());
    }

    #[test]
    fn test_validate_filename_reserved_names() {
        assert!(ContentValidator::validate_filename("CON").is_err());
        assert!(ContentValidator::validate_filename("con").is_err());
        assert!(ContentValidator::validate_filename("CON.txt").is_err());
        assert!(ContentValidator::validate_filename("PRN.log").is_err());
        assert!(ContentValidator::validate_filename("COM1").is_err());
        assert!(ContentValidator::validate_filename("LPT1.dat").is_err());

        // These should be OK (not exact matches)
        assert!(ContentValidator::validate_filename("console.log").is_ok());
        assert!(ContentValidator::validate_filename("printer.txt").is_ok());
    }

    #[test]
    fn test_validate_filename_length() {
        // Valid length
        let valid_name = "a".repeat(255);
        assert!(ContentValidator::validate_filename(&valid_name).is_ok());

        // Too long
        let too_long = "a".repeat(256);
        assert!(ContentValidator::validate_filename(&too_long).is_err());
    }

    #[test]
    fn test_validate_filename_unsafe_characters() {
        assert!(ContentValidator::validate_filename("test<>.txt").is_err());
        assert!(ContentValidator::validate_filename("file|name.txt").is_err());
        assert!(ContentValidator::validate_filename("test?.txt").is_err());
        assert!(ContentValidator::validate_filename("file*name.txt").is_err());
        assert!(ContentValidator::validate_filename("test:file.txt").is_err());
    }

    #[test]
    fn test_validate_params_valid() {
        let valid_params = json!({
            "path": "test.txt",
            "content": "Hello, World!",
            "mode": "create",
            "permissions": "644"
        });
        assert!(ContentValidator::validate_params(&valid_params).is_ok());
    }

    #[test]
    fn test_validate_params_missing_required() {
        // Missing path
        let missing_path = json!({
            "content": "Hello",
            "mode": "create"
        });
        assert!(ContentValidator::validate_params(&missing_path).is_err());

        // Missing content
        let missing_content = json!({
            "path": "test.txt",
            "mode": "create"
        });
        assert!(ContentValidator::validate_params(&missing_content).is_err());
    }

    #[test]
    fn test_validate_params_invalid_values() {
        // Invalid mode
        let invalid_mode = json!({
            "path": "test.txt",
            "content": "Hello",
            "mode": "invalid"
        });
        assert!(ContentValidator::validate_params(&invalid_mode).is_err());

        // Invalid permissions
        let invalid_permissions = json!({
            "path": "test.txt",
            "content": "Hello",
            "permissions": "888"
        });
        assert!(ContentValidator::validate_params(&invalid_permissions).is_err());

        // Content too large
        let large_content = json!({
            "path": "test.txt",
            "content": "x".repeat(2_000_000),
            "mode": "create"
        });
        assert!(ContentValidator::validate_params(&large_content).is_err());
    }

    #[test]
    fn test_validate_params_optional_fields() {
        // Only required fields
        let minimal_params = json!({
            "path": "test.txt",
            "content": "Hello"
        });
        assert!(ContentValidator::validate_params(&minimal_params).is_ok());

        // With optional mode
        let with_mode = json!({
            "path": "test.txt",
            "content": "Hello",
            "mode": "write"
        });
        assert!(ContentValidator::validate_params(&with_mode).is_ok());

        // With optional permissions
        let with_permissions = json!({
            "path": "test.txt",
            "content": "Hello",
            "permissions": "755"
        });
        assert!(ContentValidator::validate_params(&with_permissions).is_ok());
    }
}
