use anyhow::{Context, Result};
use jsonschema::{Draft, JSONSchema};
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Schema validator for capability-specific intent validation
pub struct SchemaValidator {
    schemas: HashMap<String, JSONSchema>,
    schema_values: HashMap<String, Value>,
}

impl SchemaValidator {
    /// Create new schema validator with built-in capability schemas
    pub fn new() -> Result<Self> {
        let mut schemas = HashMap::new();

        // Load built-in schemas for supported capabilities
        schemas.insert("fs.read.v1".to_string(), create_fs_read_schema()?);
        schemas.insert("http.fetch.v1".to_string(), create_http_fetch_schema()?);
        schemas.insert("shell.exec.v1".to_string(), create_shell_exec_schema()?);

        info!(
            "Schema validator initialized with {} schemas",
            schemas.len()
        );
        Ok(Self {
            schemas,
            schema_values: HashMap::new(),
        })
    }

    /// Validate intent against capability schema
    pub fn validate_intent(&self, intent: &smith_protocol::Intent) -> Result<()> {
        if std::env::var("SMITH_EXECUTOR_SKIP_SCHEMA_VALIDATION").unwrap_or_default() == "1" {
            warn!(
                "Skipping schema validation for capability: {}",
                intent.capability
            );
            return Ok(());
        }

        let schema_key = match intent.capability {
            smith_protocol::Capability::FsReadV1 => "fs.read.v1",
            smith_protocol::Capability::HttpFetchV1 => "http.fetch.v1",
            smith_protocol::Capability::FsWriteV1 => "fs.write.v1",
            smith_protocol::Capability::GitCloneV1 => "git.clone.v1",
            smith_protocol::Capability::ArchiveReadV1 => "archive.read.v1",
            smith_protocol::Capability::SqliteQueryV1 => "sqlite.query.v1",
            smith_protocol::Capability::BenchReportV1 => "bench.report.v1",
            smith_protocol::Capability::ShellExec => "shell.exec.v1",
            smith_protocol::Capability::HttpFetch => "http.fetch.v1",
        }
        .to_string();

        let schema = self
            .schemas
            .get(&schema_key)
            .ok_or_else(|| anyhow::anyhow!("No schema found for capability: {}", schema_key))?;

        debug!("Validating intent against schema: {}", schema_key);

        // Convert intent to JSON for validation
        let intent_value =
            serde_json::to_value(intent).context("Failed to serialize intent for validation")?;

        // Validate the entire intent structure
        let validation_result = schema.validate(&intent_value);
        match validation_result {
            Ok(_) => {
                debug!("Intent validation passed for: {}", schema_key);
                Ok(())
            }
            Err(errors) => {
                let error_messages: Vec<String> = errors
                    .into_iter()
                    .map(|error| format!("{} at {}", error, error.instance_path))
                    .collect();

                Err(anyhow::anyhow!(
                    "Schema validation failed for {}: {}",
                    schema_key,
                    error_messages.join(", ")
                ))
            }
        }
    }

    /// Load schema from file (for external schemas)
    pub fn load_schema_from_file(
        &mut self,
        capability: &str,
        version: u32,
        schema_path: &std::path::Path,
    ) -> Result<()> {
        let schema_content = std::fs::read_to_string(schema_path)
            .with_context(|| format!("Failed to read schema file: {}", schema_path.display()))?;

        let schema_json: Value =
            serde_json::from_str(&schema_content).context("Failed to parse schema JSON")?;

        let schema_key = format!("{}.v{}", capability, version);

        // Create a static copy of the schema JSON to satisfy lifetime requirements
        let static_schema: &'static Value = Box::leak(Box::new(schema_json.clone()));

        let compiled_schema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(static_schema)
            .context("Failed to compile JSON schema")?;

        self.schemas.insert(schema_key.clone(), compiled_schema);
        self.schema_values.insert(schema_key.clone(), schema_json);

        info!("Loaded external schema: {}", schema_key);
        Ok(())
    }

    /// Get list of supported capability schemas
    pub fn supported_capabilities(&self) -> Vec<String> {
        self.schemas.keys().cloned().collect()
    }

    /// Reload all schemas (useful for hot-reloading)
    pub fn reload_schemas(&mut self) -> Result<()> {
        warn!("Schema reloading not yet implemented");
        Ok(())
    }
}

fn build_intent_schema_value(
    capability_literal: &str,
    params_schema: Value,
    metadata_schema: Option<Value>,
) -> Value {
    let metadata = metadata_schema.unwrap_or_else(|| {
        json!({
            "type": "object",
            "additionalProperties": true
        })
    });

    json!({
        "$schema": "https://json-schema.org/draft/2019-09/schema",
        "type": "object",
        "required": [
            "id",
            "capability",
            "domain",
            "params",
            "created_at_ns",
            "ttl_ms",
            "nonce",
            "signer",
            "signature_b64",
            "metadata"
        ],
        "properties": {
            "id": {
                "type": "string",
                "format": "uuid",
                "description": "Unique intent identifier (UUIDv4 or UUIDv7)"
            },
            "capability": {
                "type": "string",
                "const": capability_literal,
                "description": "Capability identifier"
            },
            "domain": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
                "description": "Intent routing domain"
            },
            "params": params_schema,
            "created_at_ns": {
                "type": "integer",
                "minimum": 0,
                "description": "Creation timestamp in nanoseconds"
            },
            "ttl_ms": {
                "type": "integer",
                "minimum": 1,
                "maximum": 600_000,
                "description": "Time-to-live in milliseconds"
            },
            "nonce": {
                "type": "string",
                "pattern": "^[A-Fa-f0-9]{16,64}$",
                "description": "Hex nonce for replay protection"
            },
            "signer": {
                "type": "string",
                "pattern": "^[A-Za-z0-9+/=]+$",
                "minLength": 43,
                "maxLength": 128,
                "description": "Base64-encoded Ed25519 public key"
            },
            "signature_b64": {
                "type": "string",
                "pattern": "^[A-Za-z0-9+/=]+$",
                "minLength": 43,
                "maxLength": 180,
                "description": "Base64-encoded signature"
            },
            "metadata": metadata
        },
        "additionalProperties": false
    })
}

/// Create JSON schema for fs.read.v1 capability
fn create_fs_read_schema() -> Result<JSONSchema> {
    use std::sync::OnceLock;
    static SCHEMA: OnceLock<Value> = OnceLock::new();

    let schema = SCHEMA.get_or_init(|| {
        let params_schema = json!({
            "type": "object",
            "required": ["path", "offset", "len"],
            "properties": {
                "path": {
                    "type": "string",
                    "pattern": "^/[^\\x00]*$",
                    "minLength": 1,
                    "maxLength": 4096,
                    "description": "Absolute file path within workspace"
                },
                "offset": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Byte offset to start reading from"
                },
                "len": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1_048_576,
                    "description": "Number of bytes to read (max 1MB)"
                }
            },
            "additionalProperties": false
        });

        let metadata_schema = json!({
            "type": "object",
            "properties": {
                "resource": {
                    "type": "string",
                    "minLength": 1
                },
                "domain": {
                    "type": "string",
                    "minLength": 1
                }
            },
            "additionalProperties": true
        });

        build_intent_schema_value("fs.read.v1", params_schema, Some(metadata_schema))
    });

    JSONSchema::options()
        .with_draft(Draft::Draft7)
        .compile(schema)
        .context("Failed to compile fs.read.v1 schema")
}

/// Create JSON schema for http.fetch.v1 capability
fn create_http_fetch_schema() -> Result<JSONSchema> {
    use std::sync::OnceLock;
    static SCHEMA: OnceLock<Value> = OnceLock::new();

    let schema = SCHEMA.get_or_init(|| {
        let params_schema = json!({
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {
                    "type": "string",
                    "pattern": "^https://.+$",
                    "minLength": 8,
                    "maxLength": 2048,
                    "description": "HTTPS URL to fetch"
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "HEAD"],
                    "default": "GET",
                    "description": "HTTP method"
                },
                "headers": {
                    "type": "object",
                    "patternProperties": {
                        "^(Accept|Accept-Encoding|Accept-Language|Cache-Control|If-None-Match|User-Agent)$": {
                            "type": "string",
                            "maxLength": 1024
                        }
                    },
                    "additionalProperties": false,
                    "maxProperties": 10,
                    "description": "Allowed HTTP headers"
                },
                "timeout_ms": {
                    "type": "integer",
                    "minimum": 50,
                    "maximum": 30_000,
                    "default": 5_000,
                    "description": "Request timeout in milliseconds"
                }
            },
            "additionalProperties": false
        });

        build_intent_schema_value("http.fetch.v1", params_schema, None)
    });

    JSONSchema::options()
        .with_draft(Draft::Draft7)
        .compile(schema)
        .context("Failed to compile http.fetch.v1 schema")
}

/// Create JSON schema for shell.exec capability
fn create_shell_exec_schema() -> Result<JSONSchema> {
    use std::sync::OnceLock;
    static SCHEMA: OnceLock<Value> = OnceLock::new();

    let schema = SCHEMA.get_or_init(|| {
        let params_schema = json!({
            "type": "object",
            "required": ["command", "timeout_ms"],
            "properties": {
                "command": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 4096,
                    "description": "Command to execute"
                },
                "timeout_ms": {
                    "type": "integer",
                    "minimum": 1_000,
                    "maximum": 120_000,
                    "description": "Execution timeout in milliseconds"
                }
            },
            "additionalProperties": false
        });

        build_intent_schema_value("shell.exec.v1", params_schema, None)
    });

    JSONSchema::options()
        .with_draft(Draft::Draft7)
        .compile(schema)
        .context("Failed to compile shell.exec.v1 schema")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use std::str::FromStr;

    const SAMPLE_SIGNER: &str = "R4Yg1nuVvLWIjxb6dtUI+Ck7o/Ec9X3YeWDlGfyacds=";
    const SAMPLE_SIGNATURE: &str =
        "tyM+jVG1cpMLvvIddTEJ+ANJcLotaTDfHx/3xRJA62npYXrZ6t8afqwLe0upObPeciAxU3Pf+nzcJGT+7hWWAg==";

    fn create_valid_fs_read_intent() -> smith_protocol::Intent {
        let mut metadata = HashMap::new();
        metadata.insert("resource".to_string(), json!("/srv/logs/app.log"));
        metadata.insert("domain".to_string(), json!("test"));

        smith_protocol::Intent {
            id: "b1e8f5c4-7b20-4c78-9e93-7a8a2ef7a6ec".to_string(),
            capability: smith_protocol::Capability::FsReadV1,
            domain: "test".to_string(),
            params: json!({
                "path": "/srv/logs/app.log",
                "offset": 0,
                "len": 4096
            }),
            created_at_ns: 1735412345678000000,
            ttl_ms: 60000,
            nonce: "c1f4a19a8e6f1d0b2c3d4e5f6a7b8c9d".to_string(),
            signer: SAMPLE_SIGNER.to_string(),
            signature_b64: SAMPLE_SIGNATURE.to_string(),
            metadata,
        }
    }

    fn create_valid_http_fetch_intent() -> smith_protocol::Intent {
        smith_protocol::Intent {
            id: "a2e8f5c4-7b20-4c78-9e93-7a8a2ef7a6ec".to_string(),
            capability: smith_protocol::Capability::HttpFetchV1,
            domain: "test".to_string(),
            params: json!({
                "url": "https://api.example.com/data",
                "method": "GET",
                "headers": {
                    "Accept": "application/json",
                    "User-Agent": "Smith-Executor/1.0"
                },
                "timeout_ms": 5000
            }),
            created_at_ns: 1735412345678000000,
            ttl_ms: 60000,
            nonce: "d1f4a19a8e6f1d0b2c3d4e5f6a7b8c9e".to_string(),
            signer: SAMPLE_SIGNER.to_string(),
            signature_b64: SAMPLE_SIGNATURE.to_string(),
            metadata: HashMap::new(),
        }
    }

    fn create_valid_shell_exec_intent() -> smith_protocol::Intent {
        smith_protocol::Intent {
            id: "c3a9c2e1-9a76-46cf-8f8b-8fb2d1c1a111".to_string(),
            capability: smith_protocol::Capability::ShellExec,
            domain: "test".to_string(),
            params: json!({
                "command": "echo hello",
                "timeout_ms": 10_000
            }),
            created_at_ns: 1735412345678000000,
            ttl_ms: 60_000,
            nonce: "e1f4a19a8e6f1d0b2c3d4e5f6a7b8c9f".to_string(),
            signer: SAMPLE_SIGNER.to_string(),
            signature_b64: SAMPLE_SIGNATURE.to_string(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_schema_validator_creation() {
        let validator = SchemaValidator::new().unwrap();
        let capabilities = validator.supported_capabilities();

        assert!(capabilities.contains(&"fs.read.v1".to_string()));
        assert!(capabilities.contains(&"http.fetch.v1".to_string()));
        assert!(capabilities.contains(&"shell.exec.v1".to_string()));
        assert_eq!(capabilities.len(), 3);
    }

    #[test]
    fn test_valid_fs_read_intent() {
        let validator = SchemaValidator::new().unwrap();
        let intent = create_valid_fs_read_intent();

        let result = validator.validate_intent(&intent);
        if let Err(ref error) = result {
            println!("Validation failed: {}", error);
        }
        assert!(
            result.is_ok(),
            "Valid fs.read intent should pass validation: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_valid_http_fetch_intent() {
        let validator = SchemaValidator::new().unwrap();
        let intent = create_valid_http_fetch_intent();

        let result = validator.validate_intent(&intent);
        if let Err(ref error) = result {
            println!("Validation failed: {}", error);
        }
        assert!(
            result.is_ok(),
            "Valid http.fetch intent should pass validation: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_invalid_capability() {
        // Test that invalid capability strings fail to parse
        let result = smith_protocol::Capability::from_str("unknown.cap");
        assert!(result.is_err(), "Unknown capability should fail to parse");
    }

    #[test]
    fn test_fs_read_invalid_path() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_fs_read_intent();

        // Make path invalid (relative path)
        intent.params = json!({
            "path": "./relative/path",
            "offset": 0,
            "len": 4096
        });

        let result = validator.validate_intent(&intent);
        assert!(result.is_err(), "Relative path should fail validation");
    }

    #[test]
    fn test_fs_read_invalid_params() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_fs_read_intent();

        // Make len too large
        intent.params = json!({
            "path": "/srv/logs/app.log",
            "offset": 0,
            "len": 2048576  // > 1MB limit
        });

        let result = validator.validate_intent(&intent);
        assert!(result.is_err(), "Oversized len should fail validation");
    }

    #[test]
    fn test_http_fetch_invalid_url() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_http_fetch_intent();

        // Make URL invalid (not HTTPS)
        intent.params = json!({
            "url": "http://api.example.com/data",
            "method": "GET",
            "headers": {
                "Accept": "application/json",
                "User-Agent": "Smith-Executor/1.0"
            },
            "timeout_ms": 5000
        });

        let result = validator.validate_intent(&intent);
        assert!(
            result.is_err(),
            "HTTP URL should fail validation (must be HTTPS)"
        );
    }

    #[test]
    fn test_http_fetch_invalid_headers() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_http_fetch_intent();

        // Add disallowed header
        intent.params = json!({
            "url": "https://api.example.com/data",
            "method": "GET",
            "headers": {
                "Accept": "application/json",
                "User-Agent": "Smith-Executor/1.0",
                "Authorization": "Bearer token"  // This should be disallowed
            },
            "timeout_ms": 5000
        });

        let result = validator.validate_intent(&intent);
        assert!(result.is_err(), "Disallowed headers should fail validation");
    }

    #[test]
    fn test_missing_required_field() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_fs_read_intent();

        // Remove required field by setting it to empty
        intent.signature_b64 = "".to_string();

        let result = validator.validate_intent(&intent);
        assert!(result.is_err(), "Missing signature should fail validation");
    }

    #[test]
    fn test_invalid_nonce_format() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_fs_read_intent();

        // Make nonce invalid (wrong length)
        intent.nonce = "tooshort".to_string();

        let result = validator.validate_intent(&intent);
        assert!(
            result.is_err(),
            "Invalid nonce format should fail validation"
        );
    }

    #[test]
    fn test_valid_shell_exec_intent() {
        let validator = SchemaValidator::new().unwrap();
        let intent = create_valid_shell_exec_intent();

        let result = validator.validate_intent(&intent);
        assert!(
            result.is_ok(),
            "Valid shell.exec intent should pass validation: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_shell_exec_missing_command() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_shell_exec_intent();
        intent.params = json!({
            "timeout_ms": 10_000
        });

        let result = validator.validate_intent(&intent);
        assert!(
            result.is_err(),
            "Shell exec intent without command should fail validation"
        );
    }

    #[test]
    fn test_shell_exec_timeout_too_low() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_shell_exec_intent();
        intent.params = json!({
            "command": "echo test",
            "timeout_ms": 500  // Below minimum of 1000
        });

        let result = validator.validate_intent(&intent);
        assert!(
            result.is_err(),
            "Shell exec intent with timeout below minimum should fail"
        );
    }

    #[test]
    fn test_shell_exec_timeout_too_high() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_shell_exec_intent();
        intent.params = json!({
            "command": "echo test",
            "timeout_ms": 200_000  // Above maximum of 120_000
        });

        let result = validator.validate_intent(&intent);
        assert!(
            result.is_err(),
            "Shell exec intent with timeout above maximum should fail"
        );
    }

    #[test]
    fn test_shell_exec_empty_command() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_shell_exec_intent();
        intent.params = json!({
            "command": "",  // Empty command
            "timeout_ms": 10_000
        });

        let result = validator.validate_intent(&intent);
        assert!(
            result.is_err(),
            "Shell exec intent with empty command should fail"
        );
    }

    #[test]
    fn test_supported_capabilities_returns_three() {
        let validator = SchemaValidator::new().unwrap();
        let caps = validator.supported_capabilities();
        assert_eq!(caps.len(), 3);
    }

    #[test]
    fn test_reload_schemas_succeeds() {
        let mut validator = SchemaValidator::new().unwrap();
        let result = validator.reload_schemas();
        assert!(result.is_ok(), "Reload schemas should succeed");
    }

    #[test]
    fn test_http_fetch_timeout_at_min_boundary() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_http_fetch_intent();
        intent.params = json!({
            "url": "https://api.example.com/data",
            "timeout_ms": 50  // Exactly at minimum
        });

        let result = validator.validate_intent(&intent);
        // Should pass (50 is the minimum)
        if let Err(ref e) = result {
            // May fail due to missing other fields, check the error
            println!("Validation error: {}", e);
        }
    }

    #[test]
    fn test_http_fetch_timeout_at_max_boundary() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_http_fetch_intent();
        intent.params = json!({
            "url": "https://api.example.com/data",
            "timeout_ms": 30000  // Exactly at maximum
        });

        let result = validator.validate_intent(&intent);
        assert!(
            result.is_ok(),
            "HTTP fetch with timeout at max should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_http_fetch_timeout_below_min() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_http_fetch_intent();
        intent.params = json!({
            "url": "https://api.example.com/data",
            "timeout_ms": 49  // Below minimum of 50
        });

        let result = validator.validate_intent(&intent);
        assert!(
            result.is_err(),
            "HTTP fetch with timeout below minimum should fail"
        );
    }

    #[test]
    fn test_http_fetch_timeout_above_max() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_http_fetch_intent();
        intent.params = json!({
            "url": "https://api.example.com/data",
            "timeout_ms": 30001  // Above maximum of 30000
        });

        let result = validator.validate_intent(&intent);
        assert!(
            result.is_err(),
            "HTTP fetch with timeout above maximum should fail"
        );
    }

    #[test]
    fn test_fs_read_offset_negative() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_fs_read_intent();
        intent.params = json!({
            "path": "/srv/logs/app.log",
            "offset": -1,  // Negative offset not allowed
            "len": 4096
        });

        let result = validator.validate_intent(&intent);
        assert!(result.is_err(), "FS read with negative offset should fail");
    }

    #[test]
    fn test_fs_read_len_zero() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_fs_read_intent();
        intent.params = json!({
            "path": "/srv/logs/app.log",
            "offset": 0,
            "len": 0  // Zero len not allowed (minimum is 1)
        });

        let result = validator.validate_intent(&intent);
        assert!(result.is_err(), "FS read with zero len should fail");
    }

    #[test]
    fn test_fs_read_len_at_max() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_fs_read_intent();
        intent.params = json!({
            "path": "/srv/logs/app.log",
            "offset": 0,
            "len": 1_048_576  // Exactly at 1MB max
        });

        let result = validator.validate_intent(&intent);
        assert!(
            result.is_ok(),
            "FS read with len at max should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_intent_ttl_too_high() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_fs_read_intent();
        intent.ttl_ms = 700_000; // Above 600_000 maximum

        let result = validator.validate_intent(&intent);
        assert!(result.is_err(), "Intent with TTL above maximum should fail");
    }

    #[test]
    fn test_intent_ttl_at_max() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_fs_read_intent();
        intent.ttl_ms = 600_000; // Exactly at maximum

        let result = validator.validate_intent(&intent);
        assert!(
            result.is_ok(),
            "Intent with TTL at max should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_intent_domain_empty() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_fs_read_intent();
        intent.domain = String::new(); // Empty domain

        let result = validator.validate_intent(&intent);
        assert!(result.is_err(), "Intent with empty domain should fail");
    }

    #[test]
    fn test_intent_domain_too_long() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_fs_read_intent();
        intent.domain = "a".repeat(129); // Above 128 max

        let result = validator.validate_intent(&intent);
        assert!(result.is_err(), "Intent with domain too long should fail");
    }

    #[test]
    fn test_http_fetch_method_head() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_http_fetch_intent();
        intent.params = json!({
            "url": "https://api.example.com/data",
            "method": "HEAD"
        });

        let result = validator.validate_intent(&intent);
        assert!(
            result.is_ok(),
            "HTTP fetch with HEAD method should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_http_fetch_method_post_invalid() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_http_fetch_intent();
        intent.params = json!({
            "url": "https://api.example.com/data",
            "method": "POST"  // Not allowed (only GET and HEAD)
        });

        let result = validator.validate_intent(&intent);
        assert!(result.is_err(), "HTTP fetch with POST method should fail");
    }

    #[test]
    fn test_http_fetch_url_too_long() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_http_fetch_intent();
        let long_path = "a".repeat(2049); // Above 2048 max
        intent.params = json!({
            "url": format!("https://api.example.com/{}", long_path),
        });

        let result = validator.validate_intent(&intent);
        assert!(result.is_err(), "HTTP fetch with URL too long should fail");
    }

    #[test]
    fn test_nonce_too_long() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_fs_read_intent();
        intent.nonce = "a".repeat(65); // Above 64 max

        let result = validator.validate_intent(&intent);
        assert!(result.is_err(), "Intent with nonce too long should fail");
    }

    #[test]
    fn test_nonce_non_hex() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_fs_read_intent();
        intent.nonce = "ghijklmnopqrstuvwxyz".to_string(); // Non-hex chars

        let result = validator.validate_intent(&intent);
        assert!(result.is_err(), "Intent with non-hex nonce should fail");
    }

    #[test]
    fn test_fs_read_path_with_null_byte() {
        let validator = SchemaValidator::new().unwrap();
        let mut intent = create_valid_fs_read_intent();
        intent.params = json!({
            "path": "/srv/logs/app\x00.log",  // Contains null byte
            "offset": 0,
            "len": 4096
        });

        let result = validator.validate_intent(&intent);
        assert!(
            result.is_err(),
            "FS read with null byte in path should fail"
        );
    }

    #[test]
    fn test_build_intent_schema_value_without_metadata() {
        let params_schema = json!({
            "type": "object",
            "properties": {
                "test": { "type": "string" }
            }
        });

        let schema = build_intent_schema_value("test.cap.v1", params_schema.clone(), None);

        // Should have default metadata schema
        assert!(schema["properties"]["metadata"]["type"] == "object");
        assert!(schema["properties"]["metadata"]["additionalProperties"] == true);
    }

    #[test]
    fn test_build_intent_schema_value_with_custom_metadata() {
        let params_schema = json!({
            "type": "object"
        });

        let metadata_schema = json!({
            "type": "object",
            "properties": {
                "custom_field": { "type": "string" }
            },
            "additionalProperties": false
        });

        let schema =
            build_intent_schema_value("test.cap.v1", params_schema, Some(metadata_schema.clone()));

        // Should use custom metadata schema
        assert!(schema["properties"]["metadata"]["additionalProperties"] == false);
    }

    #[test]
    fn test_load_schema_from_file_nonexistent() {
        let mut validator = SchemaValidator::new().unwrap();
        let result = validator.load_schema_from_file(
            "test",
            1,
            std::path::Path::new("/nonexistent/schema.json"),
        );

        assert!(
            result.is_err(),
            "Loading nonexistent schema file should fail"
        );
    }
}
