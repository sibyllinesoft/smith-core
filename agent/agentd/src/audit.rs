use anyhow::{Context, Result};
use hex;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use crate::intent::{Intent, IntentResult, IntentStatus, PolicyDecision};

/// Append-only audit logger for compliance and forensic analysis
pub struct AuditLogger {
    audit_dir: PathBuf,
    current_file: Option<tokio::fs::File>,
    current_date: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    pub timestamp_ms: u64,
    pub intent_id: String,
    pub intent_hash: String,
    pub capability_digest: String,
    pub runner_digest: String,
    pub decision: AuditDecision,
    pub sandbox_digest: String,
    pub actor: AuditActor,
    pub result: Option<AuditResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditDecision {
    pub allow: bool,
    pub code: Option<String>, // Error code if denied
    pub limits: AuditLimits,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditLimits {
    pub cpu_ms_per_100ms: u32,
    pub mem_bytes: u64,
    pub io_bytes: u64,
    pub pids_max: u32,
    pub timeout_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditActor {
    pub tenant: String,
    pub key_id: String,
    pub jwt_subject: Option<String>, // Extracted from JWT if available
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditResult {
    pub status: String,
    pub duration_ms: u64,
    pub exit_code: Option<i32>,
    pub artifacts_count: u32,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

impl AuditLogger {
    /// Create new audit logger
    pub fn new(audit_dir: &Path) -> Result<Self> {
        let audit_dir = audit_dir.to_path_buf();

        // Ensure audit directory exists
        std::fs::create_dir_all(&audit_dir).context("Failed to create audit directory")?;

        info!("Audit logger initialized at: {}", audit_dir.display());

        Ok(Self {
            audit_dir,
            current_file: None,
            current_date: String::new(),
        })
    }

    /// Log intent admission (when intent is first processed)
    pub async fn log_admission(
        &mut self,
        intent: &Intent,
        decision: &PolicyDecision,
    ) -> Result<()> {
        let record = AuditRecord {
            timestamp_ms: chrono::Utc::now().timestamp_millis() as u64,
            intent_id: intent.id.to_string(),
            intent_hash: intent.content_hash()?,
            capability_digest: decision.capability_digest.clone(),
            runner_digest: decision.runner_digest.clone(),
            decision: AuditDecision {
                allow: decision.allow,
                code: None, // No error for successful admission
                limits: AuditLimits {
                    cpu_ms_per_100ms: decision.limits_applied.cpu_ms_per_100ms,
                    mem_bytes: decision.limits_applied.mem_bytes,
                    io_bytes: decision.limits_applied.io_bytes,
                    pids_max: decision.limits_applied.pids_max,
                    timeout_ms: decision.limits_applied.timeout_ms,
                },
            },
            sandbox_digest: calculate_sandbox_digest(&intent.capability, &decision.limits_applied),
            actor: AuditActor {
                tenant: intent.actor.tenant.clone(),
                key_id: intent.actor.key_id.clone(),
                jwt_subject: extract_jwt_subject(&intent.actor.jwt),
            },
            result: None, // No result yet for admission
        };

        self.write_audit_record(&record)
            .await
            .context("Failed to write admission audit record")
    }

    /// Log intent denial (when admission fails)
    pub async fn log_denial(
        &mut self,
        intent: &Intent,
        capability_digest: &str,
        error_code: &str,
    ) -> Result<()> {
        let record = AuditRecord {
            timestamp_ms: chrono::Utc::now().timestamp_millis() as u64,
            intent_id: intent.id.to_string(),
            intent_hash: intent.content_hash()?,
            capability_digest: capability_digest.to_string(),
            runner_digest: "none".to_string(), // No runner for denied intents
            decision: AuditDecision {
                allow: false,
                code: Some(error_code.to_string()),
                limits: AuditLimits {
                    cpu_ms_per_100ms: 0,
                    mem_bytes: 0,
                    io_bytes: 0,
                    pids_max: 0,
                    timeout_ms: 0,
                },
            },
            sandbox_digest: "none".to_string(),
            actor: AuditActor {
                tenant: intent.actor.tenant.clone(),
                key_id: intent.actor.key_id.clone(),
                jwt_subject: extract_jwt_subject(&intent.actor.jwt),
            },
            result: None,
        };

        self.write_audit_record(&record)
            .await
            .context("Failed to write denial audit record")
    }

    /// Log intent execution result
    pub async fn log_result(
        &mut self,
        intent: &Intent,
        decision: &PolicyDecision,
        result: &IntentResult,
    ) -> Result<()> {
        let duration_ms = result.ended_at_ms - result.started_at_ms;

        let audit_result = AuditResult {
            status: format!("{:?}", result.status).to_lowercase(),
            duration_ms,
            exit_code: extract_exit_code(result),
            artifacts_count: result.artifacts.len() as u32,
            stdout_bytes: result.stdout.as_ref().map(|s| s.len()).unwrap_or(0) as u64,
            stderr_bytes: result.stderr.as_ref().map(|s| s.len()).unwrap_or(0) as u64,
        };

        let record = AuditRecord {
            timestamp_ms: chrono::Utc::now().timestamp_millis() as u64,
            intent_id: intent.id.to_string(),
            intent_hash: intent.content_hash()?,
            capability_digest: decision.capability_digest.clone(),
            runner_digest: decision.runner_digest.clone(),
            decision: AuditDecision {
                allow: decision.allow,
                code: None,
                limits: AuditLimits {
                    cpu_ms_per_100ms: decision.limits_applied.cpu_ms_per_100ms,
                    mem_bytes: decision.limits_applied.mem_bytes,
                    io_bytes: decision.limits_applied.io_bytes,
                    pids_max: decision.limits_applied.pids_max,
                    timeout_ms: decision.limits_applied.timeout_ms,
                },
            },
            sandbox_digest: calculate_sandbox_digest(&intent.capability, &decision.limits_applied),
            actor: AuditActor {
                tenant: intent.actor.tenant.clone(),
                key_id: intent.actor.key_id.clone(),
                jwt_subject: extract_jwt_subject(&intent.actor.jwt),
            },
            result: Some(audit_result),
        };

        self.write_audit_record(&record)
            .await
            .context("Failed to write result audit record")
    }

    /// Write audit record to compressed daily log file
    async fn write_audit_record(&mut self, record: &AuditRecord) -> Result<()> {
        let current_date = chrono::Utc::now().format("%Y-%m-%d").to_string();

        // Check if we need to rotate to a new file
        if self.current_date != current_date {
            self.rotate_log_file(&current_date).await?;
        }

        // Serialize record as JSON
        let record_json =
            serde_json::to_string(record).context("Failed to serialize audit record")?;

        // Write to current file
        if let Some(ref mut file) = self.current_file {
            file.write_all(record_json.as_bytes())
                .await
                .context("Failed to write audit record to file")?;
            file.write_all(b"\n")
                .await
                .context("Failed to write newline to audit file")?;
            file.flush().await.context("Failed to flush audit file")?;
        }

        debug!("Audit record written for intent: {}", record.intent_id);
        Ok(())
    }

    /// Rotate to new daily log file
    async fn rotate_log_file(&mut self, date: &str) -> Result<()> {
        // Close current file if open
        if let Some(file) = self.current_file.take() {
            drop(file); // Ensure file is closed

            // TODO: Compress previous day's file with zstd
            if !self.current_date.is_empty() {
                self.compress_log_file(&self.current_date).await?;
            }
        }

        // Open new file for current date
        let log_filename = format!("{}.log", date);
        let log_path = self.audit_dir.join(log_filename);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .await
            .with_context(|| format!("Failed to open audit log file: {}", log_path.display()))?;

        self.current_file = Some(file);
        self.current_date = date.to_string();

        info!("Rotated to new audit log file: {}", log_path.display());
        Ok(())
    }

    /// Compress log file with zstd
    async fn compress_log_file(&self, date: &str) -> Result<()> {
        let log_filename = format!("{}.log", date);
        let compressed_filename = format!("{}.log.zst", date);

        let log_path = self.audit_dir.join(&log_filename);
        let compressed_path = self.audit_dir.join(&compressed_filename);

        // Check if log file exists
        if !log_path.exists() {
            debug!(
                "Log file {} does not exist, skipping compression",
                log_path.display()
            );
            return Ok(());
        }

        // Read log file contents
        let log_data = tokio::fs::read(&log_path)
            .await
            .with_context(|| format!("Failed to read log file: {}", log_path.display()))?;

        if log_data.is_empty() {
            debug!(
                "Log file {} is empty, skipping compression",
                log_path.display()
            );
            // Still delete the empty file
            tokio::fs::remove_file(&log_path).await.with_context(|| {
                format!("Failed to delete empty log file: {}", log_path.display())
            })?;
            return Ok(());
        }

        // Compress with zstd (compression level 3 for good balance of speed/compression)
        let log_data_for_compression = log_data.clone();
        let compressed_data =
            tokio::task::spawn_blocking(move || zstd::bulk::compress(&log_data_for_compression, 3))
                .await?
                .context("Failed to compress log data with zstd")?;

        // Calculate compression ratio before moving compressed_data
        let compression_ratio = (compressed_data.len() as f64 / log_data.len() as f64) * 100.0;
        let compressed_size = compressed_data.len();
        let original_size = log_data.len();

        // Write compressed file
        tokio::fs::write(&compressed_path, compressed_data)
            .await
            .with_context(|| {
                format!(
                    "Failed to write compressed file: {}",
                    compressed_path.display()
                )
            })?;

        // Delete original log file
        tokio::fs::remove_file(&log_path).await.with_context(|| {
            format!("Failed to delete original log file: {}", log_path.display())
        })?;
        info!(
            "Compressed {} to {} ({}KB -> {}KB, {:.1}% of original)",
            log_filename,
            compressed_filename,
            original_size / 1024,
            compressed_size / 1024,
            compression_ratio
        );

        Ok(())
    }

    /// Get audit statistics
    pub async fn get_stats(&self) -> Result<AuditStats> {
        // Count files in audit directory
        let mut total_files = 0;
        let mut total_size = 0;

        let mut entries = tokio::fs::read_dir(&self.audit_dir)
            .await
            .context("Failed to read audit directory")?;

        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_file() {
                total_files += 1;
                total_size += metadata.len();
            }
        }

        Ok(AuditStats {
            total_files,
            total_size_bytes: total_size,
            current_date: self.current_date.clone(),
        })
    }
}

#[derive(Debug)]
pub struct AuditStats {
    pub total_files: u32,
    pub total_size_bytes: u64,
    pub current_date: String,
}

/// Calculate a digest for the sandbox configuration based on capability and limits
fn calculate_sandbox_digest(capability: &str, limits: &smith_protocol::ExecutionLimits) -> String {
    let mut hasher = Sha256::new();

    // Include capability in the digest
    hasher.update(capability.as_bytes());

    // Include resource limits
    hasher.update(&limits.cpu_ms_per_100ms.to_be_bytes());
    hasher.update(&limits.mem_bytes.to_be_bytes());
    hasher.update(&limits.io_bytes.to_be_bytes());
    hasher.update(&limits.pids_max.to_be_bytes());
    hasher.update(&limits.timeout_ms.to_be_bytes());

    // Return truncated hex hash for readability
    format!("{:.16}", hex::encode(hasher.finalize()))
}

/// Claims structure for JWT tokens used in the audit logging
#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: Option<String>,
    #[serde(flatten)]
    other: std::collections::HashMap<String, serde_json::Value>,
}

/// Extract the subject from a JWT token for audit logging
/// Returns None if the JWT cannot be decoded or doesn't have a subject claim
fn extract_jwt_subject(jwt_token: &str) -> Option<String> {
    // Try to decode without verification for audit purposes
    // We're only extracting claims for logging, not validating the token
    let mut validation = Validation::new(Algorithm::HS256);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;

    // Use a dummy key since we're not verifying the signature
    let dummy_key = DecodingKey::from_secret(b"dummy");

    match decode::<JwtClaims>(jwt_token, &dummy_key, &validation) {
        Ok(token_data) => {
            debug!("Successfully extracted JWT claims for audit logging");
            token_data.claims.sub
        }
        Err(e) => {
            warn!("Failed to extract JWT subject for audit logging: {}", e);
            None
        }
    }
}

/// Extract exit code from IntentResult's code field
/// The code field may contain an exit code if the execution terminated with a specific exit code
fn extract_exit_code(result: &IntentResult) -> Option<i32> {
    // Check if the result status indicates an error and try to parse exit code from the code field
    match result.status {
        IntentStatus::Ok => Some(0), // Success typically means exit code 0
        IntentStatus::Error => {
            // Try to parse the code field as an exit code
            if let Ok(exit_code) = result.code.parse::<i32>() {
                Some(exit_code)
            } else {
                // Check if the code field contains exit code information in a pattern like "exit:1" or "exitcode:1"
                if let Some(captures) = regex::Regex::new(r"(?:exit|exitcode)[:=](\d+)")
                    .ok()?
                    .captures(&result.code)
                {
                    captures.get(1)?.as_str().parse().ok()
                } else {
                    None // Can't extract exit code from error message
                }
            }
        }
        IntentStatus::Denied | IntentStatus::Expired => None, // These don't have exit codes from execution
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Actor, Intent, IntentStatus};
    use smith_protocol::ExecutionLimits;
    use tempfile::tempdir;
    use uuid::Uuid;

    fn create_test_intent() -> Intent {
        Intent::new(
            "fs.read".to_string(),
            1,
            "/srv/logs/test.log".to_string(),
            serde_json::json!({"offset": 0, "len": 1024}),
            serde_json::json!({"max_bytes": 1048576}),
            Actor {
                jwt: "test.jwt".to_string(),
                tenant: "test-tenant".to_string(),
                key_id: "test-key".to_string(),
            },
        )
    }

    fn create_test_decision() -> PolicyDecision {
        PolicyDecision {
            allow: true,
            capability_digest: "capability-digest".to_string(),
            runner_digest: "runner-digest".to_string(),
            limits_applied: ExecutionLimits {
                cpu_ms_per_100ms: 50,
                mem_bytes: 256_000_000,
                io_bytes: 10_000_000,
                pids_max: 32,
                timeout_ms: 30_000,
            },
            scope: serde_json::json!({"paths": ["/srv/logs/"]}),
            transforms: None,
        }
    }

    #[tokio::test]
    async fn test_audit_logger_creation() {
        let temp_dir = tempdir().unwrap();
        let logger = AuditLogger::new(temp_dir.path());
        assert!(logger.is_ok(), "Audit logger creation should succeed");
    }

    #[tokio::test]
    async fn test_log_admission() {
        let temp_dir = tempdir().unwrap();
        let mut logger = AuditLogger::new(temp_dir.path()).unwrap();

        let intent = create_test_intent();
        let decision = create_test_decision();

        let result = logger.log_admission(&intent, &decision).await;
        assert!(result.is_ok(), "Admission logging should succeed");
    }

    #[tokio::test]
    async fn test_log_denial() {
        let temp_dir = tempdir().unwrap();
        let mut logger = AuditLogger::new(temp_dir.path()).unwrap();

        let intent = create_test_intent();

        let result = logger
            .log_denial(&intent, "capability-digest", "POLICY_DENY")
            .await;
        assert!(result.is_ok(), "Denial logging should succeed");
    }

    // ==================== calculate_sandbox_digest Tests ====================

    #[test]
    fn test_calculate_sandbox_digest() {
        let limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 256_000_000,
            io_bytes: 10_000_000,
            pids_max: 32,
            timeout_ms: 30_000,
        };

        let digest = calculate_sandbox_digest("fs.read", &limits);

        // Digest should be a 16-character hex string
        assert_eq!(digest.len(), 16);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_calculate_sandbox_digest_different_capabilities() {
        let limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 256_000_000,
            io_bytes: 10_000_000,
            pids_max: 32,
            timeout_ms: 30_000,
        };

        let digest1 = calculate_sandbox_digest("fs.read", &limits);
        let digest2 = calculate_sandbox_digest("http.fetch", &limits);

        assert_ne!(digest1, digest2);
    }

    #[test]
    fn test_calculate_sandbox_digest_different_limits() {
        let limits1 = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 256_000_000,
            io_bytes: 10_000_000,
            pids_max: 32,
            timeout_ms: 30_000,
        };

        let limits2 = ExecutionLimits {
            cpu_ms_per_100ms: 100, // Different
            mem_bytes: 256_000_000,
            io_bytes: 10_000_000,
            pids_max: 32,
            timeout_ms: 30_000,
        };

        let digest1 = calculate_sandbox_digest("fs.read", &limits1);
        let digest2 = calculate_sandbox_digest("fs.read", &limits2);

        assert_ne!(digest1, digest2);
    }

    #[test]
    fn test_calculate_sandbox_digest_consistent() {
        let limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 256_000_000,
            io_bytes: 10_000_000,
            pids_max: 32,
            timeout_ms: 30_000,
        };

        let digest1 = calculate_sandbox_digest("fs.read", &limits);
        let digest2 = calculate_sandbox_digest("fs.read", &limits);

        assert_eq!(digest1, digest2);
    }

    // ==================== extract_jwt_subject Tests ====================

    #[test]
    fn test_extract_jwt_subject_invalid_token() {
        let subject = extract_jwt_subject("not.a.valid.jwt");
        assert!(subject.is_none());
    }

    #[test]
    fn test_extract_jwt_subject_empty_token() {
        let subject = extract_jwt_subject("");
        assert!(subject.is_none());
    }

    #[test]
    fn test_extract_jwt_subject_malformed_token() {
        let subject = extract_jwt_subject("header.payload");
        assert!(subject.is_none());
    }

    // ==================== extract_exit_code Tests ====================

    fn create_test_result(status: IntentStatus, code: &str) -> IntentResult {
        IntentResult {
            intent_id: Uuid::new_v4(),
            seq: 1,
            status,
            code: code.to_string(),
            started_at_ms: 0,
            ended_at_ms: 100,
            decision: create_test_decision(),
            stdout: None,
            stderr: None,
            artifacts: vec![],
            retry_after_ms: None,
        }
    }

    #[test]
    fn test_extract_exit_code_ok_status() {
        let result = create_test_result(IntentStatus::Ok, "");
        let exit_code = extract_exit_code(&result);
        assert_eq!(exit_code, Some(0));
    }

    #[test]
    fn test_extract_exit_code_error_numeric() {
        let result = create_test_result(IntentStatus::Error, "1");
        let exit_code = extract_exit_code(&result);
        assert_eq!(exit_code, Some(1));
    }

    #[test]
    fn test_extract_exit_code_error_with_pattern() {
        let result = create_test_result(IntentStatus::Error, "Command failed exit:42");
        let exit_code = extract_exit_code(&result);
        assert_eq!(exit_code, Some(42));
    }

    #[test]
    fn test_extract_exit_code_error_with_exitcode_pattern() {
        let result = create_test_result(IntentStatus::Error, "Process terminated exitcode:127");
        let exit_code = extract_exit_code(&result);
        assert_eq!(exit_code, Some(127));
    }

    #[test]
    fn test_extract_exit_code_denied_status() {
        let result = create_test_result(IntentStatus::Denied, "POLICY_DENY");
        let exit_code = extract_exit_code(&result);
        assert!(exit_code.is_none());
    }

    #[test]
    fn test_extract_exit_code_expired_status() {
        let result = create_test_result(IntentStatus::Expired, "TIMEOUT");
        let exit_code = extract_exit_code(&result);
        assert!(exit_code.is_none());
    }

    #[test]
    fn test_extract_exit_code_error_no_pattern() {
        let result = create_test_result(IntentStatus::Error, "Generic error message");
        let exit_code = extract_exit_code(&result);
        assert!(exit_code.is_none());
    }

    // ==================== AuditRecord Serialization Tests ====================

    #[test]
    fn test_audit_record_serialization() {
        let record = AuditRecord {
            timestamp_ms: 1234567890,
            intent_id: "intent-123".to_string(),
            intent_hash: "abc123".to_string(),
            capability_digest: "cap-digest".to_string(),
            runner_digest: "run-digest".to_string(),
            decision: AuditDecision {
                allow: true,
                code: None,
                limits: AuditLimits {
                    cpu_ms_per_100ms: 50,
                    mem_bytes: 256_000_000,
                    io_bytes: 10_000_000,
                    pids_max: 32,
                    timeout_ms: 30_000,
                },
            },
            sandbox_digest: "sandbox-digest".to_string(),
            actor: AuditActor {
                tenant: "test-tenant".to_string(),
                key_id: "key-123".to_string(),
                jwt_subject: Some("user@example.com".to_string()),
            },
            result: None,
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("intent-123"));
        assert!(json.contains("test-tenant"));
        assert!(json.contains("1234567890"));

        // Roundtrip
        let deserialized: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.intent_id, "intent-123");
    }

    #[test]
    fn test_audit_record_with_result() {
        let record = AuditRecord {
            timestamp_ms: 1234567890,
            intent_id: "intent-456".to_string(),
            intent_hash: "def456".to_string(),
            capability_digest: "cap-digest".to_string(),
            runner_digest: "run-digest".to_string(),
            decision: AuditDecision {
                allow: true,
                code: None,
                limits: AuditLimits {
                    cpu_ms_per_100ms: 50,
                    mem_bytes: 256_000_000,
                    io_bytes: 10_000_000,
                    pids_max: 32,
                    timeout_ms: 30_000,
                },
            },
            sandbox_digest: "sandbox-digest".to_string(),
            actor: AuditActor {
                tenant: "test-tenant".to_string(),
                key_id: "key-456".to_string(),
                jwt_subject: None,
            },
            result: Some(AuditResult {
                status: "ok".to_string(),
                duration_ms: 500,
                exit_code: Some(0),
                artifacts_count: 2,
                stdout_bytes: 1024,
                stderr_bytes: 0,
            }),
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"duration_ms\":500"));

        let deserialized: AuditRecord = serde_json::from_str(&json).unwrap();
        assert!(deserialized.result.is_some());
        assert_eq!(deserialized.result.unwrap().duration_ms, 500);
    }

    #[test]
    fn test_audit_decision_denied() {
        let decision = AuditDecision {
            allow: false,
            code: Some("POLICY_DENY".to_string()),
            limits: AuditLimits {
                cpu_ms_per_100ms: 0,
                mem_bytes: 0,
                io_bytes: 0,
                pids_max: 0,
                timeout_ms: 0,
            },
        };

        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("\"allow\":false"));
        assert!(json.contains("POLICY_DENY"));
    }

    // ==================== AuditStats Tests ====================

    #[test]
    fn test_audit_stats_debug() {
        let stats = AuditStats {
            total_files: 10,
            total_size_bytes: 1024 * 1024,
            current_date: "2024-01-15".to_string(),
        };

        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("AuditStats"));
        assert!(debug_str.contains("total_files"));
        assert!(debug_str.contains("10"));
    }

    // ==================== AuditLogger Stats Tests ====================

    #[tokio::test]
    async fn test_audit_logger_get_stats_empty() {
        let temp_dir = tempdir().unwrap();
        let logger = AuditLogger::new(temp_dir.path()).unwrap();

        let stats = logger.get_stats().await.unwrap();
        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.total_size_bytes, 0);
    }

    #[tokio::test]
    async fn test_audit_logger_get_stats_with_files() {
        let temp_dir = tempdir().unwrap();
        let mut logger = AuditLogger::new(temp_dir.path()).unwrap();

        // Write some audit records
        let intent = create_test_intent();
        let decision = create_test_decision();
        logger.log_admission(&intent, &decision).await.unwrap();

        let stats = logger.get_stats().await.unwrap();
        assert!(stats.total_files > 0);
        assert!(stats.total_size_bytes > 0);
    }

    // ==================== AuditLimits Serialization Tests ====================

    #[test]
    fn test_audit_limits_serialization() {
        let limits = AuditLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 256_000_000,
            io_bytes: 10_000_000,
            pids_max: 32,
            timeout_ms: 30_000,
        };

        let json = serde_json::to_string(&limits).unwrap();
        assert!(json.contains("\"cpu_ms_per_100ms\":50"));
        assert!(json.contains("\"mem_bytes\":256000000"));

        let deserialized: AuditLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.cpu_ms_per_100ms, 50);
    }

    // ==================== AuditActor Serialization Tests ====================

    #[test]
    fn test_audit_actor_serialization() {
        let actor = AuditActor {
            tenant: "my-tenant".to_string(),
            key_id: "key-abc".to_string(),
            jwt_subject: Some("user@test.com".to_string()),
        };

        let json = serde_json::to_string(&actor).unwrap();
        assert!(json.contains("my-tenant"));
        assert!(json.contains("key-abc"));
        assert!(json.contains("user@test.com"));

        let deserialized: AuditActor = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.tenant, "my-tenant");
    }

    #[test]
    fn test_audit_actor_no_jwt_subject() {
        let actor = AuditActor {
            tenant: "tenant-2".to_string(),
            key_id: "key-def".to_string(),
            jwt_subject: None,
        };

        let json = serde_json::to_string(&actor).unwrap();
        assert!(json.contains("tenant-2"));
        assert!(json.contains("\"jwt_subject\":null"));
    }

    // ==================== AuditResult Serialization Tests ====================

    #[test]
    fn test_audit_result_serialization() {
        let result = AuditResult {
            status: "error".to_string(),
            duration_ms: 1500,
            exit_code: Some(1),
            artifacts_count: 0,
            stdout_bytes: 512,
            stderr_bytes: 256,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"error\""));
        assert!(json.contains("\"duration_ms\":1500"));
        assert!(json.contains("\"exit_code\":1"));

        let deserialized: AuditResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.status, "error");
        assert_eq!(deserialized.exit_code, Some(1));
    }

    #[test]
    fn test_audit_result_no_exit_code() {
        let result = AuditResult {
            status: "denied".to_string(),
            duration_ms: 0,
            exit_code: None,
            artifacts_count: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"exit_code\":null"));
    }
}
