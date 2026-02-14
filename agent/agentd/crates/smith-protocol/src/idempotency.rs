//! Idempotency Key System for Smith Platform
//!
//! This module provides idempotency key generation and management to prevent
//! duplicate intent execution under network retries and failures.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

/// Idempotency key for preventing duplicate executions
///
/// Format: `idem_key = hash(run_id, episode, step_idx)`
/// This ensures network retries never cause double-execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Generate idempotency key from execution context
    ///
    /// The key is generated as: `SHA256(run_id || episode || step_idx)`
    /// This creates a deterministic, unique key for each execution step.
    pub fn generate(run_id: &str, episode: &str, step_idx: u32) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(run_id.as_bytes());
        hasher.update(b"::"); // separator
        hasher.update(episode.as_bytes());
        hasher.update(b"::"); // separator
        hasher.update(step_idx.to_string().as_bytes());

        let hash = format!("{:x}", hasher.finalize());
        Self(format!("idem_{}", &hash[0..16])) // Use first 16 chars for readability
    }

    /// Generate from intent metadata
    pub fn from_intent_metadata(
        intent_id: &str,
        actor: &str,
        episode: &str,
        step_idx: Option<u32>,
    ) -> Self {
        let step = step_idx.unwrap_or(0);
        let run_id = format!("{}:{}", intent_id, actor);
        Self::generate(&run_id, episode, step)
    }

    /// Get the raw key string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the key as an owned string
    pub fn into_string(self) -> String {
        self.0
    }

    /// Parse from string representation
    pub fn from_string(key: String) -> Result<Self, IdempotencyError> {
        if !key.starts_with("idem_") {
            return Err(IdempotencyError::InvalidFormat(key));
        }

        if key.len() != 21 {
            // "idem_" + 16 hex chars
            return Err(IdempotencyError::InvalidFormat(key));
        }

        // Validate hex characters
        let hex_part = &key[5..];
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(IdempotencyError::InvalidFormat(key));
        }

        Ok(Self(key))
    }

    /// Extract components from context (reverse operation)
    /// Note: This is not cryptographically reversible, used only for debugging
    pub fn context_hint(&self) -> String {
        format!("key:{}", &self.0[5..])
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<IdempotencyKey> for String {
    fn from(key: IdempotencyKey) -> Self {
        key.0
    }
}

/// Idempotency-related errors
#[derive(Debug, Error)]
pub enum IdempotencyError {
    #[error("Invalid idempotency key format: {0}")]
    InvalidFormat(String),

    #[error("Duplicate execution detected for key: {key}")]
    DuplicateExecution { key: String },

    #[error("Idempotency key not found: {key}")]
    KeyNotFound { key: String },

    #[error("Idempotency store error: {0}")]
    StoreError(String),
}

/// Result stored with idempotency key to prevent duplicate execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotentResult {
    /// The idempotency key this result is associated with
    pub idem_key: IdempotencyKey,
    /// Intent ID that was executed
    pub intent_id: String,
    /// Execution result (success/failure)
    pub result: IdempotentExecutionResult,
    /// When this result was first stored
    pub stored_at: chrono::DateTime<chrono::Utc>,
    /// When this result expires (for cleanup)
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Number of times this key was accessed
    pub access_count: u32,
}

/// Execution result that can be stored for idempotency
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum IdempotentExecutionResult {
    Success(serde_json::Value),
    Error { code: String, message: String },
    Timeout,
    Killed,
}

impl IdempotentResult {
    /// Create a new successful result
    pub fn success(
        idem_key: IdempotencyKey,
        intent_id: String,
        output: serde_json::Value,
        ttl_hours: u32,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            idem_key,
            intent_id,
            result: IdempotentExecutionResult::Success(output),
            stored_at: now,
            expires_at: now + chrono::Duration::hours(ttl_hours as i64),
            access_count: 0,
        }
    }

    /// Create a new error result
    pub fn error(
        idem_key: IdempotencyKey,
        intent_id: String,
        error_code: String,
        error_message: String,
        ttl_hours: u32,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            idem_key,
            intent_id,
            result: IdempotentExecutionResult::Error {
                code: error_code,
                message: error_message,
            },
            stored_at: now,
            expires_at: now + chrono::Duration::hours(ttl_hours as i64),
            access_count: 0,
        }
    }

    /// Check if this result has expired
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }

    /// Increment access count
    pub fn increment_access(&mut self) {
        self.access_count += 1;
    }
}

/// Trait for idempotency stores (in-memory, Redis, database, etc.)
#[async_trait::async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Upsert a result by idempotency key
    /// Returns true if this is a new key, false if it already existed
    async fn upsert_result(&self, result: IdempotentResult) -> Result<bool, IdempotencyError>;

    /// Get a result by idempotency key
    async fn get_result(
        &self,
        key: &IdempotencyKey,
    ) -> Result<Option<IdempotentResult>, IdempotencyError>;

    /// Delete expired results (cleanup)
    async fn cleanup_expired(&self) -> Result<u64, IdempotencyError>;

    /// Get statistics about the store
    async fn stats(&self) -> Result<IdempotencyStats, IdempotencyError>;
}

/// Statistics about idempotency store usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyStats {
    pub total_keys: u64,
    pub expired_keys: u64,
    pub hit_rate: f64,
    pub average_ttl_hours: f64,
}

/// In-memory idempotency store for development and testing
#[derive(Debug)]
pub struct InMemoryIdempotencyStore {
    results: std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<IdempotencyKey, IdempotentResult>>,
    >,
}

impl InMemoryIdempotencyStore {
    pub fn new() -> Self {
        Self {
            results: std::sync::Arc::new(
                tokio::sync::RwLock::new(std::collections::HashMap::new()),
            ),
        }
    }
}

impl Default for InMemoryIdempotencyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl IdempotencyStore for InMemoryIdempotencyStore {
    async fn upsert_result(&self, result: IdempotentResult) -> Result<bool, IdempotencyError> {
        let mut store = self.results.write().await;
        let is_new = !store.contains_key(&result.idem_key);
        store.insert(result.idem_key.clone(), result);
        Ok(is_new)
    }

    async fn get_result(
        &self,
        key: &IdempotencyKey,
    ) -> Result<Option<IdempotentResult>, IdempotencyError> {
        let mut store = self.results.write().await;
        if let Some(mut result) = store.get(key).cloned() {
            if result.is_expired() {
                store.remove(key);
                return Ok(None);
            }
            result.increment_access();
            store.insert(key.clone(), result.clone());
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    async fn cleanup_expired(&self) -> Result<u64, IdempotencyError> {
        let mut store = self.results.write().await;
        let mut expired_keys = Vec::new();

        for (key, result) in store.iter() {
            if result.is_expired() {
                expired_keys.push(key.clone());
            }
        }

        let count = expired_keys.len() as u64;
        for key in expired_keys {
            store.remove(&key);
        }

        Ok(count)
    }

    async fn stats(&self) -> Result<IdempotencyStats, IdempotencyError> {
        let store = self.results.read().await;
        let total_keys = store.len() as u64;

        let expired_keys = store.values().filter(|result| result.is_expired()).count() as u64;

        let total_accesses: u64 = store
            .values()
            .map(|result| result.access_count as u64)
            .sum();

        let hit_rate = if total_keys > 0 {
            total_accesses as f64 / total_keys as f64
        } else {
            0.0
        };

        let average_ttl = if total_keys > 0 {
            let total_ttl: i64 = store
                .values()
                .map(|result| (result.expires_at - result.stored_at).num_hours())
                .sum();
            total_ttl as f64 / total_keys as f64
        } else {
            0.0
        };

        Ok(IdempotencyStats {
            total_keys,
            expired_keys,
            hit_rate,
            average_ttl_hours: average_ttl,
        })
    }
}

/// Helper functions for common idempotency patterns
pub mod helpers {
    use super::*;

    /// Check if an execution should proceed or return cached result
    pub async fn check_idempotency(
        store: &InMemoryIdempotencyStore,
        idem_key: &IdempotencyKey,
    ) -> Result<Option<IdempotentExecutionResult>, IdempotencyError> {
        if let Some(cached_result) = store.get_result(idem_key).await? {
            return Ok(Some(cached_result.result));
        }
        Ok(None)
    }

    /// Execute with idempotency protection
    pub async fn execute_idempotent<T, F, Fut>(
        store: &InMemoryIdempotencyStore,
        idem_key: IdempotencyKey,
        intent_id: String,
        ttl_hours: u32,
        operation: F,
    ) -> Result<IdempotentExecutionResult, IdempotencyError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<serde_json::Value, (String, String)>>,
    {
        // Check for existing result
        if let Some(existing) = store.get_result(&idem_key).await? {
            return Ok(existing.result);
        }

        // Execute operation
        let result = match operation().await {
            Ok(output) => IdempotentResult::success(idem_key.clone(), intent_id, output, ttl_hours),
            Err((code, message)) => {
                IdempotentResult::error(idem_key.clone(), intent_id, code, message, ttl_hours)
            }
        };

        // Store result
        store.upsert_result(result.clone()).await?;

        Ok(result.result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_idempotency_key_generation() {
        let key1 = IdempotencyKey::generate("run123", "episode1", 5);
        let key2 = IdempotencyKey::generate("run123", "episode1", 5);
        let key3 = IdempotencyKey::generate("run123", "episode1", 6);

        // Same inputs should generate same key
        assert_eq!(key1, key2);

        // Different inputs should generate different keys
        assert_ne!(key1, key3);

        // Keys should have correct format
        assert!(key1.as_str().starts_with("idem_"));
        assert_eq!(key1.as_str().len(), 21);
    }

    #[test]
    fn test_idempotency_key_from_intent() {
        let key =
            IdempotencyKey::from_intent_metadata("intent123", "actor456", "episode789", Some(10));

        assert!(key.as_str().starts_with("idem_"));
        assert_eq!(key.as_str().len(), 21);
    }

    #[test]
    fn test_idempotency_key_parsing() {
        let original_key = IdempotencyKey::generate("test", "episode", 1);
        let key_string = original_key.to_string();

        let parsed_key = IdempotencyKey::from_string(key_string).unwrap();
        assert_eq!(original_key, parsed_key);

        // Test invalid formats
        assert!(IdempotencyKey::from_string("invalid".to_string()).is_err());
        assert!(IdempotencyKey::from_string("idem_".to_string()).is_err());
        assert!(IdempotencyKey::from_string("idem_gggg".to_string()).is_err()); // non-hex
    }

    #[tokio::test]
    async fn test_in_memory_idempotency_store() {
        let store = InMemoryIdempotencyStore::new();
        let key = IdempotencyKey::generate("test", "episode", 1);
        let result = IdempotentResult::success(
            key.clone(),
            "intent123".to_string(),
            json!({"status": "ok"}),
            24,
        );

        // Test upsert
        let is_new = store.upsert_result(result.clone()).await.unwrap();
        assert!(is_new);

        // Test get
        let retrieved = store.get_result(&key).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.intent_id, "intent123");
        assert_eq!(retrieved.access_count, 1); // Should increment on access

        // Test duplicate upsert
        let is_new = store.upsert_result(result).await.unwrap();
        assert!(!is_new);

        // Test stats
        let stats = store.stats().await.unwrap();
        assert_eq!(stats.total_keys, 1);
        assert_eq!(stats.expired_keys, 0);
    }

    #[tokio::test]
    async fn test_idempotent_result_expiration() {
        let key = IdempotencyKey::generate("test", "episode", 1);
        let mut result = IdempotentResult::success(
            key,
            "intent123".to_string(),
            json!({"status": "ok"}),
            0, // 0 hour TTL - should expire immediately
        );

        // Manually set expiration to past
        result.expires_at = chrono::Utc::now() - chrono::Duration::hours(1);

        assert!(result.is_expired());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let store = InMemoryIdempotencyStore::new();
        let key1 = IdempotencyKey::generate("test1", "episode", 1);
        let key2 = IdempotencyKey::generate("test2", "episode", 1);

        // Create one expired and one valid result
        let mut expired_result = IdempotentResult::success(
            key1,
            "intent1".to_string(),
            json!({"status": "expired"}),
            24,
        );
        expired_result.expires_at = chrono::Utc::now() - chrono::Duration::hours(1);

        let valid_result =
            IdempotentResult::success(key2, "intent2".to_string(), json!({"status": "valid"}), 24);

        store.upsert_result(expired_result).await.unwrap();
        store.upsert_result(valid_result).await.unwrap();

        // Cleanup should remove 1 expired result
        let cleaned = store.cleanup_expired().await.unwrap();
        assert_eq!(cleaned, 1);

        // Only valid result should remain
        let stats = store.stats().await.unwrap();
        assert_eq!(stats.total_keys, 1);
    }

    #[tokio::test]
    async fn test_idempotency_helpers() {
        use helpers::*;

        let store = InMemoryIdempotencyStore::new();
        let key = IdempotencyKey::generate("test", "episode", 1);

        // First check should return None (no cached result)
        let cached = check_idempotency(&store, &key).await.unwrap();
        assert!(cached.is_none());

        // Execute idempotent operation
        let result = execute_idempotent::<String, _, _>(
            &store,
            key.clone(),
            "intent123".to_string(),
            24,
            || async { Ok(json!({"computed": "value"})) },
        )
        .await
        .unwrap();

        match result {
            IdempotentExecutionResult::Success(value) => {
                assert_eq!(value, json!({"computed": "value"}));
            }
            _ => panic!("Expected success result"),
        }

        // Second check should return cached result
        let cached = check_idempotency(&store, &key).await.unwrap();
        assert!(cached.is_some());
    }

    #[test]
    fn test_idempotent_execution_result_serialization() {
        let success_result = IdempotentExecutionResult::Success(json!({"key": "value"}));
        let error_result = IdempotentExecutionResult::Error {
            code: "TEST_ERROR".to_string(),
            message: "Test error message".to_string(),
        };

        // Test serialization roundtrip
        let success_json = serde_json::to_string(&success_result).unwrap();
        let success_deserialized: IdempotentExecutionResult =
            serde_json::from_str(&success_json).unwrap();

        match success_deserialized {
            IdempotentExecutionResult::Success(value) => {
                assert_eq!(value, json!({"key": "value"}));
            }
            _ => panic!("Expected success result"),
        }

        let error_json = serde_json::to_string(&error_result).unwrap();
        let error_deserialized: IdempotentExecutionResult =
            serde_json::from_str(&error_json).unwrap();

        match error_deserialized {
            IdempotentExecutionResult::Error { code, message } => {
                assert_eq!(code, "TEST_ERROR");
                assert_eq!(message, "Test error message");
            }
            _ => panic!("Expected error result"),
        }
    }

    #[tokio::test]
    async fn test_idempotency_stats_empty_store() {
        let store = InMemoryIdempotencyStore::new();
        let stats = store.stats().await.unwrap();

        assert_eq!(stats.total_keys, 0);
        assert_eq!(stats.expired_keys, 0);
        assert_eq!(stats.hit_rate, 0.0);
        assert_eq!(stats.average_ttl_hours, 0.0);
    }

    #[tokio::test]
    async fn test_idempotency_stats_with_data() {
        let store = InMemoryIdempotencyStore::new();
        let key1 = IdempotencyKey::generate("test1", "episode", 1);
        let key2 = IdempotencyKey::generate("test2", "episode", 1);

        let mut result1 =
            IdempotentResult::success(key1, "intent1".to_string(), json!({"status": "ok"}), 24);
        result1.access_count = 5; // Simulate multiple accesses

        let result2 =
            IdempotentResult::success(key2, "intent2".to_string(), json!({"status": "ok"}), 12);

        store.upsert_result(result1).await.unwrap();
        store.upsert_result(result2).await.unwrap();

        let stats = store.stats().await.unwrap();
        assert_eq!(stats.total_keys, 2);
        assert_eq!(stats.expired_keys, 0);
        assert_eq!(stats.hit_rate, 2.5); // (5 + 0) / 2 (access_count for result2 defaults to 0)
        assert_eq!(stats.average_ttl_hours, 18.0); // (24 + 12) / 2
    }

    #[tokio::test]
    async fn test_execute_idempotent_error_case() {
        use helpers::*;

        let store = InMemoryIdempotencyStore::new();
        let key = IdempotencyKey::generate("test_error", "episode", 1);

        // Execute operation that returns error
        let result = execute_idempotent::<String, _, _>(
            &store,
            key.clone(),
            "intent123".to_string(),
            24,
            || async { Err(("ERROR_CODE".to_string(), "Error message".to_string())) },
        )
        .await
        .unwrap();

        match result {
            IdempotentExecutionResult::Error { code, message } => {
                assert_eq!(code, "ERROR_CODE");
                assert_eq!(message, "Error message");
            }
            _ => panic!("Expected error result"),
        }

        // Should return same cached error result on second execution
        let cached = check_idempotency(&store, &key).await.unwrap();
        assert!(cached.is_some());
        match cached.unwrap() {
            IdempotentExecutionResult::Error { code, message } => {
                assert_eq!(code, "ERROR_CODE");
                assert_eq!(message, "Error message");
            }
            _ => panic!("Expected cached error result"),
        }
    }

    #[test]
    fn test_idempotent_result_debug_format() {
        let key = IdempotencyKey::generate("test", "episode", 1);
        let result =
            IdempotentResult::success(key, "intent123".to_string(), json!({"status": "ok"}), 24);

        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("IdempotentResult"));
        assert!(debug_str.contains("intent123"));
    }

    #[test]
    fn test_idempotency_error_types() {
        let store_error = IdempotencyError::StoreError("Storage failed".to_string());
        let invalid_format_error = IdempotencyError::InvalidFormat("invalid-key".to_string());
        let duplicate_error = IdempotencyError::DuplicateExecution {
            key: "test-key".to_string(),
        };
        let not_found_error = IdempotencyError::KeyNotFound {
            key: "missing-key".to_string(),
        };

        // Test Display trait
        assert!(format!("{}", store_error).contains("Idempotency store error"));
        assert!(format!("{}", invalid_format_error).contains("Invalid idempotency key format"));
        assert!(format!("{}", duplicate_error).contains("Duplicate execution detected"));
        assert!(format!("{}", not_found_error).contains("Idempotency key not found"));

        // Test Debug trait
        let debug_str = format!("{:?}", store_error);
        assert!(debug_str.contains("StoreError"));
    }

    #[tokio::test]
    async fn test_upsert_result_returns_correct_bool() {
        let store = InMemoryIdempotencyStore::new();
        let key = IdempotencyKey::generate("test", "episode", 1);

        let result = IdempotentResult::success(
            key.clone(),
            "intent123".to_string(),
            json!({"status": "ok"}),
            24,
        );

        // First insert should return true (new key)
        let is_new = store.upsert_result(result.clone()).await.unwrap();
        assert!(is_new);

        // Second insert should return false (existing key)
        let is_new = store.upsert_result(result).await.unwrap();
        assert!(!is_new);
    }

    #[tokio::test]
    async fn test_get_result_nonexistent_key() {
        let store = InMemoryIdempotencyStore::new();
        let key = IdempotencyKey::generate("nonexistent", "episode", 1);

        let result = store.get_result(&key).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_idempotency_key_parsing_invalid() {
        // Test parsing invalid key format
        let invalid_key = "invalid-format".to_string();
        let result = IdempotencyKey::from_string(invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_idempotency_stats_serialization() {
        let stats = IdempotencyStats {
            total_keys: 10,
            expired_keys: 2,
            hit_rate: 1.5,
            average_ttl_hours: 24.0,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: IdempotencyStats = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.total_keys, 10);
        assert_eq!(deserialized.expired_keys, 2);
        assert_eq!(deserialized.hit_rate, 1.5);
        assert_eq!(deserialized.average_ttl_hours, 24.0);
    }
}
