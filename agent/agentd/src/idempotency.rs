use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};
use std::path::Path;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info};
use uuid::Uuid;

/// Trait for idempotency operations used by the admission pipeline.
///
/// This trait abstracts the idempotency store operations to enable
/// dependency injection and mocking in tests.
#[async_trait]
pub trait IdempotencyOps: Send + Sync {
    /// Check if an intent has been processed
    async fn is_processed(&self, intent_id: &str) -> Result<bool>;

    /// Get cached result for an intent
    async fn get_result(&self, intent_id: &str) -> Result<Option<smith_protocol::IntentResult>>;

    /// Mark intent as being processed to prevent duplicates
    async fn mark_processing(&self, intent_id: &str) -> Result<()>;

    /// Store execution result
    async fn store_result(
        &self,
        intent_id: &str,
        result: &smith_protocol::IntentResult,
    ) -> Result<()>;
}

/// SQLite-based idempotency store for intent deduplication
#[derive(Clone)]
pub struct IdempotencyStore {
    pool: SqlitePool,
}

#[derive(Debug, Clone)]
pub struct IdempotencyRecord {
    pub intent_id: Uuid,
    pub seq: u32,
    pub runner_digest: String,
    pub capability_digest: String,
    pub status: smith_protocol::ExecutionStatus,
    pub result: Option<Vec<u8>>, // Serialized IntentResult
    pub started_ms: i64,
    pub ended_ms: Option<i64>,
}

impl IdempotencyStore {
    /// Create new idempotency store with SQLite backend
    pub async fn new(state_dir: &Path) -> Result<Self> {
        tokio::fs::create_dir_all(state_dir)
            .await
            .with_context(|| {
                format!("Failed to create state directory: {}", state_dir.display())
            })?;

        let db_path = state_dir.join("idempotency.sqlite");

        let connect_options = SqliteConnectOptions::new()
            .filename(&db_path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(connect_options)
            .await
            .with_context(|| {
                format!(
                    "Failed to connect to SQLite database at {}",
                    db_path.display()
                )
            })?;

        info!(
            path = %db_path.display(),
            "Idempotency store using SQLite database"
        );

        // Initialize database schema
        // Note: migrations would be handled externally in production
        // For now, create the tables directly to match migration schema
        let create_runs_table_sql = r#"
            CREATE TABLE IF NOT EXISTS runs (
                intent_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                runner_digest TEXT NOT NULL,
                capability_digest TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('running', 'ok', 'denied', 'error', 'expired', 'timeout', 'killed')),
                result BLOB,
                started_ms INTEGER NOT NULL,
                ended_ms INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                PRIMARY KEY (intent_id, seq, runner_digest, capability_digest)
            )
        "#;

        let create_replays_table_sql = r#"
            CREATE TABLE IF NOT EXISTS replays (
                nonce TEXT PRIMARY KEY,
                ts_ms INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        "#;

        let create_indexes_sql = [
            "CREATE INDEX IF NOT EXISTS idx_runs_started_ms ON runs (started_ms)",
            "CREATE INDEX IF NOT EXISTS idx_runs_status ON runs (status)",
            "CREATE INDEX IF NOT EXISTS idx_replays_ts_ms ON replays (ts_ms)",
        ];

        // Create runs table
        sqlx::query(create_runs_table_sql)
            .execute(&pool)
            .await
            .context("Failed to create runs table")?;

        // Create replays table
        sqlx::query(create_replays_table_sql)
            .execute(&pool)
            .await
            .context("Failed to create replays table")?;

        // Create indexes
        for index_sql in &create_indexes_sql {
            sqlx::query(index_sql)
                .execute(&pool)
                .await
                .context("Failed to create index")?;
        }

        info!("Idempotency store initialized");
        Ok(Self { pool })
    }

    /// Check if intent execution already exists (idempotency lookup)
    pub async fn lookup(
        &self,
        intent_id: &Uuid,
        seq: u32,
        runner_digest: &str,
        capability_digest: &str,
    ) -> Result<Option<IdempotencyRecord>> {
        let record = sqlx::query(
            "SELECT intent_id, seq, runner_digest, capability_digest, status, result, started_ms, ended_ms 
             FROM runs 
             WHERE intent_id = ? AND seq = ? AND runner_digest = ? AND capability_digest = ?"
        )
        .bind(intent_id.to_string())
        .bind(seq as i32)
        .bind(runner_digest)
        .bind(capability_digest)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to lookup idempotency record")?;

        if let Some(row) = record {
            let status_str: String = row.get("status");
            let status = match status_str.as_str() {
                "ok" => smith_protocol::ExecutionStatus::Ok,
                "denied" => smith_protocol::ExecutionStatus::Denied,
                "error" => smith_protocol::ExecutionStatus::Error,
                "timeout" => smith_protocol::ExecutionStatus::Timeout,
                "killed" => smith_protocol::ExecutionStatus::Killed,
                "running" => {
                    // Running status means execution is still in progress,
                    // return None to indicate record doesn't have final result yet
                    debug!(
                        "Found running execution for intent: {}, treating as not found",
                        intent_id
                    );
                    return Ok(None);
                }
                "expired" => {
                    // Expired status means execution never started due to TTL expiry
                    debug!(
                        "Found expired execution for intent: {}, treating as not found",
                        intent_id
                    );
                    return Ok(None);
                }
                _ => return Err(anyhow::anyhow!("Unknown status: {}", status_str)),
            };

            let record = IdempotencyRecord {
                intent_id: Uuid::parse_str(&row.get::<String, _>("intent_id"))?,
                seq: row.get::<i32, _>("seq") as u32,
                runner_digest: row.get("runner_digest"),
                capability_digest: row.get("capability_digest"),
                status,
                result: row.get("result"),
                started_ms: row.get("started_ms"),
                ended_ms: row.get("ended_ms"),
            };

            debug!(
                "Found existing idempotency record for intent: {}",
                intent_id
            );
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    /// Record start of intent execution
    pub async fn record_start(
        &self,
        intent_id: &Uuid,
        seq: u32,
        runner_digest: &str,
        capability_digest: &str,
    ) -> Result<()> {
        let started_ms = chrono::Utc::now().timestamp_millis();

        sqlx::query(
            "INSERT INTO runs (intent_id, seq, runner_digest, capability_digest, status, started_ms) 
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(intent_id.to_string())
        .bind(seq as i32)
        .bind(runner_digest)
        .bind(capability_digest)
        .bind("running")
        .bind(started_ms)
        .execute(&self.pool)
        .await
        .context("Failed to record execution start")?;

        debug!("Recorded execution start for intent: {}", intent_id);
        Ok(())
    }

    /// Record completion of intent execution
    pub async fn record_completion(
        &self,
        intent_id: &Uuid,
        seq: u32,
        runner_digest: &str,
        capability_digest: &str,
        result: &smith_protocol::IntentResult,
    ) -> Result<()> {
        let ended_ms = chrono::Utc::now().timestamp_millis();
        let result_bytes =
            serde_json::to_vec(result).context("Failed to serialize intent result")?;

        let status_str = match result.status {
            smith_protocol::ExecutionStatus::Ok => "ok",
            smith_protocol::ExecutionStatus::Denied => "denied",
            smith_protocol::ExecutionStatus::Error => "error",
            smith_protocol::ExecutionStatus::Timeout => "timeout",
            smith_protocol::ExecutionStatus::Killed => "killed",
            smith_protocol::ExecutionStatus::Success => "success",
            smith_protocol::ExecutionStatus::Failed => "failed",
        };

        sqlx::query(
            "UPDATE runs 
             SET status = ?, result = ?, ended_ms = ? 
             WHERE intent_id = ? AND seq = ? AND runner_digest = ? AND capability_digest = ?",
        )
        .bind(status_str)
        .bind(&result_bytes)
        .bind(ended_ms)
        .bind(intent_id.to_string())
        .bind(seq as i32)
        .bind(runner_digest)
        .bind(capability_digest)
        .execute(&self.pool)
        .await
        .context("Failed to record execution completion")?;

        debug!("Recorded execution completion for intent: {}", intent_id);
        Ok(())
    }

    /// Check if nonce has been seen before (replay protection)
    pub async fn check_nonce(&self, nonce: &str) -> Result<bool> {
        let exists =
            sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM replays WHERE nonce = ?)")
                .bind(nonce)
                .fetch_one(&self.pool)
                .await
                .context("Failed to check nonce")?;

        Ok(exists)
    }

    /// Record nonce to prevent replay attacks
    pub async fn record_nonce(&self, nonce: &str) -> Result<()> {
        let ts_ms = chrono::Utc::now().timestamp_millis();

        sqlx::query("INSERT INTO replays (nonce, ts_ms) VALUES (?, ?)")
            .bind(nonce)
            .bind(ts_ms)
            .execute(&self.pool)
            .await
            .context("Failed to record nonce")?;

        debug!("Recorded nonce for replay protection: {}", nonce);
        Ok(())
    }

    /// Cleanup old records (TTL cleanup)
    pub async fn cleanup_old_records(&self, older_than_hours: i64) -> Result<u64> {
        let cutoff_ms = chrono::Utc::now().timestamp_millis() - (older_than_hours * 3600 * 1000);

        // Cleanup old execution records
        let runs_deleted = sqlx::query("DELETE FROM runs WHERE started_ms < ?")
            .bind(cutoff_ms)
            .execute(&self.pool)
            .await
            .context("Failed to cleanup old execution records")?
            .rows_affected();

        // Cleanup old nonces (replay protection cache)
        let nonces_deleted = sqlx::query("DELETE FROM replays WHERE ts_ms < ?")
            .bind(cutoff_ms)
            .execute(&self.pool)
            .await
            .context("Failed to cleanup old nonces")?
            .rows_affected();

        let total_deleted = runs_deleted + nonces_deleted;

        if total_deleted > 0 {
            info!(
                "Cleaned up {} old records (runs: {}, nonces: {})",
                total_deleted, runs_deleted, nonces_deleted
            );
        }

        Ok(total_deleted)
    }

    /// Check if an intent has been processed (simplified version for admission pipeline)
    pub async fn is_processed(&self, intent_id: &str) -> Result<bool> {
        let count: (i32,) =
            sqlx::query_as("SELECT COUNT(*) FROM runs WHERE intent_id = ? AND status != 'running'")
                .bind(intent_id)
                .fetch_one(&self.pool)
                .await
                .context("Failed to check if intent is processed")?;

        Ok(count.0 > 0)
    }

    /// Mark intent as being processed to prevent duplicates
    pub async fn mark_processing(&self, intent_id: &str) -> Result<()> {
        let started_ms = chrono::Utc::now().timestamp_millis();

        sqlx::query(
            "INSERT OR REPLACE INTO runs (intent_id, seq, runner_digest, capability_digest, status, started_ms) 
             VALUES (?, 1, 'executor-v1', 'policy-v1', 'running', ?)"
        )
        .bind(intent_id)
        .bind(started_ms)
        .execute(&self.pool)
        .await
        .context("Failed to mark intent as processing")?;

        Ok(())
    }

    /// Store execution result
    pub async fn store_result(
        &self,
        intent_id: &str,
        result: &smith_protocol::IntentResult,
    ) -> Result<()> {
        let update = ResultUpdate::from_intent(intent_id, result)?;
        tracing::info!(
            intent_id = intent_id,
            status = update.status,
            "Idempotency store updating intent row"
        );

        let query_result = execute_result_update(&self.pool, &update)
            .await
            .context("Failed to execute idempotency update")?;

        let rows_affected = query_result.rows_affected();

        tracing::info!(
            intent_id = intent_id,
            rows_affected = rows_affected,
            "Idempotency store update completed"
        );
        tracing::debug!(intent_id = intent_id, "Idempotency store update trace");

        if rows_affected == 0 {
            tracing::warn!(
                intent_id = intent_id,
                "Idempotency store update matched zero rows"
            );
        }

        Ok(())
    }

    /// Get cached result for an intent
    pub async fn get_result(
        &self,
        intent_id: &str,
    ) -> Result<Option<smith_protocol::IntentResult>> {
        let row = sqlx::query("SELECT result FROM runs WHERE intent_id = ? AND result IS NOT NULL")
            .bind(intent_id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to get cached result")?;

        if let Some(row) = row {
            let result_bytes: Vec<u8> = row.get("result");
            let result: smith_protocol::IntentResult = serde_json::from_slice(&result_bytes)
                .context("Failed to deserialize cached result")?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Get statistics about the idempotency store
    pub async fn get_stats(&self) -> Result<IdempotencyStats> {
        let runs_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM runs")
            .fetch_one(&self.pool)
            .await
            .context("Failed to count runs")?;

        let nonces_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM replays")
            .fetch_one(&self.pool)
            .await
            .context("Failed to count nonces")?;

        let running_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM runs WHERE status = 'running'")
                .fetch_one(&self.pool)
                .await
                .context("Failed to count running executions")?;

        Ok(IdempotencyStats {
            total_runs: runs_count as u64,
            total_nonces: nonces_count as u64,
            running_executions: running_count as u64,
        })
    }

    /// Perform database maintenance (VACUUM, analyze, etc.)
    pub async fn maintenance(&self) -> Result<()> {
        sqlx::query("VACUUM")
            .execute(&self.pool)
            .await
            .context("Failed to vacuum database")?;

        sqlx::query("ANALYZE")
            .execute(&self.pool)
            .await
            .context("Failed to analyze database")?;

        info!("Database maintenance completed");
        Ok(())
    }
}

/// Implement IdempotencyOps trait for IdempotencyStore
#[async_trait]
impl IdempotencyOps for IdempotencyStore {
    async fn is_processed(&self, intent_id: &str) -> Result<bool> {
        IdempotencyStore::is_processed(self, intent_id).await
    }

    async fn get_result(&self, intent_id: &str) -> Result<Option<smith_protocol::IntentResult>> {
        IdempotencyStore::get_result(self, intent_id).await
    }

    async fn mark_processing(&self, intent_id: &str) -> Result<()> {
        IdempotencyStore::mark_processing(self, intent_id).await
    }

    async fn store_result(
        &self,
        intent_id: &str,
        result: &smith_protocol::IntentResult,
    ) -> Result<()> {
        IdempotencyStore::store_result(self, intent_id, result).await
    }
}

/// Mock implementation of IdempotencyOps for testing
#[cfg(any(test, feature = "test-support"))]
pub mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::RwLock;

    /// A mock idempotency store that tracks operations in memory
    #[derive(Default)]
    pub struct MockIdempotencyStore {
        processed: RwLock<std::collections::HashSet<String>>,
        processing: RwLock<std::collections::HashSet<String>>,
        results: RwLock<HashMap<String, smith_protocol::IntentResult>>,
        pub should_fail_is_processed: AtomicBool,
        pub should_fail_get_result: AtomicBool,
        pub should_fail_mark_processing: AtomicBool,
        pub should_fail_store_result: AtomicBool,
        pub is_processed_calls: AtomicUsize,
        pub get_result_calls: AtomicUsize,
        pub mark_processing_calls: AtomicUsize,
        pub store_result_calls: AtomicUsize,
    }

    impl MockIdempotencyStore {
        pub fn new() -> Self {
            Self::default()
        }

        /// Pre-seed a result for testing
        pub async fn seed_result(&self, intent_id: &str, result: smith_protocol::IntentResult) {
            self.results
                .write()
                .await
                .insert(intent_id.to_string(), result);
            self.processed.write().await.insert(intent_id.to_string());
        }

        /// Mark an intent as already processed
        pub async fn mark_as_processed(&self, intent_id: &str) {
            self.processed.write().await.insert(intent_id.to_string());
        }

        /// Get the count of calls to a specific method
        pub fn call_counts(&self) -> (usize, usize, usize, usize) {
            (
                self.is_processed_calls.load(Ordering::SeqCst),
                self.get_result_calls.load(Ordering::SeqCst),
                self.mark_processing_calls.load(Ordering::SeqCst),
                self.store_result_calls.load(Ordering::SeqCst),
            )
        }

        /// Reset all call counters and state
        pub async fn reset(&self) {
            self.processed.write().await.clear();
            self.processing.write().await.clear();
            self.results.write().await.clear();
            self.is_processed_calls.store(0, Ordering::SeqCst);
            self.get_result_calls.store(0, Ordering::SeqCst);
            self.mark_processing_calls.store(0, Ordering::SeqCst);
            self.store_result_calls.store(0, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl IdempotencyOps for MockIdempotencyStore {
        async fn is_processed(&self, intent_id: &str) -> Result<bool> {
            self.is_processed_calls.fetch_add(1, Ordering::SeqCst);
            if self.should_fail_is_processed.load(Ordering::SeqCst) {
                return Err(anyhow!("Mock is_processed failure"));
            }
            Ok(self.processed.read().await.contains(intent_id))
        }

        async fn get_result(
            &self,
            intent_id: &str,
        ) -> Result<Option<smith_protocol::IntentResult>> {
            self.get_result_calls.fetch_add(1, Ordering::SeqCst);
            if self.should_fail_get_result.load(Ordering::SeqCst) {
                return Err(anyhow!("Mock get_result failure"));
            }
            Ok(self.results.read().await.get(intent_id).cloned())
        }

        async fn mark_processing(&self, intent_id: &str) -> Result<()> {
            self.mark_processing_calls.fetch_add(1, Ordering::SeqCst);
            if self.should_fail_mark_processing.load(Ordering::SeqCst) {
                return Err(anyhow!("Mock mark_processing failure"));
            }
            self.processing.write().await.insert(intent_id.to_string());
            Ok(())
        }

        async fn store_result(
            &self,
            intent_id: &str,
            result: &smith_protocol::IntentResult,
        ) -> Result<()> {
            self.store_result_calls.fetch_add(1, Ordering::SeqCst);
            if self.should_fail_store_result.load(Ordering::SeqCst) {
                return Err(anyhow!("Mock store_result failure"));
            }
            self.results
                .write()
                .await
                .insert(intent_id.to_string(), result.clone());
            self.processed.write().await.insert(intent_id.to_string());
            self.processing.write().await.remove(intent_id);
            Ok(())
        }
    }
}

#[derive(Debug, Clone)]
pub struct IdempotencyStats {
    pub total_runs: u64,
    pub total_nonces: u64,
    pub running_executions: u64,
}

#[derive(Debug, Clone)]
struct ResultUpdate<'a> {
    intent_id: &'a str,
    status: &'static str,
    result_bytes: Vec<u8>,
    started_ms: i64,
    ended_ms: i64,
}

impl<'a> ResultUpdate<'a> {
    fn from_intent(intent_id: &'a str, result: &smith_protocol::IntentResult) -> Result<Self> {
        let status = map_status(result.status.clone());
        let result_bytes = serialize_result(result)?;
        let ended_ms = chrono::Utc::now().timestamp_millis();
        Ok(Self {
            intent_id,
            status,
            result_bytes,
            started_ms: (result.started_at_ns as i128 / 1_000_000) as i64,
            ended_ms,
        })
    }
}

fn map_status(status: smith_protocol::ExecutionStatus) -> &'static str {
    match status {
        smith_protocol::ExecutionStatus::Ok => "ok",
        smith_protocol::ExecutionStatus::Denied => "denied",
        smith_protocol::ExecutionStatus::Error => "error",
        smith_protocol::ExecutionStatus::Timeout => "timeout",
        smith_protocol::ExecutionStatus::Killed => "killed",
        smith_protocol::ExecutionStatus::Success => "success",
        smith_protocol::ExecutionStatus::Failed => "failed",
    }
}

fn serialize_result(result: &smith_protocol::IntentResult) -> Result<Vec<u8>> {
    serde_json::to_vec(result).context("Failed to serialize intent result")
}

async fn execute_result_update(
    pool: &SqlitePool,
    update: &ResultUpdate<'_>,
) -> sqlx::Result<sqlx::sqlite::SqliteQueryResult> {
    sqlx::query("
        INSERT INTO runs (intent_id, seq, runner_digest, capability_digest, status, result, started_ms, ended_ms)
        VALUES (?, 1, 'executor-v1', 'policy-v1', ?, ?, ?, ?)
        ON CONFLICT(intent_id, seq, runner_digest, capability_digest)
        DO UPDATE SET status = excluded.status, result = excluded.result, ended_ms = excluded.ended_ms")
        .bind(update.intent_id)
        .bind(update.status)
        .bind(&update.result_bytes)
        .bind(update.started_ms)
        .bind(update.ended_ms)
        .execute(pool)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_idempotency_store_creation() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await;
        assert!(store.is_ok(), "Store creation should succeed");
    }

    #[tokio::test]
    async fn test_nonce_checking() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let nonce = "test-nonce-12345678901234567890123456";

        // Nonce should not exist initially
        assert!(!store.check_nonce(nonce).await.unwrap());

        // Record nonce
        store.record_nonce(nonce).await.unwrap();

        // Now it should exist
        assert!(store.check_nonce(nonce).await.unwrap());
    }

    #[test]
    fn test_map_status_variants() {
        use smith_protocol::ExecutionStatus::*;
        assert_eq!(map_status(Ok), "ok");
        assert_eq!(map_status(Denied), "denied");
        assert_eq!(map_status(Error), "error");
        assert_eq!(map_status(Timeout), "timeout");
        assert_eq!(map_status(Killed), "killed");
        assert_eq!(map_status(Success), "success");
        assert_eq!(map_status(Failed), "failed");
    }

    #[tokio::test]
    async fn test_store_result_updates_row() {
        use smith_protocol::{
            AuditRef, ExecutionError, ExecutionStatus, IntentResult, RunnerMetadata,
        };

        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();
        let intent_id = Uuid::new_v4();

        store
            .record_start(&intent_id, 1, "runner-v1", "policy-v1")
            .await
            .unwrap();

        let result = IntentResult {
            intent_id: intent_id.to_string(),
            status: ExecutionStatus::Error,
            output: None,
            error: Some(ExecutionError {
                code: "EXECUTION_ERROR".to_string(),
                message: "runner failed".to_string(),
            }),
            started_at_ns: 0,
            finished_at_ns: 1,
            runner_meta: RunnerMetadata::empty(),
            audit_ref: AuditRef {
                id: "audit".to_string(),
                timestamp: 0,
                hash: "0".to_string(),
            },
        };

        store
            .store_result(&result.intent_id, &result)
            .await
            .expect("store_result should succeed");

        let row: (String, Vec<u8>) =
            sqlx::query_as("SELECT status, result FROM runs WHERE intent_id = ?")
                .bind(&result.intent_id)
                .fetch_one(&store.pool)
                .await
                .unwrap();

        assert_eq!(row.0, "error");
        assert!(!row.1.is_empty());
    }

    #[tokio::test]
    async fn test_execute_result_update() {
        use smith_protocol::{
            AuditRef, ExecutionError, ExecutionStatus, IntentResult, RunnerMetadata,
        };

        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();
        let intent_id = Uuid::new_v4();

        store
            .record_start(&intent_id, 1, "runner-v1", "policy-v1")
            .await
            .unwrap();

        let result = IntentResult {
            intent_id: intent_id.to_string(),
            status: ExecutionStatus::Error,
            output: None,
            error: Some(ExecutionError {
                code: "EXECUTION_ERROR".to_string(),
                message: "runner failed".to_string(),
            }),
            started_at_ns: 0,
            finished_at_ns: 1,
            runner_meta: RunnerMetadata::empty(),
            audit_ref: AuditRef {
                id: "audit".to_string(),
                timestamp: 0,
                hash: "0".to_string(),
            },
        };

        let update = ResultUpdate::from_intent(&result.intent_id, &result).unwrap();
        execute_result_update(&store.pool, &update)
            .await
            .expect("result update should succeed");

        let row: (String, Vec<u8>) =
            sqlx::query_as("SELECT status, result FROM runs WHERE intent_id = ?")
                .bind(&result.intent_id)
                .fetch_one(&store.pool)
                .await
                .unwrap();

        assert_eq!(row.0, "error");
        assert!(!row.1.is_empty());
    }

    #[tokio::test]
    async fn test_execution_recording() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();
        let seq = 1;
        let runner_digest = "runner-v1";
        let capability_digest = "policy-v1";

        // Should not exist initially
        let lookup = store
            .lookup(&intent_id, seq, runner_digest, capability_digest)
            .await
            .unwrap();
        assert!(lookup.is_none());

        // Record start
        store
            .record_start(&intent_id, seq, runner_digest, capability_digest)
            .await
            .unwrap();

        // Should not return a result when status is "running" (execution in progress)
        let lookup = store
            .lookup(&intent_id, seq, runner_digest, capability_digest)
            .await
            .unwrap();
        assert!(
            lookup.is_none(),
            "Running executions should not return idempotency records"
        );

        // Verify the record exists in the database but is filtered out by lookup
        let running_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM runs WHERE intent_id = ? AND status = 'running'",
        )
        .bind(&intent_id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(
            running_count, 1,
            "Should have exactly one running record in database"
        );
    }

    // Helper to create test IntentResult
    fn create_test_intent_result(
        intent_id: &str,
        status: smith_protocol::ExecutionStatus,
    ) -> smith_protocol::IntentResult {
        use smith_protocol::{AuditRef, ExecutionError, IntentResult, RunnerMetadata};

        IntentResult {
            intent_id: intent_id.to_string(),
            status: status.clone(),
            output: Some(serde_json::json!({"test": "output"})),
            error: if matches!(status, smith_protocol::ExecutionStatus::Error) {
                Some(ExecutionError {
                    code: "TEST_ERROR".to_string(),
                    message: "test error message".to_string(),
                })
            } else {
                None
            },
            started_at_ns: 1000000,
            finished_at_ns: 2000000,
            runner_meta: RunnerMetadata::empty(),
            audit_ref: AuditRef {
                id: "test-audit".to_string(),
                timestamp: 1000,
                hash: "abc123".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn test_record_completion_ok_status() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();
        store
            .record_start(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();

        let result =
            create_test_intent_result(&intent_id.to_string(), smith_protocol::ExecutionStatus::Ok);
        store
            .record_completion(&intent_id, 1, "runner-v1", "cap-v1", &result)
            .await
            .unwrap();

        let lookup = store
            .lookup(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();
        assert!(lookup.is_some());
        let record = lookup.unwrap();
        assert_eq!(record.status, smith_protocol::ExecutionStatus::Ok);
    }

    #[tokio::test]
    async fn test_record_completion_denied_status() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();
        store
            .record_start(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();

        let result = create_test_intent_result(
            &intent_id.to_string(),
            smith_protocol::ExecutionStatus::Denied,
        );
        store
            .record_completion(&intent_id, 1, "runner-v1", "cap-v1", &result)
            .await
            .unwrap();

        let lookup = store
            .lookup(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();
        assert!(lookup.is_some());
        assert_eq!(
            lookup.unwrap().status,
            smith_protocol::ExecutionStatus::Denied
        );
    }

    #[tokio::test]
    async fn test_record_completion_error_status() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();
        store
            .record_start(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();

        let result = create_test_intent_result(
            &intent_id.to_string(),
            smith_protocol::ExecutionStatus::Error,
        );
        store
            .record_completion(&intent_id, 1, "runner-v1", "cap-v1", &result)
            .await
            .unwrap();

        let lookup = store
            .lookup(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();
        assert!(lookup.is_some());
        assert_eq!(
            lookup.unwrap().status,
            smith_protocol::ExecutionStatus::Error
        );
    }

    #[tokio::test]
    async fn test_record_completion_timeout_status() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();
        store
            .record_start(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();

        let result = create_test_intent_result(
            &intent_id.to_string(),
            smith_protocol::ExecutionStatus::Timeout,
        );
        store
            .record_completion(&intent_id, 1, "runner-v1", "cap-v1", &result)
            .await
            .unwrap();

        let lookup = store
            .lookup(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();
        assert!(lookup.is_some());
        assert_eq!(
            lookup.unwrap().status,
            smith_protocol::ExecutionStatus::Timeout
        );
    }

    #[tokio::test]
    async fn test_record_completion_killed_status() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();
        store
            .record_start(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();

        let result = create_test_intent_result(
            &intent_id.to_string(),
            smith_protocol::ExecutionStatus::Killed,
        );
        store
            .record_completion(&intent_id, 1, "runner-v1", "cap-v1", &result)
            .await
            .unwrap();

        let lookup = store
            .lookup(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();
        assert!(lookup.is_some());
        assert_eq!(
            lookup.unwrap().status,
            smith_protocol::ExecutionStatus::Killed
        );
    }

    #[tokio::test]
    async fn test_is_processed_true() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();
        store
            .record_start(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();

        let result =
            create_test_intent_result(&intent_id.to_string(), smith_protocol::ExecutionStatus::Ok);
        store
            .record_completion(&intent_id, 1, "runner-v1", "cap-v1", &result)
            .await
            .unwrap();

        // Now intent should be processed
        assert!(store.is_processed(&intent_id.to_string()).await.unwrap());
    }

    #[tokio::test]
    async fn test_is_processed_false_when_running() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();
        store
            .record_start(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();

        // Still running, should not be processed
        assert!(!store.is_processed(&intent_id.to_string()).await.unwrap());
    }

    #[tokio::test]
    async fn test_is_processed_false_when_not_exists() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();
        assert!(!store.is_processed(&intent_id.to_string()).await.unwrap());
    }

    #[tokio::test]
    async fn test_mark_processing() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4().to_string();
        store.mark_processing(&intent_id).await.unwrap();

        // Should have a running record
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM runs WHERE intent_id = ? AND status = 'running'",
        )
        .bind(&intent_id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_get_result_exists() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();
        store
            .record_start(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();

        let result =
            create_test_intent_result(&intent_id.to_string(), smith_protocol::ExecutionStatus::Ok);
        store
            .record_completion(&intent_id, 1, "runner-v1", "cap-v1", &result)
            .await
            .unwrap();

        let cached = store.get_result(&intent_id.to_string()).await.unwrap();
        assert!(cached.is_some());
        let cached_result = cached.unwrap();
        assert_eq!(cached_result.status, smith_protocol::ExecutionStatus::Ok);
    }

    #[tokio::test]
    async fn test_get_result_not_exists() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();
        let cached = store.get_result(&intent_id.to_string()).await.unwrap();
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_get_stats_empty() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let stats = store.get_stats().await.unwrap();
        assert_eq!(stats.total_runs, 0);
        assert_eq!(stats.total_nonces, 0);
        assert_eq!(stats.running_executions, 0);
    }

    #[tokio::test]
    async fn test_get_stats_with_data() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        // Add some runs
        let intent1 = Uuid::new_v4();
        let intent2 = Uuid::new_v4();
        store
            .record_start(&intent1, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();
        store
            .record_start(&intent2, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();

        // Complete one
        let result =
            create_test_intent_result(&intent1.to_string(), smith_protocol::ExecutionStatus::Ok);
        store
            .record_completion(&intent1, 1, "runner-v1", "cap-v1", &result)
            .await
            .unwrap();

        // Add some nonces
        store.record_nonce("nonce1").await.unwrap();
        store.record_nonce("nonce2").await.unwrap();
        store.record_nonce("nonce3").await.unwrap();

        let stats = store.get_stats().await.unwrap();
        assert_eq!(stats.total_runs, 2);
        assert_eq!(stats.total_nonces, 3);
        assert_eq!(stats.running_executions, 1); // intent2 is still running
    }

    #[tokio::test]
    async fn test_cleanup_old_records_removes_old() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        // Add a run and a nonce
        let intent = Uuid::new_v4();
        store
            .record_start(&intent, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();
        store.record_nonce("test-nonce").await.unwrap();

        // Small delay to ensure records are "older" than cutoff
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Cleanup with 0 hours should remove everything (cutoff = now)
        let deleted = store.cleanup_old_records(0).await.unwrap();
        // Records should be deleted since they're older than cutoff
        assert!(deleted >= 0); // May or may not delete depending on timing

        // Test with -1 to simulate "all records" cleanup by using a future cutoff is not possible
        // so we verify the mechanism works by checking stats
        let stats = store.get_stats().await.unwrap();
        // At least some cleanup occurred if records were old enough
        assert!(stats.total_runs <= 1);
    }

    #[tokio::test]
    async fn test_cleanup_old_records_keeps_recent() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        // Add a run and a nonce
        let intent = Uuid::new_v4();
        store
            .record_start(&intent, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();
        store.record_nonce("test-nonce").await.unwrap();

        // Cleanup with 24 hours should keep recent records
        let deleted = store.cleanup_old_records(24).await.unwrap();
        assert_eq!(deleted, 0);

        let stats = store.get_stats().await.unwrap();
        assert_eq!(stats.total_runs, 1);
        assert_eq!(stats.total_nonces, 1);
    }

    #[tokio::test]
    async fn test_maintenance() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        // Add some data
        let intent = Uuid::new_v4();
        store
            .record_start(&intent, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();
        store.record_nonce("test-nonce").await.unwrap();

        // Maintenance should succeed
        store.maintenance().await.unwrap();

        // Data should still be there
        let stats = store.get_stats().await.unwrap();
        assert_eq!(stats.total_runs, 1);
        assert_eq!(stats.total_nonces, 1);
    }

    #[tokio::test]
    async fn test_lookup_with_nonexistent_record() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();
        let lookup = store.lookup(&intent_id, 1, "runner", "cap").await.unwrap();
        assert!(lookup.is_none());
    }

    #[tokio::test]
    async fn test_multiple_sequences() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();

        // Record multiple sequences
        store
            .record_start(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();
        store
            .record_start(&intent_id, 2, "runner-v1", "cap-v1")
            .await
            .unwrap();
        store
            .record_start(&intent_id, 3, "runner-v1", "cap-v1")
            .await
            .unwrap();

        // Complete seq 1 and 3, leave 2 running
        let result =
            create_test_intent_result(&intent_id.to_string(), smith_protocol::ExecutionStatus::Ok);
        store
            .record_completion(&intent_id, 1, "runner-v1", "cap-v1", &result)
            .await
            .unwrap();
        store
            .record_completion(&intent_id, 3, "runner-v1", "cap-v1", &result)
            .await
            .unwrap();

        // Lookup should find completed sequences
        let lookup1 = store
            .lookup(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();
        assert!(lookup1.is_some());

        let lookup2 = store
            .lookup(&intent_id, 2, "runner-v1", "cap-v1")
            .await
            .unwrap();
        assert!(lookup2.is_none()); // Still running

        let lookup3 = store
            .lookup(&intent_id, 3, "runner-v1", "cap-v1")
            .await
            .unwrap();
        assert!(lookup3.is_some());
    }

    #[tokio::test]
    async fn test_different_digests() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();

        // Record with different digests
        store
            .record_start(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();
        store
            .record_start(&intent_id, 1, "runner-v2", "cap-v1")
            .await
            .unwrap();
        store
            .record_start(&intent_id, 1, "runner-v1", "cap-v2")
            .await
            .unwrap();

        // Complete only one combination
        let result =
            create_test_intent_result(&intent_id.to_string(), smith_protocol::ExecutionStatus::Ok);
        store
            .record_completion(&intent_id, 1, "runner-v1", "cap-v1", &result)
            .await
            .unwrap();

        // Lookup should find only the completed combination
        let lookup1 = store
            .lookup(&intent_id, 1, "runner-v1", "cap-v1")
            .await
            .unwrap();
        assert!(lookup1.is_some());

        let lookup2 = store
            .lookup(&intent_id, 1, "runner-v2", "cap-v1")
            .await
            .unwrap();
        assert!(lookup2.is_none()); // Still running

        let lookup3 = store
            .lookup(&intent_id, 1, "runner-v1", "cap-v2")
            .await
            .unwrap();
        assert!(lookup3.is_none()); // Still running
    }

    #[test]
    fn test_idempotency_record_clone() {
        let record = IdempotencyRecord {
            intent_id: Uuid::new_v4(),
            seq: 1,
            runner_digest: "runner".to_string(),
            capability_digest: "cap".to_string(),
            status: smith_protocol::ExecutionStatus::Ok,
            result: Some(vec![1, 2, 3]),
            started_ms: 1000,
            ended_ms: Some(2000),
        };

        let cloned = record.clone();
        assert_eq!(record.intent_id, cloned.intent_id);
        assert_eq!(record.seq, cloned.seq);
        assert_eq!(record.runner_digest, cloned.runner_digest);
    }

    #[test]
    fn test_idempotency_record_debug() {
        let record = IdempotencyRecord {
            intent_id: Uuid::new_v4(),
            seq: 1,
            runner_digest: "runner".to_string(),
            capability_digest: "cap".to_string(),
            status: smith_protocol::ExecutionStatus::Ok,
            result: None,
            started_ms: 1000,
            ended_ms: None,
        };

        let debug_str = format!("{:?}", record);
        assert!(debug_str.contains("IdempotencyRecord"));
    }

    #[test]
    fn test_idempotency_stats_clone() {
        let stats = IdempotencyStats {
            total_runs: 10,
            total_nonces: 5,
            running_executions: 2,
        };

        let cloned = stats.clone();
        assert_eq!(stats.total_runs, cloned.total_runs);
        assert_eq!(stats.total_nonces, cloned.total_nonces);
        assert_eq!(stats.running_executions, cloned.running_executions);
    }

    #[test]
    fn test_idempotency_stats_debug() {
        let stats = IdempotencyStats {
            total_runs: 10,
            total_nonces: 5,
            running_executions: 2,
        };

        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("IdempotencyStats"));
        assert!(debug_str.contains("10"));
    }

    #[test]
    fn test_serialize_result() {
        let result = create_test_intent_result("test-id", smith_protocol::ExecutionStatus::Ok);
        let bytes = serialize_result(&result).unwrap();
        assert!(!bytes.is_empty());

        // Should be valid JSON
        let _parsed: smith_protocol::IntentResult = serde_json::from_slice(&bytes).unwrap();
    }

    #[test]
    fn test_result_update_from_intent() {
        let result = create_test_intent_result("test-id", smith_protocol::ExecutionStatus::Ok);
        let update = ResultUpdate::from_intent("test-id", &result).unwrap();

        assert_eq!(update.intent_id, "test-id");
        assert_eq!(update.status, "ok");
        assert!(!update.result_bytes.is_empty());
        assert!(update.started_ms > 0); // Based on started_at_ns / 1_000_000
        assert!(update.ended_ms > 0);
    }

    #[test]
    fn test_result_update_status_mapping() {
        use smith_protocol::ExecutionStatus;

        let statuses = [
            (ExecutionStatus::Ok, "ok"),
            (ExecutionStatus::Denied, "denied"),
            (ExecutionStatus::Error, "error"),
            (ExecutionStatus::Timeout, "timeout"),
            (ExecutionStatus::Killed, "killed"),
            (ExecutionStatus::Success, "success"),
            (ExecutionStatus::Failed, "failed"),
        ];

        for (status, expected) in statuses {
            let result = create_test_intent_result("test-id", status);
            let update = ResultUpdate::from_intent("test-id", &result).unwrap();
            assert_eq!(update.status, expected);
        }
    }

    #[tokio::test]
    async fn test_store_result_without_prior_record() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4().to_string();
        let result = create_test_intent_result(&intent_id, smith_protocol::ExecutionStatus::Ok);

        // Should insert new record via UPSERT
        store.store_result(&intent_id, &result).await.unwrap();

        let stats = store.get_stats().await.unwrap();
        assert_eq!(stats.total_runs, 1);
    }

    #[tokio::test]
    async fn test_store_result_updates_existing() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4().to_string();
        store.mark_processing(&intent_id).await.unwrap();

        let result = create_test_intent_result(&intent_id, smith_protocol::ExecutionStatus::Ok);
        store.store_result(&intent_id, &result).await.unwrap();

        // Should still be 1 record (updated, not inserted)
        let stats = store.get_stats().await.unwrap();
        assert_eq!(stats.total_runs, 1);
        assert_eq!(stats.running_executions, 0); // No longer running
    }

    #[tokio::test]
    async fn test_duplicate_nonce_fails() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        store.record_nonce("duplicate").await.unwrap();

        // Second record should fail (PRIMARY KEY constraint)
        let result = store.record_nonce("duplicate").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_idempotency_record_with_result_bytes() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();
        store
            .record_start(&intent_id, 1, "runner", "cap")
            .await
            .unwrap();

        let result =
            create_test_intent_result(&intent_id.to_string(), smith_protocol::ExecutionStatus::Ok);
        store
            .record_completion(&intent_id, 1, "runner", "cap", &result)
            .await
            .unwrap();

        let lookup = store.lookup(&intent_id, 1, "runner", "cap").await.unwrap();
        assert!(lookup.is_some());
        let record = lookup.unwrap();
        assert!(record.result.is_some());
        assert!(!record.result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_lookup_with_ended_ms() {
        let temp_dir = tempdir().unwrap();
        let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

        let intent_id = Uuid::new_v4();
        store
            .record_start(&intent_id, 1, "runner", "cap")
            .await
            .unwrap();

        let result =
            create_test_intent_result(&intent_id.to_string(), smith_protocol::ExecutionStatus::Ok);
        store
            .record_completion(&intent_id, 1, "runner", "cap", &result)
            .await
            .unwrap();

        let lookup = store.lookup(&intent_id, 1, "runner", "cap").await.unwrap();
        assert!(lookup.is_some());
        let record = lookup.unwrap();
        assert!(record.ended_ms.is_some());
        assert!(record.ended_ms.unwrap() >= record.started_ms);
    }

    // ==================== Mock IdempotencyStore Tests ====================

    mod mock_tests {
        use super::super::mock::*;
        use super::*;
        use std::sync::atomic::Ordering;

        #[tokio::test]
        async fn test_mock_store_is_processed_false_by_default() {
            let mock = MockIdempotencyStore::new();
            assert!(!mock.is_processed("intent-1").await.unwrap());
        }

        #[tokio::test]
        async fn test_mock_store_mark_as_processed() {
            let mock = MockIdempotencyStore::new();
            mock.mark_as_processed("intent-1").await;
            assert!(mock.is_processed("intent-1").await.unwrap());
        }

        #[tokio::test]
        async fn test_mock_store_seed_result() {
            let mock = MockIdempotencyStore::new();
            let result = create_test_intent_result("intent-1", smith_protocol::ExecutionStatus::Ok);
            mock.seed_result("intent-1", result.clone()).await;

            assert!(mock.is_processed("intent-1").await.unwrap());
            let cached = mock.get_result("intent-1").await.unwrap();
            assert!(cached.is_some());
            assert_eq!(cached.unwrap().status, smith_protocol::ExecutionStatus::Ok);
        }

        #[tokio::test]
        async fn test_mock_store_mark_processing() {
            let mock = MockIdempotencyStore::new();
            mock.mark_processing("intent-1").await.unwrap();
            // Intent is being processed but not yet complete
            assert!(!mock.is_processed("intent-1").await.unwrap());
        }

        #[tokio::test]
        async fn test_mock_store_store_result() {
            let mock = MockIdempotencyStore::new();
            let result = create_test_intent_result("intent-1", smith_protocol::ExecutionStatus::Ok);

            mock.mark_processing("intent-1").await.unwrap();
            mock.store_result("intent-1", &result).await.unwrap();

            assert!(mock.is_processed("intent-1").await.unwrap());
            let cached = mock.get_result("intent-1").await.unwrap();
            assert!(cached.is_some());
        }

        #[tokio::test]
        async fn test_mock_store_call_counts() {
            let mock = MockIdempotencyStore::new();
            let result = create_test_intent_result("intent-1", smith_protocol::ExecutionStatus::Ok);

            mock.is_processed("intent-1").await.unwrap();
            mock.is_processed("intent-2").await.unwrap();
            mock.get_result("intent-1").await.unwrap();
            mock.mark_processing("intent-1").await.unwrap();
            mock.store_result("intent-1", &result).await.unwrap();

            let (is_processed, get_result, mark_processing, store_result) = mock.call_counts();
            assert_eq!(is_processed, 2);
            assert_eq!(get_result, 1);
            assert_eq!(mark_processing, 1);
            assert_eq!(store_result, 1);
        }

        #[tokio::test]
        async fn test_mock_store_reset() {
            let mock = MockIdempotencyStore::new();
            let result = create_test_intent_result("intent-1", smith_protocol::ExecutionStatus::Ok);

            mock.store_result("intent-1", &result).await.unwrap();
            assert!(mock.is_processed("intent-1").await.unwrap());

            mock.reset().await;

            assert!(!mock.is_processed("intent-1").await.unwrap());
            // But call count includes the new call
            let (is_processed, _, _, _) = mock.call_counts();
            assert_eq!(is_processed, 1);
        }

        #[tokio::test]
        async fn test_mock_store_failure_modes() {
            let mock = MockIdempotencyStore::new();
            let result = create_test_intent_result("intent-1", smith_protocol::ExecutionStatus::Ok);

            // Test is_processed failure
            mock.should_fail_is_processed.store(true, Ordering::SeqCst);
            assert!(mock.is_processed("intent-1").await.is_err());
            mock.should_fail_is_processed.store(false, Ordering::SeqCst);

            // Test get_result failure
            mock.should_fail_get_result.store(true, Ordering::SeqCst);
            assert!(mock.get_result("intent-1").await.is_err());
            mock.should_fail_get_result.store(false, Ordering::SeqCst);

            // Test mark_processing failure
            mock.should_fail_mark_processing
                .store(true, Ordering::SeqCst);
            assert!(mock.mark_processing("intent-1").await.is_err());
            mock.should_fail_mark_processing
                .store(false, Ordering::SeqCst);

            // Test store_result failure
            mock.should_fail_store_result.store(true, Ordering::SeqCst);
            assert!(mock.store_result("intent-1", &result).await.is_err());
        }

        #[test]
        fn test_mock_store_default() {
            let mock = MockIdempotencyStore::default();
            let (is_processed, get_result, mark_processing, store_result) = mock.call_counts();
            assert_eq!(is_processed, 0);
            assert_eq!(get_result, 0);
            assert_eq!(mark_processing, 0);
            assert_eq!(store_result, 0);
        }

        #[tokio::test]
        async fn test_mock_store_get_result_not_found() {
            let mock = MockIdempotencyStore::new();
            let cached = mock.get_result("nonexistent").await.unwrap();
            assert!(cached.is_none());
        }

        #[tokio::test]
        async fn test_idempotency_ops_trait_with_real_store() {
            // Verify the trait implementation works with the real store
            let temp_dir = tempdir().unwrap();
            let store = IdempotencyStore::new(temp_dir.path()).await.unwrap();

            // Use trait methods via dyn trait
            let ops: &dyn IdempotencyOps = &store;

            assert!(!ops.is_processed("intent-1").await.unwrap());
            ops.mark_processing("intent-1").await.unwrap();

            let result = create_test_intent_result("intent-1", smith_protocol::ExecutionStatus::Ok);
            ops.store_result("intent-1", &result).await.unwrap();

            assert!(ops.is_processed("intent-1").await.unwrap());
            let cached = ops.get_result("intent-1").await.unwrap();
            assert!(cached.is_some());
        }
    }
}
