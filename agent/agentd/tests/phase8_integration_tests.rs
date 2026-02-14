// Integration tests for Phase 8 Extended Capabilities - CURRENTLY DISABLED
// Tests security boundaries, resource quotas, and sandbox integration
// NOTE: Archive capability tests are disabled because ArchiveReadV1Capability doesn't exist yet
/*
#[cfg(test)]
mod tests {
    #![allow(unexpected_cfgs)]
    use super::super::*;
    use crate::capability::{Capability, ExecCtx, ExecutionLimits, ExecutionScope, SandboxConfig};
    use serde_json::json;
    use smith_protocol::{Capability as ProtoCapability, Intent, SandboxMode};
    use std::collections::HashMap;
    use std::io::Write;
    use tempfile::TempDir;
    use tokio::fs;

    /// Test helper to create a basic execution context
    fn create_test_context(workdir: std::path::PathBuf, sandbox_mode: SandboxMode) -> ExecCtx {
        ExecCtx {
            workdir,
            limits: ExecutionLimits::default(),
            scope: ExecutionScope::default(),
            trace_id: "test-trace".to_string(),
            sandbox: SandboxConfig {
                mode: sandbox_mode,
                landlock_enabled: true,
                seccomp_enabled: true,
                cgroups_enabled: true,
                namespaces_enabled: true,
            },
        }
    }

    /// Test helper to create a context with custom scope
    fn create_test_context_with_scope(
        workdir: std::path::PathBuf,
        sandbox_mode: SandboxMode,
        custom_scope: HashMap<String, serde_json::Value>,
    ) -> ExecCtx {
        ExecCtx {
            workdir,
            limits: ExecutionLimits::default(),
            scope: ExecutionScope {
                paths: vec![],
                urls: vec![],
                env_vars: vec![],
                custom: custom_scope,
            },
            trace_id: "test-trace".to_string(),
            sandbox: SandboxConfig {
                mode: sandbox_mode,
                landlock_enabled: true,
                seccomp_enabled: true,
                cgroups_enabled: true,
                namespaces_enabled: true,
            },
        }
    }

    #[tokio::test]
    #[ignore]  // Archive capability is disabled - waiting for implementation
    async fn test_archive_read_security_boundaries() {
        let capability = archive_read_v1::ArchiveReadV1Capability::new();
        let temp_dir = TempDir::new().unwrap();

        // Create a malicious ZIP file with path traversal
        let zip_path = temp_dir.path().join("malicious.zip");

        // Use zip crate to create a ZIP with a malicious entry
        let zip_file = std::fs::File::create(&zip_path).unwrap();
        let mut zip_writer = zip::ZipWriter::new(zip_file);

        let options =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        // Add malicious entry with path traversal
        zip_writer
            .start_file("../../../etc/passwd", options)
            .unwrap();
        zip_writer.write_all(b"malicious content").unwrap();
        zip_writer.finish().unwrap();

        // Create intent to read the malicious archive
        let intent = Intent::new(
            ProtoCapability::ArchiveReadV1,
            "test".to_string(),
            json!({
                "path": "malicious.zip",
                "extract_content": true
            }),
            30000,
            "test-signer".to_string(),
        );

        let mut custom_scope = HashMap::new();
        custom_scope.insert("allow_archives".to_string(), serde_json::Value::Bool(true));
        let ctx = create_test_context_with_scope(temp_dir.path().to_path_buf(), SandboxMode::Full, custom_scope);

        // Should fail due to path traversal detection
        let result = capability.execute(intent, ctx).await;
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert_eq!(error.code, "ARCHIVE_PROCESSING_ERROR");
        assert!(error.message.contains("unsafe path"));
    }

    #[tokio::test]
    #[ignore]  // Archive capability is disabled - waiting for implementation
    async fn test_archive_read_size_limits() {
        let capability = archive_read_v1::ArchiveReadV1Capability::with_quotas(
            1024, // 1KB max archive size
            10,   // 10 max entries
            512,  // 512 bytes max entry size
            2048, // 2KB max total uncompressed
        );
        let temp_dir = TempDir::new().unwrap();

        // Create a ZIP file that exceeds size limits
        let zip_path = temp_dir.path().join("large.zip");
        let large_content = "x".repeat(2048); // 2KB content

        fs::write(&zip_path, large_content).await.unwrap();

        let intent = Intent::new(
            ProtoCapability::ArchiveReadV1,
            "test".to_string(),
            json!({
                "path": "large.zip"
            }),
            30000,
            "test-signer".to_string(),
        );

        let ctx = create_test_context(temp_dir.path().to_path_buf(), SandboxMode::Demo);

        // Should fail due to size limits
        let result = capability.execute(intent, ctx).await;
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert_eq!(error.code, "ARCHIVE_TOO_LARGE");
    }

    #[tokio::test]
    #[ignore]  // Archive capability is disabled - waiting for implementation
    async fn test_archive_read_strict_security_mode() {
        let capability = archive_read_v1::ArchiveReadV1Capability::new();
        let temp_dir = TempDir::new().unwrap();

        // Create a valid ZIP file
        let zip_path = temp_dir.path().join("valid.zip");
        let zip_file = std::fs::File::create(&zip_path).unwrap();
        let mut zip_writer = zip::ZipWriter::new(zip_file);

        let options = zip::write::FileOptions::default();
        zip_writer.start_file("test.txt", options).unwrap();
        zip_writer.write_all(b"test content").unwrap();
        zip_writer.finish().unwrap();

        let intent = Intent::new(
            ProtoCapability::ArchiveReadV1,
            "test".to_string(),
            json!({
                "path": "valid.zip"
            }),
            30000,
            "test-signer".to_string(),
        );

        // Test strict mode without explicit archive permission - should fail
        let ctx_strict = create_test_context(temp_dir.path().to_path_buf(), SandboxMode::Full);
        let result = capability.execute(intent.clone(), ctx_strict).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "ARCHIVE_DENIED_STRICT_MODE");

        // Test strict mode with explicit archive permission - should succeed
        let mut custom_scope = HashMap::new();
        custom_scope.insert("allow_archives".to_string(), json!(true));
        let ctx_allowed = create_test_context_with_scope(
            temp_dir.path().to_path_buf(),
            SandboxMode::Full,
            custom_scope,
        );
        let result = capability.execute(intent, ctx_allowed).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sqlite_query_read_only_enforcement() {
        let capability = sqlite_query_v1::SqliteQueryV1Capability::new();
        let temp_dir = TempDir::new().unwrap();

        // Create a test SQLite database
        let db_path = temp_dir.path().join("test.db");

        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).await.unwrap();
        }

        // Create empty database file
        fs::File::create(&db_path).await.unwrap();

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(&format!("sqlite:{}", db_path.to_string_lossy()))
            .await
            .unwrap();

        // Create test table and data
        sqlx::query("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (name) VALUES ('Alice'), ('Bob')")
            .execute(&pool)
            .await
            .unwrap();
        drop(pool);

        // Test valid read-only query
        let valid_intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({
                "database_path": "test.db",
                "query": "SELECT * FROM users WHERE name = ?",
                "params": ["Alice"]
            }),
            30000,
            "test-signer".to_string(),
        );

        let mut custom_scope = HashMap::new();
        custom_scope.insert("allow_database".to_string(), json!(true));
        let ctx = create_test_context_with_scope(
            temp_dir.path().to_path_buf(),
            SandboxMode::Full,
            custom_scope,
        );

        let result = capability.execute(valid_intent, ctx).await;
        assert!(result.is_ok());

        // Test forbidden write operations
        let write_operations = vec![
            "INSERT INTO users (name) VALUES ('Charlie')",
            "UPDATE users SET name = 'Charles' WHERE name = 'Charlie'",
            "DELETE FROM users WHERE name = 'Alice'",
            "DROP TABLE users",
            "CREATE TABLE malicious (id INTEGER)",
            "PRAGMA table_info(users)",
        ];

        for write_query in write_operations {
            let write_intent = Intent::new(
                ProtoCapability::SqliteQueryV1,
                "test".to_string(),
                json!({
                    "database_path": "test.db",
                    "query": write_query
                }),
                30000,
                "test-signer".to_string(),
            );

            // Should fail validation
            let validation_result = capability.validate(&write_intent);
            assert!(
                validation_result.is_err(),
                "Should reject write operation: {}",
                write_query
            );
        }
    }

    #[tokio::test]
    async fn test_sqlite_query_strict_security_mode() {
        let capability = sqlite_query_v1::SqliteQueryV1Capability::new();
        let temp_dir = TempDir::new().unwrap();

        // Create a test database
        let db_path = temp_dir.path().join("test.db");

        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).await.unwrap();
        }

        // Create empty database file
        fs::File::create(&db_path).await.unwrap();

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(&format!("sqlite:{}", db_path.to_string_lossy()))
            .await
            .unwrap();
        sqlx::query("CREATE TABLE test (id INTEGER)")
            .execute(&pool)
            .await
            .unwrap();
        drop(pool);

        let intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({
                "database_path": "test.db",
                "query": "SELECT * FROM test"
            }),
            30000,
            "test-signer".to_string(),
        );

        // Test strict mode without database permission - should fail
        let ctx_strict = create_test_context(temp_dir.path().to_path_buf(), SandboxMode::Full);
        let result = capability.execute(intent.clone(), ctx_strict).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "DATABASE_DENIED_STRICT_MODE");

        // Test with explicit permission - should succeed
        let mut custom_scope = HashMap::new();
        custom_scope.insert("allow_database".to_string(), json!(true));
        let ctx_allowed = create_test_context_with_scope(
            temp_dir.path().to_path_buf(),
            SandboxMode::Full,
            custom_scope,
        );
        let result = capability.execute(intent, ctx_allowed).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sqlite_query_limits_enforcement() {
        let capability = sqlite_query_v1::SqliteQueryV1Capability::with_limits(
            10,   // max 10 rows
            1000, // 1 second timeout
            1024, // 1KB max database size
        );
        let temp_dir = TempDir::new().unwrap();

        // Create a database with many rows
        let db_path = temp_dir.path().join("large.db");
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(&format!("sqlite://{}?mode=rwc", db_path.to_string_lossy()))
            .await
            .unwrap();

        sqlx::query("CREATE TABLE large_table (id INTEGER, data TEXT)")
            .execute(&pool)
            .await
            .unwrap();

        // Insert many rows
        for i in 0..100 {
            sqlx::query("INSERT INTO large_table (id, data) VALUES (?, ?)")
                .bind(i)
                .bind(format!("data_{}", i))
                .execute(&pool)
                .await
                .unwrap();
        }
        drop(pool);

        let intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({
                "database_path": "large.db",
                "query": "SELECT * FROM large_table",
                "max_rows": 50  // Try to request more than capability allows
            }),
            30000,
            "test-signer".to_string(),
        );

        // Should fail validation due to row limit
        let validation_result = capability.validate(&intent);
        assert!(validation_result.is_err());
        assert_eq!(validation_result.unwrap_err().code, "LIMIT_EXCEEDED");
    }

    #[tokio::test]
    async fn test_benchmark_report_functionality() {
        let capability = bench_report_v1::BenchReportV1Capability::new();
        let temp_dir = TempDir::new().unwrap();

        let mut metrics = HashMap::new();
        metrics.insert("response_time_ms".to_string(), 125.5);
        metrics.insert("throughput_rps".to_string(), 850.2);
        metrics.insert("memory_usage_mb".to_string(), 45.3);

        let mut metadata = HashMap::new();
        metadata.insert("environment".to_string(), json!("test"));
        metadata.insert("version".to_string(), json!("1.0.0"));

        let intent = Intent::new(
            ProtoCapability::BenchReportV1,
            "test".to_string(),
            json!({
                "benchmark_name": "api_performance_test",
                "metrics": metrics,
                "metadata": metadata,
                "retention_days": 7
            }),
            30000,
            "test-signer".to_string(),
        );

        let ctx = create_test_context(temp_dir.path().to_path_buf(), SandboxMode::Demo);

        // First execution - no historical data
        let result = capability.execute(intent.clone(), ctx.clone()).await;
        assert!(result.is_ok());

        let result_data = result.unwrap();
        assert_eq!(result_data.status, smith_protocol::ExecutionStatus::Ok);

        let output = result_data.output.unwrap();
        assert_eq!(output["benchmark_name"], "api_performance_test");
        assert_eq!(output["historical_count"], 1); // Including current data point

        // Second execution - should have historical data for regression analysis
        let mut updated_metrics = HashMap::new();
        updated_metrics.insert("response_time_ms".to_string(), 200.0); // Much slower
        updated_metrics.insert("throughput_rps".to_string(), 600.0); // Much lower

        let second_intent = Intent::new(
            ProtoCapability::BenchReportV1,
            "test".to_string(),
            json!({
                "benchmark_name": "api_performance_test",
                "metrics": updated_metrics,
                "retention_days": 7
            }),
            30000,
            "test-signer-2".to_string(),
        );

        let second_result = capability.execute(second_intent, ctx).await;
        assert!(second_result.is_ok());

        let second_output = second_result.unwrap().output.unwrap();
        assert_eq!(second_output["historical_count"], 2);

        // Check that benchmark file was created
        let benchmark_file = temp_dir.path().join("benchmarks/api_performance_test.json");
        assert!(benchmark_file.exists());

        // Verify file contents
        let file_content = fs::read_to_string(&benchmark_file).await.unwrap();
        let data_points: Vec<benchmark_statistics::BenchmarkDataPoint> =
            serde_json::from_str(&file_content).unwrap();
        assert_eq!(data_points.len(), 2);
    }

    #[tokio::test]
    async fn test_benchmark_report_name_validation() {
        let capability = bench_report_v1::BenchReportV1Capability::new();

        // Test invalid benchmark names
        let invalid_names = vec![
            ("", "INVALID_BENCHMARK_NAME"),
            ("benchmark with spaces", "INVALID_BENCHMARK_NAME_FORMAT"),
            ("benchmark/with/slashes", "INVALID_BENCHMARK_NAME_FORMAT"),
            ("benchmark.with.dots", "INVALID_BENCHMARK_NAME_FORMAT"),
            ("benchmark@special", "INVALID_BENCHMARK_NAME_FORMAT"),
        ];

        for (invalid_name, expected_error) in invalid_names {
            let intent = Intent::new(
                ProtoCapability::BenchReportV1,
                "test".to_string(),
                json!({
                    "benchmark_name": invalid_name,
                    "metrics": {"test": 1.0}
                }),
                30000,
                "test-signer".to_string(),
            );

            let result = capability.validate(&intent);
            assert!(result.is_err(), "Should fail for name: {}", invalid_name);
            assert_eq!(result.unwrap_err().code, expected_error);
        }

        // Test valid benchmark names
        let valid_names = vec![
            "simple_benchmark",
            "benchmark-with-dashes",
            "benchmark123",
            "UPPERCASE_BENCHMARK",
            "mixed_Case-123",
        ];

        for valid_name in valid_names {
            let intent = Intent::new(
                ProtoCapability::BenchReportV1,
                "test".to_string(),
                json!({
                    "benchmark_name": valid_name,
                    "metrics": {"test": 1.0}
                }),
                30000,
                "test-signer".to_string(),
            );

            let result = capability.validate(&intent);
            assert!(result.is_ok(), "Should succeed for name: {}", valid_name);
        }
    }

    #[tokio::test]
    async fn test_benchmark_report_regression_detection() {
        let capability = bench_report_v1::BenchReportV1Capability::new();
        let temp_dir = TempDir::new().unwrap();

        // Create baseline performance data
        for i in 0..10 {
            let mut metrics = HashMap::new();
            metrics.insert("response_time_ms".to_string(), 100.0 + (i as f64 * 0.5)); // Stable around 100ms

            let intent = Intent::new(
                ProtoCapability::BenchReportV1,
                "test".to_string(),
                json!({
                    "benchmark_name": "regression_test",
                    "metrics": metrics,
                    "retention_days": 30
                }),
                30000,
                format!("test-signer-{}", i),
            );

            let ctx = create_test_context(temp_dir.path().to_path_buf(), SandboxMode::Demo);
            let _result = capability.execute(intent, ctx).await.unwrap();

            // Small delay to ensure different timestamps
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        // Now submit a measurement with significant regression
        let mut regressed_metrics = HashMap::new();
        regressed_metrics.insert("response_time_ms".to_string(), 300.0); // Much slower

        let regression_intent = Intent::new(
            ProtoCapability::BenchReportV1,
            "test".to_string(),
            json!({
                "benchmark_name": "regression_test",
                "metrics": regressed_metrics,
                "retention_days": 30
            }),
            30000,
            "test-signer-regression".to_string(),
        );

        let ctx = create_test_context(temp_dir.path().to_path_buf(), SandboxMode::Demo);
        let result = capability.execute(regression_intent, ctx).await.unwrap();

        let output = result.output.unwrap();
        let regression_analysis = &output["regression_analysis"];

        // Should detect regression
        assert_eq!(regression_analysis["regression_detected"], true);
        assert!(regression_analysis["regressed_metrics"]
            .as_array()
            .unwrap()
            .contains(&json!("response_time_ms")));
    }

    #[tokio::test]
    #[ignore]  // Archive capability is disabled - waiting for implementation
    async fn test_all_capabilities_describe_correctly() {
        // Test that all capabilities return proper specifications
        let archive_capability = archive_read_v1::ArchiveReadV1Capability::new();
        let sqlite_capability = sqlite_query_v1::SqliteQueryV1Capability::new();
        let bench_capability = bench_report_v1::BenchReportV1Capability::new();

        let archive_spec = archive_capability.describe();
        assert_eq!(archive_spec.name, "archive.read.v1");
        assert!(!archive_spec.description.is_empty());
        assert!(!archive_spec.security_notes.is_empty());

        let sqlite_spec = sqlite_capability.describe();
        assert_eq!(sqlite_spec.name, "sqlite.query.v1");
        assert!(!sqlite_spec.description.is_empty());
        assert!(!sqlite_spec.security_notes.is_empty());

        let bench_spec = bench_capability.describe();
        assert_eq!(bench_spec.name, "bench.report.v1");
        assert!(!bench_spec.description.is_empty());
        assert!(!bench_spec.security_notes.is_empty());

        // Verify all capabilities are properly registered
        let registry = register_builtin_capabilities();
        let capability_names = registry.list();

        assert!(capability_names.contains(&"archive.read.v1".to_string()));
        assert!(capability_names.contains(&"sqlite.query.v1".to_string()));
        assert!(capability_names.contains(&"bench.report.v1".to_string()));
        assert!(capability_names.contains(&"fs.read.v1".to_string()));
        assert!(capability_names.contains(&"http.fetch.v1".to_string()));

        // Total should be 5 capabilities
        assert_eq!(capability_names.len(), 5);
    }

    #[tokio::test]
    #[ignore]  // Archive capability is disabled - waiting for implementation
    async fn test_capability_resource_quotas() {
        // Test that all capabilities report realistic resource requirements
        let archive_capability = archive_read_v1::ArchiveReadV1Capability::new();
        let sqlite_capability = sqlite_query_v1::SqliteQueryV1Capability::new();
        let bench_capability = bench_report_v1::BenchReportV1Capability::new();

        let archive_spec = archive_capability.describe();
        assert!(archive_spec.resource_requirements.memory_kb_max > 0);
        assert!(archive_spec.resource_requirements.cpu_ms_typical > 0);
        assert!(archive_spec.resource_requirements.filesystem_access);
        assert!(!archive_spec.resource_requirements.network_access);

        let sqlite_spec = sqlite_capability.describe();
        assert!(sqlite_spec.resource_requirements.memory_kb_max > 0);
        assert!(sqlite_spec.resource_requirements.cpu_ms_typical > 0);
        assert!(sqlite_spec.resource_requirements.filesystem_access);
        assert!(!sqlite_spec.resource_requirements.network_access);

        let bench_spec = bench_capability.describe();
        assert!(bench_spec.resource_requirements.memory_kb_max > 0);
        assert!(bench_spec.resource_requirements.cpu_ms_typical > 0);
        assert!(bench_spec.resource_requirements.filesystem_access);
        assert!(!bench_spec.resource_requirements.network_access);
    }
}
*/
