use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::time::Instant;
use tracing::{debug, info};

use super::{ExecContext, ExecutionResult, OutputSink, Runner};
use smith_protocol::ExecutionStatus;

/// Runner that produces a lightweight performance analysis report.
pub struct AnalysisPerformanceRunner;

impl AnalysisPerformanceRunner {
    pub fn new() -> Self {
        Self
    }

    fn derive_performance_metrics(&self, ctx: &ExecContext, params: &Value) -> Value {
        let target = params
            .get("target_service")
            .and_then(Value::as_str)
            .unwrap_or("unknown-service");
        let desired_latency = params
            .get("latency_budget_ms")
            .and_then(Value::as_f64)
            .unwrap_or(250.0);

        let workspace_size = match std::fs::metadata(&ctx.workdir) {
            Ok(metadata) => metadata.len(),
            Err(_) => 0,
        };

        let mut metrics = serde_json::Map::new();
        metrics.insert(
            "target_service".to_string(),
            Value::String(target.to_string()),
        );
        metrics.insert(
            "latency_budget_ms".to_string(),
            Value::from(desired_latency),
        );
        metrics.insert(
            "workspace_size_bytes".to_string(),
            Value::from(workspace_size),
        );

        // Derive simple heuristics based on workspace size
        let saturation = ((workspace_size as f64 / (1024.0 * 1024.0 * 128.0)).min(1.0) * 100.0)
            .round()
            .max(5.0);
        metrics.insert(
            "estimated_cpu_saturation_pct".to_string(),
            Value::from(saturation),
        );

        Value::Object(metrics)
    }

    fn format_report(&self, metrics: &Value) -> String {
        let obj = metrics.as_object().cloned().unwrap_or_default();
        let service = obj
            .get("target_service")
            .and_then(Value::as_str)
            .unwrap_or("unknown-service");
        let latency = obj
            .get("latency_budget_ms")
            .and_then(Value::as_f64)
            .unwrap_or(250.0);
        let saturation = obj
            .get("estimated_cpu_saturation_pct")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);

        format!(
            "# Performance Analysis: {service}\n\n- Target latency budget: {latency:.1} ms\n- Estimated CPU saturation: {saturation:.1}%\n- Recommendation: allocate additional capacity if saturation consistently exceeds 80%.\n",
        )
    }
}

#[async_trait]
impl Runner for AnalysisPerformanceRunner {
    fn digest(&self) -> String {
        "analysis-performance-runner-v1".to_string()
    }

    fn validate_params(&self, params: &Value) -> Result<()> {
        if let Some(latency_budget) = params.get("latency_budget_ms") {
            if !latency_budget.is_number() {
                return Err(anyhow::anyhow!(
                    "'latency_budget_ms' must be numeric when provided"
                ));
            }
        }
        Ok(())
    }

    async fn execute(
        &self,
        ctx: &ExecContext,
        params: Value,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        info!(
            target = ?params.get("target_service"),
            "Starting performance analysis runner"
        );

        let start = Instant::now();
        let metrics = self.derive_performance_metrics(ctx, &params);
        let report = self.format_report(&metrics);

        out.write_stdout(report.as_bytes())?;
        debug!("Analysis performance metrics: {}", metrics);

        let duration_ms = start.elapsed().as_millis() as u64;
        let stdout_bytes = report.as_bytes().len() as u64;

        Ok(ExecutionResult {
            status: ExecutionStatus::Success,
            exit_code: Some(0),
            artifacts: Vec::new(),
            duration_ms,
            stdout_bytes,
            stderr_bytes: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;
    use tempfile::tempdir;

    // Mock output sink for testing
    struct MockOutputSink {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    impl MockOutputSink {
        fn new() -> Self {
            Self {
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        }

        fn stdout_string(&self) -> String {
            String::from_utf8_lossy(&self.stdout).to_string()
        }
    }

    impl OutputSink for MockOutputSink {
        fn write_stdout(&mut self, data: &[u8]) -> Result<()> {
            self.stdout.extend_from_slice(data);
            Ok(())
        }

        fn write_stderr(&mut self, data: &[u8]) -> Result<()> {
            self.stderr.extend_from_slice(data);
            Ok(())
        }

        fn write_log(&mut self, _level: &str, _message: &str) -> Result<()> {
            Ok(())
        }
    }

    fn create_test_context(workdir: PathBuf) -> ExecContext {
        use crate::runners::Scope;
        ExecContext {
            workdir,
            limits: smith_protocol::ExecutionLimits {
                cpu_ms_per_100ms: 50,
                mem_bytes: 1024 * 1024 * 100,
                io_bytes: 1024 * 1024 * 10,
                pids_max: 10,
                timeout_ms: 30000,
            },
            scope: Scope {
                paths: vec![],
                urls: vec![],
            },
            creds: None,
            netns: None,
            trace_id: "test-trace-123".to_string(),
            session: None,
        }
    }

    // ==================== Constructor Tests ====================

    #[test]
    fn test_analysis_performance_runner_new() {
        let runner = AnalysisPerformanceRunner::new();
        // Just verify it doesn't panic
        let _ = runner;
    }

    // ==================== Runner Trait Tests ====================

    #[test]
    fn test_digest() {
        let runner = AnalysisPerformanceRunner::new();
        let digest = runner.digest();
        assert_eq!(digest, "analysis-performance-runner-v1");
    }

    #[test]
    fn test_validate_params_empty() {
        let runner = AnalysisPerformanceRunner::new();
        let params = json!({});
        let result = runner.validate_params(&params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_params_valid_latency_budget() {
        let runner = AnalysisPerformanceRunner::new();
        let params = json!({
            "latency_budget_ms": 100.0
        });
        let result = runner.validate_params(&params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_params_invalid_latency_budget() {
        let runner = AnalysisPerformanceRunner::new();
        let params = json!({
            "latency_budget_ms": "not a number"
        });
        let result = runner.validate_params(&params);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be numeric"));
    }

    #[test]
    fn test_validate_params_with_target_service() {
        let runner = AnalysisPerformanceRunner::new();
        let params = json!({
            "target_service": "my-service",
            "latency_budget_ms": 250.5
        });
        let result = runner.validate_params(&params);
        assert!(result.is_ok());
    }

    // ==================== derive_performance_metrics Tests ====================

    #[test]
    fn test_derive_performance_metrics_default() {
        let runner = AnalysisPerformanceRunner::new();
        let temp_dir = tempdir().unwrap();
        let ctx = create_test_context(temp_dir.path().to_path_buf());
        let params = json!({});

        let metrics = runner.derive_performance_metrics(&ctx, &params);

        assert!(metrics.is_object());
        let obj = metrics.as_object().unwrap();
        assert_eq!(
            obj.get("target_service").unwrap().as_str().unwrap(),
            "unknown-service"
        );
        assert_eq!(
            obj.get("latency_budget_ms").unwrap().as_f64().unwrap(),
            250.0
        );
        assert!(obj.contains_key("workspace_size_bytes"));
        assert!(obj.contains_key("estimated_cpu_saturation_pct"));
    }

    #[test]
    fn test_derive_performance_metrics_with_service() {
        let runner = AnalysisPerformanceRunner::new();
        let temp_dir = tempdir().unwrap();
        let ctx = create_test_context(temp_dir.path().to_path_buf());
        let params = json!({
            "target_service": "api-gateway",
            "latency_budget_ms": 150.0
        });

        let metrics = runner.derive_performance_metrics(&ctx, &params);

        let obj = metrics.as_object().unwrap();
        assert_eq!(
            obj.get("target_service").unwrap().as_str().unwrap(),
            "api-gateway"
        );
        assert_eq!(
            obj.get("latency_budget_ms").unwrap().as_f64().unwrap(),
            150.0
        );
    }

    #[test]
    fn test_derive_performance_metrics_saturation_min() {
        let runner = AnalysisPerformanceRunner::new();
        let temp_dir = tempdir().unwrap();
        let ctx = create_test_context(temp_dir.path().to_path_buf());
        let params = json!({});

        let metrics = runner.derive_performance_metrics(&ctx, &params);
        let saturation = metrics
            .get("estimated_cpu_saturation_pct")
            .unwrap()
            .as_f64()
            .unwrap();

        // Empty workspace should have minimum saturation (5%)
        assert!(saturation >= 5.0);
    }

    // ==================== format_report Tests ====================

    #[test]
    fn test_format_report_basic() {
        let runner = AnalysisPerformanceRunner::new();
        let metrics = json!({
            "target_service": "my-service",
            "latency_budget_ms": 200.0,
            "estimated_cpu_saturation_pct": 45.0
        });

        let report = runner.format_report(&metrics);

        assert!(report.contains("# Performance Analysis: my-service"));
        assert!(report.contains("Target latency budget: 200.0 ms"));
        assert!(report.contains("Estimated CPU saturation: 45.0%"));
        assert!(report.contains("Recommendation:"));
    }

    #[test]
    fn test_format_report_defaults() {
        let runner = AnalysisPerformanceRunner::new();
        let metrics = json!({});

        let report = runner.format_report(&metrics);

        assert!(report.contains("unknown-service"));
        assert!(report.contains("250.0 ms")); // default latency
        assert!(report.contains("0.0%")); // default saturation
    }

    #[test]
    fn test_format_report_high_saturation() {
        let runner = AnalysisPerformanceRunner::new();
        let metrics = json!({
            "target_service": "heavy-load-service",
            "latency_budget_ms": 100.0,
            "estimated_cpu_saturation_pct": 95.0
        });

        let report = runner.format_report(&metrics);

        assert!(report.contains("95.0%"));
        assert!(report.contains("allocate additional capacity"));
    }

    // ==================== execute Tests ====================

    #[tokio::test]
    async fn test_execute_success() {
        let runner = AnalysisPerformanceRunner::new();
        let temp_dir = tempdir().unwrap();
        let ctx = create_test_context(temp_dir.path().to_path_buf());
        let params = json!({
            "target_service": "test-service",
            "latency_budget_ms": 300.0
        });
        let mut sink = MockOutputSink::new();

        let result = runner.execute(&ctx, params, &mut sink).await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status, ExecutionStatus::Success);
        assert_eq!(result.exit_code, Some(0));
        assert!(result.stdout_bytes > 0);
        assert_eq!(result.stderr_bytes, 0);
        assert!(result.artifacts.is_empty());

        // Verify output was written
        let output = sink.stdout_string();
        assert!(output.contains("test-service"));
        assert!(output.contains("300.0 ms"));
    }

    #[tokio::test]
    async fn test_execute_without_params() {
        let runner = AnalysisPerformanceRunner::new();
        let temp_dir = tempdir().unwrap();
        let ctx = create_test_context(temp_dir.path().to_path_buf());
        let params = json!({});
        let mut sink = MockOutputSink::new();

        let result = runner.execute(&ctx, params, &mut sink).await;

        assert!(result.is_ok());
        let output = sink.stdout_string();
        assert!(output.contains("unknown-service"));
    }

    #[tokio::test]
    async fn test_execute_measures_duration() {
        let runner = AnalysisPerformanceRunner::new();
        let temp_dir = tempdir().unwrap();
        let ctx = create_test_context(temp_dir.path().to_path_buf());
        let params = json!({});
        let mut sink = MockOutputSink::new();

        let result = runner.execute(&ctx, params, &mut sink).await.unwrap();

        // Duration should be positive but small
        assert!(result.duration_ms < 1000);
    }

    #[tokio::test]
    async fn test_execute_with_nonexistent_workdir() {
        let runner = AnalysisPerformanceRunner::new();
        let ctx = create_test_context(PathBuf::from("/nonexistent/path/for/testing"));
        let params = json!({
            "target_service": "edge-case-service"
        });
        let mut sink = MockOutputSink::new();

        // Should handle nonexistent workdir gracefully
        let result = runner.execute(&ctx, params, &mut sink).await;
        assert!(result.is_ok());

        // Workspace size should be 0 for nonexistent path
        let output = sink.stdout_string();
        assert!(output.contains("edge-case-service"));
    }
}
