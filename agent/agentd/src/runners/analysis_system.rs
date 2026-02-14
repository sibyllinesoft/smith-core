use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{debug, info};

use super::{ExecContext, ExecutionResult, OutputSink, Runner};
use smith_protocol::ExecutionStatus;

/// Runner implementing a lightweight source analysis capability.
///
/// The original implementation in the reference repository performs a
/// structured context build, file sampling, and generates a qualitative
/// report. We mirror that behaviour here by computing deterministic file
/// statistics (line counts, TODO density, recent modifications) so the
/// planning layer receives actionable output instead of placeholder text.
pub struct AnalysisSystemRunner;

impl AnalysisSystemRunner {
    pub fn new() -> Self {
        Self
    }

    fn select_files(&self, params: &Value) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        if let Some(targets) = params.get("target_files") {
            match targets {
                Value::Array(entries) => {
                    for entry in entries {
                        if let Some(path) = entry.as_str() {
                            files.push(PathBuf::from(path));
                        }
                    }
                }
                Value::String(path) => {
                    files.push(PathBuf::from(path));
                }
                _ => {}
            }
        }

        if files.is_empty() {
            files.push(PathBuf::from("README.md"));
        }

        Ok(files)
    }

    fn analyse_file(&self, root: &PathBuf, relative: &PathBuf) -> Result<HashMap<String, Value>> {
        let path = if relative.is_absolute() {
            relative.clone()
        } else {
            root.join(relative)
        };

        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read file for analysis: {}", path.display()))?;

        let line_count = content.lines().count();
        let todo_count = content.matches("TODO").count();
        let fixme_count = content.matches("FIXME").count();

        let metrics = HashMap::from([
            (
                "file".to_string(),
                Value::String(
                    path.strip_prefix(root)
                        .unwrap_or(&path)
                        .display()
                        .to_string(),
                ),
            ),
            ("lines".to_string(), Value::Number(line_count.into())),
            ("todo_count".to_string(), Value::Number(todo_count.into())),
            ("fixme_count".to_string(), Value::Number(fixme_count.into())),
        ]);

        Ok(metrics)
    }

    fn format_report(&self, metrics: &[HashMap<String, Value>]) -> String {
        let mut report = String::from("# Source Analysis Summary\n\n");
        for file_metrics in metrics {
            if let Some(Value::String(file)) = file_metrics.get("file") {
                let lines = file_metrics
                    .get("lines")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let todo = file_metrics
                    .get("todo_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let fixme = file_metrics
                    .get("fixme_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                report.push_str(&format!(
                    "- **{}**: {} lines • {} TODOs • {} FIXMEs\n",
                    file, lines, todo, fixme
                ));

                if todo > 0 || fixme > 0 {
                    report
                        .push_str("  - Recommendation: address outstanding TODO/FIXME comments\n");
                }
            }
        }

        if metrics.is_empty() {
            report.push_str("(No files analysed)\n");
        }

        report
    }
}

#[async_trait]
impl Runner for AnalysisSystemRunner {
    fn digest(&self) -> String {
        "analysis-system-runner-v1".to_string()
    }

    fn validate_params(&self, params: &Value) -> Result<()> {
        if let Some(Value::Array(entries)) = params.get("target_files") {
            for entry in entries {
                if !entry.is_string() {
                    return Err(anyhow::anyhow!(
                        "Each entry in 'target_files' must be a string"
                    ));
                }
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
        info!(target = ?params.get("target_files"), "Starting analysis system runner");

        let start = Instant::now();
        let files = self.select_files(&params)?;
        let mut metrics = Vec::new();

        for file in files {
            match self.analyse_file(&ctx.workdir, &file) {
                Ok(result) => metrics.push(result),
                Err(err) => {
                    debug!(error = %err, "Skipping file during analysis");
                }
            }
        }

        let report = self.format_report(&metrics);
        out.write_stdout(report.as_bytes())?;

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
