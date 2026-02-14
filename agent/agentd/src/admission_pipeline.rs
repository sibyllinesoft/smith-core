/*!
 * Admission pipeline module
 *
 * Extracted from main.rs to reduce complexity and improve maintainability.
 * Handles intent admission, validation, execution, and result publishing.
 */

use anyhow::{Context, Result};
use chrono::Utc;
use once_cell::sync::OnceCell;
use std::sync::{Arc, Once};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
// Tracing imports moved to functions that need them

use crate::{
    audit, config::Config, idempotency, intent, metrics, nats, policy, runners, schema, security,
    trace,
};
use smith_config::PolicyDerivations;
use smith_jailer::{self as jailer, SandboxProfile};
use smith_protocol::{ExecutionStatus, Intent, IntentResult};

static EXECUTOR_METRICS: OnceCell<Arc<tokio::sync::RwLock<metrics::ExecutorMetrics>>> =
    OnceCell::new();
static WARN_NO_SIGNERS_ONCE: Once = Once::new();

/// Outcome of the admission pipeline once an intent has been handled.
#[derive(Debug, Clone)]
pub enum ProcessingOutcome {
    /// Intent executed successfully and the result was published.
    Completed,
    /// Intent was denied by policy and a denial result was emitted.
    Denied { reason: String },
}

/// Main intent processing function that coordinates the admission pipeline
#[allow(clippy::too_many_arguments)]
pub async fn process_intent(
    message: async_nats::jetstream::Message,
    idempotency_store: &idempotency::IdempotencyStore,
    policy_engine: &policy::PolicyEngine,
    schema_validator: &Arc<schema::SchemaValidator>,
    runner_registry: &Arc<runners::RunnerRegistry>,
    trusted_signers: &Arc<security::TrustedSigners>,
    config: &Config,
    nats_client: &nats::NatsClient,
    metrics: &Arc<tokio::sync::RwLock<metrics::ExecutorMetrics>>,
    _audit_logger: &Arc<tokio::sync::Mutex<audit::AuditLogger>>,
    capability: &str,
    intent_id: &str,
    trace_id: &str,
    expected_capability_digest: &str,
    derivations: &Arc<PolicyDerivations>,
) -> Result<ProcessingOutcome> {
    let admission_span = trace::ExecutorTracer::span_intent_admission(intent_id, capability)
        .with_trace_id(trace_id.to_string());

    log_pipeline_start(trace_id, intent_id, capability);

    let _ = EXECUTOR_METRICS.get_or_init(|| Arc::clone(metrics));

    let result = execute_admission_pipeline(
        message,
        idempotency_store,
        policy_engine,
        schema_validator,
        runner_registry,
        trusted_signers,
        config,
        nats_client,
        expected_capability_digest,
        derivations,
        &admission_span,
        trace_id,
    )
    .await;

    handle_admission_result(
        result,
        metrics,
        capability,
        trace_id,
        intent_id,
        admission_span,
    )
    .await
}

fn log_pipeline_start(trace_id: &str, intent_id: &str, capability: &str) {
    tracing::info!(
        trace_id = trace_id,
        intent_id = intent_id,
        capability = capability,
        seq = 1,
        status = "admitted",
        "Starting intent admission pipeline"
    );
}

#[allow(clippy::too_many_arguments)]
async fn execute_admission_pipeline(
    message: async_nats::jetstream::Message,
    idempotency_store: &idempotency::IdempotencyStore,
    policy_engine: &policy::PolicyEngine,
    schema_validator: &Arc<schema::SchemaValidator>,
    runner_registry: &Arc<runners::RunnerRegistry>,
    trusted_signers: &Arc<security::TrustedSigners>,
    config: &Config,
    nats_client: &nats::NatsClient,
    expected_capability_digest: &str,
    derivations: &Arc<PolicyDerivations>,
    admission_span: &trace::AdmissionSpan,
    trace_id: &str,
) -> Result<ProcessingOutcome> {
    // 1. Decode & canonicalize JSON
    admission_span.record_event("decode_json", &[("step", "1")]);
    let intent = decode_intent_from_message(&message, trace_id)?;

    // 2-4. Security validations (digest, signature, freshness)
    validate_intent_security(
        &message,
        &intent,
        expected_capability_digest,
        trusted_signers,
        admission_span,
        trace_id,
    )
    .await?;

    // 5. JSON Schema validation
    admission_span.record_event("schema_validate", &[("step", "5")]);
    schema_validator.validate_intent(&intent)?;

    // 6. Policy evaluation
    admission_span.record_event("policy_evaluate", &[("step", "6")]);
    let policy_result = policy_engine.evaluate(&intent).await?;
    if !policy_result.allow {
        admission_span.record_event("policy_denied", &[("step", "6a")]);
        let denial_reason = policy_result
            .reason
            .clone()
            .unwrap_or_else(|| "Intent denied by policy".to_string());
        tracing::warn!(
            trace_id = trace_id,
            intent_id = %intent.id,
            capability = ?intent.capability,
            reason = %denial_reason,
            "Intent denied by policy; publishing denial result"
        );

        if let Err(err) = message.ack().await {
            tracing::error!(
                trace_id = trace_id,
                intent_id = %intent.id,
                capability = ?intent.capability,
                error = %err,
                "Failed to ack denied intent message"
            );
        }

        let audit_ref = format!("audit-{}", intent.id);
        let denial_result =
            IntentResult::denied(intent.id.clone(), denial_reason.clone(), audit_ref);

        if let Err(err) = idempotency_store
            .store_result(&intent.id, &denial_result)
            .await
        {
            tracing::warn!(
                trace_id = trace_id,
                intent_id = %intent.id,
                capability = ?intent.capability,
                error = %err,
                "Failed to store denial result in idempotency store"
            );
        }

        if let Err(err) = nats_client.publish_result(&intent.id, &denial_result).await {
            tracing::error!(
                trace_id = trace_id,
                intent_id = %intent.id,
                capability = ?intent.capability,
                error = %err,
                "Failed to publish denial result to NATS"
            );
            return Err(err);
        }

        tracing::info!(
            trace_id = trace_id,
            intent_id = %intent.id,
            capability = ?intent.capability,
            "Policy denial result published successfully"
        );

        return Ok(ProcessingOutcome::Denied {
            reason: denial_reason,
        });
    }

    // 7. Idempotency handling
    if handle_idempotency(
        &intent,
        idempotency_store,
        nats_client,
        trace_id,
        admission_span,
    )
    .await?
    {
        return Ok(ProcessingOutcome::Completed); // Already processed
    }

    // 9. Ack message early
    admission_span.record_event("ack_message", &[("step", "9")]);
    message
        .ack()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to ack message: {}", e))?;

    // 10-15. Execution pipeline
    execute_intent_with_sandbox(
        intent,
        policy_result,
        config,
        derivations,
        runner_registry,
        idempotency_store,
        nats_client,
        expected_capability_digest,
        admission_span,
        trace_id,
    )
    .await?;

    Ok(ProcessingOutcome::Completed)
}

fn decode_intent_from_message(
    message: &async_nats::jetstream::Message,
    trace_id: &str,
) -> Result<Intent> {
    let intent: Intent =
        serde_json::from_slice(&message.payload).context("Failed to decode intent JSON")?;

    let payload_preview: String = String::from_utf8_lossy(&message.payload)
        .chars()
        .take(512)
        .collect();
    tracing::debug!(
        trace_id = trace_id,
        payload_preview = %payload_preview,
        "Intent payload preview"
    );
    tracing::debug!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = %intent.capability,
        domain = intent.domain,
        "Decoded intent from message"
    );

    Ok(intent)
}

async fn validate_intent_security(
    message: &async_nats::jetstream::Message,
    intent: &Intent,
    expected_capability_digest: &str,
    trusted_signers: &security::TrustedSigners,
    admission_span: &trace::AdmissionSpan,
    trace_id: &str,
) -> Result<()> {
    // 2. Capability digest verification
    admission_span.record_event("verify_capability_digest", &[("step", "2")]);
    validate_capability_digest_header(message, expected_capability_digest, intent, trace_id)?;

    // 3. Signature verification
    admission_span.record_event("verify_signature", &[("step", "3")]);
    if trusted_signers.is_empty() {
        WARN_NO_SIGNERS_ONCE.call_once(|| {
            tracing::warn!(
                "No trusted signer keys configured; skipping intent signature verification (development mode)."
            );
        });
        return Ok(());
    }
    let signer_entry = trusted_signers
        .get(&intent.signer)
        .ok_or_else(|| anyhow::anyhow!("Intent signer is not trusted"))?;

    let is_valid_signature = intent
        .verify_with_key(signer_entry.verifying_key())
        .context("Failed to verify intent signature")?;
    if !is_valid_signature {
        return Err(anyhow::anyhow!("Intent signature verification failed"));
    }

    tracing::debug!(
        trace_id = trace_id,
        intent_id = %intent.id,
        signer_fingerprint = signer_entry.fingerprint(),
        "Intent signature verified"
    );

    // 4. Freshness checks
    admission_span.record_event("freshness_check", &[("step", "4")]);
    if intent.is_expired() {
        let now_ns = Utc::now().timestamp_nanos() as u128;
        tracing::warn!(
            trace_id = trace_id,
            intent_id = %intent.id,
            created_at_ns = intent.created_at_ns,
            ttl_ms = intent.ttl_ms,
            now_ns,
            age_ms = ((now_ns.saturating_sub(intent.created_at_ns)) / 1_000_000) as u64,
            "Intent has expired; acknowledging to drop stale message"
        );
        if let Err(err) = message.ack().await {
            tracing::error!(
                trace_id = trace_id,
                intent_id = %intent.id,
                error = %err,
                "Failed to ack expired intent message"
            );
        }
        return Err(anyhow::anyhow!("Intent has expired"));
    }

    Ok(())
}

fn validate_capability_digest_header(
    message: &async_nats::jetstream::Message,
    expected_capability_digest: &str,
    intent: &Intent,
    trace_id: &str,
) -> Result<()> {
    let intent_capability_digest = message
        .headers
        .as_ref()
        .and_then(|headers| headers.get("capability-digest"))
        .map(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("Intent missing required capability_digest header"))?;

    if intent_capability_digest != expected_capability_digest {
        tracing::error!(
            trace_id = trace_id,
            intent_id = %intent.id,
            expected_digest = expected_capability_digest,
            received_digest = intent_capability_digest,
            "Capability digest mismatch - NACK intent"
        );

        return Err(anyhow::anyhow!(
            "Capability digest mismatch. Expected: {}, received: {}",
            expected_capability_digest,
            intent_capability_digest
        ));
    }

    tracing::debug!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability_digest = intent_capability_digest,
        "Capability digest verified successfully"
    );

    Ok(())
}

async fn handle_idempotency(
    intent: &Intent,
    idempotency_store: &idempotency::IdempotencyStore,
    nats_client: &nats::NatsClient,
    trace_id: &str,
    admission_span: &trace::AdmissionSpan,
) -> Result<bool> {
    admission_span.record_event("idempotency_check", &[("step", "7")]);

    if idempotency_store.is_processed(&intent.id).await? {
        tracing::info!(
            trace_id = trace_id,
            intent_id = %intent.id,
            "Intent already processed (idempotent)"
        );

        // Return cached result if available
        let cached_result = idempotency_store.get_result(&intent.id).await?;
        if let Some(result) = cached_result {
            nats_client.publish_result(&intent.id, &result).await?;
        }
        return Ok(true); // Already processed
    }

    // Mark as processing to prevent duplicates
    admission_span.record_event("mark_processing", &[("step", "8")]);
    idempotency_store.mark_processing(&intent.id).await?;

    Ok(false) // Not processed yet
}

#[allow(clippy::too_many_arguments)]
async fn execute_intent_with_sandbox(
    intent: Intent,
    policy_result: policy::PolicyResult,
    config: &Config,
    derivations: &Arc<PolicyDerivations>,
    runner_registry: &Arc<runners::RunnerRegistry>,
    idempotency_store: &idempotency::IdempotencyStore,
    nats_client: &nats::NatsClient,
    expected_capability_digest: &str,
    admission_span: &trace::AdmissionSpan,
    trace_id: &str,
) -> Result<()> {
    // Map capability to sandbox profiles
    admission_span.record_event("map_sandbox_profiles", &[("step", "10")]);
    let sandbox_profile = extract_sandbox_profile(&intent, derivations, trace_id)?;

    // Execute with sandbox
    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = ?intent.capability,
        "Entering secure sandbox execution phase"
    );

    let execution_result = execute_in_secure_sandbox(
        &intent,
        &policy_result,
        &sandbox_profile,
        config,
        runner_registry,
        expected_capability_digest,
        admission_span,
        trace_id,
    )
    .await
    .map_err(|err| {
        tracing::error!(
            trace_id = trace_id,
            intent_id = %intent.id,
            capability = ?intent.capability,
            error = %err,
            "Sandbox execution returned error"
        );
        err
    })?;

    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = ?intent.capability,
        "[sandbox] Execution future resolved"
    );
    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = ?intent.capability,
        "Secure sandbox execution completed; starting result finalization"
    );
    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = ?intent.capability,
        "[pipeline] Invoking finalize_execution_result"
    );

    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = ?intent.capability,
        ptr = %format!("{:p}", &execution_result),
        "Calling finalize_execution_result"
    );

    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = ?intent.capability,
        finalize_ptr = %format!("{:p}", &execution_result),
        result_status = ?execution_result.status,
        "Calling finalize_execution_result"
    );

    finalize_execution_result(
        &intent,
        execution_result,
        idempotency_store,
        nats_client,
        admission_span,
        trace_id,
    )
    .await
    .map_err(|err| {
        tracing::error!(
            trace_id = trace_id,
            intent_id = %intent.id,
            capability = ?intent.capability,
            error = %err,
            "Intent finalization failed"
        );
        err
    })?;

    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = ?intent.capability,
        "Intent finalization completed"
    );
    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = ?intent.capability,
        "[pipeline] Finalize step finished"
    );

    Ok(())
}

fn extract_sandbox_profile(
    intent: &Intent,
    derivations: &Arc<PolicyDerivations>,
    trace_id: &str,
) -> Result<SandboxProfile> {
    let (capability_versioned, capability_base) = match intent.capability {
        smith_protocol::Capability::FsReadV1 => ("fs.read.v1", "fs.read"),
        smith_protocol::Capability::HttpFetchV1 => ("http.fetch.v1", "http.fetch"),
        smith_protocol::Capability::FsWriteV1 => ("fs.write.v1", "fs.write"),
        smith_protocol::Capability::GitCloneV1 => ("git.clone.v1", "git.clone"),
        smith_protocol::Capability::ArchiveReadV1 => ("archive.read.v1", "archive.read"),
        smith_protocol::Capability::SqliteQueryV1 => ("sqlite.query.v1", "sqlite.query"),
        smith_protocol::Capability::BenchReportV1 => ("bench.report.v1", "bench.report"),
        smith_protocol::Capability::ShellExec => ("shell.exec", "shell.exec"),
        smith_protocol::Capability::HttpFetch => ("http.fetch", "http.fetch"),
    };

    // Verify all required profile data is available
    let seccomp_allowlist = derivations
        .get_seccomp_allowlist(capability_versioned)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Missing seccomp allowlist for capability: {}",
                capability_versioned
            )
        })?;
    let landlock_profile = derivations
        .get_landlock_profile(capability_versioned)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Missing landlock profile for capability: {}",
                capability_versioned
            )
        })?
        .clone();
    let cgroup_limits = derivations
        .get_cgroup_limits(capability_versioned)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Missing cgroup limits for capability: {}",
                capability_versioned
            )
        })?
        .clone();

    let mut seccomp_syscalls = Vec::with_capacity(seccomp_allowlist.len());
    for name in seccomp_allowlist {
        match jailer::seccomp::syscall_number_from_name(&name) {
            Some(number) => seccomp_syscalls.push(number),
            None => {
                tracing::warn!(
                    trace_id = trace_id,
                    capability = capability_versioned,
                    syscall = %name,
                    "Unknown syscall in policy derivations; skipping"
                );
            }
        }
    }

    tracing::debug!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = capability_versioned,
        seccomp_syscalls = seccomp_syscalls.len(),
        landlock_read_paths = landlock_profile.read.len(),
        landlock_write_paths = landlock_profile.write.len(),
        cgroup_cpu_pct = cgroup_limits.cpu_pct,
        cgroup_mem_mb = cgroup_limits.mem_mb,
        "Sandbox profiles mapped successfully"
    );

    Ok(SandboxProfile {
        capability: capability_base,
        capability_versioned,
        seccomp_syscalls,
        landlock_profile,
        cgroup_limits,
    })
}

#[allow(clippy::too_many_arguments)]
async fn execute_in_secure_sandbox(
    intent: &Intent,
    policy_result: &policy::PolicyResult,
    sandbox_profile: &SandboxProfile,
    config: &Config,
    runner_registry: &Arc<runners::RunnerRegistry>,
    expected_capability_digest: &str,
    admission_span: &trace::AdmissionSpan,
    trace_id: &str,
) -> Result<IntentResult> {
    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = ?intent.capability,
        "[sandbox] execute_in_secure_sandbox entered"
    );
    admission_span.record_event("execute_intent", &[("step", "11")]);

    let execution_start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u128;

    // Get and validate runner
    let capability_str = get_runner_capability_string(&intent.capability);
    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = capability_str,
        "[sandbox] Resolved runner capability"
    );
    let runner = runner_registry
        .get_runner(capability_str)
        .ok_or_else(|| anyhow::anyhow!("No runner found for capability: {}", capability_str))?;
    runner.validate_params(&intent.params)?;
    tracing::debug!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = capability_str,
        "[sandbox] Runner parameters validated"
    );

    // Create secure jail environment
    let jailer = jailer::Jailer::new(&config.executor.work_root, config.executor.landlock_enabled)?;
    tracing::debug!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = capability_str,
        "[sandbox] Jailer constructed"
    );
    let limits = create_execution_limits(policy_result, sandbox_profile);
    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = capability_str,
        "[sandbox] Creating jail with profile"
    );
    let jailed_execution = match jailer
        .create_jail_with_profile(intent, &limits, sandbox_profile)
        .await
    {
        Ok(jail) => {
            tracing::info!(
                trace_id = trace_id,
                intent_id = %intent.id,
                capability = capability_str,
                "[sandbox] Jail created"
            );
            jail
        }
        Err(err) => {
            tracing::error!(
                trace_id = trace_id,
                intent_id = %intent.id,
                capability = capability_str,
                error = %err,
                "Failed to create sandbox jail"
            );
            let execution_end = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u128;
            let failure_result = IntentResult::error(
                intent.id.clone(),
                intent::ErrorCode::SandboxInitFail.as_str().to_string(),
                err.to_string(),
                execution_start,
                execution_end,
                smith_protocol::RunnerMetadata::empty(),
                format!("audit-{}", intent.id),
            );
            return Ok(failure_result);
        }
    };

    // Execute in sandbox
    let mut exec_context = create_execution_context(&jailed_execution, policy_result, trace_id);
    exec_context.session = extract_session_context(intent);
    let mut output_sink = runners::MemoryOutputSink::new();
    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = capability_str,
        "Starting runner execution"
    );

    let audit_ref = format!("audit-{}", intent.id);

    let execution_result = match runner
        .execute(&exec_context, intent.params.clone(), &mut output_sink)
        .await
    {
        Ok(result) => {
            tracing::info!(
                trace_id = trace_id,
                intent_id = %intent.id,
                capability = capability_str,
                status = ?result.status,
                "Runner execution completed"
            );
            result
        }
        Err(err) => {
            tracing::error!(
                trace_id = trace_id,
                intent_id = %intent.id,
                capability = capability_str,
                error = %err,
                "Runner execution failed"
            );

            let execution_end = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u128;

            if let Err(cleanup_err) = jailer.cleanup_jail(&jailed_execution).await {
                tracing::warn!(
                    trace_id = trace_id,
                    intent_id = %intent.id,
                    capability = capability_str,
                    error = %cleanup_err,
                    "Failed to cleanup jail after runner error"
                );
            }

            let failure_result = IntentResult::error(
                intent.id.clone(),
                intent::ErrorCode::SecureExecError.as_str().to_string(),
                err.to_string(),
                execution_start,
                execution_end,
                smith_protocol::RunnerMetadata::empty(),
                audit_ref,
            );

            tracing::info!(
                trace_id = trace_id,
                intent_id = %intent.id,
                capability = capability_str,
                "[sandbox] Returning failure result after runner error"
            );

            return Ok(failure_result);
        }
    };

    let execution_end = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u128;

    // Get memory usage from cgroups before cleanup
    let memory_usage_kb = match jailer
        .get_cgroup_stats(jailed_execution.cgroup_config.as_ref())
        .await
    {
        Ok(stats) => (stats.memory_usage_bytes / 1024) as u32,
        Err(e) => {
            tracing::warn!(
                trace_id = trace_id,
                intent_id = %intent.id,
                error = %e,
                "Failed to get memory usage from cgroups, using fallback"
            );
            1024 // Fallback value
        }
    };

    // Create result and cleanup
    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = capability_str,
        "[sandbox] Constructing intent result"
    );
    let result = create_intent_result(
        intent,
        &execution_result,
        &output_sink,
        execution_start,
        execution_end,
        expected_capability_digest,
        memory_usage_kb,
    );

    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = capability_str,
        status = ?execution_result.status,
        result_status = ?result.status,
        has_output = result.output.is_some(),
        has_error = result.error.is_some(),
        output_preview = result
            .output
            .as_ref()
            .map(|v| v.to_string())
            .map(|s| s.chars().take(200).collect::<String>()),
        "Intent result generated"
    );

    // Cleanup jail environment
    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = capability_str,
        "[sandbox] Beginning jail cleanup"
    );
    if let Err(e) = jailer.cleanup_jail(&jailed_execution).await {
        tracing::warn!(
            trace_id = trace_id,
            intent_id = %intent.id,
            capability = capability_str,
            error = %e,
            "Failed to cleanup jail"
        );
    } else {
        tracing::info!(
            trace_id = trace_id,
            intent_id = %intent.id,
            capability = capability_str,
            "[sandbox] Jail cleanup completed successfully"
        );
    }

    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = capability_str,
        result_status = ?result.status,
        "[sandbox] Returning execution result to finalizer"
    );

    Ok(result)
}

fn get_runner_capability_string(capability: &smith_protocol::Capability) -> &'static str {
    match capability {
        smith_protocol::Capability::FsReadV1 => "fs.read.v1",
        smith_protocol::Capability::HttpFetchV1 => "http.fetch",
        smith_protocol::Capability::FsWriteV1 => "fs.write",
        smith_protocol::Capability::GitCloneV1 => "git.clone",
        smith_protocol::Capability::ArchiveReadV1 => "archive.read",
        smith_protocol::Capability::SqliteQueryV1 => "sqlite.query",
        smith_protocol::Capability::BenchReportV1 => "bench.report",
        smith_protocol::Capability::ShellExec => "shell.exec",
        smith_protocol::Capability::HttpFetch => "http.fetch",
    }
}

fn create_execution_limits(
    policy_result: &policy::PolicyResult,
    sandbox_profile: &SandboxProfile,
) -> smith_protocol::ExecutionLimits {
    let mut limits = policy_result.limits.clone();

    if sandbox_profile.cgroup_limits.cpu_pct > 0 {
        limits.cpu_ms_per_100ms = sandbox_profile.cgroup_limits.cpu_pct.min(100) as u32;
    }

    if sandbox_profile.cgroup_limits.mem_mb > 0 {
        let bytes = sandbox_profile
            .cgroup_limits
            .mem_mb
            .saturating_mul(1_048_576);
        limits.mem_bytes = bytes;
    }

    smith_protocol::ExecutionLimits {
        cpu_ms_per_100ms: limits.cpu_ms_per_100ms,
        mem_bytes: limits.mem_bytes,
        io_bytes: limits.io_bytes,
        pids_max: limits.pids_max,
        timeout_ms: limits.timeout_ms,
    }
}

fn create_execution_context(
    jailed_execution: &jailer::JailedExecution,
    policy_result: &policy::PolicyResult,
    trace_id: &str,
) -> runners::ExecutionContext {
    let (mut scope_paths, scope_urls) = if let Some(map) = policy_result.scope.as_object() {
        (extract_scope_paths(map), extract_scope_urls(map))
    } else {
        (Vec::new(), Vec::new())
    };

    if scope_paths.is_empty()
        && matches!(
            policy_result.policy_id.as_deref(),
            Some("policy.disabled.override")
        )
    {
        let fallback_scope = std::env::var("SMITH_WORKSPACE_ROOT")
            .ok()
            .and_then(|root| match std::fs::canonicalize(&root) {
                Ok(path) => Some(path.to_string_lossy().to_string()),
                Err(_) => Some(root),
            })
            .or_else(|| match std::env::current_dir() {
                Ok(dir) => Some(dir.to_string_lossy().to_string()),
                Err(_) => None,
            });

        if let Some(path) = fallback_scope {
            tracing::debug!(
                trace_id = trace_id,
                fallback_scope = %path,
                "Policy disabled – applying workspace fallback scope"
            );
            scope_paths.push(path);
        } else {
            tracing::warn!(
                trace_id = trace_id,
                "Policy disabled and no fallback scope resolved; fs.read intents may fail"
            );
        }
    }

    runners::create_exec_context(
        &jailed_execution.workdir,
        jailed_execution.limits.clone(),
        runners::Scope {
            paths: scope_paths,
            urls: scope_urls,
        },
        trace_id.to_string(),
    )
}

fn extract_session_context(intent: &Intent) -> Option<runners::SessionContext> {
    let session_value = intent.metadata.get("session_id")?;
    let session_id = session_value
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())?;

    let domain = intent
        .metadata
        .get("domain")
        .and_then(|value| value.as_str().map(|s| s.to_string()))
        .or_else(|| Some(intent.domain.clone()));

    let vm_profile = intent
        .metadata
        .get("vm_profile")
        .and_then(|value| value.as_str().map(|s| s.to_string()));

    Some(runners::SessionContext {
        session_id,
        domain,
        vm_profile,
    })
}

fn extract_scope_paths(scope: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    if let Some(paths) = scope.get("paths") {
        paths
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect()
    } else {
        vec![]
    }
}

fn extract_scope_urls(scope: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    if let Some(urls) = scope.get("urls") {
        urls.as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect()
    } else {
        vec![]
    }
}

fn create_intent_result(
    intent: &Intent,
    execution_result: &runners::ExecutionResult,
    output_sink: &runners::MemoryOutputSink,
    execution_start: u128,
    execution_end: u128,
    expected_capability_digest: &str,
    memory_usage_kb: u32,
) -> IntentResult {
    let runner_metadata = smith_protocol::RunnerMetadata {
        pid: std::process::id(),
        cpu_ms: execution_result.duration_ms as u32,
        max_rss_kb: memory_usage_kb,
        capability_digest: Some(expected_capability_digest.to_string()),
    };
    let audit_id = format!("audit-{}", intent.id);

    match execution_result.status {
        ExecutionStatus::Ok => IntentResult::success(
            intent.id.clone(),
            serde_json::json!({
                "stdout": String::from_utf8_lossy(&output_sink.stdout),
                "stderr": String::from_utf8_lossy(&output_sink.stderr),
                "logs": output_sink.logs,
                "exit_code": execution_result.exit_code,
                "duration_ms": execution_result.duration_ms,
                "stdout_bytes": execution_result.stdout_bytes,
                "stderr_bytes": execution_result.stderr_bytes,
            }),
            execution_start,
            execution_end,
            runner_metadata,
            audit_id,
        ),
        ExecutionStatus::Error => IntentResult::error(
            intent.id.clone(),
            "EXECUTION_ERROR".to_string(),
            format!(
                "Runner execution failed: exit_code={:?}",
                execution_result.exit_code
            ),
            execution_start,
            execution_end,
            runner_metadata,
            audit_id,
        ),
        _ => IntentResult::error(
            intent.id.clone(),
            "EXECUTION_OTHER".to_string(),
            format!(
                "Runner execution completed with status: {:?}",
                execution_result.status
            ),
            execution_start,
            execution_end,
            runner_metadata,
            audit_id,
        ),
    }
}

async fn finalize_execution_result(
    intent: &Intent,
    result: IntentResult,
    idempotency_store: &idempotency::IdempotencyStore,
    nats_client: &nats::NatsClient,
    admission_span: &trace::AdmissionSpan,
    trace_id: &str,
) -> Result<()> {
    let finalize_start = std::time::Instant::now();
    let capability_label = intent.capability.to_string();
    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        status = ?&result.status,
        has_output = result.output.is_some(),
        has_error = result.error.is_some(),
        "[finalize] Enter finalize_execution_result"
    );
    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        status = ?&result.status,
        has_output = result.output.is_some(),
        has_error = result.error.is_some(),
        "[finalize] Persisting intent result"
    );
    admission_span.record_event("store_result", &[("step", "14")]);
    let store_intent_id = intent.id.clone();
    let store_result = result.clone();
    let store_trace_id = trace_id.to_string();
    let store_handle = idempotency_store.clone();
    tokio::spawn(async move {
        match store_handle
            .store_result(&store_intent_id, &store_result)
            .await
        {
            Ok(()) => {
                tracing::info!(
                    trace_id = %store_trace_id,
                    intent_id = %store_intent_id,
                    "[finalize] Stored intent result for idempotency"
                );
            }
            Err(err) => {
                tracing::warn!(
                    trace_id = %store_trace_id,
                    intent_id = %store_intent_id,
                    error = %err,
                    "Failed to persist idempotency record; continuing"
                );
            }
        }
    });
    tracing::info!(trace_id = trace_id, intent_id = %intent.id, "[finalize] Idempotency persistence step dispatched");

    tracing::info!(trace_id = trace_id, intent_id = %intent.id, "[finalize] Publishing intent result to NATS");
    admission_span.record_event("publish_result", &[("step", "15")]);
    let publish_outcome = match nats_client.publish_result(&intent.id, &result).await {
        Ok(()) => {
            tracing::info!(trace_id = trace_id, intent_id = %intent.id, "[finalize] Published intent result to NATS");
            ("success", false)
        }
        Err(err) => {
            tracing::error!(
                trace_id = trace_id,
                intent_id = %intent.id,
                error = %err,
                "Failed to publish intent result to NATS"
            );
            ("error", true)
        }
    };
    tracing::info!(trace_id = trace_id, intent_id = %intent.id, "[finalize] NATS publish step completed");

    let finalize_ms = finalize_start.elapsed().as_secs_f64() * 1000.0;
    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = ?intent.capability,
        result_status = ?result.status,
        publish_outcome = publish_outcome.0,
        finalize_latency_ms = finalize_ms,
        has_output = result.output.is_some(),
        has_error = result.error.is_some(),
        "[finalize] Result finalization summary"
    );
    tracing::info!(
        trace_id = trace_id,
        intent_id = %intent.id,
        capability = ?intent.capability,
        "[finalize] finalize_execution_result complete"
    );

    if let Some(metrics_handle) = EXECUTOR_METRICS.get() {
        let m = metrics_handle.read().await;
        m.record_result_finalize_latency(&capability_label, finalize_ms);
        match publish_outcome.0 {
            "success" => m.record_result_published(&capability_label, "success"),
            _ => {
                m.record_result_published(&capability_label, "error");
                m.record_result_error();
            }
        }
    }

    Ok(())
}

async fn handle_admission_result(
    result: Result<ProcessingOutcome>,
    metrics: &Arc<tokio::sync::RwLock<metrics::ExecutorMetrics>>,
    capability: &str,
    trace_id: &str,
    intent_id: &str,
    admission_span: trace::AdmissionSpan,
) -> Result<ProcessingOutcome> {
    match result {
        Ok(ProcessingOutcome::Completed) => {
            let duration = admission_span.finish_success();
            let duration_ms = duration.as_secs_f64() * 1000.0;

            {
                let m = metrics.read().await;
                m.record_admission(capability, duration_ms);
            }

            tracing::info!(
                trace_id = trace_id,
                intent_id = intent_id,
                capability = capability,
                seq = 9,
                status = "admitted",
                code = "SUCCESS",
                duration_ms = duration_ms,
                "Intent admission pipeline completed successfully"
            );

            Ok(ProcessingOutcome::Completed)
        }
        Ok(ProcessingOutcome::Denied { reason }) => {
            let duration = admission_span.finish_success();
            let duration_ms = duration.as_secs_f64() * 1000.0;

            {
                let m = metrics.read().await;
                m.record_denial(capability, "POLICY_DENIED");
            }

            tracing::warn!(
                trace_id = trace_id,
                intent_id = intent_id,
                capability = capability,
                denial_reason = %reason,
                duration_ms = duration_ms,
                "Intent denied by policy; denial result published"
            );

            Ok(ProcessingOutcome::Denied { reason })
        }
        Err(e) => {
            let _duration = admission_span.finish_error(&e.to_string());

            {
                let m = metrics.read().await;
                m.record_denial(capability, "ADMISSION_ERROR");
            }

            tracing::warn!(
                trace_id = trace_id,
                intent_id = intent_id,
                capability = capability,
                error = %e,
                "Intent processing failed, audit logging skipped"
            );

            tracing::error!(
                trace_id = trace_id,
                intent_id = intent_id,
                capability = capability,
                seq = 0,
                status = "denied",
                code = "ADMISSION_ERROR",
                error = %e,
                "Intent admission pipeline failed"
            );

            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use serde_json::json;
    use smith_protocol::ExecutionStatus;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    // ==================== ProcessingOutcome Tests ====================

    #[test]
    fn test_processing_outcome_completed() {
        let outcome = ProcessingOutcome::Completed;
        assert!(matches!(outcome, ProcessingOutcome::Completed));
    }

    #[test]
    fn test_processing_outcome_denied() {
        let reason = "Policy violation".to_string();
        let outcome = ProcessingOutcome::Denied {
            reason: reason.clone(),
        };
        if let ProcessingOutcome::Denied { reason: r } = outcome {
            assert_eq!(r, reason);
        } else {
            panic!("Expected Denied variant");
        }
    }

    #[test]
    fn test_processing_outcome_clone() {
        let outcome = ProcessingOutcome::Denied {
            reason: "test".to_string(),
        };
        let cloned = outcome.clone();
        assert!(matches!(cloned, ProcessingOutcome::Denied { .. }));
    }

    #[test]
    fn test_processing_outcome_debug() {
        let outcome = ProcessingOutcome::Completed;
        let debug_str = format!("{:?}", outcome);
        assert!(debug_str.contains("Completed"));
    }

    // ==================== get_runner_capability_string Tests ====================

    #[test]
    fn test_get_runner_capability_fs_read_v1() {
        assert_eq!(
            get_runner_capability_string(&smith_protocol::Capability::FsReadV1),
            "fs.read.v1"
        );
    }

    #[test]
    fn test_get_runner_capability_http_fetch_v1() {
        assert_eq!(
            get_runner_capability_string(&smith_protocol::Capability::HttpFetchV1),
            "http.fetch"
        );
    }

    #[test]
    fn test_get_runner_capability_fs_write_v1() {
        assert_eq!(
            get_runner_capability_string(&smith_protocol::Capability::FsWriteV1),
            "fs.write"
        );
    }

    #[test]
    fn test_get_runner_capability_git_clone_v1() {
        assert_eq!(
            get_runner_capability_string(&smith_protocol::Capability::GitCloneV1),
            "git.clone"
        );
    }

    #[test]
    fn test_get_runner_capability_archive_read_v1() {
        assert_eq!(
            get_runner_capability_string(&smith_protocol::Capability::ArchiveReadV1),
            "archive.read"
        );
    }

    #[test]
    fn test_get_runner_capability_sqlite_query_v1() {
        assert_eq!(
            get_runner_capability_string(&smith_protocol::Capability::SqliteQueryV1),
            "sqlite.query"
        );
    }

    #[test]
    fn test_get_runner_capability_bench_report_v1() {
        assert_eq!(
            get_runner_capability_string(&smith_protocol::Capability::BenchReportV1),
            "bench.report"
        );
    }

    #[test]
    fn test_get_runner_capability_shell_exec() {
        assert_eq!(
            get_runner_capability_string(&smith_protocol::Capability::ShellExec),
            "shell.exec"
        );
    }

    #[test]
    fn test_get_runner_capability_http_fetch() {
        assert_eq!(
            get_runner_capability_string(&smith_protocol::Capability::HttpFetch),
            "http.fetch"
        );
    }

    // ==================== extract_scope_paths Tests ====================

    #[test]
    fn test_extract_scope_paths_empty_map() {
        let scope = serde_json::Map::new();
        let paths = extract_scope_paths(&scope);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_extract_scope_paths_with_paths() {
        let mut scope = serde_json::Map::new();
        scope.insert(
            "paths".to_string(),
            json!(["/home/user", "/tmp", "/var/log"]),
        );
        let paths = extract_scope_paths(&scope);
        assert_eq!(paths.len(), 3);
        assert!(paths.contains(&"/home/user".to_string()));
        assert!(paths.contains(&"/tmp".to_string()));
        assert!(paths.contains(&"/var/log".to_string()));
    }

    #[test]
    fn test_extract_scope_paths_empty_array() {
        let mut scope = serde_json::Map::new();
        scope.insert("paths".to_string(), json!([]));
        let paths = extract_scope_paths(&scope);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_extract_scope_paths_non_array() {
        let mut scope = serde_json::Map::new();
        scope.insert("paths".to_string(), json!("not an array"));
        let paths = extract_scope_paths(&scope);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_extract_scope_paths_mixed_types() {
        let mut scope = serde_json::Map::new();
        scope.insert(
            "paths".to_string(),
            json!(["/valid", 123, null, "/also-valid"]),
        );
        let paths = extract_scope_paths(&scope);
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&"/valid".to_string()));
        assert!(paths.contains(&"/also-valid".to_string()));
    }

    // ==================== extract_scope_urls Tests ====================

    #[test]
    fn test_extract_scope_urls_empty_map() {
        let scope = serde_json::Map::new();
        let urls = extract_scope_urls(&scope);
        assert!(urls.is_empty());
    }

    #[test]
    fn test_extract_scope_urls_with_urls() {
        let mut scope = serde_json::Map::new();
        scope.insert(
            "urls".to_string(),
            json!(["https://example.com", "https://api.github.com"]),
        );
        let urls = extract_scope_urls(&scope);
        assert_eq!(urls.len(), 2);
        assert!(urls.contains(&"https://example.com".to_string()));
        assert!(urls.contains(&"https://api.github.com".to_string()));
    }

    #[test]
    fn test_extract_scope_urls_empty_array() {
        let mut scope = serde_json::Map::new();
        scope.insert("urls".to_string(), json!([]));
        let urls = extract_scope_urls(&scope);
        assert!(urls.is_empty());
    }

    #[test]
    fn test_extract_scope_urls_non_array() {
        let mut scope = serde_json::Map::new();
        scope.insert("urls".to_string(), json!("not an array"));
        let urls = extract_scope_urls(&scope);
        assert!(urls.is_empty());
    }

    // ==================== extract_session_context Tests ====================

    fn create_test_intent_with_metadata(metadata: HashMap<String, serde_json::Value>) -> Intent {
        Intent {
            id: "test-intent-123".to_string(),
            capability: smith_protocol::Capability::FsReadV1,
            domain: "test-domain".to_string(),
            signer: "test-signer".to_string(),
            created_at_ns: 0,
            ttl_ms: 30000,
            signature_b64: "".to_string(),
            nonce: "test-nonce".to_string(),
            params: json!({}),
            metadata,
        }
    }

    #[test]
    fn test_extract_session_context_no_session_id() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let session_ctx = extract_session_context(&intent);
        assert!(session_ctx.is_none());
    }

    #[test]
    fn test_extract_session_context_invalid_session_id() {
        let mut metadata = HashMap::new();
        metadata.insert("session_id".to_string(), json!("not-a-uuid"));
        let intent = create_test_intent_with_metadata(metadata);
        let session_ctx = extract_session_context(&intent);
        assert!(session_ctx.is_none());
    }

    #[test]
    fn test_extract_session_context_valid_session() {
        let session_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let mut metadata = HashMap::new();
        metadata.insert("session_id".to_string(), json!(session_uuid));
        let intent = create_test_intent_with_metadata(metadata);

        let session_ctx = extract_session_context(&intent);
        assert!(session_ctx.is_some());
        let ctx = session_ctx.unwrap();
        assert_eq!(ctx.session_id.to_string(), session_uuid);
        // Domain should fallback to intent.domain
        assert_eq!(ctx.domain.unwrap(), "test-domain");
        assert!(ctx.vm_profile.is_none());
    }

    #[test]
    fn test_extract_session_context_with_domain() {
        let session_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let mut metadata = HashMap::new();
        metadata.insert("session_id".to_string(), json!(session_uuid));
        metadata.insert("domain".to_string(), json!("custom-domain"));
        let intent = create_test_intent_with_metadata(metadata);

        let session_ctx = extract_session_context(&intent);
        assert!(session_ctx.is_some());
        let ctx = session_ctx.unwrap();
        assert_eq!(ctx.domain.unwrap(), "custom-domain");
    }

    #[test]
    fn test_extract_session_context_with_vm_profile() {
        let session_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let mut metadata = HashMap::new();
        metadata.insert("session_id".to_string(), json!(session_uuid));
        metadata.insert("vm_profile".to_string(), json!("high-memory"));
        let intent = create_test_intent_with_metadata(metadata);

        let session_ctx = extract_session_context(&intent);
        assert!(session_ctx.is_some());
        let ctx = session_ctx.unwrap();
        assert_eq!(ctx.vm_profile.unwrap(), "high-memory");
    }

    #[test]
    fn test_extract_session_context_full() {
        let session_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let mut metadata = HashMap::new();
        metadata.insert("session_id".to_string(), json!(session_uuid));
        metadata.insert("domain".to_string(), json!("prod-domain"));
        metadata.insert("vm_profile".to_string(), json!("standard"));
        let intent = create_test_intent_with_metadata(metadata);

        let session_ctx = extract_session_context(&intent);
        assert!(session_ctx.is_some());
        let ctx = session_ctx.unwrap();
        assert_eq!(ctx.session_id.to_string(), session_uuid);
        assert_eq!(ctx.domain.unwrap(), "prod-domain");
        assert_eq!(ctx.vm_profile.unwrap(), "standard");
    }

    // ==================== create_execution_limits Tests ====================

    fn create_test_landlock_profile() -> smith_config::LandlockProfile {
        smith_config::LandlockProfile {
            read: vec![],
            write: vec![],
        }
    }

    fn create_test_jailed_execution(workdir: std::path::PathBuf) -> jailer::JailedExecution {
        jailer::JailedExecution {
            workdir,
            limits: smith_protocol::ExecutionLimits::default(),
            pid: 1234,
            namespace_handle: None,
            cgroup_config: None,
        }
    }

    #[test]
    fn test_create_execution_limits_defaults() {
        let policy_result = policy::PolicyResult {
            allow: true,
            reason: None,
            limits: smith_protocol::ExecutionLimits::default(),
            scope: serde_json::Value::Null,
            policy_id: None,
        };
        let sandbox_profile = SandboxProfile {
            capability: "test",
            capability_versioned: "test.v1",
            seccomp_syscalls: vec![],
            landlock_profile: create_test_landlock_profile(),
            cgroup_limits: smith_config::CgroupLimits {
                cpu_pct: 0,
                mem_mb: 0,
            },
        };

        let limits = create_execution_limits(&policy_result, &sandbox_profile);
        assert_eq!(
            limits.cpu_ms_per_100ms,
            policy_result.limits.cpu_ms_per_100ms
        );
        assert_eq!(limits.mem_bytes, policy_result.limits.mem_bytes);
    }

    #[test]
    fn test_create_execution_limits_with_cgroup_cpu() {
        let policy_result = policy::PolicyResult {
            allow: true,
            reason: None,
            limits: smith_protocol::ExecutionLimits {
                cpu_ms_per_100ms: 50,
                mem_bytes: 1024 * 1024,
                io_bytes: 0,
                pids_max: 10,
                timeout_ms: 5000,
            },
            scope: serde_json::Value::Null,
            policy_id: None,
        };
        let sandbox_profile = SandboxProfile {
            capability: "test",
            capability_versioned: "test.v1",
            seccomp_syscalls: vec![],
            landlock_profile: create_test_landlock_profile(),
            cgroup_limits: smith_config::CgroupLimits {
                cpu_pct: 75,
                mem_mb: 0,
            },
        };

        let limits = create_execution_limits(&policy_result, &sandbox_profile);
        assert_eq!(limits.cpu_ms_per_100ms, 75);
    }

    #[test]
    fn test_create_execution_limits_cpu_capped_at_100() {
        let policy_result = policy::PolicyResult {
            allow: true,
            reason: None,
            limits: smith_protocol::ExecutionLimits::default(),
            scope: serde_json::Value::Null,
            policy_id: None,
        };
        let sandbox_profile = SandboxProfile {
            capability: "test",
            capability_versioned: "test.v1",
            seccomp_syscalls: vec![],
            landlock_profile: create_test_landlock_profile(),
            cgroup_limits: smith_config::CgroupLimits {
                cpu_pct: 150, // Over 100%
                mem_mb: 0,
            },
        };

        let limits = create_execution_limits(&policy_result, &sandbox_profile);
        assert_eq!(limits.cpu_ms_per_100ms, 100); // Capped at 100
    }

    #[test]
    fn test_create_execution_limits_with_memory() {
        let policy_result = policy::PolicyResult {
            allow: true,
            reason: None,
            limits: smith_protocol::ExecutionLimits::default(),
            scope: serde_json::Value::Null,
            policy_id: None,
        };
        let sandbox_profile = SandboxProfile {
            capability: "test",
            capability_versioned: "test.v1",
            seccomp_syscalls: vec![],
            landlock_profile: create_test_landlock_profile(),
            cgroup_limits: smith_config::CgroupLimits {
                cpu_pct: 0,
                mem_mb: 256,
            },
        };

        let limits = create_execution_limits(&policy_result, &sandbox_profile);
        assert_eq!(limits.mem_bytes, 256 * 1_048_576);
    }

    #[test]
    fn test_create_execution_context_applies_fallback_scope_only_for_policy_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp = TempDir::new().unwrap();
        let jail_workdir = temp.path().join("jail");
        std::fs::create_dir_all(&jail_workdir).unwrap();
        let jailed_execution = create_test_jailed_execution(jail_workdir.clone());

        let policy_result = policy::PolicyResult {
            allow: true,
            reason: Some("Policy enforcement disabled by configuration".to_string()),
            limits: smith_protocol::ExecutionLimits::default(),
            scope: serde_json::json!({}),
            policy_id: Some("policy.disabled.override".to_string()),
        };

        std::env::set_var(
            "SMITH_WORKSPACE_ROOT",
            temp.path().to_string_lossy().to_string(),
        );
        let ctx = create_execution_context(&jailed_execution, &policy_result, "trace-id");
        std::env::remove_var("SMITH_WORKSPACE_ROOT");

        assert_eq!(ctx.scope.paths.len(), 1);
        assert!(ctx.scope.paths[0].contains(temp.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn test_create_execution_context_does_not_apply_fallback_scope_without_policy_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp = TempDir::new().unwrap();
        let jail_workdir = temp.path().join("jail");
        std::fs::create_dir_all(&jail_workdir).unwrap();
        let jailed_execution = create_test_jailed_execution(jail_workdir);

        let policy_result = policy::PolicyResult {
            allow: true,
            reason: None,
            limits: smith_protocol::ExecutionLimits::default(),
            scope: serde_json::json!({}),
            policy_id: Some("builtin.default.allow".to_string()),
        };

        std::env::set_var(
            "SMITH_WORKSPACE_ROOT",
            temp.path().to_string_lossy().to_string(),
        );
        std::env::set_var("SMITH_EXECUTOR_DISABLE_POLICY", "1");
        let ctx = create_execution_context(&jailed_execution, &policy_result, "trace-id");
        std::env::remove_var("SMITH_EXECUTOR_DISABLE_POLICY");
        std::env::remove_var("SMITH_WORKSPACE_ROOT");

        assert!(ctx.scope.paths.is_empty());
    }

    // ==================== create_intent_result Tests ====================

    #[test]
    fn test_create_intent_result_success() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Ok,
            exit_code: Some(0),
            artifacts: vec![],
            duration_ms: 100,
            stdout_bytes: 50,
            stderr_bytes: 0,
        };
        let output_sink = runners::MemoryOutputSink::new();

        let result = create_intent_result(
            &intent,
            &execution_result,
            &output_sink,
            1000,
            2000,
            "test-digest",
            512,
        );

        assert_eq!(result.intent_id, "test-intent-123");
        assert_eq!(result.status, ExecutionStatus::Ok);
        assert!(result.output.is_some());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_create_intent_result_error() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Error,
            exit_code: Some(1),
            artifacts: vec![],
            duration_ms: 50,
            stdout_bytes: 0,
            stderr_bytes: 100,
        };
        let output_sink = runners::MemoryOutputSink::new();

        let result = create_intent_result(
            &intent,
            &execution_result,
            &output_sink,
            1000,
            2000,
            "test-digest",
            256,
        );

        assert_eq!(result.intent_id, "test-intent-123");
        assert_eq!(result.status, ExecutionStatus::Error);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_create_intent_result_with_output() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Ok,
            exit_code: Some(0),
            artifacts: vec![],
            duration_ms: 200,
            stdout_bytes: 100,
            stderr_bytes: 25,
        };
        let mut output_sink = runners::MemoryOutputSink::new();
        output_sink.stdout = b"Hello, World!".to_vec();
        output_sink.stderr = b"Warning: test".to_vec();

        let result = create_intent_result(
            &intent,
            &execution_result,
            &output_sink,
            0,
            200_000_000, // 200ms in nanoseconds
            "sha256:abc123",
            1024,
        );

        assert_eq!(result.status, ExecutionStatus::Ok);
        let output = result.output.unwrap();
        assert_eq!(output["stdout"], "Hello, World!");
        assert_eq!(output["stderr"], "Warning: test");
        assert_eq!(output["duration_ms"], 200);
    }

    #[test]
    fn test_create_intent_result_runner_metadata() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Ok,
            exit_code: Some(0),
            artifacts: vec![],
            duration_ms: 150,
            stdout_bytes: 0,
            stderr_bytes: 0,
        };
        let output_sink = runners::MemoryOutputSink::new();

        let result = create_intent_result(
            &intent,
            &execution_result,
            &output_sink,
            1000,
            2000,
            "digest-xyz",
            2048,
        );

        assert_eq!(result.runner_meta.cpu_ms, 150);
        assert_eq!(result.runner_meta.max_rss_kb, 2048);
        assert_eq!(
            result.runner_meta.capability_digest,
            Some("digest-xyz".to_string())
        );
    }

    #[test]
    fn test_create_intent_result_audit_ref() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Ok,
            exit_code: Some(0),
            artifacts: vec![],
            duration_ms: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
        };
        let output_sink = runners::MemoryOutputSink::new();

        let result =
            create_intent_result(&intent, &execution_result, &output_sink, 0, 0, "test", 0);

        assert_eq!(result.audit_ref.id, "audit-test-intent-123");
    }

    // ==================== create_intent_result Status Branch Tests ====================

    #[test]
    fn test_create_intent_result_timeout_status() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Timeout,
            exit_code: None,
            artifacts: vec![],
            duration_ms: 30000,
            stdout_bytes: 0,
            stderr_bytes: 0,
        };
        let output_sink = runners::MemoryOutputSink::new();

        let result = create_intent_result(
            &intent,
            &execution_result,
            &output_sink,
            1000,
            31000000000,
            "test-digest",
            512,
        );

        assert_eq!(result.status, ExecutionStatus::Error);
        assert!(result.error.is_some());
        let error = result.error.unwrap();
        assert_eq!(error.code, "EXECUTION_OTHER");
        assert!(error.message.contains("Timeout"));
    }

    #[test]
    fn test_create_intent_result_denied_status() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Denied,
            exit_code: None,
            artifacts: vec![],
            duration_ms: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
        };
        let output_sink = runners::MemoryOutputSink::new();

        let result = create_intent_result(
            &intent,
            &execution_result,
            &output_sink,
            1000,
            2000,
            "test-digest",
            256,
        );

        assert_eq!(result.status, ExecutionStatus::Error);
        assert!(result.error.is_some());
        let error = result.error.unwrap();
        assert_eq!(error.code, "EXECUTION_OTHER");
        assert!(error.message.contains("Denied"));
    }

    #[test]
    fn test_create_intent_result_killed_status() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Killed,
            exit_code: Some(137),
            artifacts: vec![],
            duration_ms: 5000,
            stdout_bytes: 100,
            stderr_bytes: 50,
        };
        let output_sink = runners::MemoryOutputSink::new();

        let result = create_intent_result(
            &intent,
            &execution_result,
            &output_sink,
            1000,
            6000000000,
            "test-digest",
            1024,
        );

        assert_eq!(result.status, ExecutionStatus::Error);
        assert!(result.error.is_some());
        let error = result.error.unwrap();
        assert_eq!(error.code, "EXECUTION_OTHER");
        assert!(error.message.contains("Killed"));
    }

    #[test]
    fn test_create_intent_result_success_alias_status() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Success,
            exit_code: Some(0),
            artifacts: vec![],
            duration_ms: 100,
            stdout_bytes: 50,
            stderr_bytes: 0,
        };
        let output_sink = runners::MemoryOutputSink::new();

        let result = create_intent_result(
            &intent,
            &execution_result,
            &output_sink,
            1000,
            2000,
            "test-digest",
            512,
        );

        // Success alias should NOT match Ok, so it falls through to the catch-all
        assert_eq!(result.status, ExecutionStatus::Error);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_create_intent_result_failed_alias_status() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Failed,
            exit_code: Some(1),
            artifacts: vec![],
            duration_ms: 100,
            stdout_bytes: 0,
            stderr_bytes: 100,
        };
        let output_sink = runners::MemoryOutputSink::new();

        let result = create_intent_result(
            &intent,
            &execution_result,
            &output_sink,
            1000,
            2000,
            "test-digest",
            256,
        );

        // Failed alias should NOT match Error, so it falls through to the catch-all
        assert_eq!(result.status, ExecutionStatus::Error);
        assert!(result.error.is_some());
    }

    // ==================== log_pipeline_start Tests ====================

    #[test]
    fn test_log_pipeline_start_does_not_panic() {
        // Just verify the function runs without panicking
        log_pipeline_start("trace-123", "intent-456", "fs.read.v1");
    }

    #[test]
    fn test_log_pipeline_start_with_empty_strings() {
        // Should handle empty strings gracefully
        log_pipeline_start("", "", "");
    }

    #[test]
    fn test_log_pipeline_start_with_special_chars() {
        // Should handle special characters in trace/intent IDs
        log_pipeline_start("trace-αβγ-123", "intent-δεζ-456", "fs.read.v1");
    }

    // ==================== extract_scope_urls Additional Tests ====================

    #[test]
    fn test_extract_scope_urls_mixed_types() {
        let mut scope = serde_json::Map::new();
        scope.insert(
            "urls".to_string(),
            json!(["https://valid.com", 42, null, true, "http://also-valid.com"]),
        );
        let urls = extract_scope_urls(&scope);
        assert_eq!(urls.len(), 2);
        assert!(urls.contains(&"https://valid.com".to_string()));
        assert!(urls.contains(&"http://also-valid.com".to_string()));
    }

    // ==================== extract_session_context Additional Tests ====================

    #[test]
    fn test_extract_session_context_session_id_not_string() {
        let mut metadata = HashMap::new();
        metadata.insert("session_id".to_string(), json!(12345));
        let intent = create_test_intent_with_metadata(metadata);
        let session_ctx = extract_session_context(&intent);
        assert!(session_ctx.is_none());
    }

    #[test]
    fn test_extract_session_context_domain_not_string() {
        let session_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let mut metadata = HashMap::new();
        metadata.insert("session_id".to_string(), json!(session_uuid));
        metadata.insert("domain".to_string(), json!(12345)); // Not a string
        let intent = create_test_intent_with_metadata(metadata);

        let session_ctx = extract_session_context(&intent);
        assert!(session_ctx.is_some());
        let ctx = session_ctx.unwrap();
        // Should fallback to intent.domain
        assert_eq!(ctx.domain.unwrap(), "test-domain");
    }

    #[test]
    fn test_extract_session_context_vm_profile_not_string() {
        let session_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let mut metadata = HashMap::new();
        metadata.insert("session_id".to_string(), json!(session_uuid));
        metadata.insert("vm_profile".to_string(), json!({"invalid": "object"}));
        let intent = create_test_intent_with_metadata(metadata);

        let session_ctx = extract_session_context(&intent);
        assert!(session_ctx.is_some());
        let ctx = session_ctx.unwrap();
        assert!(ctx.vm_profile.is_none());
    }

    // ==================== create_execution_limits Additional Tests ====================

    #[test]
    fn test_create_execution_limits_both_cpu_and_memory() {
        let policy_result = policy::PolicyResult {
            allow: true,
            reason: None,
            limits: smith_protocol::ExecutionLimits {
                cpu_ms_per_100ms: 25,
                mem_bytes: 512 * 1024,
                io_bytes: 1000,
                pids_max: 5,
                timeout_ms: 10000,
            },
            scope: serde_json::Value::Null,
            policy_id: None,
        };
        let sandbox_profile = SandboxProfile {
            capability: "test",
            capability_versioned: "test.v1",
            seccomp_syscalls: vec![],
            landlock_profile: create_test_landlock_profile(),
            cgroup_limits: smith_config::CgroupLimits {
                cpu_pct: 80,
                mem_mb: 128,
            },
        };

        let limits = create_execution_limits(&policy_result, &sandbox_profile);
        assert_eq!(limits.cpu_ms_per_100ms, 80);
        assert_eq!(limits.mem_bytes, 128 * 1_048_576);
        // These should preserve policy values
        assert_eq!(limits.io_bytes, 1000);
        assert_eq!(limits.pids_max, 5);
        assert_eq!(limits.timeout_ms, 10000);
    }

    #[test]
    fn test_create_execution_limits_preserves_policy_when_cgroup_zero() {
        let policy_result = policy::PolicyResult {
            allow: true,
            reason: None,
            limits: smith_protocol::ExecutionLimits {
                cpu_ms_per_100ms: 60,
                mem_bytes: 2 * 1024 * 1024,
                io_bytes: 5000,
                pids_max: 20,
                timeout_ms: 15000,
            },
            scope: serde_json::Value::Null,
            policy_id: None,
        };
        let sandbox_profile = SandboxProfile {
            capability: "test",
            capability_versioned: "test.v1",
            seccomp_syscalls: vec![],
            landlock_profile: create_test_landlock_profile(),
            cgroup_limits: smith_config::CgroupLimits {
                cpu_pct: 0,
                mem_mb: 0,
            },
        };

        let limits = create_execution_limits(&policy_result, &sandbox_profile);
        // Should preserve policy values when cgroup limits are 0
        assert_eq!(limits.cpu_ms_per_100ms, 60);
        assert_eq!(limits.mem_bytes, 2 * 1024 * 1024);
    }

    // ==================== create_intent_result Edge Case Tests ====================

    #[test]
    fn test_create_intent_result_with_logs() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Ok,
            exit_code: Some(0),
            artifacts: vec![],
            duration_ms: 50,
            stdout_bytes: 10,
            stderr_bytes: 5,
        };
        let mut output_sink = runners::MemoryOutputSink::new();
        output_sink.logs.push("Log line 1".to_string());
        output_sink.logs.push("Log line 2".to_string());

        let result = create_intent_result(
            &intent,
            &execution_result,
            &output_sink,
            1000,
            2000,
            "test-digest",
            256,
        );

        let output = result.output.unwrap();
        let logs = output["logs"].as_array().unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0], "Log line 1");
        assert_eq!(logs[1], "Log line 2");
    }

    #[test]
    fn test_create_intent_result_zero_duration() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Ok,
            exit_code: Some(0),
            artifacts: vec![],
            duration_ms: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
        };
        let output_sink = runners::MemoryOutputSink::new();

        let result = create_intent_result(
            &intent,
            &execution_result,
            &output_sink,
            1000,
            1000, // Same start and end
            "test-digest",
            0,
        );

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert_eq!(result.runner_meta.cpu_ms, 0);
        assert_eq!(result.runner_meta.max_rss_kb, 0);
    }

    #[test]
    fn test_create_intent_result_large_memory_usage() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Ok,
            exit_code: Some(0),
            artifacts: vec![],
            duration_ms: 1000,
            stdout_bytes: 1_000_000,
            stderr_bytes: 500_000,
        };
        let output_sink = runners::MemoryOutputSink::new();

        let result = create_intent_result(
            &intent,
            &execution_result,
            &output_sink,
            0,
            1_000_000_000,
            "test-digest",
            4_194_304, // 4GB in KB
        );

        assert_eq!(result.runner_meta.max_rss_kb, 4_194_304);
    }

    #[test]
    fn test_create_intent_result_error_with_exit_code() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Error,
            exit_code: Some(127), // Command not found
            artifacts: vec![],
            duration_ms: 10,
            stdout_bytes: 0,
            stderr_bytes: 50,
        };
        let output_sink = runners::MemoryOutputSink::new();

        let result = create_intent_result(
            &intent,
            &execution_result,
            &output_sink,
            1000,
            2000,
            "test-digest",
            128,
        );

        assert_eq!(result.status, ExecutionStatus::Error);
        let error = result.error.unwrap();
        assert!(error.message.contains("127"));
    }

    #[test]
    fn test_create_intent_result_error_without_exit_code() {
        let intent = create_test_intent_with_metadata(HashMap::new());
        let execution_result = runners::ExecutionResult {
            status: ExecutionStatus::Error,
            exit_code: None,
            artifacts: vec![],
            duration_ms: 5,
            stdout_bytes: 0,
            stderr_bytes: 0,
        };
        let output_sink = runners::MemoryOutputSink::new();

        let result = create_intent_result(
            &intent,
            &execution_result,
            &output_sink,
            1000,
            2000,
            "test-digest",
            64,
        );

        assert_eq!(result.status, ExecutionStatus::Error);
        let error = result.error.unwrap();
        assert!(error.message.contains("None"));
    }

    // ==================== ProcessingOutcome Additional Tests ====================

    #[test]
    fn test_processing_outcome_denied_empty_reason() {
        let outcome = ProcessingOutcome::Denied {
            reason: String::new(),
        };
        if let ProcessingOutcome::Denied { reason } = outcome {
            assert!(reason.is_empty());
        } else {
            panic!("Expected Denied variant");
        }
    }

    #[test]
    fn test_processing_outcome_denied_long_reason() {
        let long_reason = "a".repeat(10000);
        let outcome = ProcessingOutcome::Denied {
            reason: long_reason.clone(),
        };
        if let ProcessingOutcome::Denied { reason } = outcome {
            assert_eq!(reason.len(), 10000);
        } else {
            panic!("Expected Denied variant");
        }
    }

    #[test]
    fn test_processing_outcome_debug_denied() {
        let outcome = ProcessingOutcome::Denied {
            reason: "test reason".to_string(),
        };
        let debug_str = format!("{:?}", outcome);
        assert!(debug_str.contains("Denied"));
        assert!(debug_str.contains("test reason"));
    }

    // ==================== Async Pipeline Tests with Mocks ====================

    mod pipeline_mock_tests {
        use super::*;
        use crate::idempotency::mock::MockIdempotencyStore;
        use crate::idempotency::IdempotencyOps;
        use crate::nats::mock::MockResultPublisher;
        use crate::nats::IntentResultPublisher;
        use smith_protocol::{AuditRef, ExecutionStatus, IntentResult, RunnerMetadata};

        fn create_test_intent(id: &str) -> Intent {
            Intent {
                id: id.to_string(),
                capability: smith_protocol::Capability::FsReadV1,
                domain: "test-domain".to_string(),
                signer: "test-signer".to_string(),
                created_at_ns: 0,
                ttl_ms: 30000,
                signature_b64: "".to_string(),
                nonce: "test-nonce".to_string(),
                params: json!({"path": "/tmp/test.txt"}),
                metadata: HashMap::new(),
            }
        }

        fn create_test_result(intent_id: &str) -> IntentResult {
            IntentResult {
                intent_id: intent_id.to_string(),
                status: ExecutionStatus::Ok,
                output: Some(json!({"stdout": "test output"})),
                error: None,
                started_at_ns: 1000000,
                finished_at_ns: 2000000,
                runner_meta: RunnerMetadata::empty(),
                audit_ref: AuditRef {
                    id: format!("audit-{}", intent_id),
                    timestamp: 1000,
                    hash: "test-hash".to_string(),
                },
            }
        }

        /// Generic version of handle_idempotency for testing
        async fn handle_idempotency_generic<I, P>(
            intent: &Intent,
            idempotency_store: &I,
            result_publisher: &P,
            trace_id: &str,
        ) -> Result<bool>
        where
            I: IdempotencyOps,
            P: IntentResultPublisher,
        {
            if idempotency_store.is_processed(&intent.id).await? {
                tracing::info!(
                    trace_id = trace_id,
                    intent_id = %intent.id,
                    "Intent already processed (idempotent)"
                );

                // Return cached result if available
                let cached_result = idempotency_store.get_result(&intent.id).await?;
                if let Some(result) = cached_result {
                    result_publisher.publish_result(&intent.id, &result).await?;
                }
                return Ok(true); // Already processed
            }

            // Mark as processing to prevent duplicates
            idempotency_store.mark_processing(&intent.id).await?;

            Ok(false) // Not processed yet
        }

        /// Generic version of finalize_execution_result for testing
        async fn finalize_execution_result_generic<I, P>(
            intent: &Intent,
            result: IntentResult,
            idempotency_store: &I,
            result_publisher: &P,
            trace_id: &str,
        ) -> Result<()>
        where
            I: IdempotencyOps,
            P: IntentResultPublisher,
        {
            tracing::info!(
                trace_id = trace_id,
                intent_id = %intent.id,
                status = ?&result.status,
                "[finalize] Persisting intent result"
            );

            // Store result for idempotency
            idempotency_store
                .store_result(&intent.id, &result)
                .await
                .ok();

            // Publish result to NATS
            result_publisher.publish_result(&intent.id, &result).await?;

            tracing::info!(
                trace_id = trace_id,
                intent_id = %intent.id,
                "[finalize] Result finalization complete"
            );

            Ok(())
        }

        // ==================== handle_idempotency Tests ====================

        #[tokio::test]
        async fn test_handle_idempotency_new_intent() {
            let mock_store = MockIdempotencyStore::new();
            let mock_publisher = MockResultPublisher::new();
            let intent = create_test_intent("intent-1");

            let result =
                handle_idempotency_generic(&intent, &mock_store, &mock_publisher, "trace-1")
                    .await
                    .unwrap();

            assert!(!result); // Not already processed
            assert_eq!(
                mock_store
                    .is_processed_calls
                    .load(std::sync::atomic::Ordering::SeqCst),
                1
            );
            assert_eq!(
                mock_store
                    .mark_processing_calls
                    .load(std::sync::atomic::Ordering::SeqCst),
                1
            );
            assert_eq!(mock_publisher.call_count(), 0); // No result to publish
        }

        #[tokio::test]
        async fn test_handle_idempotency_already_processed_with_result() {
            let mock_store = MockIdempotencyStore::new();
            let mock_publisher = MockResultPublisher::new();
            let intent = create_test_intent("intent-1");
            let cached_result = create_test_result("intent-1");

            // Pre-seed the result
            mock_store.seed_result("intent-1", cached_result).await;

            let result =
                handle_idempotency_generic(&intent, &mock_store, &mock_publisher, "trace-1")
                    .await
                    .unwrap();

            assert!(result); // Already processed
            assert_eq!(mock_publisher.call_count(), 1); // Cached result published
            let published = mock_publisher.published_results();
            assert_eq!(published[0].0, "intent-1");
        }

        #[tokio::test]
        async fn test_handle_idempotency_already_processed_no_cached_result() {
            let mock_store = MockIdempotencyStore::new();
            let mock_publisher = MockResultPublisher::new();
            let intent = create_test_intent("intent-1");

            // Mark as processed but no cached result
            mock_store.mark_as_processed("intent-1").await;

            let result =
                handle_idempotency_generic(&intent, &mock_store, &mock_publisher, "trace-1")
                    .await
                    .unwrap();

            assert!(result); // Already processed
            assert_eq!(mock_publisher.call_count(), 0); // No result to publish
        }

        #[tokio::test]
        async fn test_handle_idempotency_store_error() {
            let mock_store = MockIdempotencyStore::new();
            let mock_publisher = MockResultPublisher::new();
            let intent = create_test_intent("intent-1");

            mock_store
                .should_fail_is_processed
                .store(true, std::sync::atomic::Ordering::SeqCst);

            let result =
                handle_idempotency_generic(&intent, &mock_store, &mock_publisher, "trace-1").await;

            assert!(result.is_err());
        }

        #[tokio::test]
        async fn test_handle_idempotency_publish_error() {
            let mock_store = MockIdempotencyStore::new();
            let mock_publisher = MockResultPublisher::new();
            let intent = create_test_intent("intent-1");
            let cached_result = create_test_result("intent-1");

            mock_store.seed_result("intent-1", cached_result).await;
            mock_publisher.fail_next(1);

            let result =
                handle_idempotency_generic(&intent, &mock_store, &mock_publisher, "trace-1").await;

            assert!(result.is_err());
        }

        // ==================== finalize_execution_result Tests ====================

        #[tokio::test]
        async fn test_finalize_execution_result_success() {
            let mock_store = MockIdempotencyStore::new();
            let mock_publisher = MockResultPublisher::new();
            let intent = create_test_intent("intent-1");
            let result = create_test_result("intent-1");

            let finalize_result = finalize_execution_result_generic(
                &intent,
                result.clone(),
                &mock_store,
                &mock_publisher,
                "trace-1",
            )
            .await;

            assert!(finalize_result.is_ok());
            assert_eq!(
                mock_store
                    .store_result_calls
                    .load(std::sync::atomic::Ordering::SeqCst),
                1
            );
            assert_eq!(mock_publisher.call_count(), 1);
        }

        #[tokio::test]
        async fn test_finalize_execution_result_store_failure_continues() {
            let mock_store = MockIdempotencyStore::new();
            let mock_publisher = MockResultPublisher::new();
            let intent = create_test_intent("intent-1");
            let result = create_test_result("intent-1");

            // Store failure should not prevent publish
            mock_store
                .should_fail_store_result
                .store(true, std::sync::atomic::Ordering::SeqCst);

            let finalize_result = finalize_execution_result_generic(
                &intent,
                result.clone(),
                &mock_store,
                &mock_publisher,
                "trace-1",
            )
            .await;

            assert!(finalize_result.is_ok());
            assert_eq!(mock_publisher.call_count(), 1); // Publish still happens
        }

        #[tokio::test]
        async fn test_finalize_execution_result_publish_failure() {
            let mock_store = MockIdempotencyStore::new();
            let mock_publisher = MockResultPublisher::new();
            let intent = create_test_intent("intent-1");
            let result = create_test_result("intent-1");

            mock_publisher.fail_next(1);

            let finalize_result = finalize_execution_result_generic(
                &intent,
                result.clone(),
                &mock_store,
                &mock_publisher,
                "trace-1",
            )
            .await;

            assert!(finalize_result.is_err());
            assert_eq!(
                mock_store
                    .store_result_calls
                    .load(std::sync::atomic::Ordering::SeqCst),
                1
            );
        }

        #[tokio::test]
        async fn test_finalize_with_error_result() {
            let mock_store = MockIdempotencyStore::new();
            let mock_publisher = MockResultPublisher::new();
            let intent = create_test_intent("intent-1");
            let mut result = create_test_result("intent-1");
            result.status = ExecutionStatus::Error;
            result.error = Some(smith_protocol::ExecutionError {
                code: "TEST_ERROR".to_string(),
                message: "Test error message".to_string(),
            });

            let finalize_result = finalize_execution_result_generic(
                &intent,
                result.clone(),
                &mock_store,
                &mock_publisher,
                "trace-1",
            )
            .await;

            assert!(finalize_result.is_ok());
            let published = mock_publisher.published_results();
            assert_eq!(published[0].1.status, ExecutionStatus::Error);
        }

        #[tokio::test]
        async fn test_finalize_with_denied_result() {
            let mock_store = MockIdempotencyStore::new();
            let mock_publisher = MockResultPublisher::new();
            let intent = create_test_intent("intent-1");
            let mut result = create_test_result("intent-1");
            result.status = ExecutionStatus::Denied;

            let finalize_result = finalize_execution_result_generic(
                &intent,
                result.clone(),
                &mock_store,
                &mock_publisher,
                "trace-1",
            )
            .await;

            assert!(finalize_result.is_ok());
            let published = mock_publisher.published_results();
            assert_eq!(published[0].1.status, ExecutionStatus::Denied);
        }

        #[tokio::test]
        async fn test_finalize_with_timeout_result() {
            let mock_store = MockIdempotencyStore::new();
            let mock_publisher = MockResultPublisher::new();
            let intent = create_test_intent("intent-1");
            let mut result = create_test_result("intent-1");
            result.status = ExecutionStatus::Timeout;

            let finalize_result = finalize_execution_result_generic(
                &intent,
                result.clone(),
                &mock_store,
                &mock_publisher,
                "trace-1",
            )
            .await;

            assert!(finalize_result.is_ok());
            let published = mock_publisher.published_results();
            assert_eq!(published[0].1.status, ExecutionStatus::Timeout);
        }

        // ==================== Integration-style Tests ====================

        #[tokio::test]
        async fn test_full_intent_processing_flow() {
            let mock_store = MockIdempotencyStore::new();
            let mock_publisher = MockResultPublisher::new();
            let intent = create_test_intent("intent-1");

            // Step 1: Check idempotency (not processed)
            let is_duplicate =
                handle_idempotency_generic(&intent, &mock_store, &mock_publisher, "trace-1")
                    .await
                    .unwrap();

            assert!(!is_duplicate);

            // Step 2: Simulate execution and finalize
            let result = create_test_result("intent-1");
            finalize_execution_result_generic(
                &intent,
                result.clone(),
                &mock_store,
                &mock_publisher,
                "trace-1",
            )
            .await
            .unwrap();

            // Step 3: Try again - should be idempotent
            let is_duplicate =
                handle_idempotency_generic(&intent, &mock_store, &mock_publisher, "trace-2")
                    .await
                    .unwrap();

            assert!(is_duplicate);
            assert_eq!(mock_publisher.call_count(), 2); // Once for finalize, once for idempotent return
        }

        #[tokio::test]
        async fn test_concurrent_intents() {
            let mock_store = MockIdempotencyStore::new();
            let mock_publisher = MockResultPublisher::new();

            // Process multiple intents
            for i in 0..5 {
                let intent = create_test_intent(&format!("intent-{}", i));
                let result = create_test_result(&format!("intent-{}", i));

                let is_duplicate = handle_idempotency_generic(
                    &intent,
                    &mock_store,
                    &mock_publisher,
                    &format!("trace-{}", i),
                )
                .await
                .unwrap();

                assert!(!is_duplicate);

                finalize_execution_result_generic(
                    &intent,
                    result,
                    &mock_store,
                    &mock_publisher,
                    &format!("trace-{}", i),
                )
                .await
                .unwrap();
            }

            assert_eq!(mock_publisher.call_count(), 5);
            assert_eq!(
                mock_store
                    .mark_processing_calls
                    .load(std::sync::atomic::Ordering::SeqCst),
                5
            );
            assert_eq!(
                mock_store
                    .store_result_calls
                    .load(std::sync::atomic::Ordering::SeqCst),
                5
            );
        }
    }
}
