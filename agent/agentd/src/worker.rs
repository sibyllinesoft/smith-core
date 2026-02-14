/*!
 * Worker execution module
 *
 * Extracted from main.rs to reduce complexity and improve maintainability.
 * Handles intent worker loops and message processing from NATS JetStream.
 */

use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, instrument};
use uuid::Uuid;

use smith_config::PolicyDerivations;
// smith_protocol types used in admission_pipeline module
use crate::{
    admission_pipeline::ProcessingOutcome, audit, config::Config, idempotency, metrics, nats,
    policy, runners, schema, security, trace,
};

/// Main worker execution loop for processing intents from NATS JetStream
#[instrument(
    skip_all,
    fields(
        capability = %capability,
        worker_id = %worker_id,
        capability_digest = %capability_digest[..8]
    )
)]
pub async fn run_worker(
    capability: String,
    worker_id: u32,
    nats_client: nats::NatsClient,
    idempotency_store: idempotency::IdempotencyStore,
    policy_engine: policy::PolicyEngine,
    schema_validator: Arc<schema::SchemaValidator>,
    runner_registry: Arc<runners::RunnerRegistry>,
    trusted_signers: Arc<security::TrustedSigners>,
    config: Config,
    metrics: Arc<tokio::sync::RwLock<metrics::ExecutorMetrics>>,
    audit_logger: Arc<tokio::sync::Mutex<audit::AuditLogger>>,
    capability_digest: String,
    derivations: Arc<PolicyDerivations>,
) -> Result<()> {
    info!(
        capability = %capability,
        worker_id = %worker_id,
        capability_digest = %capability_digest[..8],
        "Worker starting for capability processing"
    );

    // Create JetStream consumer for this capability
    let stream_config = config
        .executor
        .intent_streams
        .get(&capability)
        .ok_or_else(|| anyhow::anyhow!("No stream config found for capability: {}", capability))?;
    let mut consumer = match nats_client
        .create_consumer(&capability, stream_config)
        .await
    {
        Ok(consumer) => consumer,
        Err(err) => {
            tracing::error!(
                capability = %capability,
                worker_id = worker_id,
                error = %err,
                error_debug = ?err,
                "Failed to create JetStream consumer"
            );
            return Err(err);
        }
    };

    loop {
        // Create NATS pull span for tracing
        let nats_span = trace::ExecutorTracer::span_nats_pull(
            &capability,
            &format!("{}-worker-{}", capability, worker_id),
        );

        let pull_start = Instant::now();

        // Pull message from JetStream
        match consumer.next().await {
            Ok(Some(message)) => {
                let pull_duration = pull_start.elapsed();
                {
                    let m = metrics.read().await;
                    m.record_nats_pull_latency(pull_duration.as_secs_f64() * 1000.0);
                }
                let _nats_duration = nats_span.finish_success();

                let intent_id = Uuid::new_v4(); // This will be extracted from message
                let trace_id = trace::generate_trace_id();

                tracing::info!(
                    trace_id = trace_id,
                    intent_id = %intent_id,
                    capability = capability,
                    worker_id = worker_id,
                    seq = 0,
                    status = "pulled",
                    "Intent message pulled from NATS"
                );

                // Process the intent through admission pipeline
                match crate::admission_pipeline::process_intent(
                    message.message,
                    &idempotency_store,
                    &policy_engine,
                    &schema_validator,
                    &runner_registry,
                    &trusted_signers,
                    &config,
                    &nats_client,
                    &metrics,
                    &audit_logger,
                    &capability,
                    &intent_id.to_string(),
                    &trace_id,
                    &capability_digest,
                    &derivations,
                )
                .await
                {
                    Ok(ProcessingOutcome::Completed) => {
                        tracing::info!(
                            trace_id = trace_id,
                            intent_id = %intent_id,
                            capability = capability,
                            status = "completed",
                            code = "SUCCESS",
                            "Intent processed successfully"
                        );
                    }
                    Ok(ProcessingOutcome::Denied { reason }) => {
                        tracing::info!(
                            trace_id = trace_id,
                            intent_id = %intent_id,
                            capability = capability,
                            status = "denied",
                            code = "POLICY_DENIED",
                            denial_reason = %reason,
                            "Intent denied by policy"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            trace_id = trace_id,
                            intent_id = %intent_id,
                            capability = capability,
                            status = "error",
                            code = "PROCESSING_ERROR",
                            error = %e,
                            "Intent processing failed"
                        );

                        {
                            let m = metrics.read().await;
                            m.record_result_error();
                        }
                    }
                }
            }
            Ok(None) => {
                let _nats_duration = nats_span.finish_success();

                // Update queue depth metric to 0 when no messages
                {
                    let m = metrics.read().await;
                    m.set_queue_depth(&capability, 0);
                }

                // No messages available, continue polling
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
            Err(e) => {
                let _nats_duration = nats_span.finish_error(&e.to_string());

                {
                    let m = metrics.read().await;
                    m.record_nats_connection_error();
                }

                tracing::error!(
                    capability = capability,
                    worker_id = worker_id,
                    error = %e,
                    "Error pulling message from NATS"
                );

                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}
