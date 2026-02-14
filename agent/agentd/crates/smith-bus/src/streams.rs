use anyhow::{Context, Result};
use async_nats::jetstream::{self, stream::Config as StreamConfig};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Stream manager for creating and managing JetStream streams
pub struct StreamManager {
    jetstream: jetstream::Context,
}

impl StreamManager {
    pub fn new(jetstream: jetstream::Context) -> Self {
        Self { jetstream }
    }

    /// Ensure all required Smith streams exist with proper configuration
    pub async fn bootstrap_streams(&self) -> Result<()> {
        info!("Bootstrapping Smith JetStream streams with Phase 2 performance optimization");

        // Create Phase 2 optimized stream architecture
        self.ensure_sdlc_raw_stream()
            .await
            .context("Failed to ensure SDLC_RAW stream")?;

        self.ensure_atoms_vetted_stream()
            .await
            .context("Failed to ensure ATOMS_VETTED stream")?;

        self.ensure_atoms_results_stream()
            .await
            .context("Failed to ensure ATOMS_RESULTS stream")?;

        self.ensure_audit_streams()
            .await
            .context("Failed to ensure AUDIT streams")?;

        self.ensure_backpressure_streams()
            .await
            .context("Failed to ensure BACKPRESSURE streams")?;

        info!("All Smith Phase 2 streams bootstrapped successfully");
        Ok(())
    }

    /// Phase 2: Raw intent ingestion stream (sdlc.raw)
    pub async fn ensure_sdlc_raw_stream(&self) -> Result<()> {
        let stream_name = "SDLC_RAW";
        let subjects = vec![
            "smith.intents.raw.*".to_string(), // All raw intents
        ];

        let config = StreamConfig {
            name: stream_name.to_string(),
            description: Some(
                "Phase 2: Raw intent ingestion with high-throughput optimization".to_string(),
            ),
            subjects,
            retention: jetstream::stream::RetentionPolicy::WorkQueue, // Work queue semantics
            max_age: Duration::from_secs(6 * 60 * 60), // 6 hours - shorter for raw processing
            max_bytes: 500 * 1024 * 1024,              // 500MB for high throughput
            max_messages: 50_000,                      // Higher message limit for load testing
            max_message_size: 2 * 1024 * 1024,         // 2MB for complex intents
            storage: jetstream::stream::StorageType::File,
            num_replicas: 1,
            discard: jetstream::stream::DiscardPolicy::Old,
            duplicate_window: Duration::from_secs(60), // 1 minute deduplication
            ..Default::default()
        };

        self.create_or_update_stream(config).await?;
        info!("SDLC_RAW stream ensured with high-throughput configuration");
        Ok(())
    }

    /// Phase 2: Policy-approved intents stream (atoms.vetted)
    pub async fn ensure_atoms_vetted_stream(&self) -> Result<()> {
        let stream_name = "ATOMS_VETTED";
        let subjects = vec![
            "smith.intents.vetted.*".to_string(), // Policy-approved intents
        ];

        let config = StreamConfig {
            name: stream_name.to_string(),
            description: Some(
                "Phase 2: Policy-approved intents with ordering guarantees".to_string(),
            ),
            subjects,
            retention: jetstream::stream::RetentionPolicy::Interest, // Keep until all consumers processed
            max_age: Duration::from_secs(12 * 60 * 60),              // 12 hours retention
            max_bytes: 1024 * 1024 * 1024,                           // 1GB for larger workloads
            max_messages: 100_000, // Higher capacity for load testing
            max_message_size: 2 * 1024 * 1024, // 2MB max
            storage: jetstream::stream::StorageType::File,
            num_replicas: 1,
            discard: jetstream::stream::DiscardPolicy::Old,
            duplicate_window: Duration::from_secs(2 * 60), // 2 minutes deduplication
            ..Default::default()
        };

        self.create_or_update_stream(config).await?;
        info!("ATOMS_VETTED stream ensured with ordering guarantees");
        Ok(())
    }

    /// Phase 2: Execution results stream (atoms.results)
    pub async fn ensure_atoms_results_stream(&self) -> Result<()> {
        let stream_name = "ATOMS_RESULTS";
        let subjects = vec![
            "smith.results.*".to_string(), // All execution results
        ];

        let config = StreamConfig {
            name: stream_name.to_string(),
            description: Some("Phase 2: Execution results with performance tracking".to_string()),
            subjects,
            retention: jetstream::stream::RetentionPolicy::Limits, // Time/size limited retention
            max_age: Duration::from_secs(48 * 60 * 60),            // 48 hours for analysis
            max_bytes: 2048 * 1024 * 1024,                         // 2GB for comprehensive results
            max_messages: 200_000, // High capacity for load testing results
            max_message_size: 4 * 1024 * 1024, // 4MB for detailed execution results
            storage: jetstream::stream::StorageType::File,
            num_replicas: 1,
            discard: jetstream::stream::DiscardPolicy::Old,
            duplicate_window: Duration::from_secs(5 * 60), // 5 minutes for results deduplication
            ..Default::default()
        };

        self.create_or_update_stream(config).await?;
        info!("ATOMS_RESULTS stream ensured with performance tracking");
        Ok(())
    }

    /// Phase 2: Audit and compliance streams
    pub async fn ensure_audit_streams(&self) -> Result<()> {
        // Security and compliance audit stream
        let audit_config = StreamConfig {
            name: "AUDIT_SECURITY".to_string(),
            description: Some("Phase 2: Security and compliance audit events".to_string()),
            subjects: vec!["smith.audit.*".to_string()],
            retention: jetstream::stream::RetentionPolicy::Interest, // Permanent retention for compliance
            max_age: Duration::from_secs(365 * 24 * 60 * 60),        // 1 year retention
            max_bytes: 10 * 1024 * 1024 * 1024, // 10GB for comprehensive audit trail
            max_messages: 1_000_000,            // High capacity for detailed auditing
            max_message_size: 1024 * 1024,      // 1MB for audit events
            storage: jetstream::stream::StorageType::File,
            num_replicas: 1,
            discard: jetstream::stream::DiscardPolicy::Old,
            duplicate_window: Duration::from_secs(60), // 1 minute deduplication
            ..Default::default()
        };

        self.create_or_update_stream(audit_config).await?;
        info!("AUDIT_SECURITY stream ensured with compliance retention");
        Ok(())
    }

    /// Phase 2: Backpressure and quarantine streams
    pub async fn ensure_backpressure_streams(&self) -> Result<()> {
        // Backpressure handling stream
        let backpressure_config = StreamConfig {
            name: "SDLC_QUARANTINE_BACKPRESSURE".to_string(),
            description: Some("Phase 2: Backpressure and quarantine handling".to_string()),
            subjects: vec!["smith.intents.quarantine.*".to_string()],
            retention: jetstream::stream::RetentionPolicy::WorkQueue, // Process and remove
            max_age: Duration::from_secs(2 * 60 * 60), // 2 hours for backpressure handling
            max_bytes: 100 * 1024 * 1024,              // 100MB for quarantined items
            max_messages: 10_000,                      // Reasonable limit for quarantine
            max_message_size: 1024 * 1024,             // 1MB max
            storage: jetstream::stream::StorageType::File,
            num_replicas: 1,
            discard: jetstream::stream::DiscardPolicy::Old,
            duplicate_window: Duration::from_secs(30), // 30 seconds deduplication
            ..Default::default()
        };

        self.create_or_update_stream(backpressure_config).await?;
        info!("SDLC_QUARANTINE_BACKPRESSURE stream ensured");
        Ok(())
    }

    /// Ensure the INTENT_RESULTS stream exists with proper configuration
    pub async fn ensure_results_stream(&self) -> Result<()> {
        let stream_name = "INTENT_RESULTS";
        let subjects = vec!["smith.results.*".to_string()];

        let config = StreamConfig {
            name: stream_name.to_string(),
            description: Some("Results from intent execution".to_string()),
            subjects,
            retention: jetstream::stream::RetentionPolicy::Limits, // Keep for specified time/count
            max_age: Duration::from_secs(48 * 60 * 60),            // Keep results for 48 hours
            max_bytes: 500 * 1024 * 1024,                          // 500MB max stream size
            max_messages: 50_000,                                  // 50k messages max
            max_message_size: 1024 * 1024,                         // 1MB max message size
            storage: jetstream::stream::StorageType::File,
            num_replicas: 1,
            discard: jetstream::stream::DiscardPolicy::Old,
            duplicate_window: Duration::from_secs(5 * 60),
            ..Default::default()
        };

        self.create_or_update_stream(config).await?;
        info!("INTENT_RESULTS stream ensured");
        Ok(())
    }

    /// Ensure the AUDIT_LOGS stream exists with proper configuration
    pub async fn ensure_audit_stream(&self) -> Result<()> {
        let stream_name = "AUDIT_LOGS";
        let subjects = vec!["smith.audit.*".to_string()];

        let config = StreamConfig {
            name: stream_name.to_string(),
            description: Some("Audit logs for compliance and debugging".to_string()),
            subjects,
            retention: jetstream::stream::RetentionPolicy::Limits,
            max_age: Duration::from_secs(30 * 24 * 60 * 60), // Keep audit logs for 30 days
            max_bytes: 1024 * 1024 * 1024,                   // 1GB max stream size
            max_messages: 100_000,                           // 100k messages max
            max_message_size: 512 * 1024,                    // 512KB max message size
            storage: jetstream::stream::StorageType::File,
            num_replicas: 1,
            discard: jetstream::stream::DiscardPolicy::Old,
            duplicate_window: Duration::from_secs(60),
            ..Default::default()
        };

        self.create_or_update_stream(config).await?;
        info!("AUDIT_LOGS stream ensured");
        Ok(())
    }

    /// Ensure the SYSTEM_EVENTS stream exists with proper configuration
    pub async fn ensure_system_events_stream(&self) -> Result<()> {
        let stream_name = "SYSTEM_EVENTS";
        let subjects = vec!["smith.system.*".to_string()];

        let config = StreamConfig {
            name: stream_name.to_string(),
            description: Some("System-level events and health monitoring".to_string()),
            subjects,
            retention: jetstream::stream::RetentionPolicy::Limits,
            max_age: Duration::from_secs(12 * 60 * 60), // Keep system events for 12 hours
            max_bytes: 50 * 1024 * 1024,                // 50MB max stream size
            max_messages: 10_000,                       // 10k messages max
            max_message_size: 64 * 1024,                // 64KB max message size
            storage: jetstream::stream::StorageType::File,
            num_replicas: 1,
            discard: jetstream::stream::DiscardPolicy::Old,
            duplicate_window: Duration::from_secs(30),
            ..Default::default()
        };

        self.create_or_update_stream(config).await?;
        info!("SYSTEM_EVENTS stream ensured");
        Ok(())
    }

    /// Create or update a stream with the given configuration
    async fn create_or_update_stream(&self, config: StreamConfig) -> Result<()> {
        let stream_name = config.name.clone();

        debug!("Checking if stream {} exists", stream_name);

        match self.jetstream.get_stream(&stream_name).await {
            Ok(mut existing_stream) => {
                // Stream exists, check if update is needed
                let existing_config = existing_stream.info().await?.config.clone();

                if self.configs_differ(&existing_config, &config) {
                    info!("Updating stream {} configuration", stream_name);
                    self.jetstream
                        .update_stream(&config)
                        .await
                        .with_context(|| format!("Failed to update stream: {}", stream_name))?;
                    info!("Stream {} updated successfully", stream_name);
                } else {
                    debug!(
                        "Stream {} already exists with correct configuration",
                        stream_name
                    );
                }
            }
            Err(_) => {
                // Stream doesn't exist, create it
                info!("Creating stream: {}", stream_name);
                match self.jetstream.create_stream(&config).await {
                    Ok(_) => {
                        info!("Stream {} created successfully", stream_name);
                    }
                    Err(err) => {
                        warn!(
                            "Stream {} creation returned error ({}); assuming it already exists",
                            stream_name, err
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if stream configurations differ significantly
    fn configs_differ(&self, existing: &StreamConfig, new: &StreamConfig) -> bool {
        // Compare key configuration fields
        existing.subjects != new.subjects
            || existing.retention != new.retention
            || existing.max_age != new.max_age
            || existing.max_bytes != new.max_bytes
            || existing.max_messages != new.max_messages
            || existing.storage != new.storage
    }

    /// Get information about all Smith streams
    pub async fn get_streams_info(&self) -> Result<Vec<StreamInfo>> {
        let stream_names = vec!["INTENTS", "INTENT_RESULTS", "AUDIT_LOGS", "SYSTEM_EVENTS"];
        let mut streams_info = Vec::new();

        for stream_name in stream_names {
            match self.jetstream.get_stream(stream_name).await {
                Ok(mut stream) => {
                    let info = stream.info().await?;
                    streams_info.push(StreamInfo {
                        name: stream_name.to_string(),
                        subjects: info.config.subjects.clone(),
                        messages: info.state.messages,
                        bytes: info.state.bytes,
                        first_seq: info.state.first_sequence,
                        last_seq: info.state.last_sequence,
                        consumer_count: info.state.consumer_count,
                        exists: true,
                    });
                }
                Err(_) => {
                    streams_info.push(StreamInfo {
                        name: stream_name.to_string(),
                        subjects: vec![],
                        messages: 0,
                        bytes: 0,
                        first_seq: 0,
                        last_seq: 0,
                        consumer_count: 0,
                        exists: false,
                    });
                }
            }
        }

        Ok(streams_info)
    }

    /// Delete a stream (use with caution)
    pub async fn delete_stream(&self, stream_name: &str) -> Result<()> {
        warn!("Deleting stream: {}", stream_name);

        self.jetstream
            .delete_stream(stream_name)
            .await
            .with_context(|| format!("Failed to delete stream: {}", stream_name))?;

        info!("Stream {} deleted successfully", stream_name);
        Ok(())
    }
}

/// Information about a JetStream stream
#[derive(Debug, Clone)]
pub struct StreamInfo {
    /// Stream name
    pub name: String,
    /// Subjects this stream listens to
    pub subjects: Vec<String>,
    /// Number of messages in the stream
    pub messages: u64,
    /// Total bytes in the stream
    pub bytes: u64,
    /// First sequence number
    pub first_seq: u64,
    /// Last sequence number
    pub last_seq: u64,
    /// Number of consumers attached to this stream
    pub consumer_count: usize,
    /// Whether the stream exists
    pub exists: bool,
}

impl StreamInfo {
    /// Check if the stream is healthy (exists and not at capacity)
    pub fn is_healthy(&self) -> bool {
        self.exists && self.messages < 8000 && self.bytes < 80 * 1024 * 1024
    }

    /// Get utilization percentage (0-100)
    pub fn utilization_percent(&self) -> f64 {
        if !self.exists {
            return 0.0;
        }

        // Estimate based on typical stream limits
        let msg_util = (self.messages as f64 / 10000.0) * 100.0;
        let byte_util = (self.bytes as f64 / (100.0 * 1024.0 * 1024.0)) * 100.0;

        msg_util.max(byte_util).min(100.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_info_health() {
        let healthy_stream = StreamInfo {
            name: "TEST".to_string(),
            subjects: vec!["test.*".to_string()],
            messages: 1000,
            bytes: 10 * 1024 * 1024, // 10MB
            first_seq: 1,
            last_seq: 1000,
            consumer_count: 2,
            exists: true,
        };

        assert!(healthy_stream.is_healthy());

        let unhealthy_stream = StreamInfo {
            name: "TEST".to_string(),
            subjects: vec!["test.*".to_string()],
            messages: 9000,          // Too many messages
            bytes: 90 * 1024 * 1024, // 90MB - too much data
            first_seq: 1,
            last_seq: 9000,
            consumer_count: 1,
            exists: true,
        };

        assert!(!unhealthy_stream.is_healthy());
    }

    #[test]
    fn test_stream_utilization() {
        let stream = StreamInfo {
            name: "TEST".to_string(),
            subjects: vec!["test.*".to_string()],
            messages: 5000,          // 50% of 10k limit
            bytes: 50 * 1024 * 1024, // 50% of 100MB limit
            first_seq: 1,
            last_seq: 5000,
            consumer_count: 1,
            exists: true,
        };

        let utilization = stream.utilization_percent();
        assert!((45.0..=55.0).contains(&utilization)); // Should be around 50%
    }

    #[test]
    fn test_non_existent_stream() {
        let stream = StreamInfo {
            name: "MISSING".to_string(),
            subjects: vec![],
            messages: 0,
            bytes: 0,
            first_seq: 0,
            last_seq: 0,
            consumer_count: 0,
            exists: false,
        };

        assert!(!stream.is_healthy());
        assert_eq!(stream.utilization_percent(), 0.0);
    }
}
