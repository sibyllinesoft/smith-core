//! Episode-based subject sharding for ordering guarantees
//!
//! This module implements subject-hash sharding to ensure ordering guarantees
//! within episode boundaries while allowing parallel processing across episodes.

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Episode identifier for sharding and ordering
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct EpisodeId {
    /// Unique episode identifier
    pub id: String,
    /// Optional project context for isolation
    pub project: Option<String>,
}

impl EpisodeId {
    pub fn new(id: String) -> Self {
        Self { id, project: None }
    }

    pub fn with_project(id: String, project: String) -> Self {
        Self {
            id,
            project: Some(project),
        }
    }

    /// Generate a subject suffix based on episode hash for sharding
    pub fn to_subject_suffix(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        let hash = hasher.finish();

        // Use modulo to create consistent sharding
        let shard = hash % 16; // 16 shards for good distribution
        format!("shard.{:02x}", shard)
    }
}

/// Subject builder with episode-based sharding support
pub struct ShardedSubjectBuilder {
    base_subject: String,
    episode_id: Option<EpisodeId>,
}

impl ShardedSubjectBuilder {
    pub fn new(base_subject: String) -> Self {
        Self {
            base_subject,
            episode_id: None,
        }
    }

    pub fn with_episode(mut self, episode_id: EpisodeId) -> Self {
        self.episode_id = Some(episode_id);
        self
    }

    /// Build the sharded subject
    pub fn build(self) -> String {
        match self.episode_id {
            Some(episode) => {
                format!("{}.{}", self.base_subject, episode.to_subject_suffix())
            }
            None => self.base_subject,
        }
    }
}

/// Consumer configuration optimized for Phase 2 performance requirements
#[derive(Debug, Clone)]
pub struct OptimizedConsumerConfig {
    /// Consumer name
    pub name: String,

    /// Maximum messages to deliver without acknowledgment
    pub max_ack_pending: i64,

    /// Maximum delivery attempts before dead letter
    pub max_deliver: i64,

    /// Acknowledgment wait time
    pub ack_wait: std::time::Duration,

    /// Pull-based consumer batch size
    pub batch_size: usize,

    /// Consumer filter subject (supports sharding)
    pub filter_subject: Option<String>,

    /// Flow control settings
    pub flow_control: FlowControlConfig,
}

#[derive(Debug, Clone)]
pub struct FlowControlConfig {
    /// Idle heartbeat interval
    pub idle_heartbeat: std::time::Duration,

    /// Maximum waiting time for messages
    pub max_waiting: i64,

    /// Enable flow control
    pub enabled: bool,
}

impl Default for OptimizedConsumerConfig {
    fn default() -> Self {
        Self {
            name: format!("consumer-{}", uuid::Uuid::new_v4()),
            max_ack_pending: 1000, // Higher for throughput
            max_deliver: 3,
            ack_wait: std::time::Duration::from_secs(60), // Longer for complex processing
            batch_size: 50,                               // Optimized batch size
            filter_subject: None,
            flow_control: FlowControlConfig {
                idle_heartbeat: std::time::Duration::from_secs(5),
                max_waiting: 512, // Higher concurrency
                enabled: true,
            },
        }
    }
}

impl OptimizedConsumerConfig {
    /// Create consumer config optimized for fs.read capability
    pub fn for_fs_read() -> Self {
        Self {
            name: "fs-read-consumer".to_string(),
            max_ack_pending: 2000, // High throughput
            max_deliver: 3,
            ack_wait: std::time::Duration::from_secs(30), // Fast I/O operations
            batch_size: 100,                              // Large batches for file operations
            filter_subject: Some("smith.intents.vetted.fs.read.*".to_string()),
            flow_control: FlowControlConfig {
                idle_heartbeat: std::time::Duration::from_secs(2),
                max_waiting: 1024,
                enabled: true,
            },
        }
    }

    /// Create consumer config optimized for http.fetch capability  
    pub fn for_http_fetch() -> Self {
        Self {
            name: "http-fetch-consumer".to_string(),
            max_ack_pending: 500, // Moderate throughput for network I/O
            max_deliver: 5,       // More retries for network failures
            ack_wait: std::time::Duration::from_secs(120), // Longer for HTTP timeouts
            batch_size: 25,       // Smaller batches for network operations
            filter_subject: Some("smith.intents.vetted.http.fetch.*".to_string()),
            flow_control: FlowControlConfig {
                idle_heartbeat: std::time::Duration::from_secs(10),
                max_waiting: 256,
                enabled: true,
            },
        }
    }

    /// Create consumer config optimized for admission control
    pub fn for_admission() -> Self {
        Self {
            name: "admission-consumer".to_string(),
            max_ack_pending: 5000, // Very high throughput for policy checks
            max_deliver: 2,        // Fast failures for admission
            ack_wait: std::time::Duration::from_secs(5), // Very fast processing
            batch_size: 200,       // Large batches for policy validation
            filter_subject: Some("smith.intents.raw.*".to_string()),
            flow_control: FlowControlConfig {
                idle_heartbeat: std::time::Duration::from_secs(1),
                max_waiting: 2048, // Very high concurrency
                enabled: true,
            },
        }
    }
}

/// Backpressure detection and management
#[derive(Debug, Clone)]
pub struct BackpressureManager {
    /// Threshold for consumer lag (messages)
    pub lag_threshold: u64,

    /// Threshold for pending acks
    pub pending_ack_threshold: i64,

    /// Backpressure response actions
    pub response_actions: Vec<BackpressureAction>,
}

#[derive(Debug, Clone)]
pub enum BackpressureAction {
    /// Route overload to quarantine stream
    RouteToQuarantine,

    /// Reduce batch sizes
    ReduceBatchSize(usize),

    /// Increase ack wait times
    ExtendAckWait(std::time::Duration),

    /// Alert operations team
    AlertOps(String),
}

impl Default for BackpressureManager {
    fn default() -> Self {
        Self {
            lag_threshold: 1000,        // 1000 messages behind
            pending_ack_threshold: 500, // 500 unacked messages
            response_actions: vec![
                BackpressureAction::RouteToQuarantine,
                BackpressureAction::ReduceBatchSize(10),
                BackpressureAction::AlertOps("High consumer lag detected".to_string()),
            ],
        }
    }
}

impl BackpressureManager {
    /// Check if backpressure should be applied
    pub fn should_apply_backpressure(&self, consumer_lag: u64, pending_acks: i64) -> bool {
        consumer_lag > self.lag_threshold || pending_acks > self.pending_ack_threshold
    }

    /// Generate backpressure response
    pub fn generate_backpressure_response(
        &self,
        consumer_lag: u64,
        pending_acks: i64,
    ) -> Vec<BackpressureAction> {
        if self.should_apply_backpressure(consumer_lag, pending_acks) {
            self.response_actions.clone()
        } else {
            vec![]
        }
    }
}

/// Performance optimization helpers for JetStream consumers
pub struct ConsumerOptimizer;

impl ConsumerOptimizer {
    /// Calculate optimal MaxAckPending based on executor concurrency
    pub fn calculate_max_ack_pending(executor_concurrency: usize, capability: &str) -> i64 {
        let base_multiplier = match capability {
            "fs.read" => 10,   // Fast I/O operations
            "http.fetch" => 5, // Slower network operations
            "admission" => 20, // Very fast policy checks
            _ => 8,            // Default multiplier
        };

        (executor_concurrency * base_multiplier) as i64
    }

    /// Calculate optimal batch size based on message processing time
    pub fn calculate_batch_size(avg_processing_time_ms: u64, capability: &str) -> usize {
        let base_size = match capability {
            "fs.read" => 100,   // Large batches for file I/O
            "http.fetch" => 25, // Smaller batches for network
            "admission" => 200, // Very large batches for fast processing
            _ => 50,            // Default batch size
        };

        // Adjust based on processing time
        if avg_processing_time_ms < 10 {
            base_size * 2 // Very fast processing, larger batches
        } else if avg_processing_time_ms > 1000 {
            base_size / 2 // Slow processing, smaller batches
        } else {
            base_size
        }
    }

    /// Generate optimized consumer configuration
    pub fn optimize_consumer_config(
        capability: &str,
        executor_concurrency: usize,
        avg_processing_time_ms: u64,
    ) -> OptimizedConsumerConfig {
        let base_config = match capability {
            "fs.read" => OptimizedConsumerConfig::for_fs_read(),
            "http.fetch" => OptimizedConsumerConfig::for_http_fetch(),
            "admission" => OptimizedConsumerConfig::for_admission(),
            _ => OptimizedConsumerConfig::default(),
        };

        OptimizedConsumerConfig {
            max_ack_pending: Self::calculate_max_ack_pending(executor_concurrency, capability),
            batch_size: Self::calculate_batch_size(avg_processing_time_ms, capability),
            ..base_config
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_episode_id_sharding() {
        let episode1 = EpisodeId::new("episode-123".to_string());
        let episode2 = EpisodeId::new("episode-456".to_string());

        let suffix1 = episode1.to_subject_suffix();
        let suffix2 = episode2.to_subject_suffix();

        // Different episodes should get different suffixes
        assert_ne!(suffix1, suffix2);

        // Same episode should get same suffix
        let episode1_duplicate = EpisodeId::new("episode-123".to_string());
        assert_eq!(suffix1, episode1_duplicate.to_subject_suffix());
    }

    #[test]
    fn test_sharded_subject_builder() {
        let episode = EpisodeId::new("test-episode".to_string());
        let subject = ShardedSubjectBuilder::new("smith.intents.vetted.fs.read.v1".to_string())
            .with_episode(episode.clone())
            .build();

        assert!(subject.starts_with("smith.intents.vetted.fs.read.v1.shard."));
        assert!(subject.contains(&episode.to_subject_suffix()));
    }

    #[test]
    fn test_consumer_config_optimization() {
        let fs_read_config = OptimizedConsumerConfig::for_fs_read();
        assert_eq!(fs_read_config.batch_size, 100);
        assert_eq!(fs_read_config.max_ack_pending, 2000);

        let http_fetch_config = OptimizedConsumerConfig::for_http_fetch();
        assert_eq!(http_fetch_config.batch_size, 25);
        assert_eq!(http_fetch_config.max_deliver, 5); // More retries for network

        let admission_config = OptimizedConsumerConfig::for_admission();
        assert_eq!(admission_config.batch_size, 200);
        assert_eq!(admission_config.max_ack_pending, 5000);
    }

    #[test]
    fn test_backpressure_manager() {
        let manager = BackpressureManager::default();

        // Normal conditions - no backpressure
        assert!(!manager.should_apply_backpressure(100, 50));

        // High lag - should apply backpressure
        assert!(manager.should_apply_backpressure(1500, 50));

        // High pending acks - should apply backpressure
        assert!(manager.should_apply_backpressure(100, 600));

        // Both high - should apply backpressure
        assert!(manager.should_apply_backpressure(1500, 600));
    }

    #[test]
    fn test_consumer_optimizer() {
        // Test MaxAckPending calculation
        let max_ack_pending = ConsumerOptimizer::calculate_max_ack_pending(10, "fs.read");
        assert_eq!(max_ack_pending, 100); // 10 * 10

        let max_ack_pending = ConsumerOptimizer::calculate_max_ack_pending(8, "http.fetch");
        assert_eq!(max_ack_pending, 40); // 8 * 5

        // Test batch size calculation
        let batch_size = ConsumerOptimizer::calculate_batch_size(5, "fs.read"); // Very fast
        assert_eq!(batch_size, 200); // 100 * 2

        let batch_size = ConsumerOptimizer::calculate_batch_size(2000, "http.fetch"); // Slow
        assert_eq!(batch_size, 12); // 25 / 2

        // Test full optimization
        let config = ConsumerOptimizer::optimize_consumer_config("fs.read", 16, 8);
        assert_eq!(config.max_ack_pending, 160); // 16 * 10
        assert_eq!(config.batch_size, 200); // Fast processing, larger batches
    }
}
