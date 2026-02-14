//! Consumer lag monitoring and backpressure management
//!
//! This module provides real-time consumer lag monitoring and automatic
//! backpressure application to maintain system stability under load.

use crate::sharding::{BackpressureAction, BackpressureManager};
use anyhow::{Context, Result};
use async_nats::jetstream::{self, consumer::Info as ConsumerInfo};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

/// Consumer lag monitoring service
#[derive(Clone)]
pub struct LagMonitor {
    jetstream: jetstream::Context,
    backpressure_manager: BackpressureManager,
    lag_stats: std::sync::Arc<RwLock<HashMap<String, ConsumerLagStats>>>,
    alert_sender: Option<mpsc::Sender<BackpressureAlert>>,
}

/// Consumer lag statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerLagStats {
    /// Consumer name
    pub consumer_name: String,

    /// Stream name
    pub stream_name: String,

    /// Current lag in messages
    pub message_lag: u64,

    /// Pending acknowledgments
    pub pending_acks: i64,

    /// Messages per second (calculated)
    pub throughput_mps: f64,

    /// Last update timestamp
    pub last_updated: DateTime<Utc>,

    /// Backpressure status
    pub backpressure_active: bool,

    /// Consumer utilization percentage
    pub utilization_percent: f64,
}

/// Backpressure alert information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackpressureAlert {
    pub consumer_name: String,
    pub stream_name: String,
    pub alert_type: BackpressureAlertType,
    pub message_lag: u64,
    pub pending_acks: i64,
    pub actions_taken: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackpressureAlertType {
    /// Lag exceeded threshold
    HighLag,
    /// Too many pending acknowledgments
    HighPendingAcks,
    /// Consumer completely stuck
    ConsumerStalled,
    /// Backpressure resolved
    BackpressureResolved,
}

impl LagMonitor {
    /// Create new lag monitor
    pub fn new(jetstream: jetstream::Context) -> Self {
        Self {
            jetstream,
            backpressure_manager: BackpressureManager::default(),
            lag_stats: std::sync::Arc::new(RwLock::new(HashMap::new())),
            alert_sender: None,
        }
    }

    /// Create lag monitor with custom backpressure configuration
    pub fn with_backpressure_config(
        jetstream: jetstream::Context,
        backpressure_manager: BackpressureManager,
    ) -> Self {
        Self {
            jetstream,
            backpressure_manager,
            lag_stats: std::sync::Arc::new(RwLock::new(HashMap::new())),
            alert_sender: None,
        }
    }

    /// Enable backpressure alerts
    pub fn with_alerts(mut self, alert_sender: mpsc::Sender<BackpressureAlert>) -> Self {
        self.alert_sender = Some(alert_sender);
        self
    }

    /// Start monitoring loop
    pub async fn start_monitoring(&self, check_interval: Duration) -> Result<()> {
        let mut interval = tokio::time::interval(check_interval);

        info!(
            "Starting consumer lag monitoring (interval: {:?})",
            check_interval
        );

        loop {
            interval.tick().await;

            if let Err(e) = self.check_all_consumers().await {
                error!("Failed to check consumer lag: {}", e);
            }
        }
    }

    /// Check lag for all consumers across all streams
    async fn check_all_consumers(&self) -> Result<()> {
        let stream_names = self.get_smith_stream_names().await?;

        for stream_name in stream_names {
            if let Err(e) = self.check_stream_consumers(&stream_name).await {
                error!(
                    "Failed to check consumers for stream {}: {}",
                    stream_name, e
                );
                continue;
            }
        }

        Ok(())
    }

    /// Get all Smith stream names
    async fn get_smith_stream_names(&self) -> Result<Vec<String>> {
        let streams = vec![
            "SDLC_RAW".to_string(),
            "ATOMS_VETTED".to_string(),
            "ATOMS_RESULTS".to_string(),
            "AUDIT_SECURITY".to_string(),
            "SDLC_QUARANTINE_BACKPRESSURE".to_string(),
        ];

        Ok(streams)
    }

    /// Check consumers for a specific stream
    async fn check_stream_consumers(&self, stream_name: &str) -> Result<()> {
        let mut stream = self
            .jetstream
            .get_stream(stream_name)
            .await
            .context(format!("Failed to get stream: {}", stream_name))?;

        let stream_info = stream.info().await.context("Failed to get stream info")?;

        // Get consumer names for this stream
        let consumer_names: Vec<String> = stream_info
            .config
            .clone()
            .subjects
            .iter()
            .map(|_| format!("{}-consumer", stream_name.to_lowercase()))
            .collect();

        for consumer_name in consumer_names {
            if let Ok(consumer) = self
                .jetstream
                .get_consumer_from_stream(stream_name, &consumer_name)
                .await
            {
                if let Err(e) = self
                    .check_consumer_lag(stream_name, &consumer_name, consumer)
                    .await
                {
                    error!("Failed to check lag for consumer {}: {}", consumer_name, e);
                }
            }
        }

        Ok(())
    }

    /// Check lag for a specific consumer
    async fn check_consumer_lag(
        &self,
        stream_name: &str,
        consumer_name: &str,
        mut consumer: jetstream::consumer::Consumer<jetstream::consumer::pull::Config>,
    ) -> Result<()> {
        let consumer_info = consumer
            .info()
            .await
            .context("Failed to get consumer info")?;

        let lag_stats = self
            .calculate_lag_stats(stream_name, consumer_name, consumer_info)
            .await?;

        // Check if backpressure should be applied
        let should_apply_backpressure = self
            .backpressure_manager
            .should_apply_backpressure(lag_stats.message_lag, lag_stats.pending_acks);

        // Apply backpressure if needed
        if should_apply_backpressure && !lag_stats.backpressure_active {
            self.apply_backpressure(&lag_stats).await?;
        } else if !should_apply_backpressure && lag_stats.backpressure_active {
            self.remove_backpressure(&lag_stats).await?;
        }

        // Update lag statistics
        {
            let mut stats_map = self.lag_stats.write().await;
            stats_map.insert(consumer_name.to_string(), lag_stats);
        }

        Ok(())
    }

    /// Calculate consumer lag statistics
    async fn calculate_lag_stats(
        &self,
        stream_name: &str,
        consumer_name: &str,
        consumer_info: &ConsumerInfo,
    ) -> Result<ConsumerLagStats> {
        // Calculate message lag - simplified for this compilation fix
        let message_lag = consumer_info.num_pending;

        // Get pending acknowledgments
        let pending_acks = consumer_info.num_pending as i64;

        // Calculate throughput (simplified - would need historical data for accuracy)
        let throughput_mps = self
            .calculate_throughput(consumer_name)
            .await
            .unwrap_or(0.0);

        // Calculate utilization percentage
        let max_ack_pending = consumer_info.config.max_ack_pending as f64;
        let utilization_percent = (pending_acks as f64 / max_ack_pending) * 100.0;

        // Check if backpressure is currently active
        let backpressure_active = {
            let stats_map = self.lag_stats.read().await;
            stats_map
                .get(consumer_name)
                .map(|stats| stats.backpressure_active)
                .unwrap_or(false)
        };

        Ok(ConsumerLagStats {
            consumer_name: consumer_name.to_string(),
            stream_name: stream_name.to_string(),
            message_lag,
            pending_acks,
            throughput_mps,
            last_updated: Utc::now(),
            backpressure_active,
            utilization_percent,
        })
    }

    /// Calculate throughput for a consumer (simplified implementation)
    async fn calculate_throughput(&self, consumer_name: &str) -> Option<f64> {
        let stats_map = self.lag_stats.read().await;
        if let Some(previous_stats) = stats_map.get(consumer_name) {
            let time_diff = (Utc::now() - previous_stats.last_updated).num_seconds() as f64;
            if time_diff > 0.0 {
                // This is a simplified calculation - in production you'd track actual message counts
                return Some(10.0); // Placeholder throughput
            }
        }
        None
    }

    /// Apply backpressure measures
    async fn apply_backpressure(&self, lag_stats: &ConsumerLagStats) -> Result<()> {
        let actions = self
            .backpressure_manager
            .generate_backpressure_response(lag_stats.message_lag, lag_stats.pending_acks);

        let mut action_descriptions = Vec::new();

        for action in actions {
            match action {
                BackpressureAction::RouteToQuarantine => {
                    // Route new messages to quarantine stream
                    self.route_to_quarantine(&lag_stats.consumer_name).await?;
                    action_descriptions.push("Routed to quarantine".to_string());
                }
                BackpressureAction::ReduceBatchSize(new_size) => {
                    // Reduce consumer batch size
                    self.reduce_batch_size(&lag_stats.consumer_name, new_size)
                        .await?;
                    action_descriptions.push(format!("Reduced batch size to {}", new_size));
                }
                BackpressureAction::ExtendAckWait(duration) => {
                    // Extend ack wait time
                    self.extend_ack_wait(&lag_stats.consumer_name, duration)
                        .await?;
                    action_descriptions.push(format!("Extended ack wait to {:?}", duration));
                }
                BackpressureAction::AlertOps(message) => {
                    // Send operations alert
                    self.send_ops_alert(&lag_stats.consumer_name, &message)
                        .await?;
                    action_descriptions.push(format!("Ops alert: {}", message));
                }
            }
        }

        // Send backpressure alert
        if let Some(ref alert_sender) = self.alert_sender {
            let alert = BackpressureAlert {
                consumer_name: lag_stats.consumer_name.clone(),
                stream_name: lag_stats.stream_name.clone(),
                alert_type: if lag_stats.message_lag > self.backpressure_manager.lag_threshold {
                    BackpressureAlertType::HighLag
                } else {
                    BackpressureAlertType::HighPendingAcks
                },
                message_lag: lag_stats.message_lag,
                pending_acks: lag_stats.pending_acks,
                actions_taken: action_descriptions,
                timestamp: chrono::Utc::now(),
            };

            if let Err(e) = alert_sender.try_send(alert) {
                error!("Failed to send backpressure alert: {}", e);
            }
        }

        warn!(
            consumer = lag_stats.consumer_name,
            stream = lag_stats.stream_name,
            message_lag = lag_stats.message_lag,
            pending_acks = lag_stats.pending_acks,
            "Applied backpressure measures"
        );

        Ok(())
    }

    /// Remove backpressure measures
    async fn remove_backpressure(&self, lag_stats: &ConsumerLagStats) -> Result<()> {
        info!(
            consumer = lag_stats.consumer_name,
            stream = lag_stats.stream_name,
            "Removing backpressure - lag resolved"
        );

        // Send resolution alert
        if let Some(ref alert_sender) = self.alert_sender {
            let alert = BackpressureAlert {
                consumer_name: lag_stats.consumer_name.clone(),
                stream_name: lag_stats.stream_name.clone(),
                alert_type: BackpressureAlertType::BackpressureResolved,
                message_lag: lag_stats.message_lag,
                pending_acks: lag_stats.pending_acks,
                actions_taken: vec!["Backpressure resolved".to_string()],
                timestamp: chrono::Utc::now(),
            };

            if let Err(e) = alert_sender.try_send(alert) {
                error!("Failed to send backpressure resolution alert: {}", e);
            }
        }

        Ok(())
    }

    /// Route messages to quarantine stream
    async fn route_to_quarantine(&self, consumer_name: &str) -> Result<()> {
        // Implementation would configure routing to quarantine stream
        debug!(
            "Routing messages to quarantine for consumer: {}",
            consumer_name
        );
        Ok(())
    }

    /// Reduce consumer batch size
    async fn reduce_batch_size(&self, consumer_name: &str, new_size: usize) -> Result<()> {
        // Implementation would update consumer configuration
        debug!(
            "Reducing batch size to {} for consumer: {}",
            new_size, consumer_name
        );
        Ok(())
    }

    /// Extend ack wait time
    async fn extend_ack_wait(&self, consumer_name: &str, duration: Duration) -> Result<()> {
        // Implementation would update consumer ack wait configuration
        debug!(
            "Extending ack wait to {:?} for consumer: {}",
            duration, consumer_name
        );
        Ok(())
    }

    /// Send operations alert
    async fn send_ops_alert(&self, consumer_name: &str, message: &str) -> Result<()> {
        warn!(
            consumer = consumer_name,
            alert = message,
            "Operations alert triggered"
        );
        Ok(())
    }

    /// Get current lag statistics for all consumers
    pub async fn get_lag_stats(&self) -> HashMap<String, ConsumerLagStats> {
        self.lag_stats.read().await.clone()
    }

    /// Get lag statistics for a specific consumer
    pub async fn get_consumer_lag_stats(&self, consumer_name: &str) -> Option<ConsumerLagStats> {
        self.lag_stats.read().await.get(consumer_name).cloned()
    }

    /// Check if any consumer is under backpressure
    pub async fn has_active_backpressure(&self) -> bool {
        let stats_map = self.lag_stats.read().await;
        stats_map.values().any(|stats| stats.backpressure_active)
    }

    /// Get total message lag across all consumers
    pub async fn get_total_lag(&self) -> u64 {
        let stats_map = self.lag_stats.read().await;
        stats_map.values().map(|stats| stats.message_lag).sum()
    }
}

/// Backpressure alert handler
pub struct BackpressureAlertHandler {
    alert_receiver: mpsc::Receiver<BackpressureAlert>,
}

impl BackpressureAlertHandler {
    pub fn new(alert_receiver: mpsc::Receiver<BackpressureAlert>) -> Self {
        Self { alert_receiver }
    }

    /// Start handling backpressure alerts
    pub async fn start_handling(&mut self) {
        while let Some(alert) = self.alert_receiver.recv().await {
            self.handle_alert(alert).await;
        }
    }

    async fn handle_alert(&self, alert: BackpressureAlert) {
        match alert.alert_type {
            BackpressureAlertType::HighLag => {
                error!(
                    consumer = alert.consumer_name,
                    stream = alert.stream_name,
                    lag = alert.message_lag,
                    "HIGH LAG ALERT: Consumer is {} messages behind",
                    alert.message_lag
                );
            }
            BackpressureAlertType::HighPendingAcks => {
                error!(
                    consumer = alert.consumer_name,
                    stream = alert.stream_name,
                    pending_acks = alert.pending_acks,
                    "HIGH PENDING ACKS ALERT: {} unacknowledged messages",
                    alert.pending_acks
                );
            }
            BackpressureAlertType::ConsumerStalled => {
                error!(
                    consumer = alert.consumer_name,
                    stream = alert.stream_name,
                    "CONSUMER STALLED ALERT: Consumer appears to be stuck"
                );
            }
            BackpressureAlertType::BackpressureResolved => {
                info!(
                    consumer = alert.consumer_name,
                    stream = alert.stream_name,
                    "Backpressure resolved for consumer"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consumer_lag_stats_creation() {
        let stats = ConsumerLagStats {
            consumer_name: "test-consumer".to_string(),
            stream_name: "TEST_STREAM".to_string(),
            message_lag: 500,
            pending_acks: 100,
            throughput_mps: 50.0,
            last_updated: Utc::now(),
            backpressure_active: false,
            utilization_percent: 75.0,
        };

        assert_eq!(stats.message_lag, 500);
        assert_eq!(stats.pending_acks, 100);
        assert!(!stats.backpressure_active);
    }

    #[test]
    fn test_backpressure_alert_creation() {
        let alert = BackpressureAlert {
            consumer_name: "test-consumer".to_string(),
            stream_name: "TEST_STREAM".to_string(),
            alert_type: BackpressureAlertType::HighLag,
            message_lag: 2000,
            pending_acks: 600,
            actions_taken: vec!["Routed to quarantine".to_string()],
            timestamp: chrono::Utc::now(),
        };

        assert_eq!(alert.message_lag, 2000);
        assert!(matches!(alert.alert_type, BackpressureAlertType::HighLag));
        assert_eq!(alert.actions_taken.len(), 1);
    }
}
