//! Metrics for Smith logging infrastructure

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Metrics collector for logging infrastructure
#[derive(Debug, Clone)]
pub struct LoggingMetrics {
    /// Total log entries processed
    pub entries_processed: Arc<AtomicU64>,

    /// Total log entries published to NATS
    pub entries_published: Arc<AtomicU64>,

    /// Total log entries that failed to publish
    pub entries_failed: Arc<AtomicU64>,

    /// Total log entries dropped due to rate limiting
    pub entries_rate_limited: Arc<AtomicU64>,

    /// Total log entries dropped due to buffer overflow
    pub entries_buffer_overflow: Arc<AtomicU64>,

    /// Total bytes published to NATS
    pub bytes_published: Arc<AtomicU64>,

    /// Total publish attempts
    pub publish_attempts: Arc<AtomicU64>,

    /// Total publish retries
    pub publish_retries: Arc<AtomicU64>,

    /// Current buffer size (approximate)
    pub buffer_size: Arc<AtomicU64>,
}

impl Default for LoggingMetrics {
    fn default() -> Self {
        Self {
            entries_processed: Arc::new(AtomicU64::new(0)),
            entries_published: Arc::new(AtomicU64::new(0)),
            entries_failed: Arc::new(AtomicU64::new(0)),
            entries_rate_limited: Arc::new(AtomicU64::new(0)),
            entries_buffer_overflow: Arc::new(AtomicU64::new(0)),
            bytes_published: Arc::new(AtomicU64::new(0)),
            publish_attempts: Arc::new(AtomicU64::new(0)),
            publish_retries: Arc::new(AtomicU64::new(0)),
            buffer_size: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl LoggingMetrics {
    /// Create new metrics instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment entries processed counter
    pub fn inc_entries_processed(&self) {
        self.entries_processed.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment entries published counter
    pub fn inc_entries_published(&self) {
        self.entries_published.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment entries failed counter
    pub fn inc_entries_failed(&self) {
        self.entries_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment entries rate limited counter
    pub fn inc_entries_rate_limited(&self) {
        self.entries_rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment entries buffer overflow counter
    pub fn inc_entries_buffer_overflow(&self) {
        self.entries_buffer_overflow.fetch_add(1, Ordering::Relaxed);
    }

    /// Add to bytes published counter
    pub fn add_bytes_published(&self, bytes: u64) {
        self.bytes_published.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment publish attempts counter
    pub fn inc_publish_attempts(&self) {
        self.publish_attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment publish retries counter
    pub fn inc_publish_retries(&self) {
        self.publish_retries.fetch_add(1, Ordering::Relaxed);
    }

    /// Set current buffer size
    pub fn set_buffer_size(&self, size: u64) {
        self.buffer_size.store(size, Ordering::Relaxed);
    }

    /// Get entries processed count
    pub fn get_entries_processed(&self) -> u64 {
        self.entries_processed.load(Ordering::Relaxed)
    }

    /// Get entries published count
    pub fn get_entries_published(&self) -> u64 {
        self.entries_published.load(Ordering::Relaxed)
    }

    /// Get entries failed count
    pub fn get_entries_failed(&self) -> u64 {
        self.entries_failed.load(Ordering::Relaxed)
    }

    /// Get entries rate limited count
    pub fn get_entries_rate_limited(&self) -> u64 {
        self.entries_rate_limited.load(Ordering::Relaxed)
    }

    /// Get entries buffer overflow count
    pub fn get_entries_buffer_overflow(&self) -> u64 {
        self.entries_buffer_overflow.load(Ordering::Relaxed)
    }

    /// Get bytes published count
    pub fn get_bytes_published(&self) -> u64 {
        self.bytes_published.load(Ordering::Relaxed)
    }

    /// Get publish attempts count
    pub fn get_publish_attempts(&self) -> u64 {
        self.publish_attempts.load(Ordering::Relaxed)
    }

    /// Get publish retries count
    pub fn get_publish_retries(&self) -> u64 {
        self.publish_retries.load(Ordering::Relaxed)
    }

    /// Get current buffer size
    pub fn get_buffer_size(&self) -> u64 {
        self.buffer_size.load(Ordering::Relaxed)
    }

    /// Calculate success rate as percentage
    pub fn get_success_rate(&self) -> f64 {
        let published = self.get_entries_published();
        let total = self.get_entries_processed();

        if total == 0 {
            0.0
        } else {
            (published as f64 / total as f64) * 100.0
        }
    }

    /// Calculate average bytes per entry
    pub fn get_avg_bytes_per_entry(&self) -> f64 {
        let bytes = self.get_bytes_published();
        let entries = self.get_entries_published();

        if entries == 0 {
            0.0
        } else {
            bytes as f64 / entries as f64
        }
    }

    /// Get summary statistics
    pub fn get_summary(&self) -> LoggingMetricsSummary {
        LoggingMetricsSummary {
            entries_processed: self.get_entries_processed(),
            entries_published: self.get_entries_published(),
            entries_failed: self.get_entries_failed(),
            entries_rate_limited: self.get_entries_rate_limited(),
            entries_buffer_overflow: self.get_entries_buffer_overflow(),
            bytes_published: self.get_bytes_published(),
            publish_attempts: self.get_publish_attempts(),
            publish_retries: self.get_publish_retries(),
            current_buffer_size: self.get_buffer_size(),
            success_rate: self.get_success_rate(),
            avg_bytes_per_entry: self.get_avg_bytes_per_entry(),
        }
    }
}

/// Summary of logging metrics
#[derive(Debug, Clone)]
pub struct LoggingMetricsSummary {
    pub entries_processed: u64,
    pub entries_published: u64,
    pub entries_failed: u64,
    pub entries_rate_limited: u64,
    pub entries_buffer_overflow: u64,
    pub bytes_published: u64,
    pub publish_attempts: u64,
    pub publish_retries: u64,
    pub current_buffer_size: u64,
    pub success_rate: f64,
    pub avg_bytes_per_entry: f64,
}

impl std::fmt::Display for LoggingMetricsSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LoggingMetrics {{ processed: {}, published: {}, failed: {}, rate_limited: {}, buffer_overflow: {}, success_rate: {:.2}%, avg_bytes: {:.1} }}", 
               self.entries_processed,
               self.entries_published,
               self.entries_failed,
               self.entries_rate_limited,
               self.entries_buffer_overflow,
               self.success_rate,
               self.avg_bytes_per_entry)
    }
}
