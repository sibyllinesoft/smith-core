use super::{
    DeliveryMetrics, DeliveryTracker, EscalationPreferences, GlobalNotificationPreferences,
    InteractionHandler, NotificationSystem, PreferenceManager, QuietHoursPolicy, TimeoutManager,
    UserInterventionOption,
};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

impl InteractionHandler {
    pub(crate) fn new() -> Self {
        Self {
            interaction_channels: Arc::new(RwLock::new(HashMap::new())),
            response_validators: Arc::new(RwLock::new(Vec::new())),
            timeout_manager: Arc::new(TimeoutManager::new()),
        }
    }
}

impl TimeoutManager {
    fn new() -> Self {
        Self {
            timeout_policies: Arc::new(RwLock::new(HashMap::new())),
            active_timeouts: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl NotificationSystem {
    pub(crate) fn new() -> Self {
        Self {
            notification_channels: Arc::new(RwLock::new(Vec::new())),
            delivery_tracker: Arc::new(DeliveryTracker::new()),
            preference_manager: Arc::new(PreferenceManager::new()),
        }
    }

    pub(crate) async fn send_intervention_notification(
        &self,
        _intervention_id: Uuid,
        _options: &[UserInterventionOption],
    ) -> Result<()> {
        Ok(())
    }
}

impl DeliveryTracker {
    fn new() -> Self {
        Self {
            delivery_records: Arc::new(RwLock::new(HashMap::new())),
            delivery_metrics: Arc::new(RwLock::new(DeliveryMetrics {
                total_messages: 0,
                successful_deliveries: 0,
                failed_deliveries: 0,
                average_delivery_time: Duration::from_secs(0),
                delivery_rate_by_channel: HashMap::new(),
            })),
        }
    }
}

impl PreferenceManager {
    fn new() -> Self {
        Self {
            user_preferences: Arc::new(RwLock::new(HashMap::new())),
            global_preferences: Arc::new(RwLock::new(GlobalNotificationPreferences {
                default_channels: vec!["email".to_string()],
                emergency_channels: vec!["slack".to_string(), "sms".to_string()],
                quiet_hours_policy: QuietHoursPolicy {
                    enforce_quiet_hours: true,
                    emergency_override: true,
                    time_zones: vec!["UTC".to_string()],
                    exceptions: vec!["critical".to_string()],
                },
                escalation_preferences: EscalationPreferences {
                    auto_escalate: true,
                    escalation_delay: Duration::from_secs(1800),
                    escalation_channels: vec!["slack".to_string()],
                    notification_frequency: Duration::from_secs(300),
                },
            })),
        }
    }
}
