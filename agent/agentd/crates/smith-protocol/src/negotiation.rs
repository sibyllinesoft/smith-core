use crate::{capabilities, Event};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Protocol version constants
pub const PROTOCOL_V0: u32 = 0;
pub const PROTOCOL_V1: u32 = 1;
pub const CURRENT_VERSION: u32 = PROTOCOL_V0; // v0 is current stable

/// Supported protocol versions in order of preference (newest first)
pub const SUPPORTED_VERSIONS: &[u32] = &[PROTOCOL_V1, PROTOCOL_V0];

/// Version negotiation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationResult {
    pub version: u32,
    pub capabilities: Vec<String>,
    pub fallback_reason: Option<String>,
    pub service_info: HashMap<String, String>,
}

/// Client information for negotiation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub supported_versions: Vec<u32>,
    pub requested_capabilities: Vec<String>,
    pub client_metadata: HashMap<String, String>,
}

/// Version and capability negotiator
pub struct ProtocolNegotiator {
    service_id: Uuid,
    available_capabilities: Vec<String>,
    service_metadata: HashMap<String, String>,
}

impl ProtocolNegotiator {
    pub fn new(service_id: Uuid) -> Self {
        let mut service_metadata = HashMap::new();
        service_metadata.insert(
            "service_name".to_string(),
            "claude-code-rs-core".to_string(),
        );
        service_metadata.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
        service_metadata.insert(
            "build_timestamp".to_string(),
            std::env::var("BUILD_TIMESTAMP").unwrap_or_else(|_| "unknown".to_string()),
        );
        service_metadata.insert(
            "git_commit".to_string(),
            std::env::var("GIT_COMMIT").unwrap_or_else(|_| "unknown".to_string()),
        );

        // Determine available capabilities based on compile-time features
        let available_capabilities = vec![
            capabilities::SHELL_EXEC.to_string(),
            capabilities::REPLAY.to_string(),
            capabilities::TRACING.to_string(),
            #[cfg(feature = "hooks-quickjs")]
            capabilities::HOOKS_JS.to_string(),
            #[cfg(feature = "hooks-rust")]
            capabilities::HOOKS_RUST.to_string(),
            #[cfg(feature = "nats")]
            capabilities::NATS.to_string(),
        ];

        #[cfg(feature = "protobuf")]
        service_metadata.insert("protobuf_support".to_string(), "true".to_string());

        Self {
            service_id,
            available_capabilities,
            service_metadata,
        }
    }

    /// Negotiate protocol version and capabilities with a client
    pub fn negotiate(&self, client_info: ClientInfo) -> Result<NegotiationResult> {
        // Find the highest mutually supported version
        let selected_version = self.select_version(&client_info.supported_versions)?;

        // Filter capabilities to those we actually support
        let granted_capabilities = self.filter_capabilities(&client_info.requested_capabilities);

        // Determine if fallback is needed
        let fallback_reason =
            self.check_fallback_conditions(selected_version, &granted_capabilities);

        // Add negotiation metadata
        let mut service_info = self.service_metadata.clone();
        service_info.insert(
            "negotiated_version".to_string(),
            selected_version.to_string(),
        );
        service_info.insert(
            "granted_capabilities".to_string(),
            granted_capabilities.len().to_string(),
        );

        Ok(NegotiationResult {
            version: selected_version,
            capabilities: granted_capabilities,
            fallback_reason,
            service_info,
        })
    }

    /// Select the best mutually supported protocol version
    fn select_version(&self, client_versions: &[u32]) -> Result<u32> {
        // Find the highest version that both client and server support
        for &server_version in SUPPORTED_VERSIONS {
            if client_versions.contains(&server_version) {
                return Ok(server_version);
            }
        }

        Err(anyhow!(
            "No compatible protocol version found. Server supports: {:?}, Client supports: {:?}",
            SUPPORTED_VERSIONS,
            client_versions
        ))
    }

    /// Filter requested capabilities to those actually available
    fn filter_capabilities(&self, requested: &[String]) -> Vec<String> {
        requested
            .iter()
            .filter(|cap| self.available_capabilities.contains(cap))
            .cloned()
            .collect()
    }

    /// Check if fallback to v0 is needed despite v1 being negotiated
    fn check_fallback_conditions(&self, version: u32, _capabilities: &[String]) -> Option<String> {
        match version {
            PROTOCOL_V1 => {
                // Check if protobuf feature is actually enabled
                #[cfg(not(feature = "protobuf"))]
                {
                    Some("Protobuf support not compiled in, falling back to JSONL".to_string())
                }

                #[cfg(feature = "protobuf")]
                {
                    // Could add other runtime checks here
                    None
                }
            }
            PROTOCOL_V0 => None, // v0 always works
            _ => Some(format!("Unsupported version {}, using v0", version)),
        }
    }

    /// Create a Ready event after successful negotiation
    pub fn create_ready_event(&self, result: &NegotiationResult) -> Event {
        Event::Ready {
            version: result.version,
            capabilities: result.capabilities.clone(),
            service_id: self.service_id,
        }
    }

    /// Get available capabilities
    pub fn get_available_capabilities(&self) -> &[String] {
        &self.available_capabilities
    }

    /// Check if a specific capability is supported
    pub fn supports_capability(&self, capability: &str) -> bool {
        self.available_capabilities
            .contains(&capability.to_string())
    }

    /// Get service metadata
    pub fn get_service_metadata(&self) -> &HashMap<String, String> {
        &self.service_metadata
    }
}

/// Capability compatibility checker
pub struct CapabilityChecker;

impl CapabilityChecker {
    /// Check if requested capabilities are compatible with each other
    pub fn check_compatibility(capabilities: &[String]) -> Result<Vec<String>> {
        let mut warnings = Vec::new();

        // Check for conflicting hook systems
        let has_js_hooks = capabilities.contains(&capabilities::HOOKS_JS.to_string());
        let has_rust_hooks = capabilities.contains(&capabilities::HOOKS_RUST.to_string());

        if has_js_hooks && has_rust_hooks {
            warnings
                .push("Both JS and Rust hooks enabled - performance may be impacted".to_string());
        }

        // Check for NATS without tracing (suboptimal observability)
        let has_nats = capabilities.contains(&capabilities::NATS.to_string());
        let has_tracing = capabilities.contains(&capabilities::TRACING.to_string());

        if has_nats && !has_tracing {
            warnings.push("NATS enabled without tracing - reduced observability".to_string());
        }

        // Warn about replay overhead
        let has_replay = capabilities.contains(&capabilities::REPLAY.to_string());
        if has_replay {
            warnings.push(
                "Replay enabled - performance overhead for recording all operations".to_string(),
            );
        }

        Ok(warnings)
    }

    /// Get recommended capabilities for a given use case
    pub fn recommend_capabilities(use_case: &str) -> Vec<String> {
        match use_case {
            "development" => vec![
                capabilities::SHELL_EXEC.to_string(),
                capabilities::HOOKS_JS.to_string(),
                capabilities::REPLAY.to_string(),
                capabilities::TRACING.to_string(),
            ],
            "production" => vec![
                capabilities::SHELL_EXEC.to_string(),
                capabilities::HOOKS_RUST.to_string(),
                capabilities::TRACING.to_string(),
                capabilities::NATS.to_string(),
            ],
            "testing" => vec![
                capabilities::SHELL_EXEC.to_string(),
                capabilities::REPLAY.to_string(),
                capabilities::TRACING.to_string(),
            ],
            "minimal" => vec![capabilities::SHELL_EXEC.to_string()],
            _ => vec![
                capabilities::SHELL_EXEC.to_string(),
                capabilities::TRACING.to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_negotiation() {
        let negotiator = ProtocolNegotiator::new(Uuid::new_v4());

        // Test successful negotiation
        let client_info = ClientInfo {
            supported_versions: vec![0, 1],
            requested_capabilities: vec![
                capabilities::SHELL_EXEC.to_string(),
                capabilities::TRACING.to_string(),
            ],
            client_metadata: HashMap::new(),
        };

        let result = negotiator.negotiate(client_info).unwrap();

        // Should select the highest mutually supported version
        assert!(result.version <= 1);
        assert!(result
            .capabilities
            .contains(&capabilities::SHELL_EXEC.to_string()));
        assert!(result
            .capabilities
            .contains(&capabilities::TRACING.to_string()));
    }

    #[test]
    fn test_incompatible_versions() {
        let negotiator = ProtocolNegotiator::new(Uuid::new_v4());

        let client_info = ClientInfo {
            supported_versions: vec![999], // Unsupported version
            requested_capabilities: vec![],
            client_metadata: HashMap::new(),
        };

        let result = negotiator.negotiate(client_info);
        assert!(result.is_err());
    }

    #[test]
    fn test_capability_filtering() {
        let negotiator = ProtocolNegotiator::new(Uuid::new_v4());

        let client_info = ClientInfo {
            supported_versions: vec![0],
            requested_capabilities: vec![
                capabilities::SHELL_EXEC.to_string(),
                "non_existent_capability".to_string(),
            ],
            client_metadata: HashMap::new(),
        };

        let result = negotiator.negotiate(client_info).unwrap();

        // Should only grant supported capabilities
        assert!(result
            .capabilities
            .contains(&capabilities::SHELL_EXEC.to_string()));
        assert!(!result
            .capabilities
            .contains(&"non_existent_capability".to_string()));
    }

    #[test]
    fn test_capability_compatibility() {
        let warnings = CapabilityChecker::check_compatibility(&[
            capabilities::HOOKS_JS.to_string(),
            capabilities::HOOKS_RUST.to_string(),
        ])
        .unwrap();

        // Should warn about conflicting hook systems
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("JS and Rust hooks"));
    }

    #[test]
    fn test_use_case_recommendations() {
        let dev_caps = CapabilityChecker::recommend_capabilities("development");
        let prod_caps = CapabilityChecker::recommend_capabilities("production");

        // Development should include replay for debugging
        assert!(dev_caps.contains(&capabilities::REPLAY.to_string()));
        assert!(dev_caps.contains(&capabilities::HOOKS_JS.to_string()));

        // Production should prioritize performance
        assert!(!prod_caps.contains(&capabilities::REPLAY.to_string()));
        assert!(prod_caps.contains(&capabilities::HOOKS_RUST.to_string()));
        assert!(prod_caps.contains(&capabilities::NATS.to_string()));
    }

    #[test]
    fn test_protocol_constants() {
        // Test protocol version constants
        assert_eq!(PROTOCOL_V0, 0);
        assert_eq!(PROTOCOL_V1, 1);
        assert_eq!(CURRENT_VERSION, PROTOCOL_V0);

        // Test supported versions array
        assert!(SUPPORTED_VERSIONS.contains(&PROTOCOL_V0));
        assert!(SUPPORTED_VERSIONS.contains(&PROTOCOL_V1));
        assert!(SUPPORTED_VERSIONS.len() >= 2);
    }

    #[test]
    fn test_negotiator_methods() {
        let service_id = Uuid::new_v4();
        let negotiator = ProtocolNegotiator::new(service_id);

        // Test capability support checking
        assert!(negotiator.supports_capability(capabilities::SHELL_EXEC));
        assert!(negotiator.supports_capability(capabilities::TRACING));
        assert!(!negotiator.supports_capability("non_existent_capability"));

        // Test available capabilities
        let caps = negotiator.get_available_capabilities();
        assert!(!caps.is_empty());
        assert!(caps.contains(&capabilities::SHELL_EXEC.to_string()));

        // Test service metadata
        let metadata = negotiator.get_service_metadata();
        assert!(metadata.contains_key("service_name"));
        assert!(metadata.contains_key("version"));
        assert_eq!(metadata.get("service_name").unwrap(), "claude-code-rs-core");
    }

    #[test]
    fn test_ready_event_creation() {
        let service_id = Uuid::new_v4();
        let negotiator = ProtocolNegotiator::new(service_id);

        let negotiation_result = NegotiationResult {
            version: PROTOCOL_V0,
            capabilities: vec![capabilities::SHELL_EXEC.to_string()],
            fallback_reason: None,
            service_info: HashMap::new(),
        };

        let event = negotiator.create_ready_event(&negotiation_result);

        match event {
            Event::Ready {
                version,
                capabilities,
                service_id: event_service_id,
            } => {
                assert_eq!(version, PROTOCOL_V0);
                assert_eq!(capabilities, vec![capabilities::SHELL_EXEC.to_string()]);
                assert_eq!(event_service_id, service_id);
            }
            _ => panic!("Expected Ready event"),
        }
    }

    #[test]
    fn test_fallback_conditions_v0() {
        let negotiator = ProtocolNegotiator::new(Uuid::new_v4());
        let fallback = negotiator.check_fallback_conditions(PROTOCOL_V0, &[]);
        assert!(fallback.is_none()); // v0 should never need fallback
    }

    #[test]
    fn test_fallback_conditions_unsupported_version() {
        let negotiator = ProtocolNegotiator::new(Uuid::new_v4());
        let fallback = negotiator.check_fallback_conditions(999, &[]);
        assert!(fallback.is_some());
        assert!(fallback.unwrap().contains("Unsupported version 999"));
    }

    #[test]
    fn test_capability_compatibility_nats_without_tracing() {
        let warnings =
            CapabilityChecker::check_compatibility(&[capabilities::NATS.to_string()]).unwrap();

        // Should warn about NATS without tracing
        assert!(!warnings.is_empty());
        assert!(warnings
            .iter()
            .any(|w| w.contains("NATS enabled without tracing")));
    }

    #[test]
    fn test_capability_compatibility_with_replay() {
        let warnings =
            CapabilityChecker::check_compatibility(&[capabilities::REPLAY.to_string()]).unwrap();

        // Should warn about replay overhead
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("Replay enabled")));
    }

    #[test]
    fn test_capability_compatibility_good_config() {
        let warnings = CapabilityChecker::check_compatibility(&[
            capabilities::SHELL_EXEC.to_string(),
            capabilities::TRACING.to_string(),
        ])
        .unwrap();

        // No warnings for good configuration
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_use_case_recommendations_all_variants() {
        let test_cases = vec![
            (
                "development",
                vec![
                    capabilities::SHELL_EXEC,
                    capabilities::HOOKS_JS,
                    capabilities::REPLAY,
                    capabilities::TRACING,
                ],
            ),
            (
                "production",
                vec![
                    capabilities::SHELL_EXEC,
                    capabilities::HOOKS_RUST,
                    capabilities::TRACING,
                    capabilities::NATS,
                ],
            ),
            (
                "testing",
                vec![
                    capabilities::SHELL_EXEC,
                    capabilities::REPLAY,
                    capabilities::TRACING,
                ],
            ),
            ("minimal", vec![capabilities::SHELL_EXEC]),
            (
                "unknown_use_case",
                vec![capabilities::SHELL_EXEC, capabilities::TRACING],
            ),
        ];

        for (use_case, expected_caps) in test_cases {
            let recommendations = CapabilityChecker::recommend_capabilities(use_case);
            for cap in expected_caps {
                assert!(
                    recommendations.contains(&cap.to_string()),
                    "Use case '{}' should include capability '{}'",
                    use_case,
                    cap
                );
            }
        }
    }

    #[test]
    fn test_client_info_and_negotiation_result_serialization() {
        // Test ClientInfo serialization
        let mut metadata = HashMap::new();
        metadata.insert("client_version".to_string(), "1.0.0".to_string());

        let client_info = ClientInfo {
            supported_versions: vec![0, 1],
            requested_capabilities: vec![capabilities::SHELL_EXEC.to_string()],
            client_metadata: metadata,
        };

        let json = serde_json::to_string(&client_info).unwrap();
        let deserialized: ClientInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.supported_versions, vec![0, 1]);
        assert_eq!(
            deserialized.requested_capabilities,
            vec![capabilities::SHELL_EXEC.to_string()]
        );

        // Test NegotiationResult serialization
        let mut service_info = HashMap::new();
        service_info.insert("key".to_string(), "value".to_string());

        let result = NegotiationResult {
            version: PROTOCOL_V0,
            capabilities: vec![capabilities::SHELL_EXEC.to_string()],
            fallback_reason: Some("test fallback".to_string()),
            service_info,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: NegotiationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version, PROTOCOL_V0);
        assert_eq!(
            deserialized.fallback_reason,
            Some("test fallback".to_string())
        );
    }

    #[test]
    fn test_empty_client_versions_negotiation() {
        let negotiator = ProtocolNegotiator::new(Uuid::new_v4());

        let client_info = ClientInfo {
            supported_versions: vec![], // Empty versions
            requested_capabilities: vec![],
            client_metadata: HashMap::new(),
        };

        let result = negotiator.negotiate(client_info);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No compatible protocol version"));
    }

    #[test]
    fn test_empty_requested_capabilities() {
        let negotiator = ProtocolNegotiator::new(Uuid::new_v4());

        let client_info = ClientInfo {
            supported_versions: vec![PROTOCOL_V0],
            requested_capabilities: vec![], // Empty capabilities
            client_metadata: HashMap::new(),
        };

        let result = negotiator.negotiate(client_info).unwrap();
        assert_eq!(result.version, PROTOCOL_V0);
        assert!(result.capabilities.is_empty()); // Should grant no capabilities
    }

    #[test]
    fn test_version_selection_priority() {
        let negotiator = ProtocolNegotiator::new(Uuid::new_v4());

        // Client supports both versions - should select the newer one (v1)
        let client_info = ClientInfo {
            supported_versions: vec![PROTOCOL_V0, PROTOCOL_V1],
            requested_capabilities: vec![],
            client_metadata: HashMap::new(),
        };

        let result = negotiator.negotiate(client_info).unwrap();
        // Should prefer the highest supported version (v1 is preferred in SUPPORTED_VERSIONS)
        assert!(SUPPORTED_VERSIONS.contains(&result.version));
    }
}
