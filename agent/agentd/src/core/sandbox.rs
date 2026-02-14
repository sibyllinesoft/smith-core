//! Sandbox lifecycle management
//!
//! This module defines the sandbox manager that handles:
//! - Creating new sandboxes
//! - Attaching to existing sandboxes
//! - Detaching from sandboxes (leaving them running)
//! - Suspending and resuming sandboxes
//! - Managing sandbox pools for warm starts
//! - Session tracking for sandbox reuse

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use super::intent::Command;
use super::isolation::{
    BackendCapabilities, ExecContext, ExecOutput, IsolationBackend, Sandbox, SandboxCapabilities,
    SandboxSpec,
};

/// Unique identifier for a sandbox
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SandboxId(pub String);

impl SandboxId {
    /// Create a new random sandbox ID
    pub fn new() -> Self {
        Self(format!("sbx-{}", Uuid::new_v4()))
    }

    /// Create from an existing string
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the string value
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SandboxId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SandboxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A session tracks the association between a client and a sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSession {
    /// Unique session identifier
    pub session_id: String,

    /// Associated sandbox ID
    pub sandbox_id: SandboxId,

    /// Client identifier that owns this session
    pub client_id: String,

    /// When the session was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When the session was last active
    pub last_active_at: chrono::DateTime<chrono::Utc>,

    /// Session state
    pub state: SessionState,

    /// Session metadata
    pub metadata: HashMap<String, String>,

    /// Timeout configuration
    pub timeouts: SessionTimeouts,
}

impl SandboxSession {
    /// Create a new session
    pub fn new(sandbox_id: SandboxId, client_id: &str) -> Self {
        let now = chrono::Utc::now();
        Self {
            session_id: format!("sess-{}", Uuid::new_v4()),
            sandbox_id,
            client_id: client_id.to_string(),
            created_at: now,
            last_active_at: now,
            state: SessionState::Active,
            metadata: HashMap::new(),
            timeouts: SessionTimeouts::default(),
        }
    }

    /// Check if the session has timed out
    pub fn is_timed_out(&self) -> bool {
        let now = chrono::Utc::now();
        let idle_duration = now - self.last_active_at;

        match self.state {
            SessionState::Active => {
                idle_duration > chrono::Duration::from_std(self.timeouts.idle_timeout).unwrap()
            }
            SessionState::Detached => {
                idle_duration > chrono::Duration::from_std(self.timeouts.detach_timeout).unwrap()
            }
            SessionState::Suspended => {
                idle_duration > chrono::Duration::from_std(self.timeouts.suspend_timeout).unwrap()
            }
            SessionState::Terminated => true,
        }
    }

    /// Update the last active timestamp
    pub fn touch(&mut self) {
        self.last_active_at = chrono::Utc::now();
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session is active and processing requests
    Active,
    /// Session is detached (client disconnected, sandbox still running)
    Detached,
    /// Session is suspended (sandbox paused)
    Suspended,
    /// Session is terminated
    Terminated,
}

/// Timeout configuration for sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTimeouts {
    /// How long before an idle active session times out
    pub idle_timeout: Duration,
    /// How long before a detached session's sandbox is destroyed
    pub detach_timeout: Duration,
    /// How long before a suspended session's sandbox is destroyed
    pub suspend_timeout: Duration,
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(300),      // 5 minutes
            detach_timeout: Duration::from_secs(3600),   // 1 hour
            suspend_timeout: Duration::from_secs(86400), // 24 hours
        }
    }
}

/// Request to attach to an existing sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachRequest {
    /// Sandbox ID to attach to
    pub sandbox_id: SandboxId,

    /// Client identifier requesting attachment
    pub client_id: String,

    /// Whether to create if it doesn't exist
    pub create_if_missing: bool,

    /// Spec for creation if create_if_missing is true
    pub create_spec: Option<SandboxSpec>,
}

/// Result of sandbox attachment
#[derive(Debug, Clone)]
pub struct AttachResult {
    /// The session for the attached sandbox
    pub session: SandboxSession,

    /// Whether the sandbox was newly created
    pub newly_created: bool,

    /// Sandbox capabilities
    pub capabilities: SandboxCapabilities,
}

/// Options for sandbox selection
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxSelectionOptions {
    /// Prefer a specific sandbox ID
    pub preferred_id: Option<SandboxId>,

    /// Require a fresh (newly created) sandbox
    pub require_fresh: bool,

    /// Minimum required capabilities
    pub required_capabilities: RequiredCapabilities,

    /// Preferred isolation backend
    pub preferred_backend: Option<String>,

    /// Labels that the sandbox must have
    pub required_labels: HashMap<String, String>,

    /// Whether to use a warm sandbox from the pool if available
    pub use_pool: bool,
}

/// Required capabilities for sandbox selection
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequiredCapabilities {
    /// Require network access
    pub network: Option<bool>,

    /// Require filesystem write access
    pub write_access: Option<bool>,

    /// Minimum memory limit
    pub min_memory_bytes: Option<u64>,

    /// Required readable paths
    pub readable_paths: Vec<String>,

    /// Required writable paths
    pub writable_paths: Vec<String>,
}

/// Statistics for the sandbox manager
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxManagerStats {
    /// Total sandboxes created
    pub sandboxes_created: u64,

    /// Currently active sandboxes
    pub active_sandboxes: u64,

    /// Active sessions
    pub active_sessions: u64,

    /// Detached sessions waiting
    pub detached_sessions: u64,

    /// Sandboxes in warm pool
    pub pool_size: u64,

    /// Pool hit rate (0.0 - 1.0)
    pub pool_hit_rate: f64,

    /// Average sandbox creation time in milliseconds
    pub avg_creation_time_ms: f64,

    /// Sandboxes destroyed due to timeout
    pub timeout_destroys: u64,
}

/// The sandbox manager handles sandbox lifecycle
#[async_trait]
pub trait SandboxManager: Send + Sync {
    /// Get or create a sandbox based on selection options
    ///
    /// This is the primary entry point for execution. It handles:
    /// - Checking for existing sandboxes matching the criteria
    /// - Creating new sandboxes if needed
    /// - Warming pool management
    async fn acquire(
        &self,
        spec: &SandboxSpec,
        options: &SandboxSelectionOptions,
        client_id: &str,
    ) -> Result<(SandboxSession, Arc<dyn Sandbox>)>;

    /// Release a sandbox after execution
    ///
    /// Depending on the session configuration, this may:
    /// - Keep the sandbox alive for reattachment
    /// - Return it to the warm pool
    /// - Destroy it immediately
    async fn release(&self, session: &SandboxSession, keep_alive: bool) -> Result<()>;

    /// Attach to an existing sandbox
    async fn attach(&self, request: AttachRequest) -> Result<AttachResult>;

    /// Detach from a sandbox without destroying it
    async fn detach(&self, session: &SandboxSession) -> Result<()>;

    /// Suspend a sandbox
    async fn suspend(&self, session: &SandboxSession) -> Result<()>;

    /// Resume a suspended sandbox
    async fn resume(&self, session: &SandboxSession) -> Result<SandboxSession>;

    /// Terminate a session and destroy its sandbox
    async fn terminate(&self, session: &SandboxSession) -> Result<()>;

    /// List all active sessions
    async fn list_sessions(&self) -> Result<Vec<SandboxSession>>;

    /// Get session by ID
    async fn get_session(&self, session_id: &str) -> Result<Option<SandboxSession>>;

    /// Get session by sandbox ID
    async fn get_session_by_sandbox(
        &self,
        sandbox_id: &SandboxId,
    ) -> Result<Option<SandboxSession>>;

    /// Get active session for a client (for session reuse)
    async fn get_session_by_client(&self, client_id: &str) -> Result<Option<SandboxSession>>;

    /// Get a sandbox by ID (for executing operations)
    async fn get_sandbox(&self, sandbox_id: &SandboxId) -> Result<Option<Arc<dyn Sandbox>>>;

    /// Set the default sandbox ID (used when no sandbox is specified)
    async fn set_default_sandbox(&self, sandbox_id: Option<SandboxId>) -> Result<()>;

    /// Get the default sandbox ID
    async fn get_default_sandbox(&self) -> Option<SandboxId>;

    /// Clean up timed-out sessions and sandboxes
    async fn cleanup_expired(&self) -> Result<u64>;

    /// Get current statistics
    async fn stats(&self) -> SandboxManagerStats;

    /// Health check
    async fn health(&self) -> Result<bool>;
}

/// Default implementation of the sandbox manager
pub struct DefaultSandboxManager {
    backends: Vec<Arc<dyn IsolationBackend>>,
    sessions: tokio::sync::RwLock<HashMap<String, SandboxSession>>,
    sandboxes: tokio::sync::RwLock<HashMap<SandboxId, Arc<dyn Sandbox>>>,
    pool: tokio::sync::RwLock<Vec<(SandboxSpec, Arc<dyn Sandbox>)>>,
    config: SandboxManagerConfig,
    stats: tokio::sync::RwLock<SandboxManagerStats>,
    /// The default sandbox ID to use when no sandbox is specified
    default_sandbox_id: tokio::sync::RwLock<Option<SandboxId>>,
}

/// Configuration for the sandbox manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxManagerConfig {
    /// Maximum number of concurrent sandboxes
    pub max_sandboxes: u32,

    /// Pool configuration
    pub pool: PoolConfig,

    /// Default session timeouts
    pub default_timeouts: SessionTimeouts,

    /// How often to run cleanup
    pub cleanup_interval: Duration,
}

impl Default for SandboxManagerConfig {
    fn default() -> Self {
        Self {
            max_sandboxes: 100,
            pool: PoolConfig::default(),
            default_timeouts: SessionTimeouts::default(),
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

/// Pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Whether pooling is enabled
    pub enabled: bool,

    /// Minimum warm sandboxes to maintain
    pub min_warm: u32,

    /// Maximum warm sandboxes
    pub max_warm: u32,

    /// How long to keep warm sandboxes before recycling
    pub warm_ttl: Duration,

    /// Profiles to pre-warm
    pub warm_profiles: Vec<String>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_warm: 2,
            max_warm: 10,
            warm_ttl: Duration::from_secs(600), // 10 minutes
            warm_profiles: vec!["default".to_string()],
        }
    }
}

impl DefaultSandboxManager {
    /// Create a new sandbox manager
    pub fn new(backends: Vec<Arc<dyn IsolationBackend>>, config: SandboxManagerConfig) -> Self {
        Self {
            backends,
            sessions: tokio::sync::RwLock::new(HashMap::new()),
            sandboxes: tokio::sync::RwLock::new(HashMap::new()),
            pool: tokio::sync::RwLock::new(Vec::new()),
            config,
            stats: tokio::sync::RwLock::new(SandboxManagerStats::default()),
            default_sandbox_id: tokio::sync::RwLock::new(None),
        }
    }

    /// Select the best backend for the given spec
    async fn select_backend(
        &self,
        spec: &SandboxSpec,
        preferred: Option<&str>,
    ) -> Result<Arc<dyn IsolationBackend>> {
        // If a specific backend is preferred, try that first
        if let Some(name) = preferred {
            if let Some(backend) = self.backends.iter().find(|b| b.name() == name) {
                return Ok(backend.clone());
            }
        }

        // Otherwise, probe backends and select the best one
        for backend in &self.backends {
            let caps = backend.probe().await?;

            // Check if this backend can satisfy the spec
            if self.backend_satisfies_spec(&caps, spec) {
                return Ok(backend.clone());
            }
        }

        anyhow::bail!("No suitable isolation backend found for spec")
    }

    /// Check if a backend's capabilities satisfy a spec
    fn backend_satisfies_spec(&self, caps: &BackendCapabilities, spec: &SandboxSpec) -> bool {
        // For now, just check basic requirements
        if spec.network_enabled && !caps.network_isolation {
            // If network is needed but backend doesn't isolate, that's OK
            // (it means the backend will allow network access)
        }

        // Check profile availability
        if !spec.profile.is_empty() && spec.profile != "default" {
            if !caps.available_profiles.contains(&spec.profile) {
                return false;
            }
        }

        true
    }
}

#[async_trait]
impl SandboxManager for DefaultSandboxManager {
    async fn acquire(
        &self,
        spec: &SandboxSpec,
        options: &SandboxSelectionOptions,
        client_id: &str,
    ) -> Result<(SandboxSession, Arc<dyn Sandbox>)> {
        // Check for existing sandbox by ID
        if let Some(ref id) = options.preferred_id {
            if !options.require_fresh {
                let sandboxes = self.sandboxes.read().await;
                if let Some(sandbox) = sandboxes.get(id) {
                    let session = SandboxSession::new(id.clone(), client_id);
                    return Ok((session, sandbox.clone()));
                }
            }
        }

        // Try to get from pool
        if options.use_pool && !options.require_fresh && self.config.pool.enabled {
            let mut pool = self.pool.write().await;
            if let Some(idx) = pool.iter().position(|(s, _)| s.profile == spec.profile) {
                let (_, sandbox) = pool.remove(idx);
                let session = SandboxSession::new(sandbox.id().clone(), client_id);

                // Update stats
                {
                    let mut stats = self.stats.write().await;
                    stats.active_sandboxes += 1;
                    stats.active_sessions += 1;
                }

                return Ok((session, sandbox));
            }
        }

        // Create new sandbox
        let backend = self
            .select_backend(spec, options.preferred_backend.as_deref())
            .await?;

        let start = std::time::Instant::now();
        let sandbox = backend.create_sandbox(spec).await?;
        let creation_time = start.elapsed();

        let sandbox_id = sandbox.id().clone();
        let sandbox: Arc<dyn Sandbox> = Arc::from(sandbox);

        // Store sandbox reference
        {
            let mut sandboxes = self.sandboxes.write().await;
            sandboxes.insert(sandbox_id.clone(), sandbox.clone());
        }

        // Create session
        let session = SandboxSession::new(sandbox_id, client_id);

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session.session_id.clone(), session.clone());
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.sandboxes_created += 1;
            stats.active_sandboxes += 1;
            stats.active_sessions += 1;

            // Update average creation time
            let total = stats.sandboxes_created as f64;
            let current_avg = stats.avg_creation_time_ms;
            stats.avg_creation_time_ms =
                current_avg + (creation_time.as_millis() as f64 - current_avg) / total;
        }

        Ok((session, sandbox))
    }

    async fn release(&self, session: &SandboxSession, keep_alive: bool) -> Result<()> {
        let sandbox = {
            let sandboxes = self.sandboxes.read().await;
            sandboxes.get(&session.sandbox_id).cloned()
        };

        if let Some(sandbox) = sandbox {
            if keep_alive {
                // Return to pool if possible
                if self.config.pool.enabled {
                    let mut pool = self.pool.write().await;
                    if pool.len() < self.config.pool.max_warm as usize {
                        let spec = SandboxSpec {
                            profile: sandbox.capabilities().profile.clone(),
                            ..Default::default()
                        };
                        pool.push((spec, sandbox));

                        // Update session state
                        let mut sessions = self.sessions.write().await;
                        if let Some(s) = sessions.get_mut(&session.session_id) {
                            s.state = SessionState::Detached;
                        }

                        return Ok(());
                    }
                }
            }

            // Destroy sandbox
            sandbox.destroy().await?;

            // Remove from storage
            {
                let mut sandboxes = self.sandboxes.write().await;
                sandboxes.remove(&session.sandbox_id);
            }
            {
                let mut sessions = self.sessions.write().await;
                sessions.remove(&session.session_id);
            }

            // Update stats
            {
                let mut stats = self.stats.write().await;
                stats.active_sandboxes = stats.active_sandboxes.saturating_sub(1);
                stats.active_sessions = stats.active_sessions.saturating_sub(1);
            }
        }

        Ok(())
    }

    async fn attach(&self, request: AttachRequest) -> Result<AttachResult> {
        let sandboxes = self.sandboxes.read().await;

        if let Some(sandbox) = sandboxes.get(&request.sandbox_id) {
            let session = SandboxSession::new(request.sandbox_id.clone(), &request.client_id);
            let capabilities = sandbox.capabilities().clone();

            // Store session
            {
                drop(sandboxes);
                let mut sessions = self.sessions.write().await;
                sessions.insert(session.session_id.clone(), session.clone());
            }

            return Ok(AttachResult {
                session,
                newly_created: false,
                capabilities,
            });
        }

        drop(sandboxes);

        if request.create_if_missing {
            if let Some(spec) = request.create_spec {
                let (session, sandbox) = self
                    .acquire(
                        &spec,
                        &SandboxSelectionOptions::default(),
                        &request.client_id,
                    )
                    .await?;

                let capabilities = sandbox.capabilities().clone();

                return Ok(AttachResult {
                    session,
                    newly_created: true,
                    capabilities,
                });
            }
        }

        anyhow::bail!("Sandbox {} not found", request.sandbox_id)
    }

    async fn detach(&self, session: &SandboxSession) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(s) = sessions.get_mut(&session.session_id) {
            s.state = SessionState::Detached;
            s.touch();

            let mut stats = self.stats.write().await;
            stats.active_sessions = stats.active_sessions.saturating_sub(1);
            stats.detached_sessions += 1;
        }
        Ok(())
    }

    async fn suspend(&self, session: &SandboxSession) -> Result<()> {
        let sandbox = {
            let sandboxes = self.sandboxes.read().await;
            sandboxes.get(&session.sandbox_id).cloned()
        };

        if let Some(sandbox) = sandbox {
            sandbox.suspend().await?;

            let mut sessions = self.sessions.write().await;
            if let Some(s) = sessions.get_mut(&session.session_id) {
                s.state = SessionState::Suspended;
                s.touch();
            }
        }

        Ok(())
    }

    async fn resume(&self, session: &SandboxSession) -> Result<SandboxSession> {
        let sandbox = {
            let sandboxes = self.sandboxes.read().await;
            sandboxes.get(&session.sandbox_id).cloned()
        };

        if let Some(sandbox) = sandbox {
            sandbox.resume().await?;

            let mut sessions = self.sessions.write().await;
            if let Some(s) = sessions.get_mut(&session.session_id) {
                s.state = SessionState::Active;
                s.touch();
                return Ok(s.clone());
            }
        }

        anyhow::bail!("Session not found")
    }

    async fn terminate(&self, session: &SandboxSession) -> Result<()> {
        self.release(session, false).await
    }

    async fn list_sessions(&self) -> Result<Vec<SandboxSession>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.values().cloned().collect())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SandboxSession>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(session_id).cloned())
    }

    async fn get_session_by_sandbox(
        &self,
        sandbox_id: &SandboxId,
    ) -> Result<Option<SandboxSession>> {
        let sessions = self.sessions.read().await;
        Ok(sessions
            .values()
            .find(|s| s.sandbox_id == *sandbox_id)
            .cloned())
    }

    async fn get_sandbox(&self, sandbox_id: &SandboxId) -> Result<Option<Arc<dyn Sandbox>>> {
        let sandboxes = self.sandboxes.read().await;
        Ok(sandboxes.get(sandbox_id).cloned())
    }

    async fn get_session_by_client(&self, client_id: &str) -> Result<Option<SandboxSession>> {
        let sessions = self.sessions.read().await;
        Ok(sessions
            .values()
            .find(|s| s.client_id == client_id && s.state == SessionState::Active)
            .cloned())
    }

    async fn set_default_sandbox(&self, sandbox_id: Option<SandboxId>) -> Result<()> {
        let mut default = self.default_sandbox_id.write().await;
        *default = sandbox_id;
        Ok(())
    }

    async fn get_default_sandbox(&self) -> Option<SandboxId> {
        self.default_sandbox_id.read().await.clone()
    }

    async fn cleanup_expired(&self) -> Result<u64> {
        let mut cleaned = 0u64;

        // Find expired sessions
        let expired_sessions: Vec<SandboxSession> = {
            let sessions = self.sessions.read().await;
            sessions
                .values()
                .filter(|s| s.is_timed_out())
                .cloned()
                .collect()
        };

        // Terminate them
        for session in expired_sessions {
            if let Err(e) = self.terminate(&session).await {
                tracing::warn!(
                    session_id = %session.session_id,
                    error = %e,
                    "Failed to cleanup expired session"
                );
            } else {
                cleaned += 1;
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.timeout_destroys += cleaned;
        }

        Ok(cleaned)
    }

    async fn stats(&self) -> SandboxManagerStats {
        self.stats.read().await.clone()
    }

    async fn health(&self) -> Result<bool> {
        // Check that at least one backend is healthy
        for backend in &self.backends {
            let health = backend.health_check().await?;
            if health.healthy {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_id_new() {
        let id = SandboxId::new();
        assert!(id.as_str().starts_with("sbx-"));
        assert!(!id.as_str().is_empty());
    }

    #[test]
    fn test_sandbox_id_from_string() {
        let id = SandboxId::from_string("custom-id-123");
        assert_eq!(id.as_str(), "custom-id-123");
    }

    #[test]
    fn test_sandbox_id_display() {
        let id = SandboxId::from_string("test-sandbox");
        assert_eq!(format!("{}", id), "test-sandbox");
    }

    #[test]
    fn test_sandbox_id_default() {
        let id = SandboxId::default();
        assert!(id.as_str().starts_with("sbx-"));
    }

    #[test]
    fn test_sandbox_id_equality() {
        let id1 = SandboxId::from_string("same-id");
        let id2 = SandboxId::from_string("same-id");
        let id3 = SandboxId::from_string("different-id");
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_sandbox_session_new() {
        let sandbox_id = SandboxId::new();
        let session = SandboxSession::new(sandbox_id.clone(), "client-123");

        assert!(session.session_id.starts_with("sess-"));
        assert_eq!(session.sandbox_id, sandbox_id);
        assert_eq!(session.client_id, "client-123");
        assert_eq!(session.state, SessionState::Active);
        assert!(session.metadata.is_empty());
    }

    #[test]
    fn test_sandbox_session_touch() {
        let sandbox_id = SandboxId::new();
        let mut session = SandboxSession::new(sandbox_id, "client-123");

        let original_time = session.last_active_at;
        std::thread::sleep(std::time::Duration::from_millis(10));
        session.touch();

        assert!(session.last_active_at > original_time);
    }

    #[test]
    fn test_session_state_equality() {
        assert_eq!(SessionState::Active, SessionState::Active);
        assert_eq!(SessionState::Detached, SessionState::Detached);
        assert_eq!(SessionState::Suspended, SessionState::Suspended);
        assert_eq!(SessionState::Terminated, SessionState::Terminated);
        assert_ne!(SessionState::Active, SessionState::Detached);
    }

    #[test]
    fn test_session_timeouts_default() {
        let timeouts = SessionTimeouts::default();
        assert_eq!(timeouts.idle_timeout, Duration::from_secs(300));
        assert_eq!(timeouts.detach_timeout, Duration::from_secs(3600));
        assert_eq!(timeouts.suspend_timeout, Duration::from_secs(86400));
    }

    #[test]
    fn test_sandbox_selection_options_default() {
        let options = SandboxSelectionOptions::default();
        assert!(options.preferred_id.is_none());
        assert!(!options.require_fresh);
        assert!(options.preferred_backend.is_none());
        assert!(options.required_labels.is_empty());
        // use_pool defaults to false (bool Default)
        assert!(!options.use_pool);
    }

    #[test]
    fn test_required_capabilities_default() {
        let caps = RequiredCapabilities::default();
        assert!(caps.network.is_none());
        assert!(caps.write_access.is_none());
        assert!(caps.min_memory_bytes.is_none());
        assert!(caps.readable_paths.is_empty());
        assert!(caps.writable_paths.is_empty());
    }

    #[test]
    fn test_sandbox_manager_stats_default() {
        let stats = SandboxManagerStats::default();
        assert_eq!(stats.sandboxes_created, 0);
        assert_eq!(stats.active_sandboxes, 0);
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.detached_sessions, 0);
        assert_eq!(stats.pool_size, 0);
        assert_eq!(stats.pool_hit_rate, 0.0);
        assert_eq!(stats.avg_creation_time_ms, 0.0);
        assert_eq!(stats.timeout_destroys, 0);
    }

    #[test]
    fn test_sandbox_manager_config_default() {
        let config = SandboxManagerConfig::default();
        assert_eq!(config.max_sandboxes, 100);
        assert!(config.pool.enabled);
        assert_eq!(config.cleanup_interval, Duration::from_secs(60));
    }

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert!(config.enabled);
        assert_eq!(config.min_warm, 2);
        assert_eq!(config.max_warm, 10);
        assert_eq!(config.warm_ttl, Duration::from_secs(600));
        assert_eq!(config.warm_profiles, vec!["default".to_string()]);
    }

    #[test]
    fn test_attach_request_creation() {
        let request = AttachRequest {
            sandbox_id: SandboxId::from_string("test-sandbox"),
            client_id: "client-123".to_string(),
            create_if_missing: true,
            create_spec: None,
        };
        assert_eq!(request.sandbox_id.as_str(), "test-sandbox");
        assert_eq!(request.client_id, "client-123");
        assert!(request.create_if_missing);
    }

    #[test]
    fn test_attach_result_creation() {
        use super::super::isolation::ResourceLimits;
        use std::path::PathBuf;

        let session = SandboxSession::new(SandboxId::new(), "client");
        let capabilities = SandboxCapabilities {
            sandbox_id: "test-sandbox".to_string(),
            backend: "test-backend".to_string(),
            profile: "default".to_string(),
            can_write_filesystem: false,
            readable_paths: vec![],
            writable_paths: vec![],
            has_network: false,
            allowed_destinations: vec![],
            limits: ResourceLimits::default(),
            syscall_filter_active: false,
            blocked_syscall_categories: vec![],
            is_persistent: false,
            created_at: chrono::Utc::now(),
            time_remaining_ms: None,
        };

        let result = AttachResult {
            session: session.clone(),
            newly_created: true,
            capabilities: capabilities.clone(),
        };

        assert!(result.newly_created);
        assert_eq!(result.session.session_id, session.session_id);
    }

    #[test]
    fn test_sandbox_session_is_timed_out_active() {
        let sandbox_id = SandboxId::new();
        let session = SandboxSession::new(sandbox_id, "client");

        // Just created - should not be timed out
        assert!(!session.is_timed_out());
    }

    #[test]
    fn test_sandbox_session_is_timed_out_terminated() {
        let sandbox_id = SandboxId::new();
        let mut session = SandboxSession::new(sandbox_id, "client");
        session.state = SessionState::Terminated;

        // Terminated sessions are always "timed out"
        assert!(session.is_timed_out());
    }
}
