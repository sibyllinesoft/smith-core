use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use futures::StreamExt;
use regorus::{compile_policy_with_entrypoint, CompiledPolicy, PolicyModule, Value as RegoValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::task;
use tracing::{debug, error, info, warn};

use crate::config::{Config, PolicyConfig};
use crate::nats::NatsClient;
use smith_protocol::ExecutionLimits;

const DEFAULT_TIMEOUT_MS: u64 = 30_000;

#[derive(Clone)]
pub struct PolicyEngine {
    registry: Arc<PolicyRegistry>,
    host_context: HostContext,
    workspace_root: Option<PathBuf>,
    allow_policy_disable_override: bool,
}

impl PolicyEngine {
    pub fn new(config: &Config) -> Result<Self> {
        let defaults = &config.executor.limits.defaults;
        let default_limits = ExecutionLimits {
            cpu_ms_per_100ms: defaults.cpu_ms_per_100ms,
            mem_bytes: defaults.mem_bytes,
            io_bytes: defaults.io_bytes,
            pids_max: defaults.pids_max,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        };

        let host_context = HostContext {
            tags: vec!["default".to_string()],
            hostname: gethostname::gethostname()
                .into_string()
                .unwrap_or_else(|_| "unknown".to_string()),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };

        let workspace_root = env::var("SMITH_WORKSPACE_ROOT")
            .ok()
            .map(PathBuf::from)
            .and_then(|path| match path.canonicalize() {
                Ok(canon) => Some(canon),
                Err(_) => Some(path),
            });

        Ok(Self {
            registry: Arc::new(PolicyRegistry::new(default_limits)),
            host_context,
            workspace_root,
            allow_policy_disable_override: !config.executor.capabilities.enforcement_enabled,
        })
    }

    pub async fn start_policy_listener(
        &self,
        nats_client: NatsClient,
        policy_config: &PolicyConfig,
    ) -> Result<PolicySyncHandle> {
        let subject = policy_config.updates_subject.clone();
        let queue = policy_config.updates_queue.clone();

        info!(subject = subject.as_str(), "Subscribing to policy updates");
        let mut subscriber = nats_client
            .subscribe(&subject, queue.as_deref())
            .await
            .context("Failed to subscribe to policy updates subject")?;

        let registry = self.registry.clone();
        let handle = tokio::spawn(async move {
            while let Some(message) = subscriber.next().await {
                let payload = message.payload;
                match serde_json::from_slice::<smith_protocol::policy::PolicyUpdate>(&payload) {
                    Ok(update) => {
                        if let Err(err) = registry.apply_update(update).await {
                            error!("Failed to apply policy update: {err:?}");
                        }
                    }
                    Err(err) => {
                        warn!("Discarding malformed policy update: {err}");
                    }
                }
            }
            debug!("Policy updates subscription closed");
        });

        Ok(PolicySyncHandle { handle })
    }

    pub async fn evaluate(&self, intent: &smith_protocol::Intent) -> Result<PolicyResult> {
        if std::env::var("SMITH_EXECUTOR_DISABLE_POLICY").unwrap_or_default() == "1" {
            if self.allow_policy_disable_override {
                warn!(
                    capability = ?intent.capability,
                    "Policy enforcement disabled; auto-allowing intent"
                );
                return Ok(PolicyResult {
                    allow: true,
                    reason: Some("Policy enforcement disabled by configuration".to_string()),
                    limits: self.registry.default_limits(),
                    scope: serde_json::json!({}),
                    policy_id: Some("policy.disabled.override".to_string()),
                });
            }

            warn!(
                capability = ?intent.capability,
                "Ignored SMITH_EXECUTOR_DISABLE_POLICY=1 because capability enforcement is enabled"
            );
        }

        let capability_key = map_capability(&intent.capability)?;
        let policies = match self
            .registry
            .policies_for(capability_key, intent.domain.as_str())
        {
            Some(policies) if !policies.is_empty() => policies,
            _ => {
                debug!(
                    capability = capability_key,
                    tenant = intent.domain.as_str(),
                    "No registered policies; falling back to built-in guardrails"
                );
                return self.evaluate_builtin(capability_key, intent);
            }
        };

        let resource = extract_resource_identifier(intent)?;
        let policy_input = PolicyInput {
            capability: capability_key.to_string(),
            resource,
            params: intent.params.clone(),
            actor: ActorContext {
                tenant: intent.domain.clone(),
                claims: serde_json::json!({}),
            },
            constraints: serde_json::json!({}),
            host: self.host_context.clone(),
        };

        let input_value = RegoValue::from(serde_json::to_value(&policy_input)?);
        let mut final_allow: Option<PolicyResult> = None;

        for policy in policies.iter() {
            match policy.evaluate(&input_value) {
                Ok(PolicyDecision::NotApplicable) => continue,
                Ok(PolicyDecision::Deny { reason }) => {
                    return Ok(PolicyResult {
                        allow: false,
                        reason: Some(
                            reason.unwrap_or_else(|| {
                                format!("Denied by policy {}", policy.policy_id)
                            }),
                        ),
                        limits: self.registry.default_limits(),
                        scope: serde_json::json!({}),
                        policy_id: Some(policy.policy_id.clone()),
                    });
                }
                Ok(PolicyDecision::Allow {
                    reason,
                    limits,
                    scope,
                }) => {
                    if final_allow.is_none() {
                        final_allow = Some(PolicyResult {
                            allow: true,
                            reason,
                            limits: limits.unwrap_or_else(|| policy.limits.clone()),
                            scope: scope.unwrap_or_else(|| policy.scope.clone()),
                            policy_id: Some(policy.policy_id.clone()),
                        });
                    }
                }
                Err(err) => {
                    error!(
                        policy_id = policy.policy_id,
                        ?err,
                        "Policy evaluation failed"
                    );
                }
            }
        }

        if let Some(result) = final_allow {
            Ok(result)
        } else {
            self.evaluate_builtin(capability_key, intent)
        }
    }

    fn evaluate_builtin(
        &self,
        capability_key: &str,
        intent: &smith_protocol::Intent,
    ) -> Result<PolicyResult> {
        match capability_key {
            "fs.read.v1" => self.evaluate_builtin_fs_read(intent),
            _ => Ok(PolicyResult {
                allow: true,
                reason: Some(format!(
                    "Allowed by built-in permissive policy for {}",
                    capability_key
                )),
                limits: self.registry.default_limits(),
                scope: json!({}),
                policy_id: Some("builtin.default.allow".to_string()),
            }),
        }
    }

    fn evaluate_builtin_fs_read(&self, intent: &smith_protocol::Intent) -> Result<PolicyResult> {
        let path_value = intent
            .params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'path' parameter for fs.read intent"))?;

        if let Some(workspace_root) = &self.workspace_root {
            let workspace_canon = canonicalize_soft(workspace_root);
            let requested_path = PathBuf::from(path_value);
            let absolute_path = if requested_path.is_absolute() {
                requested_path.clone()
            } else {
                workspace_canon.join(&requested_path)
            };
            let requested_canon = canonicalize_soft(&absolute_path);

            if requested_canon.starts_with(&workspace_canon) {
                let scope = json!({
                    "paths": [workspace_canon.to_string_lossy()]
                });
                return Ok(PolicyResult {
                    allow: true,
                    reason: Some("Allowed by built-in workspace fs.read policy".to_string()),
                    limits: self.registry.default_limits(),
                    scope,
                    policy_id: Some("builtin.fs.read.workspace".to_string()),
                });
            } else {
                return Ok(PolicyResult {
                    allow: false,
                    reason: Some(format!(
                        "Path '{}' is outside allowed workspace {}",
                        path_value,
                        workspace_canon.display()
                    )),
                    limits: self.registry.default_limits(),
                    scope: json!({}),
                    policy_id: Some("builtin.fs.read.workspace".to_string()),
                });
            }
        }

        Ok(PolicyResult {
            allow: true,
            reason: Some("Workspace root unknown; default-allowing fs.read".to_string()),
            limits: self.registry.default_limits(),
            scope: json!({}),
            policy_id: Some("builtin.fs.read.default".to_string()),
        })
    }

    pub fn policy_count(&self) -> usize {
        self.registry.total_policies()
    }
}

fn map_capability(capability: &smith_protocol::Capability) -> Result<&'static str> {
    use smith_protocol::Capability;
    Ok(match capability {
        Capability::FsReadV1 => "fs.read.v1",
        Capability::HttpFetchV1 => "http.fetch.v1",
        Capability::FsWriteV1 => "fs.write.v1",
        Capability::GitCloneV1 => "git.clone.v1",
        Capability::ArchiveReadV1 => "archive.read.v1",
        Capability::SqliteQueryV1 => "sqlite.query.v1",
        Capability::BenchReportV1 => "bench.report.v1",
        Capability::ShellExec => "shell.exec",
        Capability::HttpFetch => "http.fetch",
    })
}

fn canonicalize_soft(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn extract_resource_identifier(intent: &smith_protocol::Intent) -> Result<String> {
    match intent.capability {
        smith_protocol::Capability::FsReadV1
        | smith_protocol::Capability::FsWriteV1
        | smith_protocol::Capability::ArchiveReadV1 => intent
            .params
            .get("path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Missing 'path' parameter")),
        smith_protocol::Capability::HttpFetchV1 | smith_protocol::Capability::HttpFetch => intent
            .params
            .get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Missing 'url' parameter")),
        smith_protocol::Capability::GitCloneV1 => intent
            .params
            .get("repository_url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Missing 'repository_url' parameter")),
        smith_protocol::Capability::SqliteQueryV1 => intent
            .params
            .get("database_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Missing 'database_path' parameter")),
        smith_protocol::Capability::BenchReportV1 => intent
            .params
            .get("benchmark_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Missing 'benchmark_name' parameter")),
        smith_protocol::Capability::ShellExec => intent
            .params
            .get("command")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Missing 'command' parameter")),
    }
}

#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub allow: bool,
    pub reason: Option<String>,
    pub limits: ExecutionLimits,
    pub scope: serde_json::Value,
    pub policy_id: Option<String>,
}

#[derive(Debug, Clone)]
struct PolicyEntry {
    policy_id: String,
    capability: String,
    tenant: Option<String>,
    priority: u32,
    version: u64,
    compiled: CompiledPolicy,
    limits: ExecutionLimits,
    scope: serde_json::Value,
    metadata: Option<serde_json::Value>,
}

impl PolicyEntry {
    fn evaluate(&self, input: &RegoValue) -> Result<PolicyDecision> {
        let result = self.compiled.eval_with_input(input.clone())?;

        match result {
            RegoValue::Undefined => Ok(PolicyDecision::NotApplicable),
            _ => {
                let json = serde_json::to_value(&result)?;
                if json.is_null() {
                    return Ok(PolicyDecision::NotApplicable);
                }

                if json.is_boolean() {
                    return if json.as_bool().unwrap_or(false) {
                        Ok(PolicyDecision::Allow {
                            reason: None,
                            limits: None,
                            scope: None,
                        })
                    } else {
                        Ok(PolicyDecision::Deny { reason: None })
                    };
                }

                let envelope: PolicyDecisionEnvelope = serde_json::from_value(json)?;
                if envelope.allow {
                    Ok(PolicyDecision::Allow {
                        reason: envelope.reason,
                        limits: envelope.limits.map(ExecutionLimits::from),
                        scope: envelope.scope,
                    })
                } else {
                    Ok(PolicyDecision::Deny {
                        reason: envelope.reason,
                    })
                }
            }
        }
    }
}

#[derive(Debug)]
enum PolicyDecision {
    Allow {
        reason: Option<String>,
        limits: Option<ExecutionLimits>,
        scope: Option<serde_json::Value>,
    },
    Deny {
        reason: Option<String>,
    },
    NotApplicable,
}

#[derive(Debug, Deserialize)]
struct PolicyDecisionEnvelope {
    allow: bool,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    limits: Option<smith_protocol::policy::PolicyLimits>,
    #[serde(default)]
    scope: Option<serde_json::Value>,
}

struct PolicyRegistry {
    default_limits: ExecutionLimits,
    policy_locator: DashMap<String, String>,
    capabilities: DashMap<String, CapabilityAggregate>,
}

impl PolicyRegistry {
    fn new(default_limits: ExecutionLimits) -> Self {
        Self {
            default_limits,
            policy_locator: DashMap::new(),
            capabilities: DashMap::new(),
        }
    }

    fn default_limits(&self) -> ExecutionLimits {
        self.default_limits.clone()
    }

    async fn apply_update(&self, update: smith_protocol::policy::PolicyUpdate) -> Result<()> {
        match update {
            smith_protocol::policy::PolicyUpdate::Upsert { policy } => self.upsert(policy).await,
            smith_protocol::policy::PolicyUpdate::Remove { policy_id } => {
                self.remove(&policy_id);
                Ok(())
            }
            smith_protocol::policy::PolicyUpdate::Reset { capability } => {
                self.reset(capability.as_deref());
                Ok(())
            }
        }
    }

    async fn upsert(&self, policy: smith_protocol::policy::OpaPolicy) -> Result<()> {
        let compiled = compile_policy(policy.clone()).await?;

        if let Some(previous_capability) = self
            .policy_locator
            .insert(policy.policy_id.clone(), policy.capability.clone())
        {
            if previous_capability != policy.capability {
                self.remove_from_capability(&policy.policy_id, &previous_capability);
            }
        }

        let entry = Arc::new(PolicyEntry {
            policy_id: policy.policy_id.clone(),
            capability: policy.capability.clone(),
            tenant: policy.tenant.clone(),
            priority: policy.priority,
            version: policy.version,
            compiled,
            limits: policy
                .limits
                .map(ExecutionLimits::from)
                .unwrap_or_else(|| self.default_limits()),
            scope: policy.scope.unwrap_or_else(|| serde_json::json!({})),
            metadata: policy.metadata,
        });

        let mut aggregate = self
            .capabilities
            .entry(policy.capability.clone())
            .or_insert_with(CapabilityAggregate::default);

        aggregate.policies.insert(policy.policy_id.clone(), entry);
        aggregate.rebuild_index();
        info!(
            capability = policy.capability,
            policy_id = policy.policy_id,
            "Policy upserted"
        );
        Ok(())
    }

    fn remove(&self, policy_id: &str) {
        if let Some((_, capability)) = self.policy_locator.remove(policy_id) {
            self.remove_from_capability(policy_id, &capability);
            info!(policy_id, capability, "Policy removed");
        } else {
            debug!(policy_id, "Policy remove ignored - unknown id");
        }
    }

    fn reset(&self, capability: Option<&str>) {
        match capability {
            Some(cap) => {
                if let Some(existing) = self.capabilities.get(cap) {
                    let ids: Vec<String> = existing
                        .policies
                        .iter()
                        .map(|entry| entry.key().clone())
                        .collect();
                    drop(existing);
                    self.capabilities.remove(cap);
                    for id in ids {
                        self.policy_locator.remove(&id);
                    }
                }
                info!(capability = cap, "Reset policies for capability");
            }
            None => {
                self.capabilities.clear();
                self.policy_locator.clear();
                info!("Cleared all policy registrations");
            }
        }
    }

    fn remove_from_capability(&self, policy_id: &str, capability: &str) {
        if let Some(mut aggregate) = self.capabilities.get_mut(capability) {
            aggregate.policies.remove(policy_id);
            if aggregate.policies.is_empty() {
                drop(aggregate);
                self.capabilities.remove(capability);
            } else {
                aggregate.rebuild_index();
            }
        }
    }

    fn policies_for(&self, capability: &str, tenant: &str) -> Option<Arc<Vec<Arc<PolicyEntry>>>> {
        self.capabilities.get(capability).map(|aggregate| {
            let snapshot = aggregate.compiled.load_full();
            let result = snapshot
                .per_tenant
                .get(tenant)
                .cloned()
                .unwrap_or_else(|| snapshot.global.clone());
            drop(aggregate);
            result
        })
    }

    fn total_policies(&self) -> usize {
        self.policy_locator.len()
    }
}

#[derive(Debug)]
struct CapabilityAggregate {
    policies: DashMap<String, Arc<PolicyEntry>>,
    compiled: ArcSwap<CapabilityPolicies>,
}

impl Default for CapabilityAggregate {
    fn default() -> Self {
        Self {
            policies: DashMap::new(),
            compiled: ArcSwap::new(Arc::new(CapabilityPolicies::default())),
        }
    }
}

impl CapabilityAggregate {
    fn rebuild_index(&self) {
        let mut global = Vec::new();
        let mut per_tenant: HashMap<String, Vec<Arc<PolicyEntry>>> = HashMap::new();

        for entry in self.policies.iter() {
            let policy = entry.value().clone();
            match &policy.tenant {
                Some(tenant) => per_tenant.entry(tenant.clone()).or_default().push(policy),
                None => global.push(policy),
            }
        }

        global.sort_by(policy_ordering);
        let global_arc = Arc::new(global);

        let mut per_tenant_final = HashMap::new();
        for (tenant, mut policies) in per_tenant.into_iter() {
            policies.sort_by(policy_ordering);
            let merged = merge_policies(&global_arc, &policies);
            per_tenant_final.insert(tenant, Arc::new(merged));
        }

        let snapshot = CapabilityPolicies {
            global: global_arc.clone(),
            per_tenant: per_tenant_final,
        };

        self.compiled.store(Arc::new(snapshot));
    }
}

fn merge_policies(
    global: &Arc<Vec<Arc<PolicyEntry>>>,
    tenant_specific: &[Arc<PolicyEntry>],
) -> Vec<Arc<PolicyEntry>> {
    let mut merged = Vec::with_capacity(global.len() + tenant_specific.len());
    let mut g_idx = 0;
    let mut t_idx = 0;

    while g_idx < global.len() && t_idx < tenant_specific.len() {
        let g = &global[g_idx];
        let t = &tenant_specific[t_idx];
        if policy_ordering(g, t).is_le() {
            merged.push(g.clone());
            g_idx += 1;
        } else {
            merged.push(t.clone());
            t_idx += 1;
        }
    }

    while g_idx < global.len() {
        merged.push(global[g_idx].clone());
        g_idx += 1;
    }

    while t_idx < tenant_specific.len() {
        merged.push(tenant_specific[t_idx].clone());
        t_idx += 1;
    }

    merged
}

fn policy_ordering(a: &Arc<PolicyEntry>, b: &Arc<PolicyEntry>) -> std::cmp::Ordering {
    a.priority
        .cmp(&b.priority)
        .then_with(|| a.version.cmp(&b.version).reverse())
        .then_with(|| a.policy_id.cmp(&b.policy_id))
}

#[derive(Debug, Default)]
struct CapabilityPolicies {
    global: Arc<Vec<Arc<PolicyEntry>>>,
    per_tenant: HashMap<String, Arc<Vec<Arc<PolicyEntry>>>>,
}

pub struct PolicySyncHandle {
    handle: tokio::task::JoinHandle<()>,
}

impl PolicySyncHandle {
    pub fn abort(self) {
        self.handle.abort();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostContext {
    pub tags: Vec<String>,
    pub hostname: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    pub capability: String,
    pub resource: String,
    pub params: serde_json::Value,
    pub actor: ActorContext,
    pub constraints: serde_json::Value,
    pub host: HostContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorContext {
    pub tenant: String,
    pub claims: serde_json::Value,
}

async fn compile_policy(policy: smith_protocol::policy::OpaPolicy) -> Result<CompiledPolicy> {
    let modules = vec![PolicyModule {
        id: format!("policy::{}", policy.policy_id).into(),
        content: policy.module.clone().into(),
    }];

    task::spawn_blocking(move || {
        let data = policy
            .data
            .map(RegoValue::from)
            .unwrap_or_else(RegoValue::new_object);
        compile_policy_with_entrypoint(data, &modules, policy.entrypoint.into())
    })
    .await
    .context("Policy compilation task cancelled")?
    .context("Failed to compile OPA policy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use once_cell::sync::Lazy;
    use smith_protocol::Capability;
    use std::sync::Mutex;
    use tempfile::tempdir;

    static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn create_test_intent(
        capability: Capability,
        params: serde_json::Value,
    ) -> smith_protocol::Intent {
        smith_protocol::Intent::new(
            capability,
            "test-tenant".to_string(),
            params,
            30000, // ttl_ms
            "test-signer".to_string(),
        )
    }

    #[tokio::test]
    async fn test_policy_disable_override_respected_when_enforcement_disabled() {
        let _guard = ENV_LOCK.lock().unwrap();
        let config = Config::testing();
        let engine = PolicyEngine::new(&config).unwrap();
        std::env::set_var("SMITH_EXECUTOR_DISABLE_POLICY", "1");
        let intent = create_test_intent(Capability::ShellExec, json!({"command": "echo hi"}));

        let result = engine.evaluate(&intent).await.unwrap();
        std::env::remove_var("SMITH_EXECUTOR_DISABLE_POLICY");

        assert!(result.allow);
        assert_eq!(
            result.policy_id.as_deref(),
            Some("policy.disabled.override")
        );
    }

    #[tokio::test]
    async fn test_policy_disable_override_ignored_when_enforcement_enabled() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut config = Config::testing();
        config.executor.capabilities.enforcement_enabled = true;
        let engine = PolicyEngine::new(&config).unwrap();
        std::env::set_var("SMITH_EXECUTOR_DISABLE_POLICY", "1");
        let intent = create_test_intent(Capability::ShellExec, json!({"command": "echo hi"}));

        let result = engine.evaluate(&intent).await.unwrap();
        std::env::remove_var("SMITH_EXECUTOR_DISABLE_POLICY");

        assert!(result.allow);
        assert_ne!(
            result.policy_id.as_deref(),
            Some("policy.disabled.override")
        );
    }

    #[test]
    fn test_map_capability_fs_read() {
        let result = map_capability(&Capability::FsReadV1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "fs.read.v1");
    }

    #[test]
    fn test_map_capability_http_fetch() {
        let result = map_capability(&Capability::HttpFetchV1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "http.fetch.v1");
    }

    #[test]
    fn test_map_capability_fs_write() {
        let result = map_capability(&Capability::FsWriteV1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "fs.write.v1");
    }

    #[test]
    fn test_map_capability_git_clone() {
        let result = map_capability(&Capability::GitCloneV1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "git.clone.v1");
    }

    #[test]
    fn test_map_capability_archive_read() {
        let result = map_capability(&Capability::ArchiveReadV1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "archive.read.v1");
    }

    #[test]
    fn test_map_capability_sqlite_query() {
        let result = map_capability(&Capability::SqliteQueryV1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "sqlite.query.v1");
    }

    #[test]
    fn test_map_capability_bench_report() {
        let result = map_capability(&Capability::BenchReportV1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "bench.report.v1");
    }

    #[test]
    fn test_map_capability_shell_exec() {
        let result = map_capability(&Capability::ShellExec);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "shell.exec");
    }

    #[test]
    fn test_map_capability_http_fetch_legacy() {
        let result = map_capability(&Capability::HttpFetch);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "http.fetch");
    }

    #[test]
    fn test_canonicalize_soft_existing_path() {
        let temp = tempdir().unwrap();
        let path = temp.path();
        let result = canonicalize_soft(path);
        assert!(result.is_absolute());
    }

    #[test]
    fn test_canonicalize_soft_nonexistent_path() {
        let path = PathBuf::from("/nonexistent/path/to/file");
        let result = canonicalize_soft(&path);
        assert_eq!(result, path);
    }

    #[test]
    fn test_extract_resource_fs_read() {
        let intent = create_test_intent(Capability::FsReadV1, json!({"path": "/tmp/test.txt"}));
        let result = extract_resource_identifier(&intent);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/tmp/test.txt");
    }

    #[test]
    fn test_extract_resource_fs_write() {
        let intent = create_test_intent(Capability::FsWriteV1, json!({"path": "/tmp/output.txt"}));
        let result = extract_resource_identifier(&intent);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/tmp/output.txt");
    }

    #[test]
    fn test_extract_resource_http_fetch() {
        let intent = create_test_intent(
            Capability::HttpFetchV1,
            json!({"url": "https://example.com/api"}),
        );
        let result = extract_resource_identifier(&intent);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/api");
    }

    #[test]
    fn test_extract_resource_git_clone() {
        let intent = create_test_intent(
            Capability::GitCloneV1,
            json!({"repository_url": "https://github.com/test/repo"}),
        );
        let result = extract_resource_identifier(&intent);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://github.com/test/repo");
    }

    #[test]
    fn test_extract_resource_sqlite_query() {
        let intent = create_test_intent(
            Capability::SqliteQueryV1,
            json!({"database_path": "/data/test.db"}),
        );
        let result = extract_resource_identifier(&intent);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/data/test.db");
    }

    #[test]
    fn test_extract_resource_bench_report() {
        let intent = create_test_intent(
            Capability::BenchReportV1,
            json!({"benchmark_name": "performance_test"}),
        );
        let result = extract_resource_identifier(&intent);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "performance_test");
    }

    #[test]
    fn test_extract_resource_shell_exec() {
        let intent = create_test_intent(Capability::ShellExec, json!({"command": "ls -la"}));
        let result = extract_resource_identifier(&intent);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "ls -la");
    }

    #[test]
    fn test_extract_resource_archive_read() {
        let intent = create_test_intent(
            Capability::ArchiveReadV1,
            json!({"path": "/tmp/archive.zip"}),
        );
        let result = extract_resource_identifier(&intent);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/tmp/archive.zip");
    }

    #[test]
    fn test_extract_resource_missing_path() {
        let intent = create_test_intent(Capability::FsReadV1, json!({}));
        let result = extract_resource_identifier(&intent);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Missing 'path'"));
    }

    #[test]
    fn test_extract_resource_missing_url() {
        let intent = create_test_intent(Capability::HttpFetchV1, json!({}));
        let result = extract_resource_identifier(&intent);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Missing 'url'"));
    }

    #[test]
    fn test_extract_resource_missing_repository_url() {
        let intent = create_test_intent(Capability::GitCloneV1, json!({}));
        let result = extract_resource_identifier(&intent);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Missing 'repository_url'"));
    }

    #[test]
    fn test_extract_resource_missing_database_path() {
        let intent = create_test_intent(Capability::SqliteQueryV1, json!({}));
        let result = extract_resource_identifier(&intent);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Missing 'database_path'"));
    }

    #[test]
    fn test_extract_resource_missing_benchmark_name() {
        let intent = create_test_intent(Capability::BenchReportV1, json!({}));
        let result = extract_resource_identifier(&intent);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Missing 'benchmark_name'"));
    }

    #[test]
    fn test_extract_resource_missing_command() {
        let intent = create_test_intent(Capability::ShellExec, json!({}));
        let result = extract_resource_identifier(&intent);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Missing 'command'"));
    }

    #[test]
    fn test_policy_registry_creation() {
        let default_limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 1024 * 1024,
            io_bytes: 1024 * 1024,
            pids_max: 10,
            timeout_ms: 30000,
        };
        let registry = PolicyRegistry::new(default_limits.clone());

        let retrieved = registry.default_limits();
        assert_eq!(retrieved.cpu_ms_per_100ms, default_limits.cpu_ms_per_100ms);
        assert_eq!(retrieved.mem_bytes, default_limits.mem_bytes);
        assert_eq!(retrieved.io_bytes, default_limits.io_bytes);
        assert_eq!(retrieved.pids_max, default_limits.pids_max);
        assert_eq!(retrieved.timeout_ms, default_limits.timeout_ms);
        assert_eq!(registry.total_policies(), 0);
    }

    #[test]
    fn test_policy_registry_reset_all() {
        let default_limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 1024 * 1024,
            io_bytes: 1024 * 1024,
            pids_max: 10,
            timeout_ms: 30000,
        };
        let registry = PolicyRegistry::new(default_limits);

        registry.reset(None);
        assert_eq!(registry.total_policies(), 0);
    }

    #[test]
    fn test_policy_registry_reset_capability() {
        let default_limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 1024 * 1024,
            io_bytes: 1024 * 1024,
            pids_max: 10,
            timeout_ms: 30000,
        };
        let registry = PolicyRegistry::new(default_limits);

        registry.reset(Some("fs.read.v1"));
        assert_eq!(registry.total_policies(), 0);
    }

    #[test]
    fn test_policy_registry_remove_nonexistent() {
        let default_limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 1024 * 1024,
            io_bytes: 1024 * 1024,
            pids_max: 10,
            timeout_ms: 30000,
        };
        let registry = PolicyRegistry::new(default_limits);

        registry.remove("nonexistent-policy");
        assert_eq!(registry.total_policies(), 0);
    }

    #[test]
    fn test_policy_registry_policies_for_empty() {
        let default_limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 1024 * 1024,
            io_bytes: 1024 * 1024,
            pids_max: 10,
            timeout_ms: 30000,
        };
        let registry = PolicyRegistry::new(default_limits);

        let result = registry.policies_for("fs.read.v1", "test-tenant");
        assert!(result.is_none());
    }

    #[test]
    fn test_merge_policies_empty() {
        let global: Arc<Vec<Arc<PolicyEntry>>> = Arc::new(vec![]);
        let tenant: Vec<Arc<PolicyEntry>> = vec![];

        let merged = merge_policies(&global, &tenant);
        assert!(merged.is_empty());
    }

    #[test]
    fn test_capability_aggregate_default() {
        let aggregate = CapabilityAggregate::default();
        assert!(aggregate.policies.is_empty());
    }

    #[test]
    fn test_host_context_serialization() {
        let context = HostContext {
            tags: vec!["test".to_string(), "dev".to_string()],
            hostname: "test-host".to_string(),
            version: "1.0.0".to_string(),
        };

        let json = serde_json::to_string(&context).unwrap();
        let deserialized: HostContext = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tags, context.tags);
        assert_eq!(deserialized.hostname, context.hostname);
        assert_eq!(deserialized.version, context.version);
    }

    #[test]
    fn test_policy_input_serialization() {
        let input = PolicyInput {
            capability: "fs.read.v1".to_string(),
            resource: "/tmp/test.txt".to_string(),
            params: json!({"path": "/tmp/test.txt"}),
            actor: ActorContext {
                tenant: "test-tenant".to_string(),
                claims: json!({}),
            },
            constraints: json!({}),
            host: HostContext {
                tags: vec![],
                hostname: "test".to_string(),
                version: "1.0.0".to_string(),
            },
        };

        let json = serde_json::to_string(&input).unwrap();
        let deserialized: PolicyInput = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.capability, input.capability);
        assert_eq!(deserialized.resource, input.resource);
    }

    #[test]
    fn test_actor_context_serialization() {
        let actor = ActorContext {
            tenant: "test-tenant".to_string(),
            claims: json!({"role": "admin"}),
        };

        let json = serde_json::to_string(&actor).unwrap();
        let deserialized: ActorContext = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tenant, actor.tenant);
        assert_eq!(deserialized.claims, actor.claims);
    }

    #[test]
    fn test_policy_result_construction() {
        let result = PolicyResult {
            allow: true,
            reason: Some("Test reason".to_string()),
            limits: ExecutionLimits {
                cpu_ms_per_100ms: 50,
                mem_bytes: 1024 * 1024,
                io_bytes: 1024 * 1024,
                pids_max: 10,
                timeout_ms: 30000,
            },
            scope: json!({"paths": ["/tmp"]}),
            policy_id: Some("test-policy".to_string()),
        };

        assert!(result.allow);
        assert_eq!(result.reason, Some("Test reason".to_string()));
        assert_eq!(result.policy_id, Some("test-policy".to_string()));
    }

    #[test]
    fn test_policy_result_denied() {
        let result = PolicyResult {
            allow: false,
            reason: Some("Access denied".to_string()),
            limits: ExecutionLimits {
                cpu_ms_per_100ms: 50,
                mem_bytes: 1024 * 1024,
                io_bytes: 1024 * 1024,
                pids_max: 10,
                timeout_ms: 30000,
            },
            scope: json!({}),
            policy_id: Some("deny-policy".to_string()),
        };

        assert!(!result.allow);
        assert_eq!(result.reason, Some("Access denied".to_string()));
    }

    #[tokio::test]
    async fn test_policy_registry_apply_update_remove() {
        let default_limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 1024 * 1024,
            io_bytes: 1024 * 1024,
            pids_max: 10,
            timeout_ms: 30000,
        };
        let registry = PolicyRegistry::new(default_limits);

        let update = smith_protocol::policy::PolicyUpdate::Remove {
            policy_id: "nonexistent".to_string(),
        };

        let result = registry.apply_update(update).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_policy_registry_apply_update_reset() {
        let default_limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 1024 * 1024,
            io_bytes: 1024 * 1024,
            pids_max: 10,
            timeout_ms: 30000,
        };
        let registry = PolicyRegistry::new(default_limits);

        let update = smith_protocol::policy::PolicyUpdate::Reset {
            capability: Some("fs.read.v1".to_string()),
        };

        let result = registry.apply_update(update).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_policy_registry_apply_update_reset_all() {
        let default_limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 1024 * 1024,
            io_bytes: 1024 * 1024,
            pids_max: 10,
            timeout_ms: 30000,
        };
        let registry = PolicyRegistry::new(default_limits);

        let update = smith_protocol::policy::PolicyUpdate::Reset { capability: None };

        let result = registry.apply_update(update).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_policy_sync_handle_abort() {
        let handle = tokio::runtime::Runtime::new().unwrap().spawn(async {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        });

        let sync_handle = PolicySyncHandle { handle };
        sync_handle.abort();
    }

    #[test]
    fn test_capability_policies_default() {
        let policies = CapabilityPolicies::default();
        assert!(policies.global.is_empty());
        assert!(policies.per_tenant.is_empty());
    }

    #[test]
    fn test_policy_decision_envelope_deserialization() {
        let json = r#"{"allow": true, "reason": "test reason"}"#;
        let envelope: PolicyDecisionEnvelope = serde_json::from_str(json).unwrap();
        assert!(envelope.allow);
        assert_eq!(envelope.reason, Some("test reason".to_string()));
    }

    #[test]
    fn test_policy_decision_envelope_deny() {
        let json = r#"{"allow": false, "reason": "denied"}"#;
        let envelope: PolicyDecisionEnvelope = serde_json::from_str(json).unwrap();
        assert!(!envelope.allow);
        assert_eq!(envelope.reason, Some("denied".to_string()));
    }

    #[test]
    fn test_policy_decision_envelope_with_limits() {
        let json = r#"{
            "allow": true,
            "limits": {
                "cpu_ms_per_100ms": 100,
                "mem_bytes": 2048,
                "io_bytes": 4096,
                "pids_max": 5,
                "timeout_ms": 60000
            }
        }"#;
        let envelope: PolicyDecisionEnvelope = serde_json::from_str(json).unwrap();
        assert!(envelope.allow);
        assert!(envelope.limits.is_some());
    }

    #[test]
    fn test_policy_decision_envelope_with_scope() {
        let json = r#"{"allow": true, "scope": {"paths": ["/tmp"]}}"#;
        let envelope: PolicyDecisionEnvelope = serde_json::from_str(json).unwrap();
        assert!(envelope.allow);
        assert!(envelope.scope.is_some());
    }
}
