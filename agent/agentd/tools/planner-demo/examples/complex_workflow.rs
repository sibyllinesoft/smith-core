//! # Complex Multi-Step Workflow Example
//!
//! This example demonstrates the advanced capabilities of the planner-executor
//! controller with a complex orchestration scenario involving multiple steps,
//! sub-workflows, and sophisticated AI decision-making.
//!
//! ## What This Example Shows
//!
//! - Complex orchestration workflow execution
//! - Oracle deep research and planning committee
//! - Guard security validation
//! - Stall detection and recovery
//! - Performance monitoring
//! - Comprehensive result analysis
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example complex_workflow
//! ```

use anyhow::Result;
use futures::StreamExt;
use planner_demo::{
    monitor::{MonitorConfig, WorkflowMonitor},
    scenarios::{ScenarioLibrary, WorkflowPattern},
};
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// Import demo modules
use smith_bus::SmithBus;
use smith_protocol::{Capability, Intent};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging with debug level
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    
    info!("🚀 Starting Complex Workflow Example");
    
    // Connect to NATS
    let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
    let bus = SmithBus::connect(&nats_url).await?;
    info!("✅ Connected to NATS at {}", nats_url);
    
    // Load a complex scenario
    let library = ScenarioLibrary::new();
    let complex_scenarios = library.get_scenarios_by_pattern(WorkflowPattern::Complex);
    
    if complex_scenarios.is_empty() {
        warn!("No complex scenarios available");
        return Ok(());
    }
    
    // Select the multi-service deployment scenario for demonstration
    let scenario = complex_scenarios
        .iter()
        .find(|s| s.name == "multi-service-deployment")
        .unwrap_or(&complex_scenarios[0]);
    
    info!("📋 Selected scenario: {}", scenario.name);
    info!("📝 Description: {}", scenario.description);
    info!("🎯 Goal: {}", scenario.goal);
    info!("⚙️  Complexity: {}/5", scenario.complexity);
    info!("📊 Expected steps: {}", scenario.expected_steps);
    
    // Generate unique workflow ID
    let workflow_id = Uuid::new_v4().to_string();
    info!("🆔 Workflow ID: {}", workflow_id);
    
    // Start background monitor
    let monitor_handle = start_workflow_monitor(&nats_url, &workflow_id).await?;
    
    // Create comprehensive intent parameters
    let params = create_complex_intent_params(&workflow_id, scenario)?;
    
    // Create and publish intent
    let intent = Intent::new(
        Capability::PlannerExecV1,
        "production".to_string(), // Use production environment for complex workflow
        params,
        scenario.timeout_seconds.unwrap_or(600) * 1000, // Extended TTL for complex workflows
        "complex-workflow-example".to_string(),
    );
    
    let subject = format!("smith.intents.raw.planner_exec.v1.{}", workflow_id);
    info!("📤 Publishing complex intent to subject: {}", subject);
    
    bus.publish(subject, &intent).await?;
    info!("✅ Intent published successfully");
    
    // Subscribe to multiple event streams for comprehensive monitoring
    let result_subject = format!("smith.results.planner_exec.v1.{}", workflow_id);
    let events_subject = format!("smith.events.planner_exec.{}", workflow_id);
    let metrics_subject = format!("smith.metrics.planner_exec.{}", workflow_id);
    
    info!("📥 Subscribing to multiple streams:");
    info!("   Results: {}", result_subject);
    info!("   Events: {}", events_subject);
    info!("   Metrics: {}", metrics_subject);
    
    let mut result_subscriber = bus.subscribe(&result_subject).await?;
    let mut events_subscriber = bus.subscribe(&events_subject).await?;
    let mut metrics_subscriber = bus.subscribe(&metrics_subject).await?;
    
    // Advanced monitoring with comprehensive tracking
    let execution_tracker = ExecutionTracker::new(scenario.max_steps);
    monitor_complex_execution(
        &mut result_subscriber,
        &mut events_subscriber,
        &mut metrics_subscriber,
        execution_tracker,
        scenario.timeout_seconds.unwrap_or(600),
    ).await?;
    
    // Stop background monitor
    monitor_handle.abort();
    info!("🛑 Stopped background monitor");
    
    Ok(())
}

/// Create comprehensive intent parameters for complex workflow
fn create_complex_intent_params(
    workflow_id: &str,
    scenario: &planner_demo::scenarios::DemoScenario,
) -> Result<serde_json::Value> {
    let params = json!({
        "workflow_id": workflow_id,
        "goal": scenario.goal,
        "workflow_type": scenario.workflow_type,
        "max_steps": scenario.max_steps,
        "timeout_ms": scenario.timeout_seconds.map(|s| s * 1000),
        "context": {
            "demo_mode": true,
            "example": "complex_workflow",
            "scenario_name": scenario.name,
            "complexity_level": scenario.complexity,
            "expected_steps": scenario.expected_steps,
            "environment": "production",
            "monitoring_enabled": true,
            "advanced_features": {
                "oracle_deep_research": true,
                "planning_committee": true,
                "stall_detection": true,
                "auto_recovery": true,
                "performance_optimization": true
            }
        },
        "allowed_capabilities": [
            "fs.read.v1",
            "fs.write.v1",
            "http.fetch.v1",
            "sqlite.query.v1",
            "archive.read.v1"
        ],
        "resource_limits": {
            "max_memory_mb": 1024,    // Increased for complex workflows
            "max_cpu_seconds": 600,   // 10 minutes
            "max_fs_operations": 5000,
            "max_network_requests": 500,
            "max_parallel_executions": 8
        },
        "preferences": {
            "verbosity": "debug",
            "interactive": false,
            "parallel_execution": true,
            "auto_retry": true,
            "save_intermediate_results": true,
            "optimization_level": "aggressive",
            "monitoring_detail": "comprehensive"
        },
        "workflow_config": {
            "oracle_settings": {
                "research_depth": "deep",
                "committee_size": 5,
                "consensus_threshold": 0.8,
                "confidence_threshold": 0.7
            },
            "guard_settings": {
                "security_level": "strict",
                "policy_enforcement": "mandatory",
                "audit_level": "detailed"
            },
            "stall_detection": {
                "enabled": true,
                "timeout_seconds": 60,
                "retry_attempts": 3,
                "escalation_enabled": true
            },
            "performance_monitoring": {
                "enabled": true,
                "metrics_interval_ms": 1000,
                "resource_tracking": true,
                "bottleneck_detection": true
            }
        }
    });
    
    Ok(params)
}

/// Start background workflow monitor
async fn start_workflow_monitor(nats_url: &str, workflow_id: &str) -> Result<tokio::task::JoinHandle<()>> {
    let config = MonitorConfig {
        nats_url: nats_url.to_string(),
        workflow_filter: Some(workflow_id.to_string()),
        refresh_rate_ms: 100,
        max_history: 1000,
    };
    
    info!("🖥️  Starting background workflow monitor");
    
    let handle = tokio::spawn(async move {
        match WorkflowMonitor::new(config).await {
            Ok(monitor) => {
                info!("📊 Workflow monitor started");
                if let Err(e) = monitor.run().await {
                    error!("Monitor error: {}", e);
                }
            }
            Err(e) => {
                error!("Failed to create monitor: {}", e);
            }
        }
    });
    
    // Give monitor time to start
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    Ok(handle)
}

/// Advanced execution tracker for complex workflows
#[derive(Debug)]
struct ExecutionTracker {
    start_time: Instant,
    max_steps: usize,
    step_count: usize,
    state_history: Vec<StateTransition>,
    oracle_events: Vec<OracleEvent>,
    guard_decisions: Vec<GuardDecision>,
    performance_metrics: HashMap<String, f64>,
    stall_alerts: Vec<StallAlert>,
    last_activity: Instant,
}

#[derive(Debug, Clone)]
struct StateTransition {
    timestamp: Instant,
    from_state: String,
    to_state: String,
    reason: String,
}

#[derive(Debug, Clone)]
struct OracleEvent {
    timestamp: Instant,
    event_type: String,
    confidence: f64,
    description: String,
}

#[derive(Debug, Clone)]
struct GuardDecision {
    timestamp: Instant,
    action: String,
    verdict: String,
    reasoning: String,
}

#[derive(Debug, Clone)]
struct StallAlert {
    timestamp: Instant,
    alert_type: String,
    description: String,
    recovery_action: String,
}

impl ExecutionTracker {
    fn new(max_steps: usize) -> Self {
        Self {
            start_time: Instant::now(),
            max_steps,
            step_count: 0,
            state_history: Vec::new(),
            oracle_events: Vec::new(),
            guard_decisions: Vec::new(),
            performance_metrics: HashMap::new(),
            stall_alerts: Vec::new(),
            last_activity: Instant::now(),
        }
    }
    
    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
    
    fn add_state_transition(&mut self, from: String, to: String, reason: String) {
        self.state_history.push(StateTransition {
            timestamp: Instant::now(),
            from_state: from,
            to_state: to,
            reason,
        });
        self.update_activity();
    }
    
    fn add_oracle_event(&mut self, event_type: String, confidence: f64, description: String) {
        self.oracle_events.push(OracleEvent {
            timestamp: Instant::now(),
            event_type,
            confidence,
            description,
        });
        self.update_activity();
    }
    
    fn add_guard_decision(&mut self, action: String, verdict: String, reasoning: String) {
        self.guard_decisions.push(GuardDecision {
            timestamp: Instant::now(),
            action,
            verdict,
            reasoning,
        });
        self.update_activity();
    }
    
    fn update_metric(&mut self, name: String, value: f64) {
        self.performance_metrics.insert(name, value);
        self.update_activity();
    }
    
    fn add_stall_alert(&mut self, alert_type: String, description: String, recovery_action: String) {
        self.stall_alerts.push(StallAlert {
            timestamp: Instant::now(),
            alert_type,
            description,
            recovery_action,
        });
        self.update_activity();
    }
    
    fn print_summary(&self) {
        println!("\n🏁 COMPLEX WORKFLOW EXECUTION SUMMARY");
        println!("====================================");
        
        let duration = self.start_time.elapsed();
        println!("⏱️  Total Duration: {:.2}s", duration.as_secs_f64());
        println!("👣 Steps Executed: {}/{}", self.step_count, self.max_steps);
        
        if !self.state_history.is_empty() {
            println!("\n🔄 State Transitions: {}", self.state_history.len());
            for (i, transition) in self.state_history.iter().take(5).enumerate() {
                println!("   {}. {} → {} ({})", 
                    i + 1, 
                    transition.from_state, 
                    transition.to_state, 
                    transition.reason
                );
            }
            if self.state_history.len() > 5 {
                println!("   ... and {} more", self.state_history.len() - 5);
            }
        }
        
        if !self.oracle_events.is_empty() {
            println!("\n🧠 Oracle Events: {}", self.oracle_events.len());
            for (i, event) in self.oracle_events.iter().take(3).enumerate() {
                println!("   {}. {} (confidence: {:.1}%): {}", 
                    i + 1, 
                    event.event_type, 
                    event.confidence * 100.0,
                    event.description
                );
            }
            if self.oracle_events.len() > 3 {
                println!("   ... and {} more", self.oracle_events.len() - 3);
            }
        }
        
        if !self.guard_decisions.is_empty() {
            println!("\n🛡️  Guard Decisions: {}", self.guard_decisions.len());
            for (i, decision) in self.guard_decisions.iter().take(3).enumerate() {
                println!("   {}. {} → {}: {}", 
                    i + 1, 
                    decision.action, 
                    decision.verdict,
                    decision.reasoning
                );
            }
            if self.guard_decisions.len() > 3 {
                println!("   ... and {} more", self.guard_decisions.len() - 3);
            }
        }
        
        if !self.performance_metrics.is_empty() {
            println!("\n📊 Performance Metrics:");
            for (name, value) in &self.performance_metrics {
                println!("   {}: {:.2}", name, value);
            }
        }
        
        if !self.stall_alerts.is_empty() {
            println!("\n🚨 Stall Alerts: {}", self.stall_alerts.len());
            for (i, alert) in self.stall_alerts.iter().enumerate() {
                println!("   {}. {}: {} (Recovery: {})", 
                    i + 1, 
                    alert.alert_type, 
                    alert.description,
                    alert.recovery_action
                );
            }
        }
        
        println!();
    }
}

/// Monitor complex workflow execution with comprehensive tracking
async fn monitor_complex_execution(
    result_subscriber: &mut futures::stream::BoxStream<'_, async_nats::Message>,
    events_subscriber: &mut futures::stream::BoxStream<'_, async_nats::Message>,
    metrics_subscriber: &mut futures::stream::BoxStream<'_, async_nats::Message>,
    mut tracker: ExecutionTracker,
    timeout_seconds: u64,
) -> Result<()> {
    let timeout_duration = Duration::from_secs(timeout_seconds);
    let start_time = Instant::now();
    
    info!("⏳ Starting comprehensive execution monitoring...");
    info!("   Timeout: {}s", timeout_seconds);
    info!("   Max steps: {}", tracker.max_steps);
    
    loop {
        // Check global timeout
        if start_time.elapsed() > timeout_duration {
            warn!("⏰ Global execution timeout reached");
            break;
        }
        
        // Use select to monitor multiple streams simultaneously
        tokio::select! {
            // Result stream - primary workflow results
            result = timeout(Duration::from_millis(500), result_subscriber.next()) => {
                match result {
                    Ok(Some(msg)) => {
                        match serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                            Ok(result) => {
                                tracker.step_count += 1;
                                info!("📊 Step {}: Result received", tracker.step_count);
                                
                                // Process result
                                if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
                                    info!("   Status: {}", status);
                                    
                                    if status == "completed" {
                                        info!("🎉 Complex workflow completed successfully!");
                                        tracker.print_summary();
                                        return Ok(());
                                    } else if status == "failed" {
                                        warn!("❌ Complex workflow failed!");
                                        if let Some(error) = result.get("error").and_then(|v| v.as_str()) {
                                            warn!("   Error: {}", error);
                                        }
                                        tracker.print_summary();
                                        return Ok(());
                                    }
                                }
                                
                                // Track state transitions
                                if let (Some(from), Some(to)) = (
                                    result.get("previous_state").and_then(|v| v.as_str()),
                                    result.get("current_state").and_then(|v| v.as_str())
                                ) {
                                    tracker.add_state_transition(
                                        from.to_string(),
                                        to.to_string(),
                                        "Workflow progression".to_string()
                                    );
                                }
                            }
                            Err(e) => {
                                warn!("Failed to parse result: {}", e);
                            }
                        }
                    }
                    Ok(None) => {
                        debug!("Result stream ended");
                    }
                    Err(_) => {
                        // Timeout, continue
                    }
                }
            }
            
            // Events stream - oracle, guard, and other events
            event = timeout(Duration::from_millis(500), events_subscriber.next()) => {
                match event {
                    Ok(Some(msg)) => {
                        match serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                            Ok(event) => {
                                debug!("📅 Event received: {}", event);
                                
                                // Process different event types
                                if let Some(event_type) = event.get("type").and_then(|v| v.as_str()) {
                                    match event_type {
                                        "oracle_decision" => {
                                            if let (Some(confidence), Some(description)) = (
                                                event.get("confidence").and_then(|v| v.as_f64()),
                                                event.get("description").and_then(|v| v.as_str())
                                            ) {
                                                tracker.add_oracle_event(
                                                    "Decision".to_string(),
                                                    confidence,
                                                    description.to_string()
                                                );
                                                info!("🧠 Oracle decision: {} (confidence: {:.1}%)", 
                                                    description, confidence * 100.0);
                                            }
                                        }
                                        "guard_validation" => {
                                            if let (Some(action), Some(verdict), Some(reasoning)) = (
                                                event.get("action").and_then(|v| v.as_str()),
                                                event.get("verdict").and_then(|v| v.as_str()),
                                                event.get("reasoning").and_then(|v| v.as_str())
                                            ) {
                                                tracker.add_guard_decision(
                                                    action.to_string(),
                                                    verdict.to_string(),
                                                    reasoning.to_string()
                                                );
                                                info!("🛡️  Guard: {} → {} ({})", action, verdict, reasoning);
                                            }
                                        }
                                        "stall_detected" => {
                                            if let (Some(alert_type), Some(description), Some(recovery)) = (
                                                event.get("alert_type").and_then(|v| v.as_str()),
                                                event.get("description").and_then(|v| v.as_str()),
                                                event.get("recovery_action").and_then(|v| v.as_str())
                                            ) {
                                                tracker.add_stall_alert(
                                                    alert_type.to_string(),
                                                    description.to_string(),
                                                    recovery.to_string()
                                                );
                                                warn!("🚨 Stall detected: {} - {}", alert_type, description);
                                                info!("🔧 Recovery action: {}", recovery);
                                            }
                                        }
                                        _ => {
                                            debug!("Unknown event type: {}", event_type);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to parse event: {}", e);
                            }
                        }
                    }
                    Ok(None) => {
                        debug!("Events stream ended");
                    }
                    Err(_) => {
                        // Timeout, continue
                    }
                }
            }
            
            // Metrics stream - performance data
            metric = timeout(Duration::from_millis(500), metrics_subscriber.next()) => {
                match metric {
                    Ok(Some(msg)) => {
                        match serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                            Ok(metrics) => {
                                debug!("📈 Metrics received: {}", metrics);
                                
                                // Update performance metrics
                                if let Some(cpu) = metrics.get("cpu_usage").and_then(|v| v.as_f64()) {
                                    tracker.update_metric("cpu_usage".to_string(), cpu);
                                }
                                if let Some(memory) = metrics.get("memory_usage").and_then(|v| v.as_f64()) {
                                    tracker.update_metric("memory_usage".to_string(), memory);
                                }
                                if let Some(throughput) = metrics.get("throughput").and_then(|v| v.as_f64()) {
                                    tracker.update_metric("throughput".to_string(), throughput);
                                }
                            }
                            Err(e) => {
                                warn!("Failed to parse metrics: {}", e);
                            }
                        }
                    }
                    Ok(None) => {
                        debug!("Metrics stream ended");
                    }
                    Err(_) => {
                        // Timeout, continue
                    }
                }
            }
        }
        
        // Progress update every 10 seconds
        if tracker.step_count > 0 && tracker.step_count % 10 == 0 {
            let elapsed = start_time.elapsed().as_secs();
            let progress = (tracker.step_count as f64 / tracker.max_steps as f64) * 100.0;
            info!("⏱️  Progress: {:.1}% ({}/{} steps) after {}s", 
                progress, tracker.step_count, tracker.max_steps, elapsed);
        }
    }
    
    warn!("⏰ Monitoring ended - timeout reached");
    tracker.print_summary();
    
    Ok(())
}