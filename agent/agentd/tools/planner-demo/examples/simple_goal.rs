//! # Simple Goal Execution Example
//!
//! This example demonstrates the basic usage of the planner-executor demo
//! for executing a simple, linear goal with minimal complexity.
//!
//! ## What This Example Shows
//!
//! - Basic goal submission to the planner-executor
//! - Simple workflow execution monitoring
//! - Result handling and display
//! - Error handling patterns
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example simple_goal
//! ```

use anyhow::Result;
use planner_demo::{
    scenarios::{ScenarioLibrary, WorkflowPattern},
};
use serde_json::json;
use std::time::Duration;
use tracing::{info, warn};
use uuid::Uuid;

// Import demo modules
use smith_bus::SmithBus;
use smith_protocol::{Capability, Intent};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    info!("🚀 Starting Simple Goal Execution Example");
    
    // Connect to NATS
    let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
    let bus = SmithBus::connect(&nats_url).await?;
    info!("✅ Connected to NATS at {}", nats_url);
    
    // Load a simple scenario
    let library = ScenarioLibrary::new();
    let simple_scenarios = library.get_scenarios_by_pattern(WorkflowPattern::Simple);
    
    if simple_scenarios.is_empty() {
        warn!("No simple scenarios available");
        return Ok(());
    }
    
    let scenario = &simple_scenarios[0]; // Use first simple scenario
    info!("📋 Selected scenario: {}", scenario.name);
    info!("🎯 Goal: {}", scenario.goal);
    
    // Generate unique workflow ID
    let workflow_id = Uuid::new_v4().to_string();
    info!("🆔 Workflow ID: {}", workflow_id);
    
    // Create intent parameters
    let params = json!({
        "workflow_id": workflow_id,
        "goal": scenario.goal,
        "workflow_type": scenario.workflow_type,
        "max_steps": scenario.max_steps,
        "timeout_ms": scenario.timeout_seconds.map(|s| s * 1000),
        "context": {
            "demo_mode": true,
            "example": "simple_goal",
            "scenario_name": scenario.name
        },
        "allowed_capabilities": [
            "fs.read.v1",
            "http.fetch.v1"
        ],
        "resource_limits": {
            "max_memory_mb": 256,
            "max_cpu_seconds": 60,
            "max_fs_operations": 100,
            "max_network_requests": 10,
            "max_parallel_executions": 2
        },
        "preferences": {
            "verbosity": "info",
            "interactive": false,
            "parallel_execution": false,
            "auto_retry": true,
            "save_intermediate_results": true
        }
    });
    
    // Create and publish intent
    let intent = Intent::new(
        Capability::PlannerExecV1,
        "demo".to_string(),
        params,
        scenario.timeout_seconds.unwrap_or(60) * 1000, // TTL in milliseconds
        "simple-goal-example".to_string(),
    );
    
    let subject = format!("smith.intents.raw.planner_exec.v1.{}", workflow_id);
    info!("📤 Publishing intent to subject: {}", subject);
    
    bus.publish(subject, &intent).await?;
    info!("✅ Intent published successfully");
    
    // Subscribe to results
    let result_subject = format!("smith.results.planner_exec.v1.{}", workflow_id);
    info!("📥 Subscribing to results on: {}", result_subject);
    
    let mut result_subscriber = bus.subscribe(&result_subject).await?;
    
    // Monitor execution with timeout
    let timeout_duration = Duration::from_secs(scenario.timeout_seconds.unwrap_or(60));
    let start_time = std::time::Instant::now();
    let mut step_count = 0;
    
    info!("⏳ Monitoring execution...");
    
    while start_time.elapsed() < timeout_duration {
        // Try to receive result with 1-second timeout
        match tokio::time::timeout(Duration::from_secs(1), result_subscriber.next()).await {
            Ok(Some(msg)) => {
                step_count += 1;
                
                match serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                    Ok(result) => {
                        info!("📊 Step {}: Received result", step_count);
                        
                        // Display key information
                        if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
                            info!("   Status: {}", status);
                        }
                        
                        if let Some(state) = result.get("current_state").and_then(|v| v.as_str()) {
                            info!("   State: {}", state);
                        }
                        
                        if let Some(message) = result.get("message").and_then(|v| v.as_str()) {
                            info!("   Message: {}", message);
                        }
                        
                        // Check for completion
                        if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
                            if status == "completed" {
                                info!("🎉 Workflow completed successfully!");
                                print_final_results(&result);
                                return Ok(());
                            } else if status == "failed" {
                                warn!("❌ Workflow failed!");
                                if let Some(error) = result.get("error").and_then(|v| v.as_str()) {
                                    warn!("   Error: {}", error);
                                }
                                print_final_results(&result);
                                return Ok(());
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse result JSON: {}", e);
                    }
                }
            }
            Ok(None) => {
                info!("No more messages in result stream");
                break;
            }
            Err(_) => {
                // Timeout, continue monitoring
                info!("⏱️  Still monitoring... ({}s elapsed)", start_time.elapsed().as_secs());
            }
        }
    }
    
    warn!("⏰ Execution monitoring timed out after {}s", timeout_duration.as_secs());
    info!("📊 Total steps monitored: {}", step_count);
    
    Ok(())
}

/// Display final execution results
fn print_final_results(result: &serde_json::Value) {
    println!("\n🏁 EXECUTION SUMMARY");
    println!("===================");
    
    if let Some(duration) = result.get("duration_ms").and_then(|v| v.as_u64()) {
        println!("⏱️  Duration: {}ms ({:.2}s)", duration, duration as f64 / 1000.0);
    }
    
    if let Some(steps) = result.get("total_steps").and_then(|v| v.as_u64()) {
        println!("👣 Total Steps: {}", steps);
    }
    
    if let Some(summary) = result.get("execution_summary") {
        println!("📋 Summary:");
        println!("{}", serde_json::to_string_pretty(summary).unwrap_or_default());
    }
    
    if let Some(artifacts) = result.get("artifacts").and_then(|v| v.as_array()) {
        if !artifacts.is_empty() {
            println!("📁 Artifacts: {} items", artifacts.len());
        }
    }
    
    println!();
}