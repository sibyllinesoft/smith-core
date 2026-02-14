//! # User Intervention Demo Example
//!
//! This example demonstrates the interactive capabilities of the planner-executor
//! controller including user intervention, stall detection and recovery,
//! and manual workflow control.
//!
//! ## What This Example Shows
//!
//! - Interactive workflow execution with user decision points
//! - Stall detection and user-guided recovery
//! - Manual workflow intervention and control
//! - Menu system integration
//! - Pause/resume functionality
//! - Emergency stop and recovery procedures
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example user_intervention
//! ```

use anyhow::Result;
use console::Term;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use futures::StreamExt;
use planner_demo::{
    scenarios::{ScenarioLibrary, WorkflowPattern},
};
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// Import demo modules
use smith_bus::SmithBus;
use smith_protocol::{Capability, Intent};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    
    let term = Term::stdout();
    term.clear_screen()?;
    
    println!("🎮 SMITH PLANNER-EXECUTOR USER INTERVENTION DEMO");
    println!("==============================================");
    println!();
    
    // Connect to NATS
    let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
    let bus = SmithBus::connect(&nats_url).await?;
    info!("✅ Connected to NATS at {}", nats_url);
    
    // Load interactive scenarios
    let library = ScenarioLibrary::new();
    let interactive_scenarios = library.get_scenarios_by_pattern(WorkflowPattern::Interactive);
    
    if interactive_scenarios.is_empty() {
        println!("❌ No interactive scenarios available");
        return Ok(());
    }
    
    // Let user select scenario
    let scenario_names: Vec<String> = interactive_scenarios
        .iter()
        .map(|s| format!("{} - {}", s.name, s.description))
        .collect();
    
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select an interactive scenario")
        .items(&scenario_names)
        .interact()?;
    
    let scenario = &interactive_scenarios[selection];
    
    println!();
    println!("📋 Selected scenario: {}", scenario.name);
    println!("📝 Description: {}", scenario.description);
    println!("🎯 Goal: {}", scenario.goal);
    println!("🎮 Interactive mode: {}", if scenario.interactive { "✅ Yes" } else { "❌ No" });
    println!();
    
    // Confirm start
    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Ready to start interactive workflow execution?")
        .interact()?
    {
        println!("Demo cancelled.");
        return Ok(());
    }
    
    // Generate unique workflow ID
    let workflow_id = Uuid::new_v4().to_string();
    info!("🆔 Workflow ID: {}", workflow_id);
    
    // Create interactive intent parameters
    let params = create_interactive_intent_params(&workflow_id, scenario)?;
    
    // Create and publish intent
    let intent = Intent::new(
        Capability::PlannerExecV1,
        "interactive".to_string(),
        params,
        scenario.timeout_seconds.unwrap_or(300) * 1000,
        "user-intervention-example".to_string(),
    );
    
    let subject = format!("smith.intents.raw.planner_exec.v1.{}", workflow_id);
    info!("📤 Publishing interactive intent");
    
    bus.publish(subject, &intent).await?;
    println!("✅ Interactive workflow started!");
    println!();
    
    // Subscribe to workflow streams
    let result_subject = format!("smith.results.planner_exec.v1.{}", workflow_id);
    let control_subject = format!("smith.control.planner_exec.{}", workflow_id);
    let intervention_subject = format!("smith.intervention.planner_exec.{}", workflow_id);
    
    let mut result_subscriber = bus.subscribe(&result_subject).await?;
    let control_publisher = bus.clone();
    let intervention_publisher = bus.clone();
    
    // Start interactive monitoring
    let monitor = InteractiveMonitor::new(
        workflow_id.clone(),
        control_publisher,
        intervention_publisher,
        scenario.timeout_seconds.unwrap_or(300),
    );
    
    monitor.run(&mut result_subscriber).await?;
    
    println!();
    println!("🎉 Interactive demo completed!");
    
    Ok(())
}

/// Create interactive intent parameters
fn create_interactive_intent_params(
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
            "example": "user_intervention",
            "scenario_name": scenario.name,
            "interaction_enabled": true,
            "manual_control": true
        },
        "allowed_capabilities": [
            "fs.read.v1",
            "http.fetch.v1"
        ],
        "resource_limits": {
            "max_memory_mb": 512,
            "max_cpu_seconds": 300,
            "max_fs_operations": 1000,
            "max_network_requests": 100,
            "max_parallel_executions": 4
        },
        "preferences": {
            "verbosity": "info",
            "interactive": true,
            "parallel_execution": false,
            "auto_retry": false,  // Disabled for interactive mode
            "save_intermediate_results": true,
            "pause_on_error": true,
            "require_confirmation": true
        },
        "interaction_config": {
            "intervention_points": [
                "planning_complete",
                "before_execution",
                "on_error",
                "on_stall",
                "before_sensitive_operation"
            ],
            "timeout_for_response_seconds": 60,
            "default_action_on_timeout": "pause",
            "escalation_enabled": true
        }
    });
    
    Ok(params)
}

/// Interactive workflow monitor with user intervention capabilities
struct InteractiveMonitor {
    workflow_id: String,
    control_publisher: SmithBus,
    intervention_publisher: SmithBus,
    timeout_seconds: u64,
    step_count: usize,
    start_time: Instant,
    last_user_interaction: Instant,
    workflow_state: WorkflowState,
}

#[derive(Debug, Clone)]
enum WorkflowState {
    Initializing,
    Planning,
    AwaitingUserInput,
    Executing,
    Stalled,
    Paused,
    Completed,
    Failed,
}

impl WorkflowState {
    fn emoji(&self) -> &'static str {
        match self {
            WorkflowState::Initializing => "🔄",
            WorkflowState::Planning => "🧠",
            WorkflowState::AwaitingUserInput => "⏳",
            WorkflowState::Executing => "⚡",
            WorkflowState::Stalled => "🚨",
            WorkflowState::Paused => "⏸️",
            WorkflowState::Completed => "✅",
            WorkflowState::Failed => "❌",
        }
    }
}

impl InteractiveMonitor {
    fn new(
        workflow_id: String,
        control_publisher: SmithBus,
        intervention_publisher: SmithBus,
        timeout_seconds: u64,
    ) -> Self {
        Self {
            workflow_id,
            control_publisher,
            intervention_publisher,
            timeout_seconds,
            step_count: 0,
            start_time: Instant::now(),
            last_user_interaction: Instant::now(),
            workflow_state: WorkflowState::Initializing,
        }
    }
    
    async fn run(&mut self, result_subscriber: &mut futures::stream::BoxStream<'_, async_nats::Message>) -> Result<()> {
        println!("🎮 Starting interactive monitoring...");
        println!("💡 You will be prompted for input at key decision points");
        println!("⚠️  Watch for intervention requests!");
        println!();
        
        let timeout_duration = Duration::from_secs(self.timeout_seconds);
        
        loop {
            // Check global timeout
            if self.start_time.elapsed() > timeout_duration {
                println!("⏰ Workflow timeout reached");
                break;
            }
            
            // Wait for messages or user input
            tokio::select! {
                // Workflow result messages
                result = timeout(Duration::from_secs(2), result_subscriber.next()) => {
                    match result {
                        Ok(Some(msg)) => {
                            if let Ok(data) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                                self.handle_workflow_message(data).await?;
                            }
                        }
                        Ok(None) => {
                            println!("📡 Result stream ended");
                            break;
                        }
                        Err(_) => {
                            // Timeout - check for user intervention needs
                            self.check_intervention_needs().await?;
                        }
                    }
                }
                
                // Manual intervention trigger
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    self.periodic_status_check().await?;
                }
            }
        }
        
        Ok(())
    }
    
    async fn handle_workflow_message(&mut self, data: serde_json::Value) -> Result<()> {
        self.step_count += 1;
        
        // Update workflow state
        if let Some(state_str) = data.get("current_state").and_then(|v| v.as_str()) {
            self.workflow_state = match state_str {
                "Initializing" => WorkflowState::Initializing,
                "Planning" => WorkflowState::Planning,
                "AwaitingUserInput" => WorkflowState::AwaitingUserInput,
                "Executing" => WorkflowState::Executing,
                "Stalled" => WorkflowState::Stalled,
                "Paused" => WorkflowState::Paused,
                "Completed" => WorkflowState::Completed,
                "Failed" => WorkflowState::Failed,
                _ => WorkflowState::Executing,
            };
        }
        
        // Display status update
        println!("{} Step {}: State = {:?}", 
            self.workflow_state.emoji(), 
            self.step_count, 
            self.workflow_state
        );
        
        // Handle specific message types
        if let Some(message_type) = data.get("type").and_then(|v| v.as_str()) {
            match message_type {
                "intervention_request" => {
                    self.handle_intervention_request(&data).await?;
                }
                "planning_complete" => {
                    self.handle_planning_complete(&data).await?;
                }
                "stall_detected" => {
                    self.handle_stall_detected(&data).await?;
                }
                "error_occurred" => {
                    self.handle_error_occurred(&data).await?;
                }
                "confirmation_required" => {
                    self.handle_confirmation_required(&data).await?;
                }
                _ => {
                    // Regular status update
                    if let Some(message) = data.get("message").and_then(|v| v.as_str()) {
                        println!("   📝 {}", message);
                    }
                }
            }
        }
        
        // Check for completion
        if let Some(status) = data.get("status").and_then(|v| v.as_str()) {
            match status {
                "completed" => {
                    println!("🎉 Workflow completed successfully!");
                    self.display_completion_summary(&data);
                    return Ok(());
                }
                "failed" => {
                    println!("❌ Workflow failed!");
                    if let Some(error) = data.get("error").and_then(|v| v.as_str()) {
                        println!("   Error: {}", error);
                    }
                    self.offer_recovery_options().await?;
                    return Ok(());
                }
                _ => {}
            }
        }
        
        Ok(())
    }
    
    async fn handle_intervention_request(&mut self, data: &serde_json::Value) -> Result<()> {
        println!();
        println!("🚨 USER INTERVENTION REQUESTED");
        println!("==============================");
        
        if let Some(reason) = data.get("reason").and_then(|v| v.as_str()) {
            println!("📋 Reason: {}", reason);
        }
        
        if let Some(context) = data.get("context").and_then(|v| v.as_str()) {
            println!("🔍 Context: {}", context);
        }
        
        if let Some(options) = data.get("options").and_then(|v| v.as_array()) {
            let option_strings: Vec<String> = options
                .iter()
                .filter_map(|opt| opt.as_str())
                .map(|s| s.to_string())
                .collect();
            
            if !option_strings.is_empty() {
                println!();
                let selection = Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Choose your action")
                    .items(&option_strings)
                    .interact()?;
                
                let chosen_action = &option_strings[selection];
                println!("✅ Selected: {}", chosen_action);
                
                // Send user decision back to workflow
                self.send_user_decision(chosen_action).await?;
            }
        } else {
            // Generic intervention - offer standard options
            self.offer_standard_intervention_options().await?;
        }
        
        self.last_user_interaction = Instant::now();
        println!();
        
        Ok(())
    }
    
    async fn handle_planning_complete(&mut self, data: &serde_json::Value) -> Result<()> {
        println!();
        println!("🧠 PLANNING PHASE COMPLETE");
        println!("=========================");
        
        if let Some(plan_summary) = data.get("plan_summary").and_then(|v| v.as_str()) {
            println!("📋 Plan Summary:");
            println!("{}", plan_summary);
        }
        
        if let Some(estimated_steps) = data.get("estimated_steps").and_then(|v| v.as_u64()) {
            println!("👣 Estimated Steps: {}", estimated_steps);
        }
        
        if let Some(estimated_duration) = data.get("estimated_duration_seconds").and_then(|v| v.as_u64()) {
            println!("⏱️  Estimated Duration: {}s", estimated_duration);
        }
        
        println!();
        let proceed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Proceed with execution?")
            .default(true)
            .interact()?;
        
        if proceed {
            println!("✅ Proceeding with execution...");
            self.send_control_command("proceed").await?;
        } else {
            println!("⏸️ Pausing workflow for review...");
            self.send_control_command("pause").await?;
            self.offer_pause_menu().await?;
        }
        
        self.last_user_interaction = Instant::now();
        
        Ok(())
    }
    
    async fn handle_stall_detected(&mut self, data: &serde_json::Value) -> Result<()> {
        println!();
        println!("🚨 WORKFLOW STALL DETECTED");
        println!("==========================");
        
        if let Some(stall_reason) = data.get("stall_reason").and_then(|v| v.as_str()) {
            println!("🔍 Reason: {}", stall_reason);
        }
        
        if let Some(last_activity) = data.get("seconds_since_activity").and_then(|v| v.as_u64()) {
            println!("⏱️  Time since last activity: {}s", last_activity);
        }
        
        println!();
        println!("Recovery options:");
        let recovery_options = vec![
            "🔄 Retry current step",
            "⏭️ Skip current step",
            "🛠️ Manual intervention",
            "⏸️ Pause for debugging",
            "🛑 Emergency stop",
        ];
        
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("How would you like to handle this stall?")
            .items(&recovery_options)
            .interact()?;
        
        match selection {
            0 => {
                println!("🔄 Retrying current step...");
                self.send_control_command("retry").await?;
            }
            1 => {
                let confirm = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("⚠️ Are you sure you want to skip this step?")
                    .default(false)
                    .interact()?;
                
                if confirm {
                    println!("⏭️ Skipping current step...");
                    self.send_control_command("skip").await?;
                }
            }
            2 => {
                println!("🛠️ Entering manual intervention mode...");
                self.manual_intervention_mode().await?;
            }
            3 => {
                println!("⏸️ Pausing for debugging...");
                self.send_control_command("pause").await?;
                self.offer_pause_menu().await?;
            }
            4 => {
                let confirm = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("⚠️ Are you sure you want to emergency stop?")
                    .default(false)
                    .interact()?;
                
                if confirm {
                    println!("🛑 Emergency stop initiated...");
                    self.send_control_command("emergency_stop").await?;
                    return Ok(());
                }
            }
            _ => {}
        }
        
        self.last_user_interaction = Instant::now();
        
        Ok(())
    }
    
    async fn handle_error_occurred(&mut self, data: &serde_json::Value) -> Result<()> {
        println!();
        println!("❌ ERROR OCCURRED");
        println!("=================");
        
        if let Some(error_type) = data.get("error_type").and_then(|v| v.as_str()) {
            println!("🏷️  Type: {}", error_type);
        }
        
        if let Some(error_message) = data.get("error_message").and_then(|v| v.as_str()) {
            println!("📝 Message: {}", error_message);
        }
        
        if let Some(recoverable) = data.get("recoverable").and_then(|v| v.as_bool()) {
            if recoverable {
                println!("✅ Error is recoverable");
                self.offer_error_recovery_options().await?;
            } else {
                println!("❌ Error is not recoverable");
                self.offer_termination_options().await?;
            }
        }
        
        self.last_user_interaction = Instant::now();
        
        Ok(())
    }
    
    async fn handle_confirmation_required(&mut self, data: &serde_json::Value) -> Result<()> {
        println!();
        println!("❓ CONFIRMATION REQUIRED");
        println!("=======================");
        
        if let Some(action) = data.get("action").and_then(|v| v.as_str()) {
            println!("🎯 Action: {}", action);
        }
        
        if let Some(impact) = data.get("impact").and_then(|v| v.as_str()) {
            println!("⚠️ Impact: {}", impact);
        }
        
        println!();
        let confirm = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Do you want to proceed with this action?")
            .default(false)
            .interact()?;
        
        if confirm {
            println!("✅ Action approved");
            self.send_user_decision("approve").await?;
        } else {
            println!("❌ Action rejected");
            self.send_user_decision("reject").await?;
        }
        
        self.last_user_interaction = Instant::now();
        
        Ok(())
    }
    
    async fn check_intervention_needs(&mut self) -> Result<()> {
        // Check if user intervention is overdue
        let time_since_interaction = self.last_user_interaction.elapsed();
        
        if time_since_interaction > Duration::from_secs(30) && 
           matches!(self.workflow_state, WorkflowState::AwaitingUserInput) {
            println!();
            println!("⏰ Workflow has been waiting for user input for {}s", time_since_interaction.as_secs());
            
            let options = vec![
                "Continue waiting",
                "Provide default response",
                "Pause workflow",
                "Abort workflow",
            ];
            
            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("What would you like to do?")
                .items(&options)
                .interact()?;
            
            match selection {
                0 => {
                    println!("⏳ Continuing to wait...");
                    self.last_user_interaction = Instant::now();
                }
                1 => {
                    println!("📝 Providing default response...");
                    self.send_user_decision("default").await?;
                }
                2 => {
                    println!("⏸️ Pausing workflow...");
                    self.send_control_command("pause").await?;
                }
                3 => {
                    println!("🛑 Aborting workflow...");
                    self.send_control_command("abort").await?;
                }
                _ => {}
            }
        }
        
        Ok(())
    }
    
    async fn periodic_status_check(&mut self) -> Result<()> {
        let elapsed = self.start_time.elapsed().as_secs();
        
        if elapsed % 30 == 0 && elapsed > 0 {
            println!("📊 Status: {} steps completed in {}s (State: {:?})", 
                self.step_count, elapsed, self.workflow_state);
        }
        
        Ok(())
    }
    
    async fn offer_standard_intervention_options(&mut self) -> Result<()> {
        let options = vec![
            "Continue execution",
            "Pause workflow",
            "Request more information",
            "Change workflow parameters",
            "Abort workflow",
        ];
        
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your intervention")
            .items(&options)
            .interact()?;
        
        match selection {
            0 => self.send_user_decision("continue").await?,
            1 => self.send_control_command("pause").await?,
            2 => self.send_user_decision("request_info").await?,
            3 => self.change_workflow_parameters().await?,
            4 => self.send_control_command("abort").await?,
            _ => {}
        }
        
        Ok(())
    }
    
    async fn offer_pause_menu(&mut self) -> Result<()> {
        loop {
            println!();
            println!("⏸️ WORKFLOW PAUSED - Control Menu");
            println!("=================================");
            
            let options = vec![
                "▶️ Resume execution",
                "🔍 Show workflow status",
                "⚙️ Change parameters",
                "🛠️ Manual intervention",
                "🛑 Terminate workflow",
            ];
            
            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("What would you like to do?")
                .items(&options)
                .interact()?;
            
            match selection {
                0 => {
                    println!("▶️ Resuming execution...");
                    self.send_control_command("resume").await?;
                    break;
                }
                1 => {
                    self.show_workflow_status().await?;
                }
                2 => {
                    self.change_workflow_parameters().await?;
                }
                3 => {
                    self.manual_intervention_mode().await?;
                }
                4 => {
                    let confirm = Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt("Are you sure you want to terminate the workflow?")
                        .default(false)
                        .interact()?;
                    
                    if confirm {
                        self.send_control_command("terminate").await?;
                        break;
                    }
                }
                _ => {}
            }
        }
        
        Ok(())
    }
    
    async fn manual_intervention_mode(&mut self) -> Result<()> {
        println!();
        println!("🛠️ MANUAL INTERVENTION MODE");
        println!("===========================");
        
        loop {
            let command: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter command (or 'help' for options, 'exit' to return)")
                .interact_text()?;
            
            match command.trim() {
                "help" => {
                    println!("Available commands:");
                    println!("  status    - Show current workflow status");
                    println!("  retry     - Retry current step");
                    println!("  skip      - Skip current step");
                    println!("  reset     - Reset to previous state");
                    println!("  debug     - Show debug information");
                    println!("  exit      - Exit manual mode");
                }
                "status" => {
                    self.show_workflow_status().await?;
                }
                "retry" => {
                    self.send_control_command("retry").await?;
                    println!("✅ Retry command sent");
                }
                "skip" => {
                    self.send_control_command("skip").await?;
                    println!("✅ Skip command sent");
                }
                "reset" => {
                    self.send_control_command("reset").await?;
                    println!("✅ Reset command sent");
                }
                "debug" => {
                    self.show_debug_info().await?;
                }
                "exit" => {
                    break;
                }
                _ => {
                    println!("❓ Unknown command: {}. Type 'help' for options.", command);
                }
            }
        }
        
        Ok(())
    }
    
    async fn show_workflow_status(&self) -> Result<()> {
        println!();
        println!("📊 WORKFLOW STATUS");
        println!("==================");
        println!("🆔 ID: {}", self.workflow_id);
        println!("🎯 State: {:?}", self.workflow_state);
        println!("👣 Steps: {}", self.step_count);
        println!("⏱️ Runtime: {:.1}s", self.start_time.elapsed().as_secs_f64());
        println!("🕒 Last interaction: {:.1}s ago", self.last_user_interaction.elapsed().as_secs_f64());
        
        Ok(())
    }
    
    async fn show_debug_info(&self) -> Result<()> {
        println!();
        println!("🐛 DEBUG INFORMATION");
        println!("===================");
        println!("Workflow ID: {}", self.workflow_id);
        println!("Current State: {:?}", self.workflow_state);
        println!("Step Count: {}", self.step_count);
        println!("Start Time: {:?}", self.start_time);
        println!("Last User Interaction: {:?}", self.last_user_interaction);
        println!("Timeout: {}s", self.timeout_seconds);
        
        Ok(())
    }
    
    async fn change_workflow_parameters(&mut self) -> Result<()> {
        println!();
        println!("⚙️ CHANGE WORKFLOW PARAMETERS");
        println!("=============================");
        
        let param_options = vec![
            "Increase timeout",
            "Change verbosity level",
            "Enable/disable auto-retry",
            "Modify resource limits",
            "Cancel",
        ];
        
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Which parameter would you like to change?")
            .items(&param_options)
            .interact()?;
        
        match selection {
            0 => {
                let new_timeout: u64 = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter new timeout in seconds")
                    .default(self.timeout_seconds)
                    .interact()?;
                
                self.timeout_seconds = new_timeout;
                println!("✅ Timeout updated to {}s", new_timeout);
            }
            1 => {
                let verbosity_options = vec!["debug", "info", "warn", "error"];
                let selection = Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Select verbosity level")
                    .items(&verbosity_options)
                    .interact()?;
                
                self.send_parameter_change("verbosity", verbosity_options[selection]).await?;
            }
            2 => {
                let enable_retry = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enable auto-retry?")
                    .interact()?;
                
                self.send_parameter_change("auto_retry", &enable_retry.to_string()).await?;
            }
            3 => {
                println!("Resource limits modification not implemented in demo");
            }
            4 => {
                println!("Parameter change cancelled");
            }
            _ => {}
        }
        
        Ok(())
    }
    
    async fn offer_error_recovery_options(&mut self) -> Result<()> {
        let recovery_options = vec![
            "🔄 Retry with same parameters",
            "⚙️ Retry with modified parameters",
            "⏭️ Skip and continue",
            "🛠️ Manual intervention",
            "⏸️ Pause for investigation",
            "🛑 Abort workflow",
        ];
        
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("How would you like to recover from this error?")
            .items(&recovery_options)
            .interact()?;
        
        match selection {
            0 => self.send_control_command("retry").await?,
            1 => {
                self.change_workflow_parameters().await?;
                self.send_control_command("retry").await?;
            }
            2 => self.send_control_command("skip").await?,
            3 => self.manual_intervention_mode().await?,
            4 => self.send_control_command("pause").await?,
            5 => self.send_control_command("abort").await?,
            _ => {}
        }
        
        Ok(())
    }
    
    async fn offer_termination_options(&mut self) -> Result<()> {
        let options = vec![
            "🛑 Terminate immediately",
            "💾 Save state and terminate",
            "📋 Generate error report",
            "🔄 Attempt recovery anyway",
        ];
        
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Error is not recoverable. What would you like to do?")
            .items(&options)
            .interact()?;
        
        match selection {
            0 => self.send_control_command("terminate").await?,
            1 => self.send_control_command("save_and_terminate").await?,
            2 => self.send_control_command("generate_error_report").await?,
            3 => self.send_control_command("force_recovery").await?,
            _ => {}
        }
        
        Ok(())
    }
    
    async fn send_control_command(&self, command: &str) -> Result<()> {
        let control_message = json!({
            "workflow_id": self.workflow_id,
            "command": command,
            "timestamp": chrono::Utc::now(),
            "source": "user_intervention_demo"
        });
        
        let subject = format!("smith.control.planner_exec.{}", self.workflow_id);
        self.control_publisher.publish(subject, &control_message).await?;
        
        Ok(())
    }
    
    async fn send_user_decision(&self, decision: &str) -> Result<()> {
        let decision_message = json!({
            "workflow_id": self.workflow_id,
            "decision": decision,
            "timestamp": chrono::Utc::now(),
            "source": "user_intervention_demo"
        });
        
        let subject = format!("smith.intervention.planner_exec.{}", self.workflow_id);
        self.intervention_publisher.publish(subject, &decision_message).await?;
        
        Ok(())
    }
    
    async fn send_parameter_change(&self, parameter: &str, value: &str) -> Result<()> {
        let change_message = json!({
            "workflow_id": self.workflow_id,
            "parameter": parameter,
            "value": value,
            "timestamp": chrono::Utc::now(),
            "source": "user_intervention_demo"
        });
        
        let subject = format!("smith.config.planner_exec.{}", self.workflow_id);
        self.control_publisher.publish(subject, &change_message).await?;
        
        println!("✅ Parameter change sent: {} = {}", parameter, value);
        
        Ok(())
    }
    
    fn display_completion_summary(&self, data: &serde_json::Value) {
        println!();
        println!("🏁 WORKFLOW COMPLETION SUMMARY");
        println!("==============================");
        println!("⏱️ Total Duration: {:.1}s", self.start_time.elapsed().as_secs_f64());
        println!("👣 Total Steps: {}", self.step_count);
        
        if let Some(summary) = data.get("execution_summary") {
            println!("📋 Summary:");
            println!("{}", serde_json::to_string_pretty(summary).unwrap_or_default());
        }
        
        println!("🎮 User Interventions: Interactive mode enabled");
        println!("✅ Demo completed successfully!");
    }
}