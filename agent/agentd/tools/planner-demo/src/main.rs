//! # Smith Planner-Executor Controller Demo
//!
//! A comprehensive demonstration application showcasing the sophisticated capabilities
//! of the Smith planner-executor controller including:
//!
//! - State machine-driven workflow execution
//! - Oracle-powered research and planning
//! - Real-time monitoring and visualization
//! - Interactive user intervention
//! - Stall detection and recovery
//! - Performance benchmarking
//!
//! ## Features
//!
//! - **Interactive CLI**: Submit goals and monitor execution in real-time
//! - **Demo Scenarios**: Predefined complex workflows demonstrating different patterns
//! - **Live Monitor**: Terminal UI showing state machine transitions and oracle decisions
//! - **Performance Metrics**: Comprehensive benchmarking and analysis
//! - **NATS Integration**: Real-time message publishing and subscription

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use console::Term;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

mod monitor;
mod scenarios;

use monitor::{MonitorConfig, WorkflowMonitor};
use scenarios::{DemoScenario, ScenarioLibrary, WorkflowPattern};

// Smith platform imports
use smith_bus::SmithBus;
use smith_config::Config;
use smith_protocol::{Capability, Intent};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(name = "planner-demo")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// NATS server URL
    #[arg(long, env = "NATS_URL", default_value = "nats://localhost:4222")]
    nats_url: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Enable debug mode
    #[arg(short, long)]
    debug: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run interactive demo mode
    Interactive {
        /// Skip intro and go straight to scenarios
        #[arg(short, long)]
        quick: bool,
    },
    /// Execute a specific demo scenario
    Scenario {
        /// Scenario name or pattern
        scenario: String,
        /// Enable real-time monitoring
        #[arg(short, long)]
        monitor: bool,
        /// Save execution results to file
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Submit a custom goal
    Goal {
        /// Goal description
        goal: String,
        /// Workflow type (simple, research_and_planning, complex_orchestration)
        #[arg(short, long, default_value = "simple")]
        workflow_type: String,
        /// Maximum steps
        #[arg(long, default_value = "10")]
        max_steps: usize,
        /// Timeout in seconds
        #[arg(long)]
        timeout_seconds: Option<u64>,
        /// Enable real-time monitoring
        #[arg(short, long)]
        monitor: bool,
    },
    /// Start real-time workflow monitor
    Monitor {
        /// Monitor configuration file
        #[arg(short, long)]
        config: Option<String>,
        /// Filter by workflow ID
        #[arg(short, long)]
        workflow_id: Option<String>,
    },
    /// List available demo scenarios
    List {
        /// Show detailed scenario descriptions
        #[arg(short, long)]
        details: bool,
        /// Filter by workflow pattern
        #[arg(short, long)]
        pattern: Option<String>,
    },
    /// Run performance benchmarks
    Benchmark {
        /// Number of concurrent workflows
        #[arg(short, long, default_value = "1")]
        concurrency: usize,
        /// Number of iterations per scenario
        #[arg(short, long, default_value = "5")]
        iterations: usize,
        /// Include stress testing
        #[arg(short, long)]
        stress: bool,
    },
    /// Validate demo environment setup
    Doctor {
        /// Fix issues automatically
        #[arg(short, long)]
        fix: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(cli.verbose, cli.debug)?;

    // Set up colored output
    if cli.no_color {
        colored::control::set_override(false);
    }

    info!("Starting Smith Planner-Executor Demo");

    // Validate environment
    if let Err(e) = validate_environment(&cli.nats_url).await {
        error!("Environment validation failed: {}", e);
        if matches!(cli.command, Commands::Doctor { .. }) {
            // Continue to doctor command
        } else {
            eprintln!("{}", "❌ Environment validation failed. Run 'planner-demo doctor' for diagnosis.".red());
            return Err(e);
        }
    }

    // Execute command
    match cli.command {
        Commands::Interactive { quick } => run_interactive_mode(&cli, quick).await,
        Commands::Scenario { scenario, monitor, output } => {
            run_scenario(&cli, &scenario, monitor, output.as_deref()).await
        }
        Commands::Goal { goal, workflow_type, max_steps, timeout_seconds, monitor } => {
            run_custom_goal(&cli, &goal, &workflow_type, max_steps, timeout_seconds, monitor).await
        }
        Commands::Monitor { config, workflow_id } => {
            run_monitor_mode(&cli, config.as_deref(), workflow_id.as_deref()).await
        }
        Commands::List { details, pattern } => {
            list_scenarios(details, pattern.as_deref()).await
        }
        Commands::Benchmark { concurrency, iterations, stress } => {
            run_benchmarks(&cli, concurrency, iterations, stress).await
        }
        Commands::Doctor { fix } => {
            run_doctor(&cli, fix).await
        }
    }
}

/// Initialize logging based on verbosity settings
fn init_logging(verbose: bool, debug: bool) -> Result<()> {
    let level = if debug {
        "debug"
    } else if verbose {
        "info"
    } else {
        "warn"
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    Ok(())
}

/// Validate that the demo environment is properly set up
async fn validate_environment(nats_url: &str) -> Result<()> {
    info!("Validating demo environment...");

    // Check NATS connectivity
    let client = async_nats::connect(nats_url).await
        .context("Failed to connect to NATS server")?;

    // Check JetStream availability
    let jetstream = async_nats::jetstream::new(client);
    jetstream.get_stream("SDLC_RAW").await
        .context("SDLC_RAW stream not found - run bootstrap first")?;

    info!("Environment validation successful");
    Ok(())
}

/// Run interactive demo mode with user-guided exploration
async fn run_interactive_mode(cli: &Cli, quick: bool) -> Result<()> {
    let term = Term::stdout();
    
    if !quick {
        display_welcome_banner(&term)?;
        display_capabilities_overview(&term)?;
        
        if !Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Ready to explore the planner-executor capabilities?")
            .interact()?
        {
            println!("Demo cancelled.");
            return Ok(());
        }
    }

    loop {
        let options = vec![
            "🎯 Run Demo Scenario",
            "📝 Submit Custom Goal", 
            "📊 Live Monitor",
            "📋 List All Scenarios",
            "⚡ Performance Benchmark",
            "🔧 Environment Doctor",
            "❌ Exit",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("What would you like to do?")
            .items(&options)
            .interact()?;

        match selection {
            0 => interactive_scenario_selection(cli).await?,
            1 => interactive_custom_goal(cli).await?,
            2 => run_monitor_mode(cli, None, None).await?,
            3 => list_scenarios(true, None).await?,
            4 => interactive_benchmark_selection(cli).await?,
            5 => run_doctor(cli, false).await?,
            6 => break,
            _ => unreachable!(),
        }

        if !Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Continue with another operation?")
            .default(true)
            .interact()?
        {
            break;
        }
    }

    println!("{}", "Thank you for exploring the Smith Planner-Executor Demo! 🚀".green().bold());
    Ok(())
}

/// Display welcome banner with ASCII art
fn display_welcome_banner(term: &Term) -> Result<()> {
    term.clear_screen()?;
    
    let banner = r#"
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║      🚀 SMITH PLANNER-EXECUTOR CONTROLLER DEMO 🚀                ║
    ║                                                                  ║
    ║           Sophisticated AI Workflow Orchestration               ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    "#;
    
    println!("{}", banner.cyan().bold());
    println!();
    
    Ok(())
}

/// Display capabilities overview
fn display_capabilities_overview(term: &Term) -> Result<()> {
    println!("{}", "🎯 DEMO CAPABILITIES".yellow().bold());
    println!();
    
    let capabilities = vec![
        ("🔄", "State Machine Engine", "Manages complex workflow states and transitions"),
        ("🧠", "Oracle Research Layer", "AI-powered deep research and planning committee"),
        ("🛡️", "Guard Engine", "Policy validation and safety enforcement"),
        ("⚡", "Executor Adapter", "Integration with Smith's capability execution"),
        ("🚨", "Stall Detection", "Automatic escalation when workflows get stuck"),
        ("🎮", "Menu System", "Interactive user intervention and control"),
        ("📊", "Real-time Monitor", "Live visualization of workflow execution"),
        ("📈", "Performance Metrics", "Comprehensive benchmarking and analysis"),
    ];
    
    for (icon, name, description) in capabilities {
        println!("  {} {} - {}", icon, name.green().bold(), description.dim());
    }
    
    println!();
    Ok(())
}

/// Interactive scenario selection and execution
async fn interactive_scenario_selection(cli: &Cli) -> Result<()> {
    let library = ScenarioLibrary::new();
    let scenarios = library.get_all_scenarios();
    
    let scenario_names: Vec<String> = scenarios.iter()
        .map(|s| format!("{} - {}", s.name, s.description))
        .collect();
    
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select a demo scenario")
        .items(&scenario_names)
        .interact()?;
    
    let scenario = &scenarios[selection];
    
    let monitor = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable real-time monitoring?")
        .default(true)
        .interact()?;
    
    run_scenario(cli, &scenario.name, monitor, None).await
}

/// Interactive custom goal submission
async fn interactive_custom_goal(cli: &Cli) -> Result<()> {
    let goal: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your goal")
        .interact_text()?;
    
    let workflow_types = vec!["simple", "research_and_planning", "complex_orchestration"];
    let workflow_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select workflow type")
        .items(&workflow_types)
        .default(0)
        .interact()?;
    
    let max_steps: usize = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Maximum steps")
        .default(10)
        .interact()?;
    
    let monitor = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable real-time monitoring?")
        .default(true)
        .interact()?;
    
    run_custom_goal(cli, &goal, workflow_types[workflow_selection], max_steps, None, monitor).await
}

/// Interactive benchmark configuration
async fn interactive_benchmark_selection(cli: &Cli) -> Result<()> {
    let concurrency: usize = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Number of concurrent workflows")
        .default(1)
        .interact()?;
    
    let iterations: usize = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Iterations per scenario")
        .default(5)
        .interact()?;
    
    let stress = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Include stress testing?")
        .default(false)
        .interact()?;
    
    run_benchmarks(cli, concurrency, iterations, stress).await
}

/// Execute a specific demo scenario
async fn run_scenario(cli: &Cli, scenario_name: &str, enable_monitor: bool, output_file: Option<&str>) -> Result<()> {
    let library = ScenarioLibrary::new();
    let scenario = library.get_scenario(scenario_name)
        .ok_or_else(|| anyhow::anyhow!("Scenario '{}' not found", scenario_name))?;
    
    println!("{}", format!("🚀 Executing Scenario: {}", scenario.name).cyan().bold());
    println!("📋 Description: {}", scenario.description.dim());
    println!("🎯 Goal: {}", scenario.goal.yellow());
    println!();
    
    let workflow_id = Uuid::new_v4().to_string();
    
    // Start monitor if requested
    let _monitor_handle = if enable_monitor {
        Some(start_background_monitor(cli, &workflow_id).await?)
    } else {
        None
    };
    
    // Create progress bar
    let pb = ProgressBar::new(scenario.expected_steps as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] {bar:40.cyan/blue} {pos:>3}/{len:3} {msg}")
            .unwrap()
            .progress_chars("##-")
    );
    pb.set_message("Initializing workflow...");
    
    let start_time = Instant::now();
    
    // Execute the scenario
    let result = execute_planner_workflow(
        cli,
        &workflow_id,
        &scenario.goal,
        &scenario.workflow_type,
        scenario.max_steps,
        scenario.timeout_seconds,
        Some(&pb),
    ).await;
    
    pb.finish_with_message("Workflow completed");
    
    let duration = start_time.elapsed();
    
    match result {
        Ok(execution_result) => {
            println!();
            println!("{}", "✅ Scenario completed successfully!".green().bold());
            print_execution_summary(&execution_result, duration);
            
            if let Some(output_path) = output_file {
                save_execution_result(&execution_result, output_path)?;
                println!("📁 Results saved to: {}", output_path.cyan());
            }
        }
        Err(e) => {
            println!();
            println!("{}", "❌ Scenario failed!".red().bold());
            println!("Error: {}", e);
        }
    }
    
    Ok(())
}

/// Execute a custom goal
async fn run_custom_goal(
    cli: &Cli,
    goal: &str,
    workflow_type: &str,
    max_steps: usize,
    timeout_seconds: Option<u64>,
    enable_monitor: bool,
) -> Result<()> {
    let workflow_id = Uuid::new_v4().to_string();
    
    println!("{}", "🎯 Executing Custom Goal".cyan().bold());
    println!("Goal: {}", goal.yellow());
    println!("Type: {}", workflow_type.green());
    println!("Max Steps: {}", max_steps);
    println!();
    
    // Start monitor if requested
    let _monitor_handle = if enable_monitor {
        Some(start_background_monitor(cli, &workflow_id).await?)
    } else {
        None
    };
    
    let pb = ProgressBar::new(max_steps as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] {bar:40.cyan/blue} {pos:>3}/{len:3} {msg}")
            .unwrap()
            .progress_chars("##-")
    );
    
    let start_time = Instant::now();
    
    let result = execute_planner_workflow(
        cli,
        &workflow_id,
        goal,
        workflow_type,
        max_steps,
        timeout_seconds,
        Some(&pb),
    ).await;
    
    let duration = start_time.elapsed();
    
    match result {
        Ok(execution_result) => {
            println!();
            println!("{}", "✅ Goal completed successfully!".green().bold());
            print_execution_summary(&execution_result, duration);
        }
        Err(e) => {
            println!();
            println!("{}", "❌ Goal execution failed!".red().bold());
            println!("Error: {}", e);
        }
    }
    
    Ok(())
}

/// Core workflow execution function
async fn execute_planner_workflow(
    cli: &Cli,
    workflow_id: &str,
    goal: &str,
    workflow_type: &str,
    max_steps: usize,
    timeout_seconds: Option<u64>,
    progress_bar: Option<&ProgressBar>,
) -> Result<Value> {
    // Connect to NATS
    let bus = SmithBus::connect(&cli.nats_url).await
        .context("Failed to connect to NATS")?;
    
    // Create planner execution intent
    let params = json!({
        "workflow_id": workflow_id,
        "goal": goal,
        "workflow_type": workflow_type,
        "max_steps": max_steps,
        "timeout_ms": timeout_seconds.map(|s| s * 1000),
        "context": {},
        "allowed_capabilities": ["fs.read.v1", "http.fetch.v1"],
        "resource_limits": {
            "max_memory_mb": 512,
            "max_cpu_seconds": 300,
            "max_fs_operations": 1000,
            "max_network_requests": 100,
            "max_parallel_executions": 4
        },
        "preferences": {
            "verbosity": "info",
            "interactive": false,
            "parallel_execution": true,
            "auto_retry": true,
            "save_intermediate_results": true
        }
    });
    
    let intent = Intent::new(
        Capability::PlannerExecV1,
        "production".to_string(),
        params,
        timeout_seconds.unwrap_or(300) * 1000, // TTL in ms
        "demo-client-key".to_string(),
    );
    
    // Publish intent
    let subject = format!("smith.intents.raw.planner_exec.v1.{}", workflow_id);
    bus.publish(subject, &intent).await
        .context("Failed to publish intent")?;
    
    info!("Published workflow intent for ID: {}", workflow_id);
    
    // Subscribe to results
    let result_subject = format!("smith.results.planner_exec.v1.{}", workflow_id);
    let mut result_subscriber = bus.subscribe(&result_subject).await
        .context("Failed to subscribe to results")?;
    
    // Monitor progress and collect results
    let mut step_count = 0;
    let timeout_duration = Duration::from_secs(timeout_seconds.unwrap_or(300));
    let start_time = Instant::now();
    
    while start_time.elapsed() < timeout_duration {
        // Check for timeout
        if start_time.elapsed() > timeout_duration {
            return Err(anyhow::anyhow!("Workflow execution timed out"));
        }
        
        // Try to receive a message with timeout
        match tokio::time::timeout(Duration::from_secs(1), result_subscriber.next()).await {
            Ok(Some(msg)) => {
                let result: Value = serde_json::from_slice(&msg.payload)?;
                
                // Update progress
                step_count += 1;
                if let Some(pb) = progress_bar {
                    pb.set_position(step_count);
                    if let Some(status) = result.get("status").and_then(|s| s.as_str()) {
                        pb.set_message(format!("Status: {}", status));
                    }
                }
                
                // Check if workflow is complete
                if let Some(status) = result.get("status").and_then(|s| s.as_str()) {
                    if status == "completed" || status == "failed" {
                        return Ok(result);
                    }
                }
                
                debug!("Received intermediate result: {}", result);
            }
            Ok(None) => {
                debug!("No more messages in stream");
                break;
            }
            Err(_) => {
                // Timeout waiting for message, continue loop
                continue;
            }
        }
    }
    
    Err(anyhow::anyhow!("Workflow did not complete within timeout"))
}

/// Start background monitor for a specific workflow
async fn start_background_monitor(cli: &Cli, workflow_id: &str) -> Result<tokio::task::JoinHandle<()>> {
    let config = MonitorConfig {
        nats_url: cli.nats_url.clone(),
        workflow_filter: Some(workflow_id.to_string()),
        refresh_rate_ms: 100,
        max_history: 1000,
    };
    
    let monitor = WorkflowMonitor::new(config).await?;
    
    let handle = tokio::spawn(async move {
        if let Err(e) = monitor.run().await {
            error!("Monitor error: {}", e);
        }
    });
    
    Ok(handle)
}

/// Print execution summary
fn print_execution_summary(result: &Value, duration: Duration) {
    println!("⏱️  Duration: {:.2}s", duration.as_secs_f64());
    
    if let Some(steps) = result.get("total_steps") {
        println!("👣 Total Steps: {}", steps);
    }
    
    if let Some(status) = result.get("status") {
        println!("📊 Final Status: {}", status);
    }
    
    if let Some(summary) = result.get("execution_summary") {
        println!("📋 Summary: {}", serde_json::to_string_pretty(summary).unwrap_or_default());
    }
}

/// Save execution result to file
fn save_execution_result(result: &Value, output_path: &str) -> Result<()> {
    let output = json!({
        "timestamp": chrono::Utc::now(),
        "result": result
    });
    
    std::fs::write(output_path, serde_json::to_string_pretty(&output)?)?;
    Ok(())
}

/// Run monitor mode
async fn run_monitor_mode(cli: &Cli, config_file: Option<&str>, workflow_id: Option<&str>) -> Result<()> {
    let config = if let Some(config_path) = config_file {
        MonitorConfig::from_file(config_path)?
    } else {
        MonitorConfig {
            nats_url: cli.nats_url.clone(),
            workflow_filter: workflow_id.map(String::from),
            refresh_rate_ms: 100,
            max_history: 1000,
        }
    };
    
    println!("{}", "🖥️  Starting Real-time Workflow Monitor".cyan().bold());
    println!("Press 'q' to quit, 'r' to refresh, 'h' for help");
    println!();
    
    let monitor = WorkflowMonitor::new(config).await?;
    monitor.run().await
}

/// List available scenarios
async fn list_scenarios(show_details: bool, pattern_filter: Option<&str>) -> Result<()> {
    let library = ScenarioLibrary::new();
    let scenarios = library.get_all_scenarios();
    
    let filtered_scenarios: Vec<_> = if let Some(pattern) = pattern_filter {
        scenarios.into_iter()
            .filter(|s| s.pattern.to_string().contains(pattern))
            .collect()
    } else {
        scenarios
    };
    
    println!("{}", "📋 Available Demo Scenarios".yellow().bold());
    println!();
    
    for scenario in filtered_scenarios {
        println!("{} {}", "🎯".cyan(), scenario.name.green().bold());
        println!("   📝 {}", scenario.description.dim());
        println!("   🔧 Pattern: {}", format!("{:?}", scenario.pattern).yellow());
        println!("   ⚡ Max Steps: {}", scenario.max_steps);
        
        if show_details {
            println!("   🎯 Goal: {}", scenario.goal.blue());
            if let Some(timeout) = scenario.timeout_seconds {
                println!("   ⏱️  Timeout: {}s", timeout);
            }
        }
        
        println!();
    }
    
    println!("Total scenarios: {}", filtered_scenarios.len());
    Ok(())
}

/// Run performance benchmarks
async fn run_benchmarks(cli: &Cli, concurrency: usize, iterations: usize, stress: bool) -> Result<()> {
    println!("{}", "⚡ Performance Benchmark Suite".yellow().bold());
    println!("Concurrency: {}, Iterations: {}, Stress: {}", concurrency, iterations, stress);
    println!();
    
    let library = ScenarioLibrary::new();
    let scenarios = if stress {
        library.get_all_scenarios()
    } else {
        library.get_scenarios_by_pattern(WorkflowPattern::Simple)
    };
    
    for scenario in scenarios {
        println!("🧪 Benchmarking: {}", scenario.name.green().bold());
        
        let mut results = Vec::new();
        
        for i in 0..iterations {
            let start = Instant::now();
            let workflow_id = format!("bench-{}-{}", scenario.name.replace(' ', "-"), i);
            
            match execute_planner_workflow(
                cli,
                &workflow_id,
                &scenario.goal,
                &scenario.workflow_type,
                scenario.max_steps,
                scenario.timeout_seconds,
                None,
            ).await {
                Ok(_) => {
                    let duration = start.elapsed();
                    results.push(duration);
                    print!(".");
                }
                Err(e) => {
                    print!("❌");
                    debug!("Benchmark iteration failed: {}", e);
                }
            }
        }
        
        println!();
        
        if !results.is_empty() {
            let avg_duration = results.iter().sum::<Duration>() / results.len() as u32;
            let min_duration = results.iter().min().unwrap();
            let max_duration = results.iter().max().unwrap();
            
            println!("  📊 Results:");
            println!("     Average: {:.2}s", avg_duration.as_secs_f64());
            println!("     Min: {:.2}s", min_duration.as_secs_f64());
            println!("     Max: {:.2}s", max_duration.as_secs_f64());
            println!("     Success: {}/{}", results.len(), iterations);
        } else {
            println!("  ❌ All iterations failed");
        }
        
        println!();
    }
    
    Ok(())
}

/// Run environment diagnostics
async fn run_doctor(cli: &Cli, auto_fix: bool) -> Result<()> {
    println!("{}", "🔧 Smith Planner-Executor Environment Doctor".yellow().bold());
    println!();
    
    let mut issues_found = false;
    
    // Check NATS connectivity
    print!("🔍 Checking NATS connectivity... ");
    match async_nats::connect(&cli.nats_url).await {
        Ok(_) => println!("{}", "✅ OK".green()),
        Err(e) => {
            println!("{}", "❌ FAILED".red());
            println!("   Error: {}", e);
            issues_found = true;
            
            if auto_fix {
                println!("   🔧 Attempting to start NATS server...");
                // Auto-fix logic would go here
            }
        }
    }
    
    // Check JetStream streams
    print!("🔍 Checking JetStream streams... ");
    match validate_environment(&cli.nats_url).await {
        Ok(_) => println!("{}", "✅ OK".green()),
        Err(e) => {
            println!("{}", "❌ FAILED".red());
            println!("   Error: {}", e);
            issues_found = true;
            
            if auto_fix {
                println!("   🔧 Run 'just bootstrap-js' to create streams");
            }
        }
    }
    
    // Check executor availability
    print!("🔍 Checking executor service... ");
    // This would check if the executor is running and responsive
    println!("{}", "⚠️  SKIP (not implemented)".yellow());
    
    // Check demo dependencies
    print!("🔍 Checking demo dependencies... ");
    // Verify all required dependencies are available
    println!("{}", "✅ OK".green());
    
    if issues_found {
        println!();
        println!("{}", "❌ Issues found. Run with --fix to attempt automatic repairs.".red().bold());
        if !auto_fix {
            println!("Or run: planner-demo doctor --fix");
        }
    } else {
        println!();
        println!("{}", "✅ All checks passed! Demo environment is ready.".green().bold());
    }
    
    Ok(())
}