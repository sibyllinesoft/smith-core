//! # Performance Benchmark Example
//!
//! This example demonstrates comprehensive performance testing and benchmarking
//! of the planner-executor controller under various load conditions and
//! workflow patterns.
//!
//! ## What This Example Shows
//!
//! - Concurrent workflow execution benchmarking
//! - Performance metrics collection and analysis
//! - Stress testing with high load scenarios
//! - Resource utilization monitoring
//! - Throughput and latency measurements
//! - Comparative analysis across workflow types
//!
//! ## Usage
//!
//! ```bash
//! # Basic benchmark
//! cargo run --example performance_benchmark
//! 
//! # High concurrency stress test
//! cargo run --example performance_benchmark -- --concurrency 50 --iterations 100
//! 
//! # Memory stress test
//! cargo run --example performance_benchmark -- --stress-memory
//! ```

use anyhow::Result;
use chrono::{DateTime, Utc};
use futures::future::join_all;
use planner_demo::{
    scenarios::{ScenarioLibrary, WorkflowPattern},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// Import demo modules
use smith_bus::SmithBus;
use smith_protocol::{Capability, Intent};

/// Benchmark configuration
#[derive(Debug, Clone)]
struct BenchmarkConfig {
    concurrency: usize,
    iterations_per_scenario: usize,
    stress_testing: bool,
    memory_stress: bool,
    cpu_stress: bool,
    timeout_seconds: u64,
    collect_detailed_metrics: bool,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            concurrency: 5,
            iterations_per_scenario: 10,
            stress_testing: false,
            memory_stress: false,
            cpu_stress: false,
            timeout_seconds: 300,
            collect_detailed_metrics: true,
        }
    }
}

/// Individual benchmark result
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkResult {
    workflow_id: String,
    scenario_name: String,
    workflow_type: String,
    success: bool,
    duration_ms: u64,
    steps_completed: u32,
    memory_peak_mb: f64,
    cpu_avg_percent: f64,
    network_requests: u32,
    file_operations: u32,
    error_message: Option<String>,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
}

/// Aggregated benchmark statistics
#[derive(Debug, Serialize, Deserialize)]
struct BenchmarkStatistics {
    total_executions: usize,
    successful_executions: usize,
    failed_executions: usize,
    success_rate: f64,
    
    // Timing statistics
    total_duration_ms: u64,
    avg_duration_ms: f64,
    min_duration_ms: u64,
    max_duration_ms: u64,
    p50_duration_ms: f64,
    p95_duration_ms: f64,
    p99_duration_ms: f64,
    
    // Throughput
    workflows_per_second: f64,
    steps_per_second: f64,
    
    // Resource utilization
    avg_memory_mb: f64,
    peak_memory_mb: f64,
    avg_cpu_percent: f64,
    peak_cpu_percent: f64,
    
    // Operation counts
    total_network_requests: u32,
    total_file_operations: u32,
    
    // By workflow type
    stats_by_type: HashMap<String, WorkflowTypeStats>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkflowTypeStats {
    count: usize,
    success_rate: f64,
    avg_duration_ms: f64,
    avg_steps: f64,
    avg_memory_mb: f64,
    avg_cpu_percent: f64,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    
    // Parse command line arguments (simplified)
    let args: Vec<String> = std::env::args().collect();
    let mut config = BenchmarkConfig::default();
    
    // Simple argument parsing
    for i in 1..args.len() {
        match args[i].as_str() {
            "--concurrency" if i + 1 < args.len() => {
                config.concurrency = args[i + 1].parse().unwrap_or(config.concurrency);
            }
            "--iterations" if i + 1 < args.len() => {
                config.iterations_per_scenario = args[i + 1].parse().unwrap_or(config.iterations_per_scenario);
            }
            "--stress" => {
                config.stress_testing = true;
            }
            "--stress-memory" => {
                config.memory_stress = true;
                config.stress_testing = true;
            }
            "--stress-cpu" => {
                config.cpu_stress = true;
                config.stress_testing = true;
            }
            "--timeout" if i + 1 < args.len() => {
                config.timeout_seconds = args[i + 1].parse().unwrap_or(config.timeout_seconds);
            }
            _ => {}
        }
    }
    
    println!("⚡ SMITH PLANNER-EXECUTOR PERFORMANCE BENCHMARK");
    println!("===============================================");
    println!();
    println!("📊 Configuration:");
    println!("   Concurrency: {}", config.concurrency);
    println!("   Iterations per scenario: {}", config.iterations_per_scenario);
    println!("   Stress testing: {}", if config.stress_testing { "✅" } else { "❌" });
    println!("   Timeout: {}s", config.timeout_seconds);
    println!();
    
    // Connect to NATS
    let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
    let bus = SmithBus::connect(&nats_url).await?;
    info!("✅ Connected to NATS at {}", nats_url);
    
    // Initialize benchmark runner
    let runner = BenchmarkRunner::new(bus, config.clone()).await?;
    
    // Run benchmarks
    let start_time = Instant::now();
    let results = runner.run_comprehensive_benchmark().await?;
    let total_duration = start_time.elapsed();
    
    // Generate and display statistics
    let stats = generate_statistics(&results, total_duration);
    display_results(&stats, &config);
    
    // Save detailed results if requested
    if config.collect_detailed_metrics {
        save_benchmark_results(&results, &stats, &config).await?;
    }
    
    println!();
    println!("🏁 Benchmark completed in {:.2}s", total_duration.as_secs_f64());
    
    Ok(())
}

/// Main benchmark runner
struct BenchmarkRunner {
    bus: SmithBus,
    config: BenchmarkConfig,
    scenario_library: ScenarioLibrary,
    concurrency_limiter: Arc<Semaphore>,
    results_counter: Arc<AtomicUsize>,
}

impl BenchmarkRunner {
    async fn new(bus: SmithBus, config: BenchmarkConfig) -> Result<Self> {
        let semaphore = Arc::new(Semaphore::new(config.concurrency));
        let counter = Arc::new(AtomicUsize::new(0));
        
        Ok(Self {
            bus,
            config,
            scenario_library: ScenarioLibrary::new(),
            concurrency_limiter: semaphore,
            results_counter: counter,
        })
    }
    
    async fn run_comprehensive_benchmark(&self) -> Result<Vec<BenchmarkResult>> {
        info!("🚀 Starting comprehensive benchmark suite");
        
        let mut all_results = Vec::new();
        
        // Select scenarios based on configuration
        let scenarios = if self.config.stress_testing {
            // Include stress scenarios
            let mut scenarios = self.scenario_library.get_scenarios_by_pattern(WorkflowPattern::Simple);
            scenarios.extend(self.scenario_library.get_scenarios_by_pattern(WorkflowPattern::Research));
            scenarios.extend(self.scenario_library.get_scenarios_by_pattern(WorkflowPattern::Complex));
            scenarios.extend(self.scenario_library.get_scenarios_by_pattern(WorkflowPattern::Stress));
            scenarios
        } else {
            // Standard benchmark scenarios
            let mut scenarios = self.scenario_library.get_scenarios_by_pattern(WorkflowPattern::Simple);
            scenarios.extend(self.scenario_library.get_scenarios_by_pattern(WorkflowPattern::Research));
            scenarios
        };
        
        if scenarios.is_empty() {
            error!("No scenarios available for benchmarking");
            return Ok(all_results);
        }
        
        info!("📋 Running {} scenarios with {} iterations each", 
            scenarios.len(), self.config.iterations_per_scenario);
        
        // Execute benchmarks for each scenario
        for (scenario_idx, scenario) in scenarios.iter().enumerate() {
            info!("🎯 Benchmarking scenario {}/{}: {}", 
                scenario_idx + 1, scenarios.len(), scenario.name);
            
            let scenario_results = self.benchmark_scenario(scenario).await?;
            
            let success_count = scenario_results.iter().filter(|r| r.success).count();
            let avg_duration = if !scenario_results.is_empty() {
                scenario_results.iter().map(|r| r.duration_ms).sum::<u64>() as f64 / scenario_results.len() as f64
            } else {
                0.0
            };
            
            info!("   Results: {}/{} successful, avg duration: {:.1}ms", 
                success_count, scenario_results.len(), avg_duration);
            
            all_results.extend(scenario_results);
            
            // Brief pause between scenarios to avoid overwhelming the system
            if scenario_idx < scenarios.len() - 1 {
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        }
        
        info!("✅ Comprehensive benchmark completed");
        Ok(all_results)
    }
    
    async fn benchmark_scenario(&self, scenario: &planner_demo::scenarios::DemoScenario) -> Result<Vec<BenchmarkResult>> {
        let mut tasks = Vec::new();
        
        // Create concurrent benchmark tasks
        for iteration in 0..self.config.iterations_per_scenario {
            let bus = self.bus.clone();
            let scenario = scenario.clone();
            let config = self.config.clone();
            let semaphore = self.concurrency_limiter.clone();
            let counter = self.results_counter.clone();
            
            let task = tokio::spawn(async move {
                // Acquire semaphore permit for concurrency control
                let _permit = semaphore.acquire().await.unwrap();
                
                let workflow_id = format!("{}-{}-{}", 
                    scenario.name.replace(' ', "-"), 
                    iteration, 
                    Uuid::new_v4().to_string().chars().take(8).collect::<String>()
                );
                
                let result = execute_benchmark_workflow(&bus, &workflow_id, &scenario, &config).await;
                
                // Update counter
                let completed = counter.fetch_add(1, Ordering::Relaxed) + 1;
                if completed % 10 == 0 {
                    debug!("Completed {} benchmark executions", completed);
                }
                
                result
            });
            
            tasks.push(task);
        }
        
        // Wait for all tasks to complete
        let results = join_all(tasks).await;
        
        // Collect successful results
        let mut benchmark_results = Vec::new();
        for task_result in results {
            match task_result {
                Ok(Ok(result)) => benchmark_results.push(result),
                Ok(Err(e)) => warn!("Benchmark execution failed: {}", e),
                Err(e) => warn!("Benchmark task failed: {}", e),
            }
        }
        
        Ok(benchmark_results)
    }
}

/// Execute a single benchmark workflow
async fn execute_benchmark_workflow(
    bus: &SmithBus,
    workflow_id: &str,
    scenario: &planner_demo::scenarios::DemoScenario,
    config: &BenchmarkConfig,
) -> Result<BenchmarkResult> {
    let start_time = Instant::now();
    let started_at = Utc::now();
    
    // Create benchmark-specific intent parameters
    let params = create_benchmark_intent_params(workflow_id, scenario, config)?;
    
    // Create and publish intent
    let intent = Intent::new(
        Capability::PlannerExecV1,
        "benchmark".to_string(),
        params,
        config.timeout_seconds * 1000,
        "performance-benchmark".to_string(),
    );
    
    let subject = format!("smith.intents.raw.planner_exec.v1.{}", workflow_id);
    bus.publish(subject, &intent).await?;
    
    // Subscribe to results
    let result_subject = format!("smith.results.planner_exec.v1.{}", workflow_id);
    let mut result_subscriber = bus.subscribe(&result_subject).await?;
    
    // Monitor execution with performance tracking
    let mut performance_tracker = PerformanceTracker::new();
    let timeout_duration = Duration::from_secs(config.timeout_seconds);
    
    loop {
        match tokio::time::timeout(Duration::from_secs(1), result_subscriber.next()).await {
            Ok(Some(msg)) => {
                match serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                    Ok(result) => {
                        // Update performance metrics
                        performance_tracker.update(&result);
                        
                        // Check for completion
                        if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
                            let completed_at = Utc::now();
                            let duration = start_time.elapsed();
                            
                            return Ok(BenchmarkResult {
                                workflow_id: workflow_id.to_string(),
                                scenario_name: scenario.name.clone(),
                                workflow_type: scenario.workflow_type.clone(),
                                success: status == "completed",
                                duration_ms: duration.as_millis() as u64,
                                steps_completed: performance_tracker.steps_completed,
                                memory_peak_mb: performance_tracker.memory_peak_mb,
                                cpu_avg_percent: performance_tracker.cpu_avg_percent,
                                network_requests: performance_tracker.network_requests,
                                file_operations: performance_tracker.file_operations,
                                error_message: if status == "failed" {
                                    result.get("error").and_then(|v| v.as_str()).map(String::from)
                                } else {
                                    None
                                },
                                started_at,
                                completed_at,
                            });
                        }
                    }
                    Err(e) => {
                        debug!("Failed to parse result: {}", e);
                    }
                }
            }
            Ok(None) => {
                warn!("Result stream ended for workflow {}", workflow_id);
                break;
            }
            Err(_) => {
                // Timeout - check overall timeout
                if start_time.elapsed() > timeout_duration {
                    warn!("Benchmark timeout for workflow {}", workflow_id);
                    break;
                }
            }
        }
    }
    
    // Return timeout result
    Ok(BenchmarkResult {
        workflow_id: workflow_id.to_string(),
        scenario_name: scenario.name.clone(),
        workflow_type: scenario.workflow_type.clone(),
        success: false,
        duration_ms: start_time.elapsed().as_millis() as u64,
        steps_completed: performance_tracker.steps_completed,
        memory_peak_mb: performance_tracker.memory_peak_mb,
        cpu_avg_percent: performance_tracker.cpu_avg_percent,
        network_requests: performance_tracker.network_requests,
        file_operations: performance_tracker.file_operations,
        error_message: Some("Benchmark timeout".to_string()),
        started_at,
        completed_at: Utc::now(),
    })
}

/// Create benchmark-specific intent parameters
fn create_benchmark_intent_params(
    workflow_id: &str,
    scenario: &planner_demo::scenarios::DemoScenario,
    config: &BenchmarkConfig,
) -> Result<serde_json::Value> {
    let mut resource_limits = json!({
        "max_memory_mb": 256,
        "max_cpu_seconds": 60,
        "max_fs_operations": 500,
        "max_network_requests": 50,
        "max_parallel_executions": 2
    });
    
    // Adjust limits for stress testing
    if config.stress_testing {
        if config.memory_stress {
            resource_limits["max_memory_mb"] = json!(2048);
        }
        if config.cpu_stress {
            resource_limits["max_cpu_seconds"] = json!(300);
        }
        resource_limits["max_fs_operations"] = json!(5000);
        resource_limits["max_network_requests"] = json!(500);
        resource_limits["max_parallel_executions"] = json!(8);
    }
    
    let params = json!({
        "workflow_id": workflow_id,
        "goal": scenario.goal,
        "workflow_type": scenario.workflow_type,
        "max_steps": scenario.max_steps,
        "timeout_ms": config.timeout_seconds * 1000,
        "context": {
            "benchmark_mode": true,
            "performance_tracking": true,
            "scenario_name": scenario.name,
            "stress_testing": config.stress_testing,
            "memory_stress": config.memory_stress,
            "cpu_stress": config.cpu_stress
        },
        "allowed_capabilities": [
            "fs.read.v1",
            "http.fetch.v1"
        ],
        "resource_limits": resource_limits,
        "preferences": {
            "verbosity": "error",  // Minimal logging for performance
            "interactive": false,
            "parallel_execution": true,
            "auto_retry": false,   // Disable for consistent benchmarking
            "save_intermediate_results": false,
            "optimization_level": "performance"
        }
    });
    
    Ok(params)
}

/// Performance metrics tracker
struct PerformanceTracker {
    steps_completed: u32,
    memory_peak_mb: f64,
    cpu_avg_percent: f64,
    cpu_samples: Vec<f64>,
    network_requests: u32,
    file_operations: u32,
}

impl PerformanceTracker {
    fn new() -> Self {
        Self {
            steps_completed: 0,
            memory_peak_mb: 0.0,
            cpu_avg_percent: 0.0,
            cpu_samples: Vec::new(),
            network_requests: 0,
            file_operations: 0,
        }
    }
    
    fn update(&mut self, result: &serde_json::Value) {
        // Update step count
        if let Some(step) = result.get("step_count").and_then(|v| v.as_u64()) {
            self.steps_completed = step as u32;
        }
        
        // Update memory usage
        if let Some(memory) = result.get("memory_usage_mb").and_then(|v| v.as_f64()) {
            self.memory_peak_mb = self.memory_peak_mb.max(memory);
        }
        
        // Update CPU usage
        if let Some(cpu) = result.get("cpu_usage_percent").and_then(|v| v.as_f64()) {
            self.cpu_samples.push(cpu);
            self.cpu_avg_percent = self.cpu_samples.iter().sum::<f64>() / self.cpu_samples.len() as f64;
        }
        
        // Update operation counts
        if let Some(net) = result.get("network_requests").and_then(|v| v.as_u64()) {
            self.network_requests = net as u32;
        }
        
        if let Some(fs) = result.get("file_operations").and_then(|v| v.as_u64()) {
            self.file_operations = fs as u32;
        }
    }
}

/// Generate comprehensive statistics from benchmark results
fn generate_statistics(results: &[BenchmarkResult], total_duration: Duration) -> BenchmarkStatistics {
    if results.is_empty() {
        return BenchmarkStatistics {
            total_executions: 0,
            successful_executions: 0,
            failed_executions: 0,
            success_rate: 0.0,
            total_duration_ms: total_duration.as_millis() as u64,
            avg_duration_ms: 0.0,
            min_duration_ms: 0,
            max_duration_ms: 0,
            p50_duration_ms: 0.0,
            p95_duration_ms: 0.0,
            p99_duration_ms: 0.0,
            workflows_per_second: 0.0,
            steps_per_second: 0.0,
            avg_memory_mb: 0.0,
            peak_memory_mb: 0.0,
            avg_cpu_percent: 0.0,
            peak_cpu_percent: 0.0,
            total_network_requests: 0,
            total_file_operations: 0,
            stats_by_type: HashMap::new(),
        };
    }
    
    let total_executions = results.len();
    let successful_executions = results.iter().filter(|r| r.success).count();
    let failed_executions = total_executions - successful_executions;
    let success_rate = successful_executions as f64 / total_executions as f64;
    
    // Duration statistics
    let mut durations: Vec<u64> = results.iter().map(|r| r.duration_ms).collect();
    durations.sort_unstable();
    
    let total_duration_ms = total_duration.as_millis() as u64;
    let avg_duration_ms = durations.iter().sum::<u64>() as f64 / durations.len() as f64;
    let min_duration_ms = durations.first().copied().unwrap_or(0);
    let max_duration_ms = durations.last().copied().unwrap_or(0);
    
    let p50_duration_ms = percentile(&durations, 50.0);
    let p95_duration_ms = percentile(&durations, 95.0);
    let p99_duration_ms = percentile(&durations, 99.0);
    
    // Throughput
    let total_duration_secs = total_duration.as_secs_f64();
    let workflows_per_second = if total_duration_secs > 0.0 {
        total_executions as f64 / total_duration_secs
    } else {
        0.0
    };
    
    let total_steps: u32 = results.iter().map(|r| r.steps_completed).sum();
    let steps_per_second = if total_duration_secs > 0.0 {
        total_steps as f64 / total_duration_secs
    } else {
        0.0
    };
    
    // Resource utilization
    let avg_memory_mb = results.iter().map(|r| r.memory_peak_mb).sum::<f64>() / results.len() as f64;
    let peak_memory_mb = results.iter().map(|r| r.memory_peak_mb).fold(0.0, f64::max);
    let avg_cpu_percent = results.iter().map(|r| r.cpu_avg_percent).sum::<f64>() / results.len() as f64;
    let peak_cpu_percent = results.iter().map(|r| r.cpu_avg_percent).fold(0.0, f64::max);
    
    // Operation counts
    let total_network_requests = results.iter().map(|r| r.network_requests).sum();
    let total_file_operations = results.iter().map(|r| r.file_operations).sum();
    
    // Statistics by workflow type
    let mut stats_by_type = HashMap::new();
    let mut type_groups: HashMap<String, Vec<&BenchmarkResult>> = HashMap::new();
    
    for result in results {
        type_groups.entry(result.workflow_type.clone()).or_default().push(result);
    }
    
    for (workflow_type, type_results) in type_groups {
        let count = type_results.len();
        let success_count = type_results.iter().filter(|r| r.success).count();
        let type_success_rate = success_count as f64 / count as f64;
        let type_avg_duration = type_results.iter().map(|r| r.duration_ms).sum::<u64>() as f64 / count as f64;
        let type_avg_steps = type_results.iter().map(|r| r.steps_completed).sum::<u32>() as f64 / count as f64;
        let type_avg_memory = type_results.iter().map(|r| r.memory_peak_mb).sum::<f64>() / count as f64;
        let type_avg_cpu = type_results.iter().map(|r| r.cpu_avg_percent).sum::<f64>() / count as f64;
        
        stats_by_type.insert(workflow_type, WorkflowTypeStats {
            count,
            success_rate: type_success_rate,
            avg_duration_ms: type_avg_duration,
            avg_steps: type_avg_steps,
            avg_memory_mb: type_avg_memory,
            avg_cpu_percent: type_avg_cpu,
        });
    }
    
    BenchmarkStatistics {
        total_executions,
        successful_executions,
        failed_executions,
        success_rate,
        total_duration_ms,
        avg_duration_ms,
        min_duration_ms,
        max_duration_ms,
        p50_duration_ms,
        p95_duration_ms,
        p99_duration_ms,
        workflows_per_second,
        steps_per_second,
        avg_memory_mb,
        peak_memory_mb,
        avg_cpu_percent,
        peak_cpu_percent,
        total_network_requests,
        total_file_operations,
        stats_by_type,
    }
}

/// Calculate percentile from sorted data
fn percentile(sorted_data: &[u64], percentile: f64) -> f64 {
    if sorted_data.is_empty() {
        return 0.0;
    }
    
    let index = (percentile / 100.0) * (sorted_data.len() - 1) as f64;
    let lower = index.floor() as usize;
    let upper = index.ceil() as usize;
    
    if lower == upper {
        sorted_data[lower] as f64
    } else {
        let weight = index - lower as f64;
        sorted_data[lower] as f64 * (1.0 - weight) + sorted_data[upper] as f64 * weight
    }
}

/// Display comprehensive benchmark results
fn display_results(stats: &BenchmarkStatistics, config: &BenchmarkConfig) {
    println!();
    println!("📊 PERFORMANCE BENCHMARK RESULTS");
    println!("=================================");
    
    // Overall statistics
    println!("📈 Overall Performance:");
    println!("   Total executions: {}", stats.total_executions);
    println!("   Successful: {} ({:.1}%)", stats.successful_executions, stats.success_rate * 100.0);
    println!("   Failed: {}", stats.failed_executions);
    println!();
    
    // Timing performance
    println!("⏱️  Timing Performance:");
    println!("   Average duration: {:.1}ms", stats.avg_duration_ms);
    println!("   Min duration: {}ms", stats.min_duration_ms);
    println!("   Max duration: {}ms", stats.max_duration_ms);
    println!("   P50 duration: {:.1}ms", stats.p50_duration_ms);
    println!("   P95 duration: {:.1}ms", stats.p95_duration_ms);
    println!("   P99 duration: {:.1}ms", stats.p99_duration_ms);
    println!();
    
    // Throughput
    println!("🚀 Throughput:");
    println!("   Workflows/second: {:.2}", stats.workflows_per_second);
    println!("   Steps/second: {:.2}", stats.steps_per_second);
    println!("   Total benchmark duration: {:.2}s", stats.total_duration_ms as f64 / 1000.0);
    println!();
    
    // Resource utilization
    println!("💾 Resource Utilization:");
    println!("   Average memory: {:.1}MB", stats.avg_memory_mb);
    println!("   Peak memory: {:.1}MB", stats.peak_memory_mb);
    println!("   Average CPU: {:.1}%", stats.avg_cpu_percent);
    println!("   Peak CPU: {:.1}%", stats.peak_cpu_percent);
    println!();
    
    // Operations
    println!("🔧 Operations:");
    println!("   Network requests: {}", stats.total_network_requests);
    println!("   File operations: {}", stats.total_file_operations);
    println!();
    
    // Performance by workflow type
    if !stats.stats_by_type.is_empty() {
        println!("📋 Performance by Workflow Type:");
        for (workflow_type, type_stats) in &stats.stats_by_type {
            println!("   {}:", workflow_type);
            println!("     Count: {}", type_stats.count);
            println!("     Success rate: {:.1}%", type_stats.success_rate * 100.0);
            println!("     Avg duration: {:.1}ms", type_stats.avg_duration_ms);
            println!("     Avg steps: {:.1}", type_stats.avg_steps);
            println!("     Avg memory: {:.1}MB", type_stats.avg_memory_mb);
            println!("     Avg CPU: {:.1}%", type_stats.avg_cpu_percent);
            println!();
        }
    }
    
    // Configuration summary
    println!("⚙️  Test Configuration:");
    println!("   Concurrency: {}", config.concurrency);
    println!("   Iterations per scenario: {}", config.iterations_per_scenario);
    println!("   Stress testing: {}", if config.stress_testing { "✅" } else { "❌" });
    println!("   Memory stress: {}", if config.memory_stress { "✅" } else { "❌" });
    println!("   CPU stress: {}", if config.cpu_stress { "✅" } else { "❌" });
    
    // Performance recommendations
    println!();
    println!("💡 Performance Insights:");
    if stats.success_rate < 0.9 {
        println!("   ⚠️  Success rate below 90% - consider investigating failures");
    }
    if stats.avg_duration_ms > 10000.0 {
        println!("   ⚠️  Average duration over 10s - performance optimization recommended");
    }
    if stats.peak_memory_mb > 1000.0 {
        println!("   ⚠️  High memory usage detected - memory optimization recommended");
    }
    if stats.workflows_per_second < 1.0 {
        println!("   ⚠️  Low throughput - consider scaling or optimization");
    } else if stats.workflows_per_second > 10.0 {
        println!("   ✅ Excellent throughput performance");
    }
}

/// Save detailed benchmark results to files
async fn save_benchmark_results(
    results: &[BenchmarkResult],
    stats: &BenchmarkStatistics,
    config: &BenchmarkConfig,
) -> Result<()> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    
    // Save detailed results
    let results_filename = format!("benchmark_results_{}.json", timestamp);
    let results_json = serde_json::to_string_pretty(results)?;
    tokio::fs::write(&results_filename, results_json).await?;
    println!("📁 Detailed results saved to: {}", results_filename);
    
    // Save summary statistics
    let stats_filename = format!("benchmark_stats_{}.json", timestamp);
    let stats_json = serde_json::to_string_pretty(stats)?;
    tokio::fs::write(&stats_filename, stats_json).await?;
    println!("📁 Summary statistics saved to: {}", stats_filename);
    
    // Save configuration
    let config_filename = format!("benchmark_config_{}.json", timestamp);
    let config_json = serde_json::to_string_pretty(config)?;
    tokio::fs::write(&config_filename, config_json).await?;
    println!("📁 Configuration saved to: {}", config_filename);
    
    Ok(())
}