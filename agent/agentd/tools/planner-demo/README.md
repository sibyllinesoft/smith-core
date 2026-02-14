# Smith Planner-Executor Controller Demo

A comprehensive demonstration application showcasing the sophisticated capabilities of the Smith planner-executor controller, including state machine-driven workflow execution, Oracle-powered research and planning, real-time monitoring, and interactive user intervention.

## 🚀 Features

### Core Capabilities
- **Interactive CLI Interface** - User-friendly command-line interface for goal submission and monitoring
- **Real-time Monitoring** - Live workflow state visualization with terminal UI
- **Demo Scenarios Library** - 20+ predefined scenarios across different workflow patterns
- **Performance Benchmarking** - Comprehensive load testing and performance analysis
- **User Intervention** - Interactive workflow control with manual intervention capabilities
- **NATS Integration** - Real-time message publishing and subscription

### Workflow Patterns Demonstrated
- **Simple Linear Execution** - Basic sequential task workflows (1-10 steps)
- **Research & Planning** - Deep analysis with Oracle planning committee (5-50 steps)
- **Complex Orchestration** - Multi-step workflows with sub-tasks (10-1000 steps)
- **Error Recovery** - Stall detection and automated recovery scenarios
- **Interactive Scenarios** - User-guided workflows requiring human input
- **Stress Testing** - High-load scenarios for performance validation

### Advanced Features
- **Oracle Decision Tracking** - Monitor AI-powered research and planning processes
- **Guard Security Validation** - Real-time policy enforcement and security checks
- **Stall Detection & Recovery** - Automatic detection of stuck workflows with recovery options
- **Menu System Integration** - Interactive user control interface
- **Performance Metrics** - Resource utilization and throughput monitoring
- **State Machine Visualization** - Live display of workflow state transitions

## 📋 Prerequisites

### System Requirements
- **Rust 1.70+** - Latest stable Rust toolchain
- **NATS Server with JetStream** - Message broker with streaming enabled
- **Linux/macOS/Windows** - Cross-platform compatibility
- **Terminal with Unicode support** - For optimal UI experience

### NATS Setup
The demo requires a NATS server with JetStream enabled and properly configured streams.

```bash
# Start NATS server with JetStream (using Docker)
docker run -p 4222:4222 -p 8222:8222 nats:latest -js

# Or install and run locally
# See: https://docs.nats.io/running-a-nats-service/introduction
```

### Smith Platform Integration
Ensure the Smith executor is running and properly configured:

```bash
# From the executor directory
cargo run --bin smith-executor run --demo
```

## 🛠️ Installation

### Clone and Build
```bash
# Navigate to the demo directory
cd tools/planner-demo

# Build the demo application
cargo build --release

# Or build with all features
cargo build --release --all-features
```

### Environment Configuration
```bash
# Set NATS server URL (optional, defaults to localhost)
export NATS_URL="nats://localhost:4222"

# Enable debug logging (optional)
export RUST_LOG=debug
```

## 🎮 Usage

### Interactive Demo Mode
The easiest way to explore all capabilities:

```bash
cargo run --bin planner-demo interactive
```

This launches an interactive menu system that guides you through:
- Demo scenario selection
- Custom goal submission
- Real-time monitoring
- Performance benchmarking
- Environment diagnostics

### Command-Line Interface

#### Run Specific Scenarios
```bash
# Execute a predefined scenario
cargo run --bin planner-demo scenario simple-file-ops --monitor

# List all available scenarios
cargo run --bin planner-demo list --details

# Filter scenarios by pattern
cargo run --bin planner-demo list --pattern research
```

#### Submit Custom Goals
```bash
# Simple goal execution
cargo run --bin planner-demo goal \
  "Analyze the current directory and create a project summary" \
  --workflow-type simple \
  --max-steps 10 \
  --monitor

# Complex research workflow
cargo run --bin planner-demo goal \
  "Perform comprehensive security audit of the codebase" \
  --workflow-type research_and_planning \
  --max-steps 25 \
  --timeout-seconds 300 \
  --monitor
```

#### Real-time Monitoring
```bash
# Start standalone monitor
cargo run --bin planner-demo monitor

# Monitor specific workflow
cargo run --bin planner-demo monitor --workflow-id "workflow-123"

# Monitor with custom configuration
cargo run --bin planner-demo monitor --config monitor-config.json
```

#### Performance Benchmarking
```bash
# Basic benchmark
cargo run --bin planner-demo benchmark

# High concurrency stress test
cargo run --bin planner-demo benchmark \
  --concurrency 50 \
  --iterations 100 \
  --stress

# Memory stress testing
cargo run --bin planner-demo benchmark \
  --concurrency 10 \
  --iterations 50 \
  --stress

# Save detailed results
cargo run --bin planner-demo benchmark > benchmark-results.log
```

#### Environment Diagnostics
```bash
# Check system health
cargo run --bin planner-demo doctor

# Attempt automatic fixes
cargo run --bin planner-demo doctor --fix
```

## 📊 Examples

### 1. Simple Goal Execution
Demonstrates basic workflow execution with minimal complexity:

```bash
cargo run --example simple_goal
```

**What it shows:**
- Goal submission to planner-executor
- Simple workflow monitoring
- Result handling and display
- Error handling patterns

### 2. Complex Multi-Step Workflow
Shows advanced orchestration with comprehensive monitoring:

```bash
cargo run --example complex_workflow
```

**What it shows:**
- Complex orchestration workflow execution
- Oracle deep research and planning committee
- Guard security validation
- Performance monitoring
- Comprehensive result analysis

### 3. User Intervention Demo
Interactive workflow with manual control capabilities:

```bash
cargo run --example user_intervention
```

**What it shows:**
- Interactive workflow execution
- Stall detection and recovery
- Manual workflow intervention
- Menu system integration
- Pause/resume functionality

### 4. Performance Benchmark
Comprehensive performance testing and analysis:

```bash
cargo run --example performance_benchmark
```

**What it shows:**
- Concurrent workflow execution
- Performance metrics collection
- Stress testing capabilities
- Resource utilization monitoring
- Throughput and latency measurements

## 🎯 Demo Scenarios

The demo includes 20+ predefined scenarios across different patterns:

### Simple Scenarios (1-2 complexity)
- **simple-file-ops** - Basic file system operations
- **simple-web-request** - HTTP request processing
- **config-analysis** - Configuration file validation
- **log-processing** - System log analysis

### Research Scenarios (3-4 complexity)
- **codebase-analysis** - Comprehensive code review
- **security-audit** - Security vulnerability assessment
- **performance-research** - Performance optimization research
- **tech-stack-evaluation** - Technology comparison analysis

### Complex Scenarios (4-5 complexity)
- **multi-service-deployment** - Full deployment orchestration
- **data-migration** - Complex data transformation
- **distributed-health-check** - System health monitoring
- **automated-testing-pipeline** - CI/CD pipeline setup

### Interactive Scenarios
- **user-guided-troubleshooting** - Interactive problem solving
- **configuration-wizard** - Guided configuration setup
- **code-review-assistant** - Collaborative code review

### Stress Testing Scenarios
- **high-concurrency-stress** - Concurrent execution testing
- **memory-pressure-stress** - Memory utilization testing
- **long-duration-stability** - Extended runtime testing

## 🖥️ Real-time Monitor

The terminal-based monitor provides live visualization of workflow execution:

### Monitor Features
- **Multi-tab Interface** - Workflows, Oracle Activity, Performance, Logs
- **Live State Visualization** - Real-time workflow state transitions
- **Oracle Decision Tracking** - AI decision-making process monitoring
- **Performance Metrics** - CPU, memory, and throughput graphs
- **Interactive Controls** - Workflow selection and control

### Monitor Controls
- **Tab** - Switch between monitor tabs
- **↑/↓** - Navigate workflow list
- **Enter** - Select workflow for detailed view
- **r** - Refresh display
- **h** - Show help
- **q** - Quit monitor

### Monitor Configuration
```json
{
  "nats_url": "nats://localhost:4222",
  "workflow_filter": "workflow-123",
  "refresh_rate_ms": 100,
  "max_history": 1000
}
```

## 📈 Performance Benchmarking

The benchmark suite provides comprehensive performance analysis:

### Benchmark Types
- **Throughput Testing** - Workflows per second measurement
- **Latency Analysis** - Response time distribution (P50, P95, P99)
- **Concurrency Testing** - Multi-workflow execution
- **Resource Monitoring** - CPU, memory, network usage
- **Stress Testing** - System limits and stability

### Benchmark Configuration
```bash
# Configure benchmark parameters
cargo run --bin planner-demo benchmark \
  --concurrency 20 \        # Concurrent workflows
  --iterations 50 \         # Iterations per scenario  
  --stress \               # Enable stress testing
  --timeout 300            # Timeout in seconds
```

### Performance Metrics
- **Success Rate** - Percentage of successful executions
- **Average Duration** - Mean execution time
- **Percentile Analysis** - P50, P95, P99 response times
- **Throughput** - Workflows and steps per second
- **Resource Utilization** - Peak and average usage
- **Error Analysis** - Failure patterns and causes

## 🔧 Configuration

### Environment Variables
```bash
# NATS server configuration
export NATS_URL="nats://localhost:4222"

# Logging configuration
export RUST_LOG="info"                    # info, debug, warn, error
export RUST_LOG="planner_demo=debug"      # Module-specific logging

# Demo-specific settings
export DEMO_TIMEOUT_SECONDS=300           # Default workflow timeout
export DEMO_MAX_CONCURRENCY=10            # Maximum concurrent workflows
export DEMO_ENABLE_METRICS=true           # Enable metrics collection
```

### Configuration Files
```json
// monitor-config.json
{
  "nats_url": "nats://localhost:4222",
  "workflow_filter": null,
  "refresh_rate_ms": 100,
  "max_history": 1000
}

// benchmark-config.json
{
  "concurrency": 10,
  "iterations_per_scenario": 20,
  "stress_testing": false,
  "timeout_seconds": 300,
  "collect_detailed_metrics": true
}
```

## 🐛 Troubleshooting

### Common Issues

#### NATS Connection Failed
```
Error: Failed to connect to NATS server
```
**Solution:**
1. Ensure NATS server is running: `docker run -p 4222:4222 nats:latest -js`
2. Check NATS URL: `export NATS_URL="nats://localhost:4222"`
3. Verify network connectivity and firewall settings

#### JetStream Streams Not Found
```
Error: SDLC_RAW stream not found - run bootstrap first
```
**Solution:**
1. Bootstrap JetStream streams: `just bootstrap-js`
2. Or manually create streams using NATS CLI
3. Verify JetStream is enabled on NATS server

#### Workflow Timeout
```
Warning: Workflow execution timed out
```
**Solution:**
1. Increase timeout: `--timeout-seconds 600`
2. Check system resources and performance
3. Review workflow complexity and requirements

#### Monitor Display Issues
```
Terminal UI rendering problems
```
**Solution:**
1. Ensure terminal supports Unicode and colors
2. Resize terminal window (minimum 80x24)
3. Update terminal or try different terminal emulator

### Debugging

#### Enable Debug Logging
```bash
export RUST_LOG=debug
cargo run --bin planner-demo interactive
```

#### Verbose Output
```bash
cargo run --bin planner-demo scenario simple-file-ops --verbose --debug
```

#### Environment Diagnostics
```bash
cargo run --bin planner-demo doctor --fix
```

## 🧪 Development

### Project Structure
```
planner-demo/
├── src/
│   ├── main.rs              # Main CLI application
│   ├── scenarios.rs         # Demo scenario library
│   └── monitor.rs           # Real-time monitoring system
├── examples/
│   ├── simple_goal.rs       # Basic workflow example
│   ├── complex_workflow.rs  # Advanced orchestration
│   ├── user_intervention.rs # Interactive control
│   └── performance_benchmark.rs # Performance testing
├── Cargo.toml              # Dependencies and configuration
└── README.md               # This documentation
```

### Building and Testing
```bash
# Build with all features
cargo build --all-features

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run

# Build release version
cargo build --release
```

### Adding New Scenarios
```rust
// Add to ScenarioLibrary::add_custom_scenarios()
library.scenarios.push(DemoScenario {
    name: "my-custom-scenario".to_string(),
    description: "Custom workflow demonstration".to_string(),
    goal: "Perform custom analysis and reporting".to_string(),
    pattern: WorkflowPattern::Research,
    workflow_type: "research_and_planning".to_string(),
    max_steps: 15,
    timeout_seconds: Some(180),
    expected_steps: 12,
    // ... additional configuration
});
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📚 Documentation

### API Reference
- [Smith Protocol Documentation](../../shared/smith-protocol/README.md)
- [NATS JetStream Guide](../../shared/smith-bus/README.md)
- [Planner-Executor Architecture](../../src/runners/planner_exec/README.md)

### Related Projects
- [Smith Platform](../../README.md) - Main platform documentation
- [Executor Documentation](../../README.md) - Capability execution system
- [Client Applications](../../clients/README.md) - Web and TUI clients

## 📄 License

This project is licensed under the same license as the Smith platform. See the main repository for license details.

## 🤝 Support

For questions, issues, or contributions:
1. Check the [troubleshooting section](#troubleshooting)
2. Review existing issues in the main repository
3. Create a new issue with detailed information
4. Join the development community discussions

---

**Happy Demonstrating! 🚀**

The Smith Planner-Executor Demo showcases the full power and sophistication of AI-driven workflow orchestration. Explore the scenarios, experiment with custom goals, and experience the future of intelligent automation.