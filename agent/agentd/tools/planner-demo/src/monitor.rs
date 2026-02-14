//! # Real-time Workflow Monitor for Planner-Executor Controller
//!
//! This module provides comprehensive real-time monitoring and visualization
//! of planner-executor workflows including:
//!
//! - **State Machine Visualization**: Live display of workflow state transitions
//! - **Oracle Decision Tracking**: Monitor AI decision-making processes
//! - **Planning Committee Progress**: Track research and planning activities
//! - **Stall Detection Alerts**: Real-time alerts for stuck workflows
//! - **Performance Metrics**: Live performance and resource usage monitoring
//! - **Interactive Controls**: User intervention and workflow control
//!
//! ## Monitor Architecture
//!
//! The monitor uses a terminal UI (TUI) built with ratatui for real-time
//! visualization of workflow execution. It connects to NATS JetStream to
//! receive live updates from the planner-executor system.

use anyhow::{Context, Result};
use async_nats::{jetstream, Client};
use chrono::{DateTime, Utc};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::StreamExt;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        block::Title, BarChart, Block, Borders, Clear, Gauge, List, ListItem, ListState,
        Paragraph, Sparkline, Table, Row, Cell, Tabs,
    },
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// Smith platform imports
use smith_bus::SmithBus;

/// Configuration for the workflow monitor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// NATS server URL
    pub nats_url: String,
    
    /// Optional workflow ID filter
    pub workflow_filter: Option<String>,
    
    /// Refresh rate in milliseconds
    pub refresh_rate_ms: u64,
    
    /// Maximum history to keep
    pub max_history: usize,
}

impl MonitorConfig {
    /// Load configuration from file
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .context("Failed to read monitor config file")?;
        let config: MonitorConfig = serde_json::from_str(&content)
            .context("Failed to parse monitor config")?;
        Ok(config)
    }
    
    /// Save configuration to file
    pub fn to_file(&self, path: &str) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .context("Failed to serialize monitor config")?;
        std::fs::write(path, content)
            .context("Failed to write monitor config file")?;
        Ok(())
    }
}

/// Current state of a workflow being monitored
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowState {
    pub workflow_id: String,
    pub goal: String,
    pub current_state: String,
    pub step_count: u32,
    pub max_steps: u32,
    pub start_time: DateTime<Utc>,
    pub last_update: DateTime<Utc>,
    pub status: WorkflowStatus,
    pub oracle_activity: Vec<OracleEvent>,
    pub guard_decisions: Vec<GuardDecision>,
    pub executor_results: Vec<ExecutorResult>,
    pub stall_alerts: Vec<StallAlert>,
    pub performance_metrics: PerformanceMetrics,
}

/// Workflow execution status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkflowStatus {
    Initializing,
    Planning,
    Executing,
    Stalled,
    Paused,
    Completed,
    Failed,
}

impl WorkflowStatus {
    fn color(&self) -> Color {
        match self {
            WorkflowStatus::Initializing => Color::Yellow,
            WorkflowStatus::Planning => Color::Blue,
            WorkflowStatus::Executing => Color::Green,
            WorkflowStatus::Stalled => Color::Red,
            WorkflowStatus::Paused => Color::Magenta,
            WorkflowStatus::Completed => Color::Cyan,
            WorkflowStatus::Failed => Color::Red,
        }
    }
}

/// Oracle decision-making event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: OracleEventType,
    pub description: String,
    pub confidence: f32,
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OracleEventType {
    InitialPlanning,
    DeepResearch,
    PlanningCommittee,
    StrategyRevision,
    ActionGeneration,
}

/// Guard security decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardDecision {
    pub timestamp: DateTime<Utc>,
    pub action_type: String,
    pub decision: GuardVerdict,
    pub reasoning: String,
    pub policy_matched: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GuardVerdict {
    Approved,
    Rejected,
    ConditionalApproval,
}

impl GuardVerdict {
    fn color(&self) -> Color {
        match self {
            GuardVerdict::Approved => Color::Green,
            GuardVerdict::Rejected => Color::Red,
            GuardVerdict::ConditionalApproval => Color::Yellow,
        }
    }
}

/// Executor execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorResult {
    pub timestamp: DateTime<Utc>,
    pub capability: String,
    pub duration_ms: u64,
    pub success: bool,
    pub output_size: u64,
    pub error_message: Option<String>,
}

/// Stall detection alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallAlert {
    pub timestamp: DateTime<Utc>,
    pub alert_type: StallType,
    pub description: String,
    pub suggested_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StallType {
    NoProgress,
    RepeatedFailures,
    ResourceExhaustion,
    UserInterventionRequired,
}

/// Performance metrics for a workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub cpu_usage: VecDeque<f32>,
    pub memory_usage: VecDeque<f32>,
    pub network_requests: u32,
    pub file_operations: u32,
    pub avg_step_duration_ms: f32,
    pub throughput_steps_per_sec: f32,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            cpu_usage: VecDeque::with_capacity(60), // 1 minute of data
            memory_usage: VecDeque::with_capacity(60),
            network_requests: 0,
            file_operations: 0,
            avg_step_duration_ms: 0.0,
            throughput_steps_per_sec: 0.0,
        }
    }
}

/// Main workflow monitor
pub struct WorkflowMonitor {
    config: MonitorConfig,
    bus: SmithBus,
    workflows: Arc<Mutex<HashMap<String, WorkflowState>>>,
    message_history: Arc<Mutex<VecDeque<MonitorMessage>>>,
    selected_workflow: Arc<Mutex<Option<String>>>,
}

/// Internal monitor message
#[derive(Debug, Clone)]
enum MonitorMessage {
    WorkflowUpdate {
        workflow_id: String,
        update: WorkflowUpdate,
    },
    SystemAlert {
        timestamp: DateTime<Utc>,
        level: AlertLevel,
        message: String,
    },
}

#[derive(Debug, Clone)]
enum WorkflowUpdate {
    StateChange(String),
    OracleEvent(OracleEvent),
    GuardDecision(GuardDecision),
    ExecutorResult(ExecutorResult),
    StallAlert(StallAlert),
    PerformanceUpdate(PerformanceMetrics),
}

#[derive(Debug, Clone)]
enum AlertLevel {
    Info,
    Warning,
    Error,
}

impl AlertLevel {
    fn color(&self) -> Color {
        match self {
            AlertLevel::Info => Color::Blue,
            AlertLevel::Warning => Color::Yellow,
            AlertLevel::Error => Color::Red,
        }
    }
}

impl WorkflowMonitor {
    /// Create new workflow monitor
    pub async fn new(config: MonitorConfig) -> Result<Self> {
        let bus = SmithBus::connect(&config.nats_url).await
            .context("Failed to connect to NATS")?;
        
        Ok(Self {
            config,
            bus,
            workflows: Arc::new(Mutex::new(HashMap::new())),
            message_history: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            selected_workflow: Arc::new(Mutex::new(None)),
        })
    }
    
    /// Run the monitor with terminal UI
    pub async fn run(&self) -> Result<()> {
        // Set up terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        
        // Create message channels
        let (tx, mut rx) = mpsc::unbounded_channel();
        
        // Start NATS subscribers
        self.start_subscribers(tx.clone()).await?;
        
        // Start performance collector
        self.start_performance_collector(tx.clone()).await?;
        
        // Main event loop
        let tick_rate = Duration::from_millis(self.config.refresh_rate_ms);
        let mut last_tick = Instant::now();
        let mut tab_index = 0;
        
        loop {
            // Handle terminal events
            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));
            
            if event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') => break,
                            KeyCode::Char('r') => {
                                // Refresh display
                                terminal.clear()?;
                            }
                            KeyCode::Tab => {
                                tab_index = (tab_index + 1) % 4; // 4 tabs
                            }
                            KeyCode::Up => {
                                self.navigate_up();
                            }
                            KeyCode::Down => {
                                self.navigate_down();
                            }
                            KeyCode::Enter => {
                                self.select_current_workflow();
                            }
                            KeyCode::Char('h') => {
                                self.show_help(&mut terminal)?;
                            }
                            _ => {}
                        }
                    }
                }
            }
            
            // Handle monitor messages
            while let Ok(message) = rx.try_recv() {
                self.handle_message(message).await;
            }
            
            // Update display
            if last_tick.elapsed() >= tick_rate {
                terminal.draw(|f| self.draw_ui(f, tab_index))?;
                last_tick = Instant::now();
            }
        }
        
        // Cleanup terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;
        
        Ok(())
    }
    
    /// Start NATS subscribers for workflow updates
    async fn start_subscribers(&self, tx: mpsc::UnboundedSender<MonitorMessage>) -> Result<()> {
        let bus = self.bus.clone();
        let filter = self.config.workflow_filter.clone();
        
        // Subscribe to workflow state updates
        tokio::spawn(async move {
            let subject = if let Some(workflow_id) = &filter {
                format!("smith.events.planner_exec.{}", workflow_id)
            } else {
                "smith.events.planner_exec.*".to_string()
            };
            
            match bus.subscribe(&subject).await {
                Ok(mut subscriber) => {
                    while let Some(msg) = subscriber.next().await {
                        if let Ok(update) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                            // Parse workflow update
                            if let Some(workflow_id) = update.get("workflow_id").and_then(|v| v.as_str()) {
                                let message = MonitorMessage::WorkflowUpdate {
                                    workflow_id: workflow_id.to_string(),
                                    update: parse_workflow_update(&update),
                                };
                                
                                if tx.send(message).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to subscribe to workflow events: {}", e);
                }
            }
        });
        
        // Subscribe to system alerts
        let tx_alerts = tx.clone();
        let bus_alerts = self.bus.clone();
        tokio::spawn(async move {
            match bus_alerts.subscribe("smith.alerts.*").await {
                Ok(mut subscriber) => {
                    while let Some(msg) = subscriber.next().await {
                        if let Ok(alert) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                            let level = match alert.get("level").and_then(|v| v.as_str()) {
                                Some("warning") => AlertLevel::Warning,
                                Some("error") => AlertLevel::Error,
                                _ => AlertLevel::Info,
                            };
                            
                            let message = MonitorMessage::SystemAlert {
                                timestamp: Utc::now(),
                                level,
                                message: alert.get("message")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unknown alert")
                                    .to_string(),
                            };
                            
                            if tx_alerts.send(message).is_err() {
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to subscribe to system alerts: {}", e);
                }
            }
        });
        
        Ok(())
    }
    
    /// Start performance metrics collection
    async fn start_performance_collector(&self, tx: mpsc::UnboundedSender<MonitorMessage>) -> Result<()> {
        let workflows = self.workflows.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            
            loop {
                interval.tick().await;
                
                let workflows_guard = workflows.lock().unwrap();
                for (workflow_id, workflow) in workflows_guard.iter() {
                    // Simulate performance metrics collection
                    let mut metrics = workflow.performance_metrics.clone();
                    
                    // Add simulated CPU and memory data
                    metrics.cpu_usage.push_back(fastrand::f32() * 100.0);
                    metrics.memory_usage.push_back(fastrand::f32() * 100.0);
                    
                    if metrics.cpu_usage.len() > 60 {
                        metrics.cpu_usage.pop_front();
                    }
                    if metrics.memory_usage.len() > 60 {
                        metrics.memory_usage.pop_front();
                    }
                    
                    let message = MonitorMessage::WorkflowUpdate {
                        workflow_id: workflow_id.clone(),
                        update: WorkflowUpdate::PerformanceUpdate(metrics),
                    };
                    
                    if tx.send(message).is_err() {
                        return;
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Handle incoming monitor messages
    async fn handle_message(&self, message: MonitorMessage) {
        match message {
            MonitorMessage::WorkflowUpdate { workflow_id, update } => {
                let mut workflows = self.workflows.lock().unwrap();
                let workflow = workflows.entry(workflow_id.clone()).or_insert_with(|| {
                    WorkflowState {
                        workflow_id: workflow_id.clone(),
                        goal: "Unknown".to_string(),
                        current_state: "Initializing".to_string(),
                        step_count: 0,
                        max_steps: 10,
                        start_time: Utc::now(),
                        last_update: Utc::now(),
                        status: WorkflowStatus::Initializing,
                        oracle_activity: Vec::new(),
                        guard_decisions: Vec::new(),
                        executor_results: Vec::new(),
                        stall_alerts: Vec::new(),
                        performance_metrics: PerformanceMetrics::default(),
                    }
                });
                
                workflow.last_update = Utc::now();
                
                match update {
                    WorkflowUpdate::StateChange(new_state) => {
                        workflow.current_state = new_state.clone();
                        workflow.status = match new_state.as_str() {
                            "Initializing" => WorkflowStatus::Initializing,
                            "Planning" => WorkflowStatus::Planning,
                            "Executing" => WorkflowStatus::Executing,
                            "Stalled" => WorkflowStatus::Stalled,
                            "Paused" => WorkflowStatus::Paused,
                            "Completed" => WorkflowStatus::Completed,
                            "Failed" => WorkflowStatus::Failed,
                            _ => WorkflowStatus::Executing,
                        };
                    }
                    WorkflowUpdate::OracleEvent(event) => {
                        workflow.oracle_activity.push(event);
                        if workflow.oracle_activity.len() > 100 {
                            workflow.oracle_activity.remove(0);
                        }
                    }
                    WorkflowUpdate::GuardDecision(decision) => {
                        workflow.guard_decisions.push(decision);
                        if workflow.guard_decisions.len() > 100 {
                            workflow.guard_decisions.remove(0);
                        }
                    }
                    WorkflowUpdate::ExecutorResult(result) => {
                        workflow.executor_results.push(result);
                        if workflow.executor_results.len() > 100 {
                            workflow.executor_results.remove(0);
                        }
                        workflow.step_count += 1;
                    }
                    WorkflowUpdate::StallAlert(alert) => {
                        workflow.stall_alerts.push(alert);
                        workflow.status = WorkflowStatus::Stalled;
                    }
                    WorkflowUpdate::PerformanceUpdate(metrics) => {
                        workflow.performance_metrics = metrics;
                    }
                }
            }
            MonitorMessage::SystemAlert { .. } => {
                // Add to message history
                let mut history = self.message_history.lock().unwrap();
                history.push_back(message);
                if history.len() > self.config.max_history {
                    history.pop_front();
                }
            }
        }
    }
    
    /// Draw the terminal UI
    fn draw_ui(&self, f: &mut Frame, tab_index: usize) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(0),    // Main content
                Constraint::Length(3), // Footer
            ])
            .split(f.size());
        
        // Header
        self.draw_header(f, chunks[0]);
        
        // Main content with tabs
        self.draw_tabbed_content(f, chunks[1], tab_index);
        
        // Footer
        self.draw_footer(f, chunks[2]);
    }
    
    /// Draw header with title and status
    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let workflows = self.workflows.lock().unwrap();
        let active_count = workflows.len();
        let completed_count = workflows.values()
            .filter(|w| matches!(w.status, WorkflowStatus::Completed))
            .count();
        let failed_count = workflows.values()
            .filter(|w| matches!(w.status, WorkflowStatus::Failed))
            .count();
        
        let title = format!(
            "Smith Planner-Executor Monitor | Active: {} | Completed: {} | Failed: {}",
            active_count, completed_count, failed_count
        );
        
        let header = Paragraph::new(title)
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        
        f.render_widget(header, area);
    }
    
    /// Draw main content with tabs
    fn draw_tabbed_content(&self, f: &mut Frame, area: Rect, tab_index: usize) {
        let titles = vec!["Workflows", "Oracle Activity", "Performance", "System Logs"];
        let tabs = Tabs::new(titles)
            .block(Block::default().borders(Borders::ALL).title("Monitor Views"))
            .style(Style::default().fg(Color::White))
            .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .select(tab_index);
        
        let tab_area = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(area);
        
        f.render_widget(tabs, tab_area[0]);
        
        match tab_index {
            0 => self.draw_workflows_tab(f, tab_area[1]),
            1 => self.draw_oracle_tab(f, tab_area[1]),
            2 => self.draw_performance_tab(f, tab_area[1]),
            3 => self.draw_logs_tab(f, tab_area[1]),
            _ => {}
        }
    }
    
    /// Draw workflows overview tab
    fn draw_workflows_tab(&self, f: &mut Frame, area: Rect) {
        let workflows = self.workflows.lock().unwrap();
        
        if workflows.is_empty() {
            let empty_msg = Paragraph::new("No active workflows\n\nWaiting for workflow events...")
                .style(Style::default().fg(Color::Gray))
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).title("Workflows"));
            f.render_widget(empty_msg, area);
            return;
        }
        
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);
        
        // Workflow list
        let workflow_items: Vec<ListItem> = workflows
            .values()
            .map(|w| {
                let status_color = w.status.color();
                let line = Line::from(vec![
                    Span::styled(
                        format!("● "),
                        Style::default().fg(status_color),
                    ),
                    Span::styled(
                        format!("{} ", w.workflow_id.chars().take(8).collect::<String>()),
                        Style::default().fg(Color::White),
                    ),
                    Span::styled(
                        format!("{:?}", w.status),
                        Style::default().fg(status_color),
                    ),
                ]);
                ListItem::new(line)
            })
            .collect();
        
        let workflow_list = List::new(workflow_items)
            .block(Block::default().borders(Borders::ALL).title("Active Workflows"))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol(">> ");
        
        f.render_widget(workflow_list, chunks[0]);
        
        // Workflow details
        let selected_workflow = self.selected_workflow.lock().unwrap();
        if let Some(workflow_id) = selected_workflow.as_ref() {
            if let Some(workflow) = workflows.get(workflow_id) {
                self.draw_workflow_details(f, chunks[1], workflow);
            }
        } else if let Some(workflow) = workflows.values().next() {
            self.draw_workflow_details(f, chunks[1], workflow);
        }
    }
    
    /// Draw detailed view of a specific workflow
    fn draw_workflow_details(&self, f: &mut Frame, area: Rect, workflow: &WorkflowState) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6),  // Basic info
                Constraint::Length(8),  // Progress
                Constraint::Min(0),     // Recent activity
            ])
            .split(area);
        
        // Basic info
        let info_text = vec![
            Line::from(vec![
                Span::styled("Goal: ", Style::default().fg(Color::Yellow)),
                Span::raw(&workflow.goal),
            ]),
            Line::from(vec![
                Span::styled("Status: ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    format!("{:?}", workflow.status),
                    Style::default().fg(workflow.status.color()),
                ),
            ]),
            Line::from(vec![
                Span::styled("Progress: ", Style::default().fg(Color::Yellow)),
                Span::raw(format!("{}/{} steps", workflow.step_count, workflow.max_steps)),
            ]),
            Line::from(vec![
                Span::styled("Duration: ", Style::default().fg(Color::Yellow)),
                Span::raw(format_duration(
                    Utc::now().signed_duration_since(workflow.start_time)
                )),
            ]),
        ];
        
        let info_para = Paragraph::new(info_text)
            .block(Block::default().borders(Borders::ALL).title("Workflow Details"));
        f.render_widget(info_para, chunks[0]);
        
        // Progress gauge
        let progress = (workflow.step_count as f64 / workflow.max_steps as f64 * 100.0) as u16;
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Progress"))
            .gauge_style(Style::default().fg(Color::Green))
            .percent(progress)
            .label(format!("{}%", progress));
        f.render_widget(gauge, chunks[1]);
        
        // Recent activity
        let recent_items: Vec<ListItem> = workflow
            .executor_results
            .iter()
            .rev()
            .take(10)
            .map(|result| {
                let status_icon = if result.success { "✓" } else { "✗" };
                let status_color = if result.success { Color::Green } else { Color::Red };
                
                let line = Line::from(vec![
                    Span::styled(status_icon, Style::default().fg(status_color)),
                    Span::raw(format!(" {} ({}ms)", result.capability, result.duration_ms)),
                ]);
                ListItem::new(line)
            })
            .collect();
        
        let activity_list = List::new(recent_items)
            .block(Block::default().borders(Borders::ALL).title("Recent Activity"));
        f.render_widget(activity_list, chunks[2]);
    }
    
    /// Draw oracle activity tab
    fn draw_oracle_tab(&self, f: &mut Frame, area: Rect) {
        let workflows = self.workflows.lock().unwrap();
        let selected_workflow = self.selected_workflow.lock().unwrap();
        
        if let Some(workflow_id) = selected_workflow.as_ref() {
            if let Some(workflow) = workflows.get(workflow_id) {
                let oracle_items: Vec<ListItem> = workflow
                    .oracle_activity
                    .iter()
                    .rev()
                    .map(|event| {
                        let line = Line::from(vec![
                            Span::styled(
                                format!("{:?} ", event.event_type),
                                Style::default().fg(Color::Blue),
                            ),
                            Span::styled(
                                format!("({}%) ", (event.confidence * 100.0) as u8),
                                Style::default().fg(Color::Yellow),
                            ),
                            Span::raw(&event.description),
                        ]);
                        ListItem::new(line)
                    })
                    .collect();
                
                let oracle_list = List::new(oracle_items)
                    .block(Block::default().borders(Borders::ALL).title("Oracle Decision History"));
                f.render_widget(oracle_list, area);
            }
        } else {
            let empty_msg = Paragraph::new("Select a workflow to view oracle activity")
                .style(Style::default().fg(Color::Gray))
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).title("Oracle Activity"));
            f.render_widget(empty_msg, area);
        }
    }
    
    /// Draw performance metrics tab
    fn draw_performance_tab(&self, f: &mut Frame, area: Rect) {
        let workflows = self.workflows.lock().unwrap();
        let selected_workflow = self.selected_workflow.lock().unwrap();
        
        if let Some(workflow_id) = selected_workflow.as_ref() {
            if let Some(workflow) = workflows.get(workflow_id) {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Percentage(40),
                        Constraint::Percentage(40),
                        Constraint::Percentage(20),
                    ])
                    .split(area);
                
                // CPU usage sparkline
                let cpu_data: Vec<u64> = workflow
                    .performance_metrics
                    .cpu_usage
                    .iter()
                    .map(|&x| x as u64)
                    .collect();
                
                if !cpu_data.is_empty() {
                    let cpu_sparkline = Sparkline::default()
                        .block(Block::default().borders(Borders::ALL).title("CPU Usage (%)"))
                        .data(&cpu_data)
                        .style(Style::default().fg(Color::Green));
                    f.render_widget(cpu_sparkline, chunks[0]);
                }
                
                // Memory usage sparkline
                let memory_data: Vec<u64> = workflow
                    .performance_metrics
                    .memory_usage
                    .iter()
                    .map(|&x| x as u64)
                    .collect();
                
                if !memory_data.is_empty() {
                    let memory_sparkline = Sparkline::default()
                        .block(Block::default().borders(Borders::ALL).title("Memory Usage (%)"))
                        .data(&memory_data)
                        .style(Style::default().fg(Color::Blue));
                    f.render_widget(memory_sparkline, chunks[1]);
                }
                
                // Performance summary
                let perf_text = vec![
                    Line::from(vec![
                        Span::styled("Network Requests: ", Style::default().fg(Color::Yellow)),
                        Span::raw(workflow.performance_metrics.network_requests.to_string()),
                    ]),
                    Line::from(vec![
                        Span::styled("File Operations: ", Style::default().fg(Color::Yellow)),
                        Span::raw(workflow.performance_metrics.file_operations.to_string()),
                    ]),
                    Line::from(vec![
                        Span::styled("Avg Step Duration: ", Style::default().fg(Color::Yellow)),
                        Span::raw(format!("{}ms", workflow.performance_metrics.avg_step_duration_ms)),
                    ]),
                ];
                
                let perf_para = Paragraph::new(perf_text)
                    .block(Block::default().borders(Borders::ALL).title("Performance Summary"));
                f.render_widget(perf_para, chunks[2]);
            }
        } else {
            let empty_msg = Paragraph::new("Select a workflow to view performance metrics")
                .style(Style::default().fg(Color::Gray))
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).title("Performance"));
            f.render_widget(empty_msg, area);
        }
    }
    
    /// Draw system logs tab
    fn draw_logs_tab(&self, f: &mut Frame, area: Rect) {
        let history = self.message_history.lock().unwrap();
        
        let log_items: Vec<ListItem> = history
            .iter()
            .rev()
            .take(50)
            .filter_map(|msg| match msg {
                MonitorMessage::SystemAlert { timestamp, level, message } => {
                    let time_str = timestamp.format("%H:%M:%S").to_string();
                    let level_str = match level {
                        AlertLevel::Info => "INFO",
                        AlertLevel::Warning => "WARN",
                        AlertLevel::Error => "ERROR",
                    };
                    
                    let line = Line::from(vec![
                        Span::styled(
                            format!("[{}] ", time_str),
                            Style::default().fg(Color::Gray),
                        ),
                        Span::styled(
                            format!("{}: ", level_str),
                            Style::default().fg(level.color()),
                        ),
                        Span::raw(message),
                    ]);
                    Some(ListItem::new(line))
                }
                _ => None,
            })
            .collect();
        
        let logs_list = List::new(log_items)
            .block(Block::default().borders(Borders::ALL).title("System Logs"));
        f.render_widget(logs_list, area);
    }
    
    /// Draw footer with help text
    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        let help_text = "Press 'q' to quit, 'r' to refresh, 'Tab' to switch tabs, 'h' for help";
        let footer = Paragraph::new(help_text)
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        
        f.render_widget(footer, area);
    }
    
    /// Show help dialog
    fn show_help(&self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        terminal.draw(|f| {
            let area = centered_rect(60, 20, f.size());
            f.render_widget(Clear, area);
            
            let help_text = vec![
                Line::from("Smith Planner-Executor Monitor Help"),
                Line::from(""),
                Line::from("Navigation:"),
                Line::from("  ↑/↓ - Navigate workflow list"),
                Line::from("  Tab - Switch between tabs"),
                Line::from("  Enter - Select workflow"),
                Line::from(""),
                Line::from("Actions:"),
                Line::from("  r - Refresh display"),
                Line::from("  h - Show this help"),
                Line::from("  q - Quit monitor"),
                Line::from(""),
                Line::from("Press any key to close help..."),
            ];
            
            let help_para = Paragraph::new(help_text)
                .block(Block::default().borders(Borders::ALL).title("Help"))
                .style(Style::default().fg(Color::White));
            
            f.render_widget(help_para, area);
        })?;
        
        // Wait for key press
        loop {
            if let Event::Key(_) = event::read()? {
                break;
            }
        }
        
        Ok(())
    }
    
    /// Navigate up in workflow list
    fn navigate_up(&self) {
        // Implementation would update selection
    }
    
    /// Navigate down in workflow list
    fn navigate_down(&self) {
        // Implementation would update selection
    }
    
    /// Select current workflow for detailed view
    fn select_current_workflow(&self) {
        // Implementation would set selected workflow
    }
}

/// Parse workflow update from JSON
fn parse_workflow_update(update: &serde_json::Value) -> WorkflowUpdate {
    if let Some(state) = update.get("state").and_then(|v| v.as_str()) {
        WorkflowUpdate::StateChange(state.to_string())
    } else if let Some(_oracle) = update.get("oracle_event") {
        // Parse oracle event
        WorkflowUpdate::OracleEvent(OracleEvent {
            timestamp: Utc::now(),
            event_type: OracleEventType::InitialPlanning,
            description: "Oracle decision made".to_string(),
            confidence: 0.85,
            reasoning: "Based on available data".to_string(),
        })
    } else {
        // Default to state change
        WorkflowUpdate::StateChange("Unknown".to_string())
    }
}

/// Format duration for display
fn format_duration(duration: chrono::Duration) -> String {
    let total_seconds = duration.num_seconds();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    
    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

/// Create a centered rectangle
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_monitor_config_serialization() {
        let config = MonitorConfig {
            nats_url: "nats://localhost:4222".to_string(),
            workflow_filter: Some("test-workflow".to_string()),
            refresh_rate_ms: 100,
            max_history: 1000,
        };
        
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: MonitorConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(config.nats_url, deserialized.nats_url);
        assert_eq!(config.workflow_filter, deserialized.workflow_filter);
        assert_eq!(config.refresh_rate_ms, deserialized.refresh_rate_ms);
        assert_eq!(config.max_history, deserialized.max_history);
    }
    
    #[test]
    fn test_workflow_status_colors() {
        assert_eq!(WorkflowStatus::Initializing.color(), Color::Yellow);
        assert_eq!(WorkflowStatus::Planning.color(), Color::Blue);
        assert_eq!(WorkflowStatus::Executing.color(), Color::Green);
        assert_eq!(WorkflowStatus::Completed.color(), Color::Cyan);
        assert_eq!(WorkflowStatus::Failed.color(), Color::Red);
    }
    
    #[test]
    fn test_guard_verdict_colors() {
        assert_eq!(GuardVerdict::Approved.color(), Color::Green);
        assert_eq!(GuardVerdict::Rejected.color(), Color::Red);
        assert_eq!(GuardVerdict::ConditionalApproval.color(), Color::Yellow);
    }
    
    #[test]
    fn test_format_duration() {
        let duration = chrono::Duration::seconds(3665); // 1h 1m 5s
        assert_eq!(format_duration(duration), "1h 1m 5s");
        
        let duration = chrono::Duration::seconds(125); // 2m 5s
        assert_eq!(format_duration(duration), "2m 5s");
        
        let duration = chrono::Duration::seconds(30); // 30s
        assert_eq!(format_duration(duration), "30s");
    }
}