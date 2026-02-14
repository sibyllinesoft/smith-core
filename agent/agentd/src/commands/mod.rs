/*!
 * Command handling modules for the Smith Executor
 *
 * This module provides organized command handling, extracted from main.rs
 * to reduce cognitive complexity and improve maintainability.
 */

pub mod check_config;
pub mod cli;
pub mod daemon;
pub mod self_test;

pub use check_config::CheckConfigCommand;
pub use cli::{Cli, ExecutorCommand};
pub use daemon::DaemonCommand;
pub use self_test::SelfTestCommand;
