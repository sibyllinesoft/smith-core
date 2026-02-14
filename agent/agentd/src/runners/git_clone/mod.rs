//! Git Clone Runner Module
//!
//! Modular implementation of git clone capability with separated concerns:
//! - validation: URL, path, and branch validation
//! - execution: Core git clone execution logic

pub mod validation;
pub mod execution;

pub use validation::GitValidator;
pub use execution::GitExecutor;