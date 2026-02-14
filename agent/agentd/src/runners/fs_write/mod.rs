//! File System Write Runner - Modular Implementation
//!
//! Modular implementation of fs.write capability with separated concerns:
//! - permissions: Path validation and actor isolation logic
//! - operations: File writing operations with mode and permission handling
//! - validation: Content parsing and filename validation

pub mod operations;
pub mod permissions;
pub mod validation;

// TODO: Uncomment when fs_write runner is re-implemented
// pub use permissions::PathValidator;
// pub use operations::FileWriter;
// pub use validation::ContentValidator;
