//! Runtime Attestation - Modular Implementation  
//!
//! Modular implementation of runtime attestation with separated concerns:
//! - verification: Core verification strategies and result processing
//! - policy_loader: Capability bundle and signature loading logic
//! - provenance: Runtime provenance generation and management
//! - types: Shared attestation types and result structures

pub mod verification;
pub mod policy_loader;
pub mod provenance;
pub mod types;

pub use verification::VerificationEngine;
pub use policy_loader::PolicyLoader;
pub use provenance::RuntimeProvenanceGenerator;
pub use types::{RuntimeAttestationResults, VerificationDetails};