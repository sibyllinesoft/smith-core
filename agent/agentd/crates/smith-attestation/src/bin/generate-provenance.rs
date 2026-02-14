//! Generate SLSA provenance metadata for Smith builds
//!
//! This tool generates SLSA provenance metadata for capability bundles and other
//! Smith artifacts, providing complete build attestation and supply chain
//! transparency.

use anyhow::{Context, Result};
use clap::{Arg, Command};
use smith_attestation::{
    initialize_attestation,
    provenance::{BuildArtifact, ProvenanceConfig},
    AttestationConfig, ProvenanceGenerator,
};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let matches = Command::new("generate-provenance")
        .version("0.1.0")
        .about("Generate SLSA provenance metadata for Smith builds")
        .author("Smith Team")
        .arg(
            Arg::new("bundle-path")
                .long("bundle-path")
                .value_name("FILE")
                .help("Path to capability bundle JSON file")
                .required(true),
        )
        .arg(
            Arg::new("output-dir")
                .long("output-dir")
                .value_name("DIR")
                .help("Output directory for provenance files")
                .default_value("build/attestation"),
        )
        .arg(
            Arg::new("build-info")
                .long("build-info")
                .value_name("SOURCE")
                .help("Source of build information (git, env, manual)")
                .default_value("git"),
        )
        .arg(
            Arg::new("builder-id")
                .long("builder-id")
                .value_name("ID")
                .help("Builder identity")
                .default_value("smith-build-system"),
        )
        .get_matches();

    let bundle_path = PathBuf::from(matches.get_one::<String>("bundle-path").unwrap());
    let output_dir = PathBuf::from(matches.get_one::<String>("output-dir").unwrap());
    let build_info_source = matches.get_one::<String>("build-info").unwrap();
    let builder_id = matches.get_one::<String>("builder-id").unwrap();

    info!("Starting SLSA provenance generation");
    info!("  Bundle path: {}", bundle_path.display());
    info!("  Output directory: {}", output_dir.display());
    info!("  Build info source: {}", build_info_source);
    info!("  Builder ID: {}", builder_id);

    // Initialize attestation subsystem
    let attestation_config = AttestationConfig::default();
    initialize_attestation(attestation_config)
        .await
        .context("Failed to initialize attestation subsystem")?;

    // Create provenance generator
    let provenance_config = ProvenanceConfig {
        build_environment: std::env::var("BUILD_ENVIRONMENT")
            .unwrap_or_else(|_| "local".to_string()),
        builder_id: builder_id.clone(),
        repository_url: std::env::var("GITHUB_REPOSITORY")
            .or_else(|_| std::env::var("REPOSITORY_URL"))
            .unwrap_or_else(|_| "https://github.com/smith-rs/smith".to_string()),
        build_trigger: std::env::var("GITHUB_EVENT_NAME")
            .or_else(|_| std::env::var("BUILD_TRIGGER"))
            .unwrap_or_else(|_| "manual".to_string()),
        output_dir: output_dir.clone(),
    };

    let generator = ProvenanceGenerator::new(provenance_config);

    // Collect build information
    let build_info = match build_info_source.as_str() {
        "git" => {
            info!("Collecting build information from git");
            ProvenanceGenerator::collect_build_info()
                .await
                .context("Failed to collect git build information")?
        }
        "env" => {
            warn!("Environment-based build info collection not implemented, using git");
            ProvenanceGenerator::collect_build_info()
                .await
                .context("Failed to collect build information")?
        }
        _ => {
            warn!(
                "Unknown build info source '{}', using git",
                build_info_source
            );
            ProvenanceGenerator::collect_build_info()
                .await
                .context("Failed to collect build information")?
        }
    };

    info!("Build information collected:");
    info!("  Git commit: {}", build_info.git_commit);
    info!("  Git branch: {}", build_info.git_branch);
    info!("  Rust version: {}", build_info.rust_version);
    info!("  Build timestamp: {}", build_info.build_timestamp);

    // Create artifacts list
    let mut artifacts = Vec::new();

    // Add capability bundle as artifact
    if bundle_path.exists() {
        let bundle_bytes = tokio::fs::read(&bundle_path)
            .await
            .context("Failed to read capability bundle")?;

        // Compute SHA-256 digest
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&bundle_bytes);
        let digest = format!("{:x}", hasher.finalize());

        let mut artifact_digest = HashMap::new();
        artifact_digest.insert("sha256".to_string(), digest);

        artifacts.push(BuildArtifact {
            name: bundle_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("capability_bundle.json")
                .to_string(),
            path: bundle_path.to_string_lossy().to_string(),
            digest: artifact_digest,
        });

        info!(
            "Added capability bundle artifact: {}",
            bundle_path.display()
        );
    } else {
        warn!("Capability bundle not found at: {}", bundle_path.display());
    }

    // Generate provenance
    info!("Generating SLSA provenance metadata");
    let provenance = generator
        .generate_provenance(&build_info, artifacts)
        .await
        .context("Failed to generate SLSA provenance")?;

    // Save provenance
    let provenance_file = generator
        .save_provenance(&provenance, "build-provenance.json")
        .await
        .context("Failed to save SLSA provenance")?;

    info!("SLSA provenance generated successfully");
    info!("  Provenance file: {}", provenance_file.display());
    info!("  Predicate type: {}", provenance.predicate_type);
    info!("  Subject artifacts: {}", provenance.subject.len());
    info!("  Materials: {}", provenance.predicate.materials.len());
    info!(
        "  Build ID: {}",
        provenance.predicate.metadata.build_invocation_id
    );

    Ok(())
}
