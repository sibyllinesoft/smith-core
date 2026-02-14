//! Sign capability bundle with cryptographic signature
//!
//! This tool creates cryptographic signatures for Smith capability bundles using
//! Ed25519 signatures, providing supply chain integrity verification.

use anyhow::{Context, Result};
use clap::{Arg, Command};
use smith_attestation::{initialize_attestation, AttestationConfig, CapabilitySigner};
use std::path::PathBuf;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let matches = Command::new("sign-policy-bundle")
        .version("0.1.0")
        .about("Sign Smith capability bundle with cryptographic signature")
        .author("Smith Team")
        .arg(
            Arg::new("bundle-path")
                .long("bundle-path")
                .value_name("FILE")
                .help("Path to capability bundle JSON file")
                .required(true),
        )
        .arg(
            Arg::new("output-path")
                .long("output-path")
                .value_name("FILE")
                .help("Output path for signature file")
                .required(true),
        )
        .arg(
            Arg::new("private-key")
                .long("private-key")
                .value_name("FILE")
                .help("Path to private key PEM file (optional for new key generation)"),
        )
        .arg(
            Arg::new("version")
                .long("version")
                .value_name("VERSION")
                .help("Capability bundle version")
                .default_value("1.0.0"),
        )
        .get_matches();

    let bundle_path = PathBuf::from(matches.get_one::<String>("bundle-path").unwrap());
    let output_path = PathBuf::from(matches.get_one::<String>("output-path").unwrap());
    let private_key_path = matches.get_one::<String>("private-key").map(PathBuf::from);
    let version = matches.get_one::<String>("version").unwrap();

    info!("Starting capability bundle signing");
    info!("  Bundle path: {}", bundle_path.display());
    info!("  Output path: {}", output_path.display());
    info!("  Version: {}", version);

    if let Some(ref key_path) = private_key_path {
        info!("  Private key: {}", key_path.display());
    } else {
        info!("  Private key: <generated>");
    }

    // Initialize attestation subsystem
    let attestation_config = AttestationConfig::default();
    initialize_attestation(attestation_config)
        .await
        .context("Failed to initialize attestation subsystem")?;

    // Create policy signer
    let signer = if let Some(_key_path) = private_key_path {
        // Load signer from existing key files
        // Note: This would require implementing public key derivation from private key
        warn!("Loading from existing keys not implemented, generating new key pair");
        CapabilitySigner::new()
            .await
            .context("Failed to create policy signer with new key pair")?
    } else {
        // Generate new key pair
        info!("Generating new Ed25519 key pair for signing");
        CapabilitySigner::new()
            .await
            .context("Failed to create policy signer with new key pair")?
    };

    // Read capability bundle
    info!("Reading capability bundle");
    let bundle_bytes = tokio::fs::read(&bundle_path).await.with_context(|| {
        format!(
            "Failed to read capability bundle: {}",
            bundle_path.display()
        )
    })?;

    info!("Capability bundle size: {} bytes", bundle_bytes.len());

    // Sign the capability bundle
    info!("Generating cryptographic signature");
    let signature = signer
        .sign_capability_bundle(&bundle_bytes, version.clone())
        .await
        .context("Failed to sign capability bundle")?;

    info!("Signature generated successfully");
    info!("  Algorithm: {}", signature.algorithm);
    info!("  Timestamp: {}", signature.timestamp);
    info!("  Capability digest: {}", signature.digest.digest);
    info!("  Policy version: {}", signature.digest.version);

    // Serialize signature to JSON
    let signature_json = serde_json::to_string_pretty(&signature)
        .context("Failed to serialize signature to JSON")?;

    // Write signature to output file
    tokio::fs::write(&output_path, signature_json)
        .await
        .with_context(|| format!("Failed to write signature file: {}", output_path.display()))?;

    info!(
        "Capability bundle signature saved: {}",
        output_path.display()
    );

    // Verify the signature immediately to ensure it's valid
    info!("Verifying signature integrity");
    let verification_result = signer
        .verify_capability_bundle(&bundle_bytes, &signature)
        .await
        .context("Failed to verify generated signature")?;

    if verification_result {
        info!("✅ Signature verification successful");
    } else {
        return Err(anyhow::anyhow!("❌ Signature verification failed"));
    }

    info!("Capability bundle signing completed successfully");
    Ok(())
}
