//! Policy ABI Validation CLI Tool
//!
//! This tool validates Policy ABI version stability for CI/CD pipelines.

use anyhow::Result;
use clap::{Arg, Command};
use smith_protocol::policy_abi::{PolicyAbiValidator, PolicyAbiVersion};
use std::fs;

fn main() -> Result<()> {
    let matches = Command::new("validate-policy-abi")
        .version("0.1.0")
        .about("Validate Policy ABI version stability")
        .author("Smith Team")
        .arg(
            Arg::new("check-stability")
                .long("check-stability")
                .help("Check ABI hash stability for CI validation")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("generate-hash")
                .long("generate-hash")
                .help("Generate and display current ABI hash")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("expected-hash")
                .long("expected-hash")
                .value_name("HASH")
                .help("Expected ABI hash to validate against"),
        )
        .get_matches();

    if matches.get_flag("generate-hash") {
        let hash = PolicyAbiValidator::generate_abi_hash();
        println!("{}", hash);
        return Ok(());
    }

    if matches.get_flag("check-stability") {
        // Read expected hash from file or environment
        let expected_hash = if let Some(hash) = matches.get_one::<String>("expected-hash") {
            hash.clone()
        } else if let Ok(hash) = std::env::var("SMITH_CAPABILITY_ABI_HASH")
            .or_else(|_| std::env::var("SMITH_POLICY_ABI_HASH"))
        {
            hash
        } else if let Ok(hash) = fs::read_to_string(".policy-abi-hash") {
            hash.trim().to_string()
        } else {
            eprintln!(
                "❌ No expected hash provided. Use --expected-hash, SMITH_CAPABILITY_ABI_HASH env var, or create .policy-abi-hash file"
            );
            std::process::exit(1);
        };

        let current_hash = PolicyAbiValidator::generate_abi_hash();

        match PolicyAbiValidator::validate_abi_stability(&expected_hash, &current_hash) {
            Ok(()) => {
                println!("✅ Policy ABI stability validated");
                println!("   Hash: {}", current_hash);
            }
            Err(e) => {
                eprintln!("❌ Policy ABI stability check failed:");
                eprintln!("   {}", e);
                eprintln!("   Expected: {}", expected_hash);
                eprintln!("   Current:  {}", current_hash);
                std::process::exit(1);
            }
        }
    } else {
        // Default: show current version and hash
        let version = PolicyAbiVersion::current();
        let hash = PolicyAbiValidator::generate_abi_hash();

        println!("Policy ABI Information:");
        println!("  Version: {}", version);
        println!("  Hash:    {}", hash);

        // Save hash to file for future validation
        if let Err(e) = fs::write(".policy-abi-hash", &hash) {
            eprintln!("Warning: Could not save hash to .policy-abi-hash: {}", e);
        } else {
            println!("  Saved hash to .policy-abi-hash for future validation");
        }
    }

    Ok(())
}
