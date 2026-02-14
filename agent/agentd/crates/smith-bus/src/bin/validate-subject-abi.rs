//! Subject ABI Validation CLI Tool
//!
//! This tool validates Subject ABI centralization and stability for CI/CD pipelines.

use anyhow::Result;
use clap::{Arg, Command};
use smith_bus::subjects::abi::{generate_subject_abi_hash, validate_subject_abi_stability};
use smith_bus::subjects::validation::validate_centralized_usage;
use std::fs;

fn main() -> Result<()> {
    let matches = Command::new("validate-subject-abi")
        .version("0.1.0")
        .about("Validate Subject ABI centralization and stability")
        .author("Smith Team")
        .arg(
            Arg::new("check-stability")
                .long("check-stability")
                .help("Check Subject ABI hash stability for CI validation")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("generate-hash")
                .long("generate-hash")
                .help("Generate and display current Subject ABI hash")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("check-raw-subjects")
                .long("check-raw-subjects")
                .help("Check codebase for raw subject string usage")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("expected-hash")
                .long("expected-hash")
                .value_name("HASH")
                .help("Expected Subject ABI hash to validate against"),
        )
        .arg(
            Arg::new("path")
                .long("path")
                .value_name("PATH")
                .help("Path to check for raw subjects (default: current directory)")
                .default_value("."),
        )
        .get_matches();

    if matches.get_flag("generate-hash") {
        let hash = generate_subject_abi_hash();
        println!("{}", hash);
        return Ok(());
    }

    if matches.get_flag("check-raw-subjects") {
        let path = matches.get_one::<String>("path").unwrap();
        check_raw_subjects_in_path(path)?;
        return Ok(());
    }

    if matches.get_flag("check-stability") {
        // Read expected hash from file or environment
        let expected_hash = if let Some(hash) = matches.get_one::<String>("expected-hash") {
            hash.clone()
        } else if let Ok(hash) = std::env::var("SMITH_SUBJECT_ABI_HASH") {
            hash
        } else if let Ok(hash) = fs::read_to_string(".subject-abi-hash") {
            hash.trim().to_string()
        } else {
            eprintln!(
                "❌ No expected hash provided. Use --expected-hash, SMITH_SUBJECT_ABI_HASH env var, or create .subject-abi-hash file"
            );
            std::process::exit(1);
        };

        let current_hash = generate_subject_abi_hash();

        match validate_subject_abi_stability(&expected_hash, &current_hash) {
            Ok(()) => {
                println!("✅ Subject ABI stability validated");
                println!("   Hash: {}", current_hash);
            }
            Err(e) => {
                eprintln!("❌ Subject ABI stability check failed:");
                eprintln!("   {}", e);
                std::process::exit(1);
            }
        }

        // Also check for raw subject usage
        let path = matches.get_one::<String>("path").unwrap();
        check_raw_subjects_in_path(path)?;
    } else {
        // Default: show current hash and check raw subjects
        let hash = generate_subject_abi_hash();

        println!("Subject ABI Information:");
        println!("  Hash: {}", hash);

        // Save hash to file for future validation
        if let Err(e) = fs::write(".subject-abi-hash", &hash) {
            eprintln!("Warning: Could not save hash to .subject-abi-hash: {}", e);
        } else {
            println!("  Saved hash to .subject-abi-hash for future validation");
        }

        // Check for raw subject usage
        let path = matches.get_one::<String>("path").unwrap();
        check_raw_subjects_in_path(path)?;
    }

    Ok(())
}

fn check_raw_subjects_in_path(path: &str) -> Result<()> {
    println!("🔍 Checking for raw subject strings in: {}", path);

    let mut violations = Vec::new();

    // Find all Rust files
    for entry in walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().map(|ext| ext == "rs").unwrap_or(false)
                && !e.path().to_string_lossy().contains("/target/")
                && !e.path().to_string_lossy().contains("/nats-data/")
        })
    {
        let file_path = entry.path();
        if let Ok(content) = fs::read_to_string(file_path) {
            if let Err(e) = validate_centralized_usage(&content) {
                violations.push(format!("{}:{}", file_path.display(), e));
            }
        }
    }

    if violations.is_empty() {
        println!("✅ No raw subject strings found - all subjects use centralized constants");
    } else {
        eprintln!(
            "❌ Found {} raw subject string violations:",
            violations.len()
        );
        for violation in &violations {
            eprintln!("   {}", violation);
        }
        eprintln!("\n💡 Use smith_bus::subjects constants instead of raw strings");
        std::process::exit(1);
    }

    Ok(())
}
