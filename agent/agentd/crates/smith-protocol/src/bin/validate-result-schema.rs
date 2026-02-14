//! Result Schema v1 Validation CLI Tool
//!
//! This tool validates Result Schema v1 stability for CI/CD pipelines.

use anyhow::Result;
use clap::{Arg, Command};
use smith_protocol::result_schema::{ResultSchemaValidator, RESULT_SCHEMA_VERSION};
use std::fs;

fn main() -> Result<()> {
    let matches = Command::new("validate-result-schema")
        .version("0.1.0")
        .about("Validate Result Schema v1 stability")
        .author("Smith Team")
        .arg(
            Arg::new("check-stability")
                .long("check-stability")
                .help("Check Result Schema hash stability for CI validation")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("generate-hash")
                .long("generate-hash")
                .help("Generate and display current Result Schema hash")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("validate-json")
                .long("validate-json")
                .value_name("FILE")
                .help("Validate a JSON file against Result Schema v1"),
        )
        .arg(
            Arg::new("expected-hash")
                .long("expected-hash")
                .value_name("HASH")
                .help("Expected Result Schema hash to validate against"),
        )
        .get_matches();

    if matches.get_flag("generate-hash") {
        let hash = ResultSchemaValidator::schema_hash();
        println!("{}", hash);
        return Ok(());
    }

    if let Some(json_file) = matches.get_one::<String>("validate-json") {
        validate_json_file(json_file)?;
        return Ok(());
    }

    if matches.get_flag("check-stability") {
        // Read expected hash from file or environment
        let expected_hash = if let Some(hash) = matches.get_one::<String>("expected-hash") {
            hash.clone()
        } else if let Ok(hash) = std::env::var("SMITH_RESULT_SCHEMA_HASH") {
            hash
        } else if let Ok(hash) = fs::read_to_string(".result-schema-hash") {
            hash.trim().to_string()
        } else {
            eprintln!(
                "❌ No expected hash provided. Use --expected-hash, SMITH_RESULT_SCHEMA_HASH env var, or create .result-schema-hash file"
            );
            std::process::exit(1);
        };

        let current_hash = ResultSchemaValidator::schema_hash();

        if expected_hash == current_hash {
            println!(
                "✅ Result Schema v{} stability validated",
                RESULT_SCHEMA_VERSION
            );
            println!("   Hash: {}", current_hash);
        } else {
            eprintln!("❌ Result Schema stability check failed:");
            eprintln!("   Expected: {}", expected_hash);
            eprintln!("   Current:  {}", current_hash);
            eprintln!(
                "   This indicates breaking changes to the Result Schema v{}",
                RESULT_SCHEMA_VERSION
            );
            std::process::exit(1);
        }
    } else {
        // Default: show current schema version and hash
        let hash = ResultSchemaValidator::schema_hash();

        println!("Result Schema Information:");
        println!("  Version: {}", RESULT_SCHEMA_VERSION);
        println!("  Hash:    {}", hash);

        // Show locked fields
        println!("  Locked Fields:");
        println!("    - ok (bool)");
        println!("    - status (string)");
        println!("    - latency_ms (u64)");
        println!("    - bytes (u64)");
        println!("    - capability_digest (string)");
        println!("    - commit (string)");
        println!("    - layer (string)");
        println!("    - name (string)");
        println!("    - mode (string)");
        println!("    - exp_id (string)");
        println!("    - idem_key (string)");
        println!("    - x_meta (HashMap<String, Value>) [ONLY extensibility point]");

        // Save hash to file for future validation
        if let Err(e) = fs::write(".result-schema-hash", &hash) {
            eprintln!("Warning: Could not save hash to .result-schema-hash: {}", e);
        } else {
            println!("  Saved hash to .result-schema-hash for future validation");
        }
    }

    Ok(())
}

fn validate_json_file(json_file: &str) -> Result<()> {
    println!("🔍 Validating JSON file: {}", json_file);

    let content = fs::read_to_string(json_file)
        .map_err(|e| anyhow::anyhow!("Failed to read file {}: {}", json_file, e))?;

    match ResultSchemaValidator::validate_json(&content) {
        Ok(result) => {
            println!(
                "✅ JSON validates against Result Schema v{}",
                RESULT_SCHEMA_VERSION
            );
            println!("   Status: {}", result.status);
            println!("   Layer:  {}", result.layer);
            println!("   Mode:   {}", result.mode);
            if !result.x_meta.is_empty() {
                println!("   Extensions: {} x_meta fields", result.x_meta.len());
            }
        }
        Err(e) => {
            eprintln!("❌ JSON validation failed:");
            eprintln!("   {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
