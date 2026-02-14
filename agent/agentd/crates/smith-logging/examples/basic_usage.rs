//! Basic usage example for Smith logging

use smith_config::Config;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = Config::development();

    // Initialize logging
    let _guard =
        smith_logging::init_logging(&config.logging, &config.nats, "example-service").await?;

    // Use structured logging
    info!("Service starting");
    info!(
        user_id = "user123",
        action = "login",
        "User logged in successfully"
    );
    error!(error_code = 500, "Database connection failed");

    // Logs will be sent to NATS subjects like:
    // - smith.logs.example-service.info
    // - smith.logs.errors.example-service

    Ok(())
}
