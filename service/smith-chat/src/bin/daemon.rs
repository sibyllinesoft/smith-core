use anyhow::Result;
use chat_bridge::daemon::{init_tracing, Cli};
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    if !tracing::dispatcher::has_been_set() {
        init_tracing();
    }
    let cli = Cli::parse();
    chat_bridge::daemon::run(cli).await
}
