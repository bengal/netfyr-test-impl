mod apply;

use clap::{Parser, Subcommand};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "netfyr", about = "Declarative Linux network configuration")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Apply network policies to the system
    Apply(apply::ApplyArgs),
    /// Query current system network state
    Query(QueryArgs),
}

/// Arguments for the `query` subcommand (not yet implemented).
#[derive(clap::Args)]
struct QueryArgs {}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Apply(args) => match apply::run_apply(args).await {
            Ok(code) => code,
            Err(e) => {
                eprintln!("Error: {:#}", e);
                ExitCode::from(2u8)
            }
        },
        Commands::Query(_) => {
            eprintln!("Error: the query command is not yet implemented");
            ExitCode::from(2u8)
        }
    }
}
