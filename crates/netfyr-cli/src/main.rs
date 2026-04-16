mod apply;
mod query;

use clap::{Parser, Subcommand};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "netfyr", about = "Declarative Linux network configuration")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Apply network policies to the system
    Apply(apply::ApplyArgs),
    /// Query current system network state
    Query(query::QueryArgs),
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        None => {
            println!("netfyr");
            ExitCode::from(0u8)
        }
        Some(Commands::Apply(args)) => match apply::run_apply(args).await {
            Ok(code) => code,
            Err(e) => {
                eprintln!("Error: {:#}", e);
                ExitCode::from(2u8)
            }
        },
        Some(Commands::Query(args)) => match query::run_query(args).await {
            Ok(code) => code,
            Err(e) => {
                eprintln!("Error: {:#}", e);
                ExitCode::from(2u8)
            }
        },
    }
}
