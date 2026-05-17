use clap::Parser;

mod cli;
mod env_support;
mod error;
mod handlers;
mod io;
mod lenient;
mod resolve;
#[cfg(test)]
mod test_support;

use cli::{Cli, TopLevelCommand};
use error::{CliError, CliResult};

const DEFAULT_SECRETS_FILE: &str = "secrets.json";
const REDACTED_OUTPUT: &str = "<redacted>";

fn main() {
    match run() {
        Ok(()) => {}
        Err(CliError::CommandFailed(code)) => std::process::exit(code),
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    }
}

fn run() -> CliResult<()> {
    let cli = Cli::parse();

    match cli.command {
        TopLevelCommand::Secrets(secrets) => handlers::handle_secrets_command(secrets.command),
        TopLevelCommand::Keys(keys) => handlers::keys::handle_keys_command(keys.command),
        TopLevelCommand::Assets(assets) => handlers::handle_assets_command(assets.command),
        TopLevelCommand::Docs(docs) => handlers::docs::handle_docs_command(docs.command),
    }
}
