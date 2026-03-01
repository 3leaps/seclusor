use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use seclusor_core::constants::MAX_SECRETS_DOC_BYTES;
use seclusor_core::crud::{get_credential, list_credential_keys, set_credential, unset_credential};
use seclusor_core::validate::validate_strict;
use seclusor_core::{Credential, SeclusorError, SecretsFile};
use thiserror::Error;

const DEFAULT_SECRETS_FILE: &str = "secrets.json";
const REDACTED_OUTPUT: &str = "<redacted>";

#[derive(Debug, Error)]
enum CliError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Core(#[from] SeclusorError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

type CliResult<T> = std::result::Result<T, CliError>;

#[derive(Debug, Parser)]
#[command(name = "seclusor", version)]
struct Cli {
    #[command(subcommand)]
    command: TopLevelCommand,
}

#[derive(Debug, Subcommand)]
enum TopLevelCommand {
    Secrets(SecretsCommand),
}

#[derive(Debug, Parser)]
struct SecretsCommand {
    #[command(subcommand)]
    command: SecretsSubcommand,
}

#[derive(Debug, Subcommand)]
enum SecretsSubcommand {
    Init(InitArgs),
    Set(SetArgs),
    Get(GetArgs),
    List(ListArgs),
    Unset(UnsetArgs),
    Validate(ValidateArgs),
}

#[derive(Debug, Parser)]
struct InitArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE)]
    file: PathBuf,
    #[arg(long, default_value = "default")]
    project: String,
    #[arg(long)]
    env_prefix: Option<String>,
    #[arg(long)]
    description: Option<String>,
    #[arg(long, default_value_t = false)]
    force: bool,
}

#[derive(Debug, Parser)]
struct SetArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE)]
    file: PathBuf,
    #[arg(long)]
    project: Option<String>,
    #[arg(long)]
    key: String,
    #[arg(long, default_value = "secret")]
    credential_type: String,
    #[arg(long)]
    value: Option<String>,
    #[arg(long = "ref")]
    reference: Option<String>,
    #[arg(long, default_value_t = false)]
    create_project: bool,
}

#[derive(Debug, Parser)]
struct GetArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE)]
    file: PathBuf,
    #[arg(long)]
    project: Option<String>,
    #[arg(long)]
    key: String,
    #[arg(long, default_value_t = false)]
    reveal: bool,
}

#[derive(Debug, Parser)]
struct ListArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE)]
    file: PathBuf,
    #[arg(long)]
    project: Option<String>,
}

#[derive(Debug, Parser)]
struct UnsetArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE)]
    file: PathBuf,
    #[arg(long)]
    project: Option<String>,
    #[arg(long)]
    key: String,
}

#[derive(Debug, Parser)]
struct ValidateArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE)]
    file: PathBuf,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> CliResult<()> {
    let cli = Cli::parse();

    match cli.command {
        TopLevelCommand::Secrets(secrets) => handle_secrets_command(secrets.command),
    }
}

fn handle_secrets_command(command: SecretsSubcommand) -> CliResult<()> {
    match command {
        SecretsSubcommand::Init(args) => handle_init(args),
        SecretsSubcommand::Set(args) => handle_set(args),
        SecretsSubcommand::Get(args) => handle_get(args),
        SecretsSubcommand::List(args) => handle_list(args),
        SecretsSubcommand::Unset(args) => handle_unset(args),
        SecretsSubcommand::Validate(args) => handle_validate(args),
    }
}

fn handle_init(args: InitArgs) -> CliResult<()> {
    if args.file.exists() && !args.force {
        return Err(CliError::Message(format!(
            "secrets file already exists at {}; use --force to overwrite",
            args.file.display()
        )));
    }

    let mut secrets = SecretsFile::new(&args.project);
    secrets.env_prefix = args.env_prefix;
    secrets.description = args.description;
    validate_strict(&secrets)?;
    write_secrets_file(&args.file, &secrets, !args.force)?;
    println!("{}", args.file.display());
    Ok(())
}

fn handle_set(args: SetArgs) -> CliResult<()> {
    let mut secrets = read_secrets_file(&args.file)?;
    let credential = credential_from_set_args(&args)?;
    set_credential(
        &mut secrets,
        args.project.as_deref(),
        &args.key,
        credential,
        args.create_project,
    )?;
    validate_strict(&secrets)?;
    write_secrets_file(&args.file, &secrets, false)?;
    println!("ok");
    Ok(())
}

fn handle_get(args: GetArgs) -> CliResult<()> {
    let secrets = read_secrets_file(&args.file)?;
    let credential = get_credential(&secrets, args.project.as_deref(), &args.key)?;
    if args.reveal {
        if let Some(value) = &credential.value {
            println!("{value}");
            return Ok(());
        }
        if let Some(reference) = &credential.reference {
            println!("{reference}");
            return Ok(());
        }
        return Err(CliError::Message(
            "credential has neither value nor ref".to_string(),
        ));
    }

    println!("{REDACTED_OUTPUT}");
    Ok(())
}

fn handle_list(args: ListArgs) -> CliResult<()> {
    let secrets = read_secrets_file(&args.file)?;
    let keys = list_credential_keys(&secrets, args.project.as_deref())?;
    for key in keys {
        println!("{key}");
    }
    Ok(())
}

fn handle_unset(args: UnsetArgs) -> CliResult<()> {
    let mut secrets = read_secrets_file(&args.file)?;
    let _ = get_credential(&secrets, args.project.as_deref(), &args.key)?;
    let removed = unset_credential(&mut secrets, args.project.as_deref(), &args.key)?;
    if !removed {
        return Err(CliError::Message("credential was not removed".to_string()));
    }
    validate_strict(&secrets)?;
    write_secrets_file(&args.file, &secrets, false)?;
    println!("ok");
    Ok(())
}

fn handle_validate(args: ValidateArgs) -> CliResult<()> {
    let secrets = read_secrets_file(&args.file)?;
    validate_strict(&secrets)?;
    println!("valid");
    Ok(())
}

fn credential_from_set_args(args: &SetArgs) -> CliResult<Credential> {
    match (&args.value, &args.reference) {
        (Some(value), None) => Ok(Credential::with_value(&args.credential_type, value)),
        (None, Some(reference)) => Ok(Credential::with_ref(&args.credential_type, reference)),
        (Some(_), Some(_)) => Err(CliError::Message(
            "set requires exactly one of --value or --ref".to_string(),
        )),
        (None, None) => Err(CliError::Message(
            "set requires exactly one of --value or --ref".to_string(),
        )),
    }
}

fn read_secrets_file(path: &Path) -> CliResult<SecretsFile> {
    let bytes = read_file_with_limit(path, MAX_SECRETS_DOC_BYTES)?;
    let secrets: SecretsFile = serde_json::from_slice(&bytes)?;
    validate_strict(&secrets)?;
    Ok(secrets)
}

fn write_secrets_file(path: &Path, secrets: &SecretsFile, create_new: bool) -> CliResult<()> {
    let data = serde_json::to_vec_pretty(secrets)?;
    if data.len() > MAX_SECRETS_DOC_BYTES {
        return Err(CliError::Core(SeclusorError::DocumentTooLarge {
            actual: data.len(),
            max: MAX_SECRETS_DOC_BYTES,
        }));
    }

    if create_new {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        std::io::Write::write_all(&mut file, &data)?;
        std::io::Write::write_all(&mut file, b"\n")?;
        return Ok(());
    }

    fs::write(path, data)?;
    Ok(())
}

fn read_file_with_limit(path: &Path, max: usize) -> CliResult<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let mut limited = std::io::Read::by_ref(&mut file).take((max as u64) + 1);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf)?;
    if buf.len() > max {
        return Err(CliError::Core(SeclusorError::DocumentTooLarge {
            actual: buf.len(),
            max,
        }));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture_secrets() -> SecretsFile {
        let mut secrets = SecretsFile::new("demo");
        secrets.projects[0].credentials.insert(
            "API_KEY".to_string(),
            Credential::with_value("secret", "sk-123"),
        );
        secrets.projects[0].credentials.insert(
            "VAULT".to_string(),
            Credential::with_ref("ref", "vault://demo"),
        );
        secrets
    }

    fn write_raw_json(path: &Path, json: &str) {
        let mut file = fs::File::create(path).expect("create raw json");
        file.write_all(json.as_bytes()).expect("write raw json");
    }

    #[test]
    fn credential_from_set_args_requires_exactly_one_value_source() {
        let both = SetArgs {
            file: PathBuf::from("x"),
            project: None,
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("a".to_string()),
            reference: Some("b".to_string()),
            create_project: false,
        };
        assert!(credential_from_set_args(&both).is_err());

        let neither = SetArgs {
            value: None,
            reference: None,
            ..both
        };
        assert!(credential_from_set_args(&neither).is_err());
    }

    #[test]
    fn write_and_read_secrets_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.json");
        let secrets = fixture_secrets();

        write_secrets_file(&path, &secrets, true).expect("write");
        let loaded = read_secrets_file(&path).expect("read");
        assert_eq!(loaded, secrets);
    }

    #[test]
    fn read_secrets_file_rejects_oversized_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("oversized.json");
        let file = fs::File::create(&path).expect("create");
        file.set_len((MAX_SECRETS_DOC_BYTES as u64) + 1)
            .expect("set length");
        drop(file);

        let err = read_secrets_file(&path).expect_err("must fail");
        assert!(matches!(
            err,
            CliError::Core(SeclusorError::DocumentTooLarge { .. })
        ));
    }

    #[test]
    fn handle_unset_removes_existing_key() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.json");
        let secrets = fixture_secrets();
        write_secrets_file(&path, &secrets, true).expect("write");

        handle_unset(UnsetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
        })
        .expect("unset");

        let loaded = read_secrets_file(&path).expect("reload");
        assert!(!loaded.projects[0].credentials.contains_key("API_KEY"));
    }

    #[test]
    fn handle_get_rejects_invalid_document() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v9.9.9","projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","value":"x"}}}]}"#,
        );

        let err = handle_get(GetArgs {
            file: path,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: false,
        })
        .expect_err("must reject invalid document");
        assert!(matches!(err, CliError::Core(SeclusorError::Validation(_))));
    }

    #[test]
    fn handle_list_rejects_invalid_document() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v9.9.9","projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","value":"x"}}}]}"#,
        );

        let err = handle_list(ListArgs {
            file: path,
            project: Some("demo".to_string()),
        })
        .expect_err("must reject invalid document");
        assert!(matches!(err, CliError::Core(SeclusorError::Validation(_))));
    }

    #[test]
    fn handle_set_rejects_invalid_document() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v9.9.9","projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","value":"x"}}}]}"#,
        );

        let err = handle_set(SetArgs {
            file: path,
            project: Some("demo".to_string()),
            key: "NEW_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("new-value".to_string()),
            reference: None,
            create_project: false,
        })
        .expect_err("must reject invalid document");
        assert!(matches!(err, CliError::Core(SeclusorError::Validation(_))));
    }

    #[test]
    fn handle_unset_rejects_invalid_document() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v9.9.9","projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","value":"x"}}}]}"#,
        );

        let err = handle_unset(UnsetArgs {
            file: path,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
        })
        .expect_err("must reject invalid document");
        assert!(matches!(err, CliError::Core(SeclusorError::Validation(_))));
    }
}
