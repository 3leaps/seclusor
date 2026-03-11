use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Args, Parser, Subcommand, ValueEnum};
use seclusor_codec::{
    convert_inline_to_bundle, decrypt_bundle_from_file, decrypt_inline, encrypt_bundle_to_file,
    encrypt_inline, resolve_runtime_source_from_file, StorageCodec,
};
use seclusor_core::constants::{DEFAULT_CREDENTIAL_TYPE, MAX_SECRETS_DOC_BYTES};
use seclusor_core::crud::{get_credential, list_credential_keys, set_credential, unset_credential};
use seclusor_core::env::{
    export_env, format_env_vars, import_env_vars, parse_dotenv, EnvExportOptions, EnvFilter,
    EnvFormat,
};
use seclusor_core::validate::validate_strict;
use seclusor_core::{Credential, SeclusorError, SecretsFile};
use seclusor_crypto::{load_identity_file, parse_recipients, CryptoError, Identity};
use seclusor_keyring::{
    discover_recipients, generate_identity_file, KeyringError, Recipient,
    RecipientDiscoveryOptions, DEFAULT_RECIPIENTS_ENV_VAR,
};
use thiserror::Error;

const DEFAULT_SECRETS_FILE: &str = "secrets.json";
const REDACTED_OUTPUT: &str = "<redacted>";

#[derive(Debug, Clone, Copy)]
struct EmbeddedDoc {
    slug: &'static str,
    title: &'static str,
    topic: &'static str,
    content: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/embedded_docs.rs"));

#[derive(Debug, Error)]
enum CliError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Core(#[from] SeclusorError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Codec(#[from] seclusor_codec::CodecError),
    #[error(transparent)]
    Keyring(#[from] KeyringError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("command failed with exit code {0}")]
    CommandFailed(i32),
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
    Keys(KeysCommand),
    Docs(DocsCommand),
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
    ExportEnv(ExportEnvArgs),
    ImportEnv(ImportEnvArgs),
    Run(RunArgs),
    Bundle(BundleCommand),
    Inline(InlineCommand),
    Convert(ConvertArgs),
}

#[derive(Debug, Parser)]
struct KeysCommand {
    #[command(subcommand)]
    command: KeysSubcommand,
}

#[derive(Debug, Subcommand)]
enum KeysSubcommand {
    Age(AgeCommand),
}

#[derive(Debug, Parser)]
struct AgeCommand {
    #[command(subcommand)]
    command: AgeSubcommand,
}

#[derive(Debug, Subcommand)]
enum AgeSubcommand {
    Identity(IdentityCommand),
}

#[derive(Debug, Parser)]
struct IdentityCommand {
    #[command(subcommand)]
    command: IdentitySubcommand,
}

#[derive(Debug, Subcommand)]
enum IdentitySubcommand {
    Generate(IdentityGenerateArgs),
}

#[derive(Debug, Parser)]
struct DocsCommand {
    #[command(subcommand)]
    command: DocsSubcommand,
}

#[derive(Debug, Subcommand)]
enum DocsSubcommand {
    List(DocsListArgs),
    Show(DocsShowArgs),
}

#[derive(Debug, Parser)]
struct DocsListArgs {
    #[arg(long, value_enum, default_value_t = DocsFormatArg::Plain)]
    format: DocsFormatArg,
}

#[derive(Debug, Parser)]
struct DocsShowArgs {
    #[arg(long, value_enum, default_value_t = DocsFormatArg::Plain)]
    format: DocsFormatArg,
    slug: String,
}

#[derive(Debug, Parser)]
struct IdentityGenerateArgs {
    #[arg(long)]
    output: PathBuf,
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
    #[command(flatten)]
    identities: IdentityArgs,
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

#[derive(Debug, Parser)]
struct ExportEnvArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE)]
    file: PathBuf,
    #[arg(long)]
    project: Option<String>,
    #[arg(long, value_enum, default_value_t = EnvFormatArg::Dotenv)]
    format: EnvFormatArg,
    #[arg(long)]
    prefix: Option<String>,
    #[arg(long, default_value_t = false)]
    emit_ref: bool,
    #[arg(long = "allow")]
    allow: Vec<String>,
    #[arg(long = "deny")]
    deny: Vec<String>,
    #[command(flatten)]
    identities: IdentityArgs,
}

#[derive(Debug, Parser)]
struct ImportEnvArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE)]
    file: PathBuf,
    #[arg(long)]
    project: Option<String>,
    #[arg(long, default_value = DEFAULT_CREDENTIAL_TYPE)]
    credential_type: String,
    #[arg(long)]
    prefix: Option<String>,
    #[arg(long, default_value_t = true)]
    strip_prefix: bool,
    #[arg(long)]
    dotenv_file: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    create_project: bool,
}

#[derive(Debug, Parser)]
struct RunArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE)]
    file: PathBuf,
    #[arg(long)]
    project: Option<String>,
    #[arg(long)]
    prefix: Option<String>,
    #[arg(long, default_value_t = false)]
    emit_ref: bool,
    #[arg(long = "allow")]
    allow: Vec<String>,
    #[arg(long = "deny")]
    deny: Vec<String>,
    #[command(flatten)]
    identities: IdentityArgs,
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

#[derive(Debug, Parser)]
struct BundleCommand {
    #[command(subcommand)]
    command: BundleSubcommand,
}

#[derive(Debug, Subcommand)]
enum BundleSubcommand {
    Encrypt(BundleEncryptArgs),
    Decrypt(BundleDecryptArgs),
}

#[derive(Debug, Parser)]
struct BundleEncryptArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[command(flatten)]
    recipients: RecipientArgs,
}

#[derive(Debug, Parser)]
struct BundleDecryptArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[command(flatten)]
    identities: IdentityArgs,
}

#[derive(Debug, Parser)]
struct InlineCommand {
    #[command(subcommand)]
    command: InlineSubcommand,
}

#[derive(Debug, Subcommand)]
enum InlineSubcommand {
    Encrypt(InlineEncryptArgs),
    Decrypt(InlineDecryptArgs),
}

#[derive(Debug, Parser)]
struct InlineEncryptArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[command(flatten)]
    recipients: RecipientArgs,
}

#[derive(Debug, Parser)]
struct InlineDecryptArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[command(flatten)]
    identities: IdentityArgs,
}

#[derive(Debug, Parser)]
struct ConvertArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, value_enum)]
    from: StorageCodecArg,
    #[arg(long, value_enum)]
    to: StorageCodecArg,
    #[command(flatten)]
    recipients: RecipientArgs,
    #[command(flatten)]
    identities: IdentityArgs,
}

#[derive(Debug, Clone, Args, Default)]
struct RecipientArgs {
    #[arg(long = "recipient")]
    recipients: Vec<String>,
    #[arg(long = "recipient-file")]
    recipient_file: Option<PathBuf>,
    #[arg(long = "recipient-env-var")]
    recipient_env_var: Option<String>,
}

#[derive(Debug, Clone, Args, Default)]
struct IdentityArgs {
    #[arg(long = "identity-file")]
    identity_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum EnvFormatArg {
    Dotenv,
    Export,
    Json,
}

impl From<EnvFormatArg> for EnvFormat {
    fn from(value: EnvFormatArg) -> Self {
        match value {
            EnvFormatArg::Dotenv => EnvFormat::Dotenv,
            EnvFormatArg::Export => EnvFormat::Export,
            EnvFormatArg::Json => EnvFormat::Json,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StorageCodecArg {
    Bundle,
    Inline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DocsFormatArg {
    Plain,
    Json,
}

impl From<StorageCodecArg> for StorageCodec {
    fn from(value: StorageCodecArg) -> Self {
        match value {
            StorageCodecArg::Bundle => StorageCodec::Bundle,
            StorageCodecArg::Inline => StorageCodec::Inline,
        }
    }
}

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
        TopLevelCommand::Secrets(secrets) => handle_secrets_command(secrets.command),
        TopLevelCommand::Keys(keys) => handle_keys_command(keys.command),
        TopLevelCommand::Docs(docs) => handle_docs_command(docs.command),
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
        SecretsSubcommand::ExportEnv(args) => handle_export_env(args),
        SecretsSubcommand::ImportEnv(args) => handle_import_env(args),
        SecretsSubcommand::Run(args) => handle_run(args),
        SecretsSubcommand::Bundle(args) => handle_bundle_command(args.command),
        SecretsSubcommand::Inline(args) => handle_inline_command(args.command),
        SecretsSubcommand::Convert(args) => handle_convert(args),
    }
}

fn handle_keys_command(command: KeysSubcommand) -> CliResult<()> {
    match command {
        KeysSubcommand::Age(age) => match age.command {
            AgeSubcommand::Identity(identity) => match identity.command {
                IdentitySubcommand::Generate(args) => handle_identity_generate(args),
            },
        },
    }
}

fn handle_docs_command(command: DocsSubcommand) -> CliResult<()> {
    match command {
        DocsSubcommand::List(args) => handle_docs_list(args),
        DocsSubcommand::Show(args) => handle_docs_show(args),
    }
}

fn handle_docs_list(args: DocsListArgs) -> CliResult<()> {
    match args.format {
        DocsFormatArg::Plain => {
            for doc in EMBEDDED_DOCS {
                println!("{:<32} {}", doc.slug, doc.title);
            }
        }
        DocsFormatArg::Json => {
            let out: Vec<serde_json::Value> = EMBEDDED_DOCS
                .iter()
                .map(|doc| {
                    serde_json::json!({
                        "slug": doc.slug,
                        "title": doc.title,
                        "topic": doc.topic
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }
    Ok(())
}

fn handle_docs_show(args: DocsShowArgs) -> CliResult<()> {
    let doc = find_embedded_doc(&args.slug).ok_or_else(|| {
        let mut known: Vec<&str> = EMBEDDED_DOCS.iter().map(|d| d.slug).collect();
        known.sort_unstable();
        CliError::Message(format!(
            "unknown docs slug {:?}; run `seclusor docs list` (known: {})",
            args.slug,
            known.join(", ")
        ))
    })?;

    match args.format {
        DocsFormatArg::Plain => println!("{}", doc.content),
        DocsFormatArg::Json => {
            let out = serde_json::json!({
                "slug": doc.slug,
                "title": doc.title,
                "topic": doc.topic,
                "content": doc.content
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }

    Ok(())
}

fn find_embedded_doc(slug: &str) -> Option<&'static EmbeddedDoc> {
    EMBEDDED_DOCS.iter().find(|doc| doc.slug == slug)
}

fn handle_bundle_command(command: BundleSubcommand) -> CliResult<()> {
    match command {
        BundleSubcommand::Encrypt(args) => handle_bundle_encrypt(args),
        BundleSubcommand::Decrypt(args) => handle_bundle_decrypt(args),
    }
}

fn handle_inline_command(command: InlineSubcommand) -> CliResult<()> {
    match command {
        InlineSubcommand::Encrypt(args) => handle_inline_encrypt(args),
        InlineSubcommand::Decrypt(args) => handle_inline_decrypt(args),
    }
}

fn handle_identity_generate(args: IdentityGenerateArgs) -> CliResult<()> {
    let generated = generate_identity_file(&args.output)?;
    println!("{}", generated.recipient);
    Ok(())
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
    let identities = resolve_identities(&args.identities, false)?;
    let secrets = read_runtime_secrets_file(&args.file, &identities)?;
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

fn handle_export_env(args: ExportEnvArgs) -> CliResult<()> {
    let identities = resolve_identities(&args.identities, false)?;
    let secrets = read_runtime_secrets_file(&args.file, &identities)?;
    let output = render_export_env_output(&secrets, args.project.as_deref(), &args)?;
    println!("{output}");
    Ok(())
}

fn handle_import_env(args: ImportEnvArgs) -> CliResult<()> {
    let mut secrets = read_secrets_file(&args.file)?;

    let prefix = args
        .prefix
        .clone()
        .or_else(|| secrets.env_prefix.clone())
        .ok_or_else(|| {
            CliError::Message(
                "import-env requires --prefix or secrets file env_prefix for safe filtering"
                    .to_string(),
            )
        })?;

    let source = read_import_source(&args)?;
    let filtered: Vec<(String, String)> = source
        .into_iter()
        .filter(|(key, _)| key.starts_with(&prefix))
        .collect();

    if filtered.is_empty() {
        return Err(CliError::Message(format!(
            "no environment variables matched prefix {:?}",
            prefix
        )));
    }

    let strip_prefix = if args.strip_prefix {
        Some(prefix.as_str())
    } else {
        None
    };

    let imported = import_env_vars(&filtered, Some(&args.credential_type), strip_prefix);
    if imported.is_empty() {
        return Err(CliError::Message(
            "no credentials were imported from source variables".to_string(),
        ));
    }

    let mut count = 0usize;
    for (key, credential) in imported {
        set_credential(
            &mut secrets,
            args.project.as_deref(),
            &key,
            credential,
            args.create_project,
        )?;
        count += 1;
    }

    validate_strict(&secrets)?;
    write_secrets_file(&args.file, &secrets, false)?;
    println!("{count}");
    Ok(())
}

fn handle_run(args: RunArgs) -> CliResult<()> {
    let identities = resolve_identities(&args.identities, false)?;
    let secrets = read_runtime_secrets_file(&args.file, &identities)?;
    let env_vars = resolve_export_env_vars(
        &secrets,
        args.project.as_deref(),
        args.prefix.as_deref(),
        args.emit_ref,
        &args.allow,
        &args.deny,
    )?;

    let mut command = Command::new(&args.command[0]);
    command.args(&args.command[1..]);

    for env in &env_vars {
        command.env(&env.key, &env.value);
    }

    let status = command.status()?;
    if !status.success() {
        let code = status.code().unwrap_or(1);
        return Err(CliError::CommandFailed(code));
    }

    Ok(())
}

fn handle_bundle_encrypt(args: BundleEncryptArgs) -> CliResult<()> {
    let secrets = read_secrets_file(&args.input)?;
    let recipients = resolve_recipients(&args.recipients)?;
    encrypt_bundle_to_file(&secrets, &recipients, &args.output)?;
    println!("{}", args.output.display());
    Ok(())
}

fn handle_bundle_decrypt(args: BundleDecryptArgs) -> CliResult<()> {
    let identities = resolve_identities(&args.identities, true)?;
    let secrets = decrypt_bundle_from_file(&args.input, &identities)?;
    write_secrets_file(&args.output, &secrets, false)?;
    println!("{}", args.output.display());
    Ok(())
}

fn handle_inline_encrypt(args: InlineEncryptArgs) -> CliResult<()> {
    let secrets = read_secrets_file(&args.input)?;
    let recipients = resolve_recipients(&args.recipients)?;
    let encrypted = encrypt_inline(&secrets, &recipients)?;
    write_secrets_file(&args.output, &encrypted, false)?;
    println!("{}", args.output.display());
    Ok(())
}

fn handle_inline_decrypt(args: InlineDecryptArgs) -> CliResult<()> {
    let secrets = read_secrets_file(&args.input)?;
    let identities = resolve_identities(&args.identities, false)?;
    let decrypted = decrypt_inline(&secrets, &identities)?;
    write_secrets_file(&args.output, &decrypted, false)?;
    println!("{}", args.output.display());
    Ok(())
}

fn handle_convert(args: ConvertArgs) -> CliResult<()> {
    let from: StorageCodec = args.from.into();
    let to: StorageCodec = args.to.into();
    if from == to {
        return Err(CliError::Message(
            "convert requires distinct --from and --to codecs".to_string(),
        ));
    }

    let recipients = resolve_recipients(&args.recipients)?;
    let identities = resolve_identities(&args.identities, true)?;

    match (from, to) {
        (StorageCodec::Bundle, StorageCodec::Inline) => {
            let decrypted = decrypt_bundle_from_file(&args.input, &identities)?;
            let inline = encrypt_inline(&decrypted, &recipients)?;
            write_secrets_file(&args.output, &inline, false)?;
        }
        (StorageCodec::Inline, StorageCodec::Bundle) => {
            let inline = read_secrets_file(&args.input)?;
            let bundle = convert_inline_to_bundle(&inline, &identities, &recipients)?;
            fs::write(&args.output, bundle)?;
        }
        _ => {
            return Err(CliError::Message(
                "unsupported conversion codec combination".to_string(),
            ));
        }
    }

    println!("{}", args.output.display());
    Ok(())
}

fn render_export_env_output(
    secrets: &SecretsFile,
    project_slug: Option<&str>,
    args: &ExportEnvArgs,
) -> CliResult<String> {
    let vars = resolve_export_env_vars(
        secrets,
        project_slug,
        args.prefix.as_deref(),
        args.emit_ref,
        &args.allow,
        &args.deny,
    )?;
    Ok(format_env_vars(&vars, args.format.into()))
}

fn resolve_export_env_vars(
    secrets: &SecretsFile,
    project_slug: Option<&str>,
    prefix: Option<&str>,
    emit_ref: bool,
    allow: &[String],
    deny: &[String],
) -> CliResult<Vec<seclusor_core::env::EnvVar>> {
    let filter = EnvFilter {
        allow: if allow.is_empty() {
            vec!["*".to_string()]
        } else {
            allow.to_vec()
        },
        deny: deny.to_vec(),
    };
    let opts = EnvExportOptions {
        prefix: prefix.map(ToOwned::to_owned),
        emit_ref,
        filter,
    };
    Ok(export_env(secrets, project_slug, &opts)?)
}

fn read_import_source(args: &ImportEnvArgs) -> CliResult<Vec<(String, String)>> {
    if let Some(path) = &args.dotenv_file {
        let bytes = read_file_with_limit(path, MAX_SECRETS_DOC_BYTES)?;
        let contents = String::from_utf8(bytes).map_err(|_| {
            CliError::Message(format!(
                "dotenv file must be utf-8 encoded: {}",
                path.display()
            ))
        })?;
        return Ok(parse_dotenv(&contents));
    }

    Ok(std::env::vars().collect())
}

fn resolve_recipients(args: &RecipientArgs) -> CliResult<Vec<Recipient>> {
    let mut recipients = Vec::new();

    if !args.recipients.is_empty() {
        recipients.extend(parse_recipients(
            args.recipients.iter().map(String::as_str),
        )?);
    }

    if args.recipient_file.is_some() || args.recipient_env_var.is_some() {
        let discovered = discover_recipients(&RecipientDiscoveryOptions {
            recipient_file: args.recipient_file.clone(),
            recipient_env_var: args.recipient_env_var.clone(),
        })?;
        recipients.extend(discovered);
    } else if recipients.is_empty() && std::env::var(DEFAULT_RECIPIENTS_ENV_VAR).is_ok() {
        let discovered = discover_recipients(&RecipientDiscoveryOptions {
            recipient_file: None,
            recipient_env_var: Some(DEFAULT_RECIPIENTS_ENV_VAR.to_string()),
        })?;
        recipients.extend(discovered);
    }

    if recipients.is_empty() {
        return Err(CliError::Message(
            "no recipients resolved; provide --recipient, --recipient-file, or --recipient-env-var"
                .to_string(),
        ));
    }

    let mut seen = HashSet::new();
    recipients.retain(|recipient| seen.insert(recipient.to_string()));

    Ok(recipients)
}

fn resolve_identities(args: &IdentityArgs, required: bool) -> CliResult<Vec<Identity>> {
    let mut identities = Vec::new();

    for path in &args.identity_files {
        identities.extend(load_identity_file(path)?);
    }

    if required && identities.is_empty() {
        return Err(CliError::Message(
            "no identities resolved; provide --identity-file".to_string(),
        ));
    }

    Ok(identities)
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

fn read_runtime_secrets_file(path: &Path, identities: &[Identity]) -> CliResult<SecretsFile> {
    Ok(resolve_runtime_source_from_file(path, identities)?)
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

    const TEST_IDENTITY: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

    fn fixture_secrets() -> SecretsFile {
        let mut secrets = SecretsFile::new("demo");
        secrets.env_prefix = Some("APP_".to_string());
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

    fn fixture_identity() -> Identity {
        TEST_IDENTITY.parse().expect("test identity should parse")
    }

    fn fixture_recipient_string() -> String {
        fixture_identity().to_public().to_string()
    }

    fn write_identity_file(path: &Path, identity: &str) {
        let recipient = fixture_identity().to_public().to_string();
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path)
                .expect("create identity file");
            writeln!(file, "# public key: {recipient}").expect("write public key comment");
            writeln!(file, "{identity}").expect("write identity");
        }

        #[cfg(not(unix))]
        {
            fs::write(path, format!("# public key: {recipient}\n{identity}\n"))
                .expect("write identity file");
        }
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
            identities: IdentityArgs::default(),
        })
        .expect_err("must reject invalid document");
        assert!(matches!(
            err,
            CliError::Codec(seclusor_codec::CodecError::Core(SeclusorError::Validation(_)))
        ));
    }

    #[test]
    fn handle_get_bundle_redacted_and_reveal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let identity_file = dir.path().join("identity.txt");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");
        write_identity_file(&identity_file, TEST_IDENTITY);

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        handle_get(GetArgs {
            file: bundle.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: false,
            identities: IdentityArgs {
                identity_files: vec![identity_file.clone()],
            },
        })
        .expect("get redacted from bundle");

        handle_get(GetArgs {
            file: bundle,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: true,
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
        })
        .expect("get reveal from bundle");
    }

    #[test]
    fn handle_get_bundle_requires_identity_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        let err = handle_get(GetArgs {
            file: bundle,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: false,
            identities: IdentityArgs::default(),
        })
        .expect_err("bundle runtime must require identities");

        assert!(matches!(
            err,
            CliError::Codec(seclusor_codec::CodecError::BundleIdentityRequired)
        ));
    }

    #[test]
    fn handle_get_bundle_wrong_identity_does_not_disclose_secret() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let wrong_identity_file = dir.path().join("wrong-identity.txt");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");
        let wrong_identity = seclusor_crypto::identity_to_string(&Identity::generate());
        write_identity_file(&wrong_identity_file, &wrong_identity);

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        let err = handle_get(GetArgs {
            file: bundle,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: false,
            identities: IdentityArgs {
                identity_files: vec![wrong_identity_file],
            },
        })
        .expect_err("wrong identity should fail");

        let rendered = format!("{err}");
        assert!(!rendered.contains("sk-123"));
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

    #[test]
    fn render_export_env_output_honors_format_and_filter() {
        let secrets = fixture_secrets();
        let args = ExportEnvArgs {
            file: PathBuf::from("ignored.json"),
            project: Some("demo".to_string()),
            format: EnvFormatArg::Dotenv,
            prefix: Some("APP_".to_string()),
            emit_ref: false,
            allow: vec!["APP_API_*".to_string()],
            deny: vec![],
            identities: IdentityArgs::default(),
        };

        let output = render_export_env_output(&secrets, Some("demo"), &args).expect("export");
        assert_eq!(output, "APP_API_KEY=sk-123");
    }

    #[test]
    fn handle_run_propagates_nonzero_exit_code() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.json");
        let mut secrets = SecretsFile::new("demo");
        secrets.projects[0].credentials.insert(
            "API_KEY".to_string(),
            Credential::with_value("secret", "plain-value"),
        );
        write_secrets_file(&path, &secrets, true).expect("write file");

        #[cfg(unix)]
        let command = vec!["sh".to_string(), "-c".to_string(), "exit 42".to_string()];
        #[cfg(windows)]
        let command = vec!["cmd".to_string(), "/C".to_string(), "exit 42".to_string()];

        let err = handle_run(RunArgs {
            file: path,
            project: Some("demo".to_string()),
            prefix: None,
            emit_ref: false,
            allow: vec![],
            deny: vec![],
            identities: IdentityArgs::default(),
            command,
        })
        .expect_err("run should fail with command exit status");
        assert!(matches!(err, CliError::CommandFailed(42)));
    }

    #[test]
    fn handle_export_env_accepts_bundle_with_identity_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let identity_file = dir.path().join("identity.txt");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");
        write_identity_file(&identity_file, TEST_IDENTITY);

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        handle_export_env(ExportEnvArgs {
            file: bundle,
            project: Some("demo".to_string()),
            format: EnvFormatArg::Dotenv,
            prefix: None,
            emit_ref: false,
            allow: vec!["APP_API_*".to_string()],
            deny: vec![],
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
        })
        .expect("export env from bundle");
    }

    #[test]
    fn handle_export_env_bundle_requires_identity_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        let err = handle_export_env(ExportEnvArgs {
            file: bundle,
            project: Some("demo".to_string()),
            format: EnvFormatArg::Dotenv,
            prefix: None,
            emit_ref: false,
            allow: vec!["*".to_string()],
            deny: vec![],
            identities: IdentityArgs::default(),
        })
        .expect_err("bundle runtime must require identities");

        assert!(matches!(
            err,
            CliError::Codec(seclusor_codec::CodecError::BundleIdentityRequired)
        ));
    }

    #[test]
    fn handle_run_accepts_bundle_with_identity_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let identity_file = dir.path().join("identity.txt");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");
        write_identity_file(&identity_file, TEST_IDENTITY);

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        #[cfg(unix)]
        let command = vec![
            "sh".to_string(),
            "-c".to_string(),
            r#"test "${APP_API_KEY}" = "sk-123""#.to_string(),
        ];
        #[cfg(windows)]
        let command = vec![
            "cmd".to_string(),
            "/C".to_string(),
            r#"if "%APP_API_KEY%"=="sk-123" (exit 0) else (exit 33)"#.to_string(),
        ];

        handle_run(RunArgs {
            file: bundle,
            project: Some("demo".to_string()),
            prefix: None,
            emit_ref: false,
            allow: vec!["APP_API_KEY".to_string()],
            deny: vec![],
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
            command,
        })
        .expect("run from bundle");
    }

    #[test]
    fn handle_run_bundle_wrong_identity_does_not_disclose_secret() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let wrong_identity_file = dir.path().join("wrong-identity.txt");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");
        let wrong_identity = seclusor_crypto::identity_to_string(&Identity::generate());
        write_identity_file(&wrong_identity_file, &wrong_identity);

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        #[cfg(unix)]
        let command = vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()];
        #[cfg(windows)]
        let command = vec!["cmd".to_string(), "/C".to_string(), "exit 0".to_string()];

        let err = handle_run(RunArgs {
            file: bundle,
            project: Some("demo".to_string()),
            prefix: None,
            emit_ref: false,
            allow: vec!["APP_API_KEY".to_string()],
            deny: vec![],
            identities: IdentityArgs {
                identity_files: vec![wrong_identity_file],
            },
            command,
        })
        .expect_err("wrong identity should fail");

        let rendered = format!("{err}");
        assert!(!rendered.contains("sk-123"));
    }

    #[test]
    fn handle_export_env_bundle_wrong_identity_does_not_disclose_secret() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let wrong_identity_file = dir.path().join("wrong-identity.txt");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");
        let wrong_identity = seclusor_crypto::identity_to_string(&Identity::generate());
        write_identity_file(&wrong_identity_file, &wrong_identity);

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        let err = handle_export_env(ExportEnvArgs {
            file: bundle,
            project: Some("demo".to_string()),
            format: EnvFormatArg::Dotenv,
            prefix: None,
            emit_ref: false,
            allow: vec!["APP_API_KEY".to_string()],
            deny: vec![],
            identities: IdentityArgs {
                identity_files: vec![wrong_identity_file],
            },
        })
        .expect_err("wrong identity should fail");

        let rendered = format!("{err}");
        assert!(!rendered.contains("sk-123"));
    }

    #[test]
    fn handle_import_env_from_dotenv_filters_and_strips_prefix() {
        let dir = tempfile::tempdir().expect("temp dir");
        let secrets_path = dir.path().join("secrets.json");
        let dotenv_path = dir.path().join("vars.env");

        write_secrets_file(&secrets_path, &SecretsFile::new("demo"), true).expect("write file");
        fs::write(
            &dotenv_path,
            "APP_NEW_TOKEN=abc\nAPP_DB_URL=postgres://x\nIGNORED=1\n",
        )
        .expect("write dotenv");

        handle_import_env(ImportEnvArgs {
            file: secrets_path.clone(),
            project: Some("demo".to_string()),
            credential_type: "secret".to_string(),
            prefix: Some("APP_".to_string()),
            strip_prefix: true,
            dotenv_file: Some(dotenv_path),
            create_project: false,
        })
        .expect("import env");

        let secrets = read_secrets_file(&secrets_path).expect("reload");
        let project = &secrets.projects[0];
        assert!(project.credentials.contains_key("NEW_TOKEN"));
        assert!(project.credentials.contains_key("DB_URL"));
        assert!(!project.credentials.contains_key("IGNORED"));
    }

    #[test]
    fn bundle_encrypt_then_decrypt_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let output = dir.path().join("output.json");
        let identity_file = dir.path().join("identity.txt");

        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");
        write_identity_file(&identity_file, TEST_IDENTITY);

        handle_bundle_encrypt(BundleEncryptArgs {
            input: input.clone(),
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        handle_bundle_decrypt(BundleDecryptArgs {
            input: bundle,
            output: output.clone(),
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
        })
        .expect("bundle decrypt");

        let loaded = read_secrets_file(&output).expect("read output");
        assert_eq!(loaded, secrets);
    }

    #[test]
    fn bundle_decrypt_requires_identity_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");

        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        let err = handle_bundle_decrypt(BundleDecryptArgs {
            input: bundle,
            output: dir.path().join("output.json"),
            identities: IdentityArgs {
                identity_files: vec![],
            },
        })
        .expect_err("missing identity-file should fail");

        assert!(matches!(err, CliError::Message(_)));
        assert!(format!("{err}").contains("--identity-file"));
    }

    #[test]
    fn inline_encrypt_then_decrypt_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let inline = dir.path().join("inline.json");
        let output = dir.path().join("output.json");
        let identity_file = dir.path().join("identity.txt");

        let mut secrets = SecretsFile::new("demo");
        secrets.projects[0].credentials.insert(
            "API_KEY".to_string(),
            Credential::with_value("secret", "plain-value"),
        );
        write_secrets_file(&input, &secrets, true).expect("write input");
        write_identity_file(&identity_file, TEST_IDENTITY);

        handle_inline_encrypt(InlineEncryptArgs {
            input: input.clone(),
            output: inline.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("inline encrypt");

        handle_inline_decrypt(InlineDecryptArgs {
            input: inline,
            output: output.clone(),
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
        })
        .expect("inline decrypt");

        let loaded = read_secrets_file(&output).expect("read output");
        assert_eq!(loaded, secrets);
    }

    #[test]
    fn convert_inline_to_bundle_then_back_to_inline() {
        let dir = tempfile::tempdir().expect("temp dir");
        let source = dir.path().join("source-inline.json");
        let bundle = dir.path().join("bundle.age");
        let reconverted = dir.path().join("reconverted-inline.json");
        let identity_file = dir.path().join("identity.txt");

        let mut secrets = SecretsFile::new("demo");
        secrets.projects[0].credentials.insert(
            "API_KEY".to_string(),
            Credential::with_value("secret", "plain-value"),
        );
        let inline = encrypt_inline(&secrets, &[fixture_identity().to_public()]).expect("encrypt");
        write_secrets_file(&source, &inline, true).expect("write source");
        write_identity_file(&identity_file, TEST_IDENTITY);

        handle_convert(ConvertArgs {
            input: source,
            output: bundle.clone(),
            from: StorageCodecArg::Inline,
            to: StorageCodecArg::Bundle,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file.clone()],
            },
        })
        .expect("inline->bundle");

        handle_convert(ConvertArgs {
            input: bundle,
            output: reconverted.clone(),
            from: StorageCodecArg::Bundle,
            to: StorageCodecArg::Inline,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
        })
        .expect("bundle->inline");

        let roundtrip = read_secrets_file(&reconverted).expect("read reconverted");
        assert!(roundtrip.has_inline_ciphertext());
    }

    #[test]
    fn identity_generate_writes_identity_file_outside_repo_root() {
        let dir = tempfile::tempdir().expect("temp dir");
        let output = dir.path().join("identity.txt");

        handle_identity_generate(IdentityGenerateArgs {
            output: output.clone(),
        })
        .expect("generate identity");

        assert!(output.exists());
        let contents = fs::read_to_string(output).expect("read identity file");
        assert!(contents.contains("AGE-SECRET-KEY-"));
        assert!(contents.contains("# public key:"));
    }

    #[test]
    fn cli_rejects_identity_secret_key_argument_flag() {
        let parsed = Cli::try_parse_from([
            "seclusor",
            "secrets",
            "bundle",
            "decrypt",
            "--input",
            "in.age",
            "--output",
            "out.json",
            "--identity",
            TEST_IDENTITY,
        ]);
        assert!(parsed.is_err());
    }
}
