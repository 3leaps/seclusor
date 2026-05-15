use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use seclusor_codec::StorageCodec;
use seclusor_core::constants::DEFAULT_CREDENTIAL_TYPE;
use seclusor_core::env::EnvFormat;

use crate::DEFAULT_SECRETS_FILE;

#[derive(Debug, Parser)]
#[command(name = "seclusor", version)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: TopLevelCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum TopLevelCommand {
    Secrets(SecretsCommand),
    Keys(KeysCommand),
    Docs(DocsCommand),
}

#[derive(Debug, Parser)]
pub(crate) struct SecretsCommand {
    #[command(subcommand)]
    pub(crate) command: SecretsSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SecretsSubcommand {
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
    Blob(BlobCommand),
    Convert(ConvertArgs),
}

#[derive(Debug, Parser)]
pub(crate) struct KeysCommand {
    #[command(subcommand)]
    pub(crate) command: KeysSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum KeysSubcommand {
    Age(AgeCommand),
}

#[derive(Debug, Parser)]
pub(crate) struct AgeCommand {
    #[command(subcommand)]
    pub(crate) command: AgeSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AgeSubcommand {
    Identity(IdentityCommand),
}

#[derive(Debug, Parser)]
pub(crate) struct IdentityCommand {
    #[command(subcommand)]
    pub(crate) command: IdentitySubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum IdentitySubcommand {
    Generate(IdentityGenerateArgs),
}

#[derive(Debug, Parser)]
pub(crate) struct DocsCommand {
    #[command(subcommand)]
    pub(crate) command: DocsSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum DocsSubcommand {
    List(DocsListArgs),
    Show(DocsShowArgs),
}

#[derive(Debug, Parser)]
pub(crate) struct DocsListArgs {
    #[arg(long, value_enum, default_value_t = DocsFormatArg::Plain, help = "Output format")]
    pub(crate) format: DocsFormatArg,
}

#[derive(Debug, Parser)]
pub(crate) struct DocsShowArgs {
    #[arg(long, value_enum, default_value_t = DocsFormatArg::Plain, help = "Output format")]
    pub(crate) format: DocsFormatArg,
    pub(crate) slug: String,
}

#[derive(Debug, Parser)]
pub(crate) struct IdentityGenerateArgs {
    #[arg(
        long,
        help = "Path to write the new identity file (must not exist; 0600 on Unix)"
    )]
    pub(crate) output: PathBuf,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
}

#[derive(Debug, Parser)]
pub(crate) struct InitArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE, help = "Path to secrets file")]
    pub(crate) file: PathBuf,
    #[arg(long, default_value = "default", help = "Project slug")]
    pub(crate) project: String,
    #[arg(long, help = "Default env var prefix for this project")]
    pub(crate) env_prefix: Option<String>,
    #[arg(long, help = "Project description")]
    pub(crate) description: Option<String>,
    #[arg(long, default_value_t = false, help = "Overwrite existing file")]
    pub(crate) force: bool,
}

#[derive(Debug, Parser, Clone)]
pub(crate) struct SetArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE, help = "Path to secrets file")]
    pub(crate) file: PathBuf,
    #[arg(long, help = "Project slug (auto-resolved if only one project exists)")]
    pub(crate) project: Option<String>,
    #[arg(long, help = "Credential key name (e.g. DB_PASSWORD)")]
    pub(crate) key: String,
    #[arg(long, default_value = "secret", help = "Credential type label")]
    pub(crate) credential_type: String,
    #[arg(
        long,
        help = "Store a direct secret value (mutually exclusive with --ref)"
    )]
    pub(crate) value: Option<String>,
    #[arg(
        long = "ref",
        help = "Store a reference pointer instead of a value (e.g. vault path, \
                env var name, URI). Use forward slashes for portability; \
                backslashes are preserved but may not be portable across \
                platforms. Mutually exclusive with --value"
    )]
    pub(crate) reference: Option<String>,
    #[arg(long, help = "Human-readable description (single-line, max 128 chars)")]
    pub(crate) description: Option<String>,
    #[arg(
        long,
        default_value_t = false,
        help = "Create project if it does not exist"
    )]
    pub(crate) create_project: bool,
}

#[derive(Debug, Parser)]
pub(crate) struct GetArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE, help = "Path to secrets file")]
    pub(crate) file: PathBuf,
    #[arg(long, help = "Project slug (auto-resolved if only one project exists)")]
    pub(crate) project: Option<String>,
    #[arg(long, help = "Credential key name")]
    pub(crate) key: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Show the decrypted value (default: redacted)"
    )]
    pub(crate) reveal: bool,
    #[arg(
        long,
        default_value_t = false,
        conflicts_with = "reveal",
        help = "Show description metadata only (no value)"
    )]
    pub(crate) show_description: bool,
    #[command(flatten)]
    pub(crate) identities: IdentityArgs,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
}

#[derive(Debug, Parser)]
pub(crate) struct ListArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE, help = "Path to secrets file")]
    pub(crate) file: PathBuf,
    #[arg(long, help = "Project slug (auto-resolved if only one project exists)")]
    pub(crate) project: Option<String>,
    #[arg(
        long,
        short = 'v',
        default_value_t = false,
        help = "Show KEY<TAB>description (no values)"
    )]
    pub(crate) verbose: bool,
}

#[derive(Debug, Parser)]
pub(crate) struct UnsetArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE, help = "Path to secrets file")]
    pub(crate) file: PathBuf,
    #[arg(long, help = "Project slug (auto-resolved if only one project exists)")]
    pub(crate) project: Option<String>,
    #[arg(long, help = "Credential key name to remove")]
    pub(crate) key: String,
}

#[derive(Debug, Parser)]
pub(crate) struct ValidateArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE, help = "Path to secrets file")]
    pub(crate) file: PathBuf,
}

#[derive(Debug, Parser)]
pub(crate) struct ExportEnvArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE, help = "Path to secrets file")]
    pub(crate) file: PathBuf,
    #[arg(long, help = "Project slug (auto-resolved if only one project exists)")]
    pub(crate) project: Option<String>,
    #[arg(long, value_enum, default_value_t = EnvFormatArg::Dotenv, help = "Output format")]
    pub(crate) format: EnvFormatArg,
    #[arg(long, help = "Prefix to add to exported variable names")]
    pub(crate) prefix: Option<String>,
    #[arg(
        long,
        default_value_t = false,
        help = "Include ref credentials as literal strings (default: excluded)"
    )]
    pub(crate) emit_ref: bool,
    #[arg(long = "allow", help = "Glob pattern for keys to export (repeatable)")]
    pub(crate) allow: Vec<String>,
    #[arg(long = "deny", help = "Glob pattern for keys to exclude (repeatable)")]
    pub(crate) deny: Vec<String>,
    #[command(flatten)]
    pub(crate) identities: IdentityArgs,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
}

#[derive(Debug, Parser)]
pub(crate) struct ImportEnvArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE, help = "Path to secrets file")]
    pub(crate) file: PathBuf,
    #[arg(long, help = "Project slug (auto-resolved if only one project exists)")]
    pub(crate) project: Option<String>,
    #[arg(long, default_value = DEFAULT_CREDENTIAL_TYPE, help = "Credential type label")]
    pub(crate) credential_type: String,
    #[arg(long, help = "Only import env vars with this prefix")]
    pub(crate) prefix: Option<String>,
    #[arg(
        long,
        default_value_t = true,
        help = "Strip prefix from imported key names"
    )]
    pub(crate) strip_prefix: bool,
    #[arg(
        long,
        help = "Import from a .env file instead of the current environment"
    )]
    pub(crate) dotenv_file: Option<PathBuf>,
    #[arg(
        long,
        default_value_t = false,
        help = "Create project if it does not exist"
    )]
    pub(crate) create_project: bool,
}

#[derive(Debug, Parser)]
pub(crate) struct RunArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE, help = "Path to secrets file")]
    pub(crate) file: PathBuf,
    #[arg(long, help = "Project slug (auto-resolved if only one project exists)")]
    pub(crate) project: Option<String>,
    #[arg(long, help = "Prefix to add to injected variable names")]
    pub(crate) prefix: Option<String>,
    #[arg(
        long,
        default_value_t = false,
        help = "Include ref credentials as literal strings (default: excluded)"
    )]
    pub(crate) emit_ref: bool,
    #[arg(long = "allow", help = "Glob pattern for keys to inject (repeatable)")]
    pub(crate) allow: Vec<String>,
    #[arg(long = "deny", help = "Glob pattern for keys to exclude (repeatable)")]
    pub(crate) deny: Vec<String>,
    #[command(flatten)]
    pub(crate) identities: IdentityArgs,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) command: Vec<String>,
}

#[derive(Debug, Parser)]
pub(crate) struct BundleCommand {
    #[command(subcommand)]
    pub(crate) command: BundleSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum BundleSubcommand {
    Encrypt(BundleEncryptArgs),
    Decrypt(BundleDecryptArgs),
}

#[derive(Debug, Parser)]
pub(crate) struct BundleEncryptArgs {
    #[arg(long, help = "Path to plaintext secrets file")]
    pub(crate) input: PathBuf,
    #[arg(long, help = "Path for encrypted .age output")]
    pub(crate) output: PathBuf,
    #[command(flatten)]
    pub(crate) recipients: RecipientArgs,
}

#[derive(Debug, Parser)]
pub(crate) struct BundleDecryptArgs {
    #[arg(long, help = "Path to encrypted .age bundle")]
    pub(crate) input: PathBuf,
    #[arg(long, help = "Path for decrypted output")]
    pub(crate) output: PathBuf,
    #[command(flatten)]
    pub(crate) identities: IdentityArgs,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
}

#[derive(Debug, Parser)]
pub(crate) struct InlineCommand {
    #[command(subcommand)]
    pub(crate) command: InlineSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum InlineSubcommand {
    Encrypt(InlineEncryptArgs),
    Decrypt(InlineDecryptArgs),
}

#[derive(Debug, Parser)]
pub(crate) struct InlineEncryptArgs {
    #[arg(long, help = "Path to plaintext secrets file")]
    pub(crate) input: PathBuf,
    #[arg(long, help = "Path for inline-encrypted output")]
    pub(crate) output: PathBuf,
    #[command(flatten)]
    pub(crate) recipients: RecipientArgs,
}

#[derive(Debug, Parser)]
pub(crate) struct InlineDecryptArgs {
    #[arg(long, help = "Path to inline-encrypted secrets file")]
    pub(crate) input: PathBuf,
    #[arg(long, help = "Path for decrypted output")]
    pub(crate) output: PathBuf,
    #[command(flatten)]
    pub(crate) identities: IdentityArgs,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
}

#[derive(Debug, Parser)]
pub(crate) struct BlobCommand {
    #[command(subcommand)]
    pub(crate) command: BlobSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum BlobSubcommand {
    Encrypt(BlobEncryptArgs),
    Decrypt(BlobDecryptArgs),
}

#[derive(Debug, Parser)]
pub(crate) struct BlobEncryptArgs {
    #[arg(long, help = "Path to input file (any format)")]
    pub(crate) input: PathBuf,
    #[arg(long, help = "Path for encrypted .age output")]
    pub(crate) output: PathBuf,
    #[arg(long, default_value_t = false, help = "Allow files larger than 10 MB")]
    pub(crate) allow_large: bool,
    #[command(flatten)]
    pub(crate) recipients: RecipientArgs,
}

#[derive(Debug, Parser)]
pub(crate) struct BlobDecryptArgs {
    #[arg(long, help = "Path to encrypted .age file")]
    pub(crate) input: PathBuf,
    #[arg(long, help = "Path for decrypted output")]
    pub(crate) output: PathBuf,
    #[arg(long, default_value_t = false, help = "Allow files larger than 10 MB")]
    pub(crate) allow_large: bool,
    #[command(flatten)]
    pub(crate) identities: IdentityArgs,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
}

#[derive(Debug, Parser)]
pub(crate) struct ConvertArgs {
    #[arg(long, help = "Path to input secrets file")]
    pub(crate) input: PathBuf,
    #[arg(long, help = "Path for converted output")]
    pub(crate) output: PathBuf,
    #[arg(long, value_enum, help = "Source codec (bundle or inline)")]
    pub(crate) from: StorageCodecArg,
    #[arg(long, value_enum, help = "Target codec (bundle or inline)")]
    pub(crate) to: StorageCodecArg,
    #[command(flatten)]
    pub(crate) recipients: RecipientArgs,
    #[command(flatten)]
    pub(crate) identities: IdentityArgs,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct RecipientArgs {
    #[arg(
        long = "recipient",
        help = "Age public key (age1...) to encrypt for; repeatable for multi-recipient"
    )]
    pub(crate) recipients: Vec<String>,
    #[arg(
        long = "recipient-file",
        help = "Path to a file containing age recipients (one per line, # comments allowed)"
    )]
    pub(crate) recipient_file: Option<PathBuf>,
    #[arg(
        long = "recipient-env-var",
        help = "Environment variable containing age recipients (comma or newline separated)"
    )]
    pub(crate) recipient_env_var: Option<String>,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct IdentityArgs {
    #[arg(
        long = "identity-file",
        help = "Path to an age identity file (private key) for decryption; \
                repeatable. File must be 0600 on Unix"
    )]
    pub(crate) identity_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct PassphraseArgs {
    #[arg(
        long,
        conflicts_with_all = ["passphrase_env", "passphrase_file", "passphrase_stdin"],
        help = "Prompt interactively for a passphrase (no echo)"
    )]
    pub(crate) passphrase: bool,

    #[arg(
        long,
        value_name = "VAR",
        conflicts_with_all = ["passphrase", "passphrase_file", "passphrase_stdin"],
        help = "Read passphrase from the named environment variable"
    )]
    pub(crate) passphrase_env: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["passphrase", "passphrase_env", "passphrase_stdin"],
        help = "Read passphrase from a file (first line, 0600 enforced on Unix)"
    )]
    pub(crate) passphrase_file: Option<PathBuf>,

    #[arg(
        long,
        conflicts_with_all = ["passphrase", "passphrase_env", "passphrase_file"],
        help = "Read passphrase from stdin (one line)"
    )]
    pub(crate) passphrase_stdin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum EnvFormatArg {
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
pub(crate) enum StorageCodecArg {
    Bundle,
    Inline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum DocsFormatArg {
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
