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
    Assets(AssetsCommand),
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
    /// Re-encrypt all fields to a new recipient set.
    Rekey(RekeyArgs),
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
    Signing(SigningCommand),
}

#[derive(Debug, Parser)]
pub(crate) struct AssetsCommand {
    #[command(subcommand)]
    pub(crate) command: AssetsSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AssetsSubcommand {
    Sign(AssetSignArgs),
    Verify(AssetVerifyArgs),
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
pub(crate) struct SigningCommand {
    #[command(subcommand)]
    pub(crate) command: SigningSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SigningSubcommand {
    Generate(SigningGenerateArgs),
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
pub(crate) struct SigningGenerateArgs {
    #[arg(
        long,
        help = "Path to write the age-encrypted signing key file (must not exist; 0600 on Unix)"
    )]
    pub(crate) output: PathBuf,
    #[command(flatten)]
    pub(crate) recipients: RecipientArgs,
}

#[derive(Debug, Parser)]
pub(crate) struct AssetSignArgs {
    #[arg(long, help = "Path to asset file to sign")]
    pub(crate) input: PathBuf,
    #[arg(long, help = "Path for detached .secsig signature output")]
    pub(crate) signature: Option<PathBuf>,
    #[arg(long, help = "Path to age-encrypted Ed25519 signing key file")]
    pub(crate) signing_key: PathBuf,
    #[arg(long, help = "Signed signer label metadata")]
    pub(crate) signer_label: Option<String>,
    #[arg(
        long,
        help = "Signed claimed time metadata (YYYY-MM-DDTHH:MM:SSZ; not trusted time)"
    )]
    pub(crate) claimed_at: Option<String>,
    #[command(flatten)]
    pub(crate) identities: IdentityArgs,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
}

#[derive(Debug, Parser)]
pub(crate) struct AssetVerifyArgs {
    #[arg(long, help = "Path to asset file to verify")]
    pub(crate) input: PathBuf,
    #[arg(long, help = "Path to detached .secsig signature file")]
    pub(crate) signature: Option<PathBuf>,
    #[arg(
        long,
        conflicts_with = "trust_embedded_key",
        help = "Expected public key as unpadded base64url raw Ed25519 public-key bytes"
    )]
    pub(crate) public_key: Option<String>,
    #[arg(
        long,
        conflicts_with = "trust_embedded_key",
        help = "Expected key fingerprint as unpadded base64url raw SHA-256 fingerprint bytes"
    )]
    pub(crate) fingerprint: Option<String>,
    #[arg(
        long,
        default_value_t = false,
        help = "Trust the public key embedded in the signature envelope (self-consistency only)"
    )]
    pub(crate) trust_embedded_key: bool,
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
    #[arg(
        long,
        default_value_t = false,
        help = "Overwrite an existing plaintext secrets file with an empty skeleton \
                (never combined with --codec)"
    )]
    pub(crate) force: bool,
    #[arg(
        long,
        value_enum,
        help = "Create an encrypted secrets document. Only 'bundle' is supported \
                (create-only; path must not exist). Inline encrypted documents are \
                created by encrypting a value via set/import-env/rekey"
    )]
    pub(crate) codec: Option<StorageCodecArg>,
    #[command(flatten)]
    pub(crate) recipients: RecipientArgs,
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
        help = "Store a direct secret value via argv (legacy; warns on stderr). \
                Prefer --value-stdin, --value-file, or --value-env. Mutually \
                exclusive with other value channels and --ref. Omit all value \
                channels and --ref with --description for a description-only edit"
    )]
    pub(crate) value: Option<String>,
    #[arg(
        long = "value-stdin",
        default_value_t = false,
        help = "Read the secret value from stdin (preferred non-argv channel)"
    )]
    pub(crate) value_stdin: bool,
    #[arg(
        long = "value-file",
        value_name = "PATH",
        help = "Read the secret value from a file (preferred non-argv channel)"
    )]
    pub(crate) value_file: Option<PathBuf>,
    #[arg(
        long = "value-env",
        value_name = "VAR",
        help = "Read the secret value from an environment variable (preferred \
                non-argv channel)"
    )]
    pub(crate) value_env: Option<String>,
    #[arg(
        long = "ref",
        help = "Store a reference pointer instead of a value (e.g. vault path, \
                env var name, URI). Use forward slashes for portability; \
                backslashes are preserved but may not be portable across \
                platforms. Mutually exclusive with value channels"
    )]
    pub(crate) reference: Option<String>,
    #[arg(
        long,
        help = "Human-readable description (single-line, max 128 chars). \
                With neither a value channel nor --ref: description-only edit \
                (existing credential required; empty string clears). \
                With value/--ref: set or replace description; omit to \
                preserve an existing description"
    )]
    pub(crate) description: Option<String>,
    #[arg(
        long,
        default_value_t = false,
        help = "Create project if it does not exist (requires a value channel or \
                --ref; not valid for description-only edits)"
    )]
    pub(crate) create_project: bool,
    #[command(flatten)]
    pub(crate) recipients: RecipientArgs,
    #[command(flatten)]
    pub(crate) identities: IdentityArgs,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
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
    #[command(flatten)]
    pub(crate) identities: IdentityArgs,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
}

#[derive(Debug, Parser)]
pub(crate) struct UnsetArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE, help = "Path to secrets file")]
    pub(crate) file: PathBuf,
    #[arg(long, help = "Project slug (auto-resolved if only one project exists)")]
    pub(crate) project: Option<String>,
    #[arg(long, help = "Credential key name to remove")]
    pub(crate) key: String,
    /// Required for bundle unset (encrypting whole-document rewrite).
    #[command(flatten)]
    pub(crate) recipients: RecipientArgs,
    #[command(flatten)]
    pub(crate) identities: IdentityArgs,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
}

#[derive(Debug, Parser)]
pub(crate) struct ValidateArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE, help = "Path to secrets file")]
    pub(crate) file: PathBuf,
    #[command(flatten)]
    pub(crate) identities: IdentityArgs,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
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
    #[arg(
        long = "allow",
        help = "Glob pattern for keys to export (repeatable). Required for \
                --format export (shell); optional for dotenv/json (default: all)"
    )]
    pub(crate) allow: Vec<String>,
    #[arg(long = "deny", help = "Glob pattern for keys to exclude (repeatable)")]
    pub(crate) deny: Vec<String>,
    #[arg(
        long,
        default_value_t = false,
        help = "Allow --format export to write to a TTY (values would be visible). \
                Not required when stdout is a pipe or redirect (e.g. eval)"
    )]
    pub(crate) force: bool,
    #[arg(
        long,
        short = 'v',
        default_value_t = false,
        help = "For --format export: print a completion summary on stderr \
                (variable count + project). Does not echo --allow patterns \
                unless this flag is set"
    )]
    pub(crate) verbose: bool,
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
    #[command(flatten)]
    pub(crate) recipients: RecipientArgs,
    #[command(flatten)]
    pub(crate) identities: IdentityArgs,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
}

#[derive(Debug, Parser)]
pub(crate) struct RekeyArgs {
    #[arg(long, default_value = DEFAULT_SECRETS_FILE, help = "Path to secrets file")]
    pub(crate) file: PathBuf,
    #[arg(
        long,
        help = "Write rekeyed output to this path (default: overwrite --file in place)"
    )]
    pub(crate) output: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) recipients: RecipientArgs,
    #[command(flatten)]
    pub(crate) identities: IdentityArgs,
    #[command(flatten)]
    pub(crate) passphrase: PassphraseArgs,
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
        conflicts_with = "identity_public_key",
        help = "Path to an age identity file (private key) for decryption; \
                repeatable. File must be 0600 and owned by the current user on Unix. \
                Conflicts with --identity-public-key"
    )]
    pub(crate) identity_files: Vec<PathBuf>,
    #[arg(
        long = "identity-public-key",
        value_name = "AGE1",
        conflicts_with = "identity_files",
        value_parser = parse_identity_public_key_arg,
        help = "Age recipient (age1...) for identity lookup in the bounded keyring \
                locations (config dir + identities/ subdir). Public metadata only \
                during discovery; loads only the matched file. Conflicts with \
                --identity-file"
    )]
    pub(crate) identity_public_key: Option<String>,
}

/// Clap value parser: require a well-formed age recipient (`age1...`).
fn parse_identity_public_key_arg(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("identity public key must not be empty".to_string());
    }
    trimmed
        .parse::<seclusor_crypto::Recipient>()
        .map(|r| r.to_string())
        .map_err(|_| "identity public key must be a valid age recipient (age1...)".to_string())
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
        help = "Read passphrase from the named environment variable (secrets run excludes this name from the child environment; parent process may still hold it)"
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    use crate::test_support::TEST_IDENTITY;

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

    #[test]
    fn identity_public_key_conflicts_with_identity_file() {
        let parsed = Cli::try_parse_from([
            "seclusor",
            "secrets",
            "list",
            "--file",
            "secrets.json",
            "--identity-file",
            "id.txt",
            "--identity-public-key",
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
        ]);
        assert!(parsed.is_err(), "must reject simultaneous selectors");
    }

    #[test]
    fn identity_public_key_rejects_non_age1_at_parse_time() {
        let parsed = Cli::try_parse_from([
            "seclusor",
            "secrets",
            "validate",
            "--file",
            "secrets.json",
            "--identity-public-key",
            "not-a-recipient",
        ]);
        assert!(parsed.is_err());
    }

    #[test]
    fn identity_public_key_accepts_valid_age1() {
        let pk = crate::test_support::fixture_recipient_string();
        let parsed = Cli::try_parse_from([
            "seclusor",
            "secrets",
            "list",
            "--file",
            "secrets.json",
            "--identity-public-key",
            &pk,
        ]);
        assert!(parsed.is_ok());
        match parsed.unwrap().command {
            TopLevelCommand::Secrets(cmd) => match cmd.command {
                SecretsSubcommand::List(args) => {
                    assert_eq!(
                        args.identities.identity_public_key.as_deref(),
                        Some(pk.as_str())
                    );
                    assert!(args.identities.identity_files.is_empty());
                }
                _ => panic!("expected list"),
            },
            _ => panic!("expected secrets"),
        }
    }
}
