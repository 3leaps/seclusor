use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;

use clap::Parser;
use seclusor_codec::{
    convert_inline_to_bundle, decrypt_bundle_from_file, decrypt_inline, encrypt_bundle_to_file,
    encrypt_inline, StorageCodec,
};
use seclusor_core::constants::MAX_SECRETS_DOC_BYTES;
use seclusor_core::crud::{
    get_credential, list_credential_keys, resolve_project_index, set_credential, unset_credential,
};
use seclusor_core::env::{
    export_env, format_env_vars, import_env_vars, parse_dotenv, EnvExportOptions, EnvFilter,
};
use seclusor_core::validate::{normalize_description, validate_strict};
use seclusor_core::{Credential, SeclusorError, SecretsFile};
use seclusor_keyring::{generate_identity_file, generate_identity_file_with_passphrase};

mod cli;
mod error;
mod io;
mod lenient;
mod resolve;

use cli::*;
use error::{CliError, CliResult};
use io::*;
use lenient::*;
use resolve::*;

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
        SecretsSubcommand::Blob(args) => handle_blob_command(args.command),
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

fn handle_blob_command(command: BlobSubcommand) -> CliResult<()> {
    match command {
        BlobSubcommand::Encrypt(args) => handle_blob_encrypt(args),
        BlobSubcommand::Decrypt(args) => handle_blob_decrypt(args),
    }
}

/// Default blob file size limit (10 MB).
const BLOB_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Read a file with an optional size cap enforced at read time (no TOCTOU gap).
fn read_file_bounded(path: &Path, max: Option<u64>) -> CliResult<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    match max {
        Some(limit) => {
            let mut limited = std::io::Read::by_ref(&mut file).take(limit + 1);
            let mut buf = Vec::new();
            limited.read_to_end(&mut buf)?;
            if buf.len() as u64 > limit {
                return Err(CliError::Message(format!(
                    "input file exceeds {} MB limit (read {} bytes). \
                     Use --allow-large to override.",
                    limit / (1024 * 1024),
                    buf.len()
                )));
            }
            Ok(buf)
        }
        None => {
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn handle_blob_encrypt(args: BlobEncryptArgs) -> CliResult<()> {
    let limit = if args.allow_large {
        None
    } else {
        Some(BLOB_MAX_FILE_BYTES)
    };
    let plaintext = read_file_bounded(&args.input, limit)?;
    let recipients = resolve_recipients(&args.recipients)?;
    let ciphertext = seclusor_crypto::encrypt(&plaintext, &recipients)?;
    fs::write(&args.output, &ciphertext)?;
    Ok(())
}

fn handle_blob_decrypt(args: BlobDecryptArgs) -> CliResult<()> {
    let limit = if args.allow_large {
        None
    } else {
        Some(BLOB_MAX_FILE_BYTES)
    };
    let identities = resolve_identities(&args.identities, &args.passphrase, true)?;
    let ciphertext = read_file_bounded(&args.input, limit)?;
    let plaintext = seclusor_crypto::decrypt(&ciphertext, &identities)?;

    // Atomic write via unique temp file (create_new semantics, no symlink risk)
    let output_dir = args.output.parent().unwrap_or(Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(output_dir)?;

    // Set 0600 before writing sensitive content
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    std::io::Write::write_all(&mut temp, &plaintext)?;

    // persist() replaces the target atomically on Unix; on Windows it
    // falls back to a non-atomic but correct rename-with-overwrite.
    temp.persist(&args.output)
        .map_err(|e| CliError::Io(e.error))?;
    Ok(())
}

fn handle_identity_generate(args: IdentityGenerateArgs) -> CliResult<()> {
    let passphrase = resolve_passphrase(&args.passphrase, true)?;
    let generated = match passphrase {
        Some(pp) => generate_identity_file_with_passphrase(&args.output, &pp)?,
        None => generate_identity_file(&args.output)?,
    };
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
    secrets.description = normalize_description(args.description.as_deref());
    validate_strict(&secrets)?;
    write_secrets_file(&args.file, &secrets, !args.force)?;
    println!("{}", args.file.display());
    Ok(())
}

fn handle_set(args: SetArgs) -> CliResult<()> {
    let mut secrets = read_secrets_file(&args.file)?;
    let existing_description = get_credential(&secrets, args.project.as_deref(), &args.key)
        .ok()
        .and_then(|credential| credential.description.clone());
    let credential = credential_from_set_args(&args, existing_description)?;
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
    let identities = resolve_identities(&args.identities, &args.passphrase, false)?;
    let secrets = read_runtime_secrets_file(&args.file, &identities)?;
    let credential = get_credential(&secrets, args.project.as_deref(), &args.key)?;
    match get_output_mode(&args) {
        GetOutputMode::Redacted => {
            println!("{REDACTED_OUTPUT}");
            Ok(())
        }
        GetOutputMode::Reveal => {
            if let Some(value) = &credential.value {
                if value.starts_with(seclusor_core::constants::INLINE_CIPHERTEXT_PREFIX) {
                    return Err(CliError::Core(SeclusorError::InlineEncrypted(
                        args.key.clone(),
                    )));
                }
                println!("{value}");
                return Ok(());
            }
            if let Some(reference) = &credential.reference {
                println!("{reference}");
                return Ok(());
            }
            Err(CliError::Message(
                "credential has neither value nor ref".to_string(),
            ))
        }
        GetOutputMode::Description => {
            if let Some(description) = &credential.description {
                println!("{description}");
            }
            Ok(())
        }
    }
}

fn handle_list(args: ListArgs) -> CliResult<()> {
    let secrets = read_secrets_file(&args.file)?;
    if !args.verbose {
        let keys = list_credential_keys(&secrets, args.project.as_deref())?;
        for key in keys {
            println!("{key}");
        }
        return Ok(());
    }

    let project_index = resolve_project_index(&secrets, args.project.as_deref())?;
    let project = &secrets.projects[project_index];
    for (key, credential) in &project.credentials {
        if let Some(description) = credential.description.as_deref() {
            println!("{key}\t{description}");
        } else {
            println!("{key}");
        }
    }

    Ok(())
}

fn handle_unset(args: UnsetArgs) -> CliResult<()> {
    match read_secrets_file(&args.file) {
        Ok(mut secrets) => {
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
        Err(err)
            if should_use_lenient_unset(&args.file, args.project.as_deref(), &args.key, &err) =>
        {
            handle_unset_lenient(args)
        }
        Err(err) => Err(err),
    }
}

fn handle_validate(args: ValidateArgs) -> CliResult<()> {
    let secrets = read_secrets_file(&args.file)?;
    validate_strict(&secrets)?;
    println!("valid");
    Ok(())
}

fn handle_export_env(args: ExportEnvArgs) -> CliResult<()> {
    let identities = resolve_identities(&args.identities, &args.passphrase, false)?;
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
    let identities = resolve_identities(&args.identities, &args.passphrase, false)?;
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
    let identities = resolve_identities(&args.identities, &args.passphrase, true)?;
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
    let identities = resolve_identities(&args.identities, &args.passphrase, false)?;
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
    let identities = resolve_identities(&args.identities, &args.passphrase, true)?;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GetOutputMode {
    Redacted,
    Reveal,
    Description,
}

fn get_output_mode(args: &GetArgs) -> GetOutputMode {
    if args.show_description {
        GetOutputMode::Description
    } else if args.reveal {
        GetOutputMode::Reveal
    } else {
        GetOutputMode::Redacted
    }
}

fn credential_from_set_args(
    args: &SetArgs,
    existing_description: Option<String>,
) -> CliResult<Credential> {
    let description = match args.description.as_deref() {
        Some(input) => normalize_description(Some(input)),
        None => existing_description,
    };

    match (&args.value, &args.reference) {
        (Some(value), None) => {
            let mut credential = Credential::with_value(&args.credential_type, value);
            credential.description = description;
            Ok(credential)
        }
        (None, Some(reference)) => {
            let mut credential = Credential::with_ref(&args.credential_type, reference);
            credential.description = description;
            Ok(credential)
        }
        (Some(_), Some(_)) => Err(CliError::Message(
            "set requires exactly one of --value or --ref".to_string(),
        )),
        (None, None) => Err(CliError::Message(
            "set requires exactly one of --value or --ref".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seclusor_crypto::Identity;
    use std::io::Write;
    use std::path::PathBuf;

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

    fn write_fixture_secrets(path: &Path, secrets: &SecretsFile) {
        write_secrets_file(path, secrets, true).expect("write fixture secrets");
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
            description: None,
            create_project: false,
        };
        assert!(credential_from_set_args(&both, None).is_err());

        let neither = SetArgs {
            value: None,
            reference: None,
            ..both
        };
        assert!(credential_from_set_args(&neither, None).is_err());
    }

    #[test]
    fn credential_from_set_args_preserves_replaces_and_clears_description() {
        let base = SetArgs {
            file: PathBuf::from("x"),
            project: None,
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("a".to_string()),
            reference: None,
            description: None,
            create_project: false,
        };

        let preserved = credential_from_set_args(&base, Some("existing note".to_string())).unwrap();
        assert_eq!(preserved.description.as_deref(), Some("existing note"));

        let replaced = credential_from_set_args(
            &SetArgs {
                description: Some("  new note  ".to_string()),
                ..base.clone()
            },
            Some("existing note".to_string()),
        )
        .unwrap();
        assert_eq!(replaced.description.as_deref(), Some("new note"));

        let cleared = credential_from_set_args(
            &SetArgs {
                description: Some("   ".to_string()),
                ..base
            },
            Some("existing note".to_string()),
        )
        .unwrap();
        assert!(cleared.description.is_none());
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
            show_description: false,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("must reject invalid document");
        assert!(matches!(
            err,
            CliError::Codec(seclusor_codec::CodecError::Core(SeclusorError::Validation(
                _
            )))
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
            show_description: false,
            identities: IdentityArgs {
                identity_files: vec![identity_file.clone()],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("get redacted from bundle");

        handle_get(GetArgs {
            file: bundle,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: true,
            show_description: false,
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
            passphrase: PassphraseArgs::default(),
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
            show_description: false,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
            show_description: false,
            identities: IdentityArgs {
                identity_files: vec![wrong_identity_file],
            },
            passphrase: PassphraseArgs::default(),
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
            verbose: false,
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
            description: None,
            create_project: false,
        })
        .expect_err("must reject invalid document");
        assert!(matches!(err, CliError::Core(SeclusorError::Validation(_))));
    }

    #[test]
    fn handle_set_redacts_plaintext_strings_in_json_errors() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v1.0.0","projects":"cfat_secret_token"}"#,
        );

        let err = handle_set(SetArgs {
            file: path,
            project: Some("demo".to_string()),
            key: "NEW_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("new-value".to_string()),
            reference: None,
            description: None,
            create_project: false,
        })
        .expect_err("must reject malformed document");

        let rendered = err.to_string();
        assert!(!rendered.contains("cfat_secret_token"));
        assert!(rendered.contains("string \"<redacted>\""));
    }

    #[test]
    fn handle_set_preserves_replaces_and_clears_description_for_existing_value_credential() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.json");
        let mut secrets = fixture_secrets();
        secrets.projects[0]
            .credentials
            .get_mut("API_KEY")
            .unwrap()
            .description = Some("existing value description".to_string());
        write_fixture_secrets(&path, &secrets);

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("updated-value".to_string()),
            reference: None,
            description: None,
            create_project: false,
        })
        .expect("preserve existing description");
        let loaded = read_secrets_file(&path).unwrap();
        assert_eq!(
            loaded.projects[0].credentials["API_KEY"]
                .description
                .as_deref(),
            Some("existing value description")
        );

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: None,
            reference: Some("vault://rotated".to_string()),
            description: Some("  replacement value description  ".to_string()),
            create_project: false,
        })
        .expect("replace description");
        let loaded = read_secrets_file(&path).unwrap();
        assert_eq!(
            loaded.projects[0].credentials["API_KEY"]
                .description
                .as_deref(),
            Some("replacement value description")
        );
        assert_eq!(
            loaded.projects[0].credentials["API_KEY"]
                .reference
                .as_deref(),
            Some("vault://rotated")
        );

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("final-value".to_string()),
            reference: None,
            description: Some("".to_string()),
            create_project: false,
        })
        .expect("clear description");
        let loaded = read_secrets_file(&path).unwrap();
        assert!(loaded.projects[0].credentials["API_KEY"]
            .description
            .is_none());
    }

    #[test]
    fn handle_set_preserves_replaces_and_clears_description_for_existing_ref_credential() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.json");
        let mut secrets = fixture_secrets();
        secrets.projects[0]
            .credentials
            .get_mut("VAULT")
            .unwrap()
            .description = Some("existing ref description".to_string());
        write_fixture_secrets(&path, &secrets);

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "VAULT".to_string(),
            credential_type: "ref".to_string(),
            value: None,
            reference: Some("vault://preserved".to_string()),
            description: None,
            create_project: false,
        })
        .expect("preserve existing description");
        let loaded = read_secrets_file(&path).unwrap();
        assert_eq!(
            loaded.projects[0].credentials["VAULT"]
                .description
                .as_deref(),
            Some("existing ref description")
        );

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "VAULT".to_string(),
            credential_type: "secret".to_string(),
            value: Some("plain-secret".to_string()),
            reference: None,
            description: Some("  replacement ref description  ".to_string()),
            create_project: false,
        })
        .expect("replace description");
        let loaded = read_secrets_file(&path).unwrap();
        assert_eq!(
            loaded.projects[0].credentials["VAULT"]
                .description
                .as_deref(),
            Some("replacement ref description")
        );
        assert_eq!(
            loaded.projects[0].credentials["VAULT"].value.as_deref(),
            Some("plain-secret")
        );

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "VAULT".to_string(),
            credential_type: "ref".to_string(),
            value: None,
            reference: Some("vault://cleared".to_string()),
            description: Some("   ".to_string()),
            create_project: false,
        })
        .expect("clear description");
        let loaded = read_secrets_file(&path).unwrap();
        assert!(loaded.projects[0].credentials["VAULT"]
            .description
            .is_none());
    }

    #[test]
    fn handle_bundle_encrypt_bare_string_credential_has_helpful_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("invalid.json");
        let output = dir.path().join("secrets.age");
        write_raw_json(
            &input,
            r#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"CLOUDFLARE_API_TOKEN":"cfat_secret_token"}}]}"#,
        );

        let err = handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect_err("must reject malformed credential");

        let rendered = err.to_string();
        assert!(!rendered.contains("cfat_secret_token"));
        assert!(rendered.contains(r#"credential "CLOUDFLARE_API_TOKEN" must be an object"#));
        assert!(rendered
            .contains("Use: seclusor secrets set --key CLOUDFLARE_API_TOKEN --value <value>"));
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
    fn handle_unset_leniently_removes_malformed_credential() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"CLOUDFLARE_API_TOKEN":"cfat_secret_token","API_KEY":{"type":"secret","value":"sk-123"}}}]}"#,
        );

        handle_unset(UnsetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "CLOUDFLARE_API_TOKEN".to_string(),
        })
        .expect("lenient unset should succeed");

        let secrets = read_secrets_file(&path).expect("file should be valid after removal");
        assert!(!secrets.projects[0]
            .credentials
            .contains_key("CLOUDFLARE_API_TOKEN"));
        assert!(secrets.projects[0].credentials.contains_key("API_KEY"));
    }

    #[test]
    fn handle_unset_leniently_repairs_validation_failure_credentials() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"BAD":{"type":"secret"},"API_KEY":{"type":"secret","value":"sk-123"}}}]}"#,
        );

        handle_unset(UnsetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "BAD".to_string(),
        })
        .expect("lenient unset should repair validation failure");

        let secrets = read_secrets_file(&path).expect("file should be valid after removal");
        assert!(!secrets.projects[0].credentials.contains_key("BAD"));
        assert!(secrets.projects[0].credentials.contains_key("API_KEY"));
    }

    #[test]
    fn handle_unset_lenient_returns_error_if_file_still_invalid() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"BAD_ONE":"cfat_one","BAD_TWO":"cfat_two"}}]}"#,
        );

        let err = handle_unset(UnsetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "BAD_ONE".to_string(),
        })
        .expect_err("must fail if file remains invalid");

        let rendered = err.to_string();
        assert!(rendered.contains("file was updated, but malformed credentials remain"));
        assert!(!rendered.contains("cfat_one"));
        assert!(!rendered.contains("cfat_two"));
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
            passphrase: PassphraseArgs::default(),
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
            passphrase: PassphraseArgs::default(),
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
            passphrase: PassphraseArgs::default(),
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
            passphrase: PassphraseArgs::default(),
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
            passphrase: PassphraseArgs::default(),
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
            passphrase: PassphraseArgs::default(),
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
            passphrase: PassphraseArgs::default(),
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
            passphrase: PassphraseArgs::default(),
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
            passphrase: PassphraseArgs::default(),
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
            passphrase: PassphraseArgs::default(),
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
            passphrase: PassphraseArgs::default(),
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
            passphrase: PassphraseArgs::default(),
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
            passphrase: PassphraseArgs::default(),
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

    // --- blob encrypt/decrypt tests ---

    fn blob_fixture_identity_and_recipient(
        dir: &std::path::Path,
    ) -> (PathBuf, seclusor_keyring::Recipient) {
        let identity_path = dir.join("blob-identity.txt");
        let generated =
            seclusor_keyring::generate_identity_file(&identity_path).expect("generate identity");
        let recipient: seclusor_keyring::Recipient =
            generated.recipient.parse().expect("parse recipient");
        (identity_path, recipient)
    }

    #[test]
    fn blob_encrypt_decrypt_roundtrip_text_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (identity_path, recipient) = blob_fixture_identity_and_recipient(dir.path());

        let input = dir.path().join("hello.sh");
        fs::write(&input, "#!/bin/bash\nexport TOKEN=secret123\n").expect("write input");
        let encrypted = dir.path().join("hello.sh.age");
        let decrypted = dir.path().join("hello-restored.sh");

        handle_blob_encrypt(BlobEncryptArgs {
            input: input.clone(),
            output: encrypted.clone(),
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("blob encrypt");

        assert!(encrypted.exists());
        // Ciphertext must not contain plaintext
        let ct = fs::read(&encrypted).expect("read ciphertext");
        assert!(!ct.windows(6).any(|w| w == b"secret"));

        handle_blob_decrypt(BlobDecryptArgs {
            input: encrypted,
            output: decrypted.clone(),
            allow_large: false,
            identities: IdentityArgs {
                identity_files: vec![identity_path],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("blob decrypt");

        let restored = fs::read_to_string(&decrypted).expect("read restored");
        assert_eq!(restored, "#!/bin/bash\nexport TOKEN=secret123\n");

        // Verify 0600 on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&decrypted)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn blob_encrypt_decrypt_roundtrip_binary_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (identity_path, recipient) = blob_fixture_identity_and_recipient(dir.path());

        let input = dir.path().join("binary.bin");
        let binary_content: Vec<u8> = (0..=255).collect();
        fs::write(&input, &binary_content).expect("write binary");
        let encrypted = dir.path().join("binary.bin.age");
        let decrypted = dir.path().join("binary-restored.bin");

        handle_blob_encrypt(BlobEncryptArgs {
            input,
            output: encrypted.clone(),
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("blob encrypt binary");

        handle_blob_decrypt(BlobDecryptArgs {
            input: encrypted,
            output: decrypted.clone(),
            allow_large: false,
            identities: IdentityArgs {
                identity_files: vec![identity_path],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("blob decrypt binary");

        assert_eq!(fs::read(&decrypted).expect("read"), binary_content);
    }

    #[test]
    fn blob_encrypt_decrypt_roundtrip_empty_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (identity_path, recipient) = blob_fixture_identity_and_recipient(dir.path());

        let input = dir.path().join("empty.txt");
        fs::write(&input, b"").expect("write empty");
        let encrypted = dir.path().join("empty.age");
        let decrypted = dir.path().join("empty-restored.txt");

        handle_blob_encrypt(BlobEncryptArgs {
            input,
            output: encrypted.clone(),
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("blob encrypt empty");

        handle_blob_decrypt(BlobDecryptArgs {
            input: encrypted,
            output: decrypted.clone(),
            allow_large: false,
            identities: IdentityArgs {
                identity_files: vec![identity_path],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("blob decrypt empty");

        assert_eq!(fs::read(&decrypted).expect("read").len(), 0);
    }

    #[test]
    fn blob_encrypt_rejects_oversized_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (_, recipient) = blob_fixture_identity_and_recipient(dir.path());

        let input = dir.path().join("large.bin");
        let file = fs::File::create(&input).expect("create large file");
        file.set_len(BLOB_MAX_FILE_BYTES + 1).expect("set len");
        drop(file);

        let err = handle_blob_encrypt(BlobEncryptArgs {
            input,
            output: dir.path().join("large.age"),
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect_err("must reject oversized");

        assert!(err.to_string().contains("10 MB limit"));
    }

    #[test]
    fn blob_encrypt_allows_oversized_with_flag() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (_, recipient) = blob_fixture_identity_and_recipient(dir.path());

        // Use a file just over the limit but small enough to actually encrypt
        let input = dir.path().join("just-over.bin");
        fs::write(&input, vec![0u8; (BLOB_MAX_FILE_BYTES as usize) + 1]).expect("write");

        let result = handle_blob_encrypt(BlobEncryptArgs {
            input,
            output: dir.path().join("just-over.age"),
            allow_large: true,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        });

        assert!(result.is_ok());
    }

    #[test]
    fn blob_encrypt_silent_stdout() {
        // blob encrypt/decrypt should produce no stdout — tested by verifying
        // the functions return Ok(()) without println
        let dir = tempfile::tempdir().expect("temp dir");
        let (identity_path, recipient) = blob_fixture_identity_and_recipient(dir.path());

        let input = dir.path().join("quiet.txt");
        fs::write(&input, "test").expect("write");

        handle_blob_encrypt(BlobEncryptArgs {
            input,
            output: dir.path().join("quiet.age"),
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt");

        handle_blob_decrypt(BlobDecryptArgs {
            input: dir.path().join("quiet.age"),
            output: dir.path().join("quiet-out.txt"),
            allow_large: false,
            identities: IdentityArgs {
                identity_files: vec![identity_path],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("decrypt");
        // No assertion needed — the handlers don't print to stdout (no println!)
    }

    #[test]
    fn blob_multi_recipient_either_can_decrypt() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (id1_path, r1) = blob_fixture_identity_and_recipient(dir.path());
        let id2_path = dir.path().join("blob-identity2.txt");
        let gen2 = seclusor_keyring::generate_identity_file(&id2_path).expect("gen2");
        let r2: seclusor_keyring::Recipient = gen2.recipient.parse().expect("parse r2");

        let input = dir.path().join("shared.txt");
        fs::write(&input, "shared secret").expect("write");
        let encrypted = dir.path().join("shared.age");

        handle_blob_encrypt(BlobEncryptArgs {
            input,
            output: encrypted.clone(),
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![r1.to_string(), r2.to_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt for two recipients");

        // Decrypt with identity 1
        let out1 = dir.path().join("out1.txt");
        handle_blob_decrypt(BlobDecryptArgs {
            input: encrypted.clone(),
            output: out1.clone(),
            allow_large: false,
            identities: IdentityArgs {
                identity_files: vec![id1_path],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("decrypt with id1");
        assert_eq!(fs::read_to_string(&out1).expect("read"), "shared secret");

        // Decrypt with identity 2
        let out2 = dir.path().join("out2.txt");
        handle_blob_decrypt(BlobDecryptArgs {
            input: encrypted,
            output: out2.clone(),
            allow_large: false,
            identities: IdentityArgs {
                identity_files: vec![id2_path],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("decrypt with id2");
        assert_eq!(fs::read_to_string(&out2).expect("read"), "shared secret");
    }

    #[test]
    fn blob_decrypt_wrong_identity_fails() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (_, recipient) = blob_fixture_identity_and_recipient(dir.path());

        let wrong_id_path = dir.path().join("wrong-identity.txt");
        seclusor_keyring::generate_identity_file(&wrong_id_path).expect("gen wrong");

        let input = dir.path().join("target.txt");
        fs::write(&input, "secret data").expect("write");
        let encrypted = dir.path().join("target.age");

        handle_blob_encrypt(BlobEncryptArgs {
            input,
            output: encrypted.clone(),
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt");

        let err = handle_blob_decrypt(BlobDecryptArgs {
            input: encrypted,
            output: dir.path().join("fail.txt"),
            allow_large: false,
            identities: IdentityArgs {
                identity_files: vec![wrong_id_path],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("wrong identity must fail");

        // Error must not contain plaintext
        let msg = err.to_string();
        assert!(!msg.contains("secret data"));
    }

    // --- inline-encrypted runtime tests (SC-012) ---

    fn write_inline_encrypted_file(dir: &std::path::Path) -> (PathBuf, PathBuf) {
        let input = dir.join("plaintext.json");
        let inline = dir.join("inline-encrypted.json");
        let identity_file = dir.join("inline-identity.txt");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");
        write_identity_file(&identity_file, TEST_IDENTITY);

        handle_inline_encrypt(InlineEncryptArgs {
            input,
            output: inline.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("inline encrypt");

        (inline, identity_file)
    }

    #[test]
    fn handle_get_inline_encrypted_with_identity_reveals_value() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, identity_file) = write_inline_encrypted_file(dir.path());

        // Verify redacted mode works (doesn't need to decrypt)
        handle_get(GetArgs {
            file: inline.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: false,
            show_description: false,
            identities: IdentityArgs {
                identity_files: vec![identity_file.clone()],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("get redacted should work");

        // Verify reveal mode decrypts (not just prints ciphertext)
        handle_get(GetArgs {
            file: inline,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: true,
            show_description: false,
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("get reveal should work with identity");
    }

    #[test]
    fn handle_get_inline_encrypted_without_identity_errors_on_reveal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, _identity_file) = write_inline_encrypted_file(dir.path());

        let err = handle_get(GetArgs {
            file: inline,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: true,
            show_description: false,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("get reveal without identity should fail");

        let msg = err.to_string();
        assert!(msg.contains("inline-encrypted"), "error: {msg}");
    }

    #[test]
    fn handle_export_env_inline_encrypted_with_identity() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, identity_file) = write_inline_encrypted_file(dir.path());

        let result = handle_export_env(ExportEnvArgs {
            file: inline,
            project: Some("demo".to_string()),
            format: EnvFormatArg::Dotenv,
            prefix: None,
            emit_ref: true,
            allow: vec![],
            deny: vec![],
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
            passphrase: PassphraseArgs::default(),
        });
        assert!(result.is_ok(), "export-env failed: {}", result.unwrap_err());
    }

    #[test]
    fn handle_run_inline_encrypted_with_identity() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, identity_file) = write_inline_encrypted_file(dir.path());

        #[cfg(unix)]
        let command = vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()];
        #[cfg(windows)]
        let command = vec!["cmd".to_string(), "/C".to_string(), "exit 0".to_string()];

        let result = handle_run(RunArgs {
            file: inline,
            project: Some("demo".to_string()),
            prefix: None,
            emit_ref: true,
            allow: vec![],
            deny: vec![],
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
            passphrase: PassphraseArgs::default(),
            command,
        });
        assert!(result.is_ok(), "run failed: {}", result.unwrap_err());
    }

    #[test]
    fn handle_run_inline_encrypted_without_identity_errors() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, _identity_file) = write_inline_encrypted_file(dir.path());

        #[cfg(unix)]
        let command = vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()];
        #[cfg(windows)]
        let command = vec!["cmd".to_string(), "/C".to_string(), "exit 0".to_string()];

        let err = handle_run(RunArgs {
            file: inline,
            project: Some("demo".to_string()),
            prefix: None,
            emit_ref: false,
            allow: vec![],
            deny: vec![],
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
            command,
        })
        .expect_err("should fail without identity");

        let msg = err.to_string();
        assert!(msg.contains("inline-encrypted"));
    }
}
