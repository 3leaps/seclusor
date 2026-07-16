use std::path::Path;

use seclusor_codec::{
    ensure_no_plaintext_credential_values, set_inline_description, set_inline_value,
    unset_inline_value, DescriptionAction, DocumentSource, LoadMode, SetInlineValueOptions,
};
use seclusor_core::constants::MAX_SECRETS_DOC_BYTES;
use seclusor_core::crud::{
    get_credential, list_credential_keys, resolve_project_index, set_credential, unset_credential,
};
use seclusor_core::env::{format_env_vars, import_env_vars, parse_dotenv};
use seclusor_core::validate::{normalize_description, validate_strict};
use seclusor_core::{Credential, Project, SeclusorError, SecretsFile};
use std::collections::BTreeMap;

use crate::atomic_write::{atomic_write_ciphertext, AtomicWriteOptions};
use crate::cli::{
    EnvFormatArg, ExportEnvArgs, GetArgs, ImportEnvArgs, InitArgs, ListArgs, SetArgs,
    StorageCodecArg, UnsetArgs, ValidateArgs,
};
use crate::env_support::resolve_export_env_vars;
use crate::error::{CliError, CliResult};
use crate::handlers::encrypted_write::{
    apply_establishment, commit_bundle_mutation, commit_inline_ciphertext_document,
    emit_establishment_notice, ensure_inline_stanza_count_matches,
    inline_establishment_coverage_ok, load_inline_full_for_write, recipient_channels_present,
    recipient_strings, refuse_scrypt_bundle_write, resolve_set_material, resolve_write_recipients,
    SetMaterial, ValueChannelArgs,
};
use crate::io::{
    probe_write_target, read_file_with_limit, read_runtime_document_file,
    read_runtime_secrets_file, refuse_encrypted_write, secrets_from_bytes, write_secrets_file,
    WriteTargetProbe,
};
use crate::lenient::{handle_unset_lenient_bytes, should_use_lenient_unset};
use crate::resolve::{resolve_identities, resolve_recipients};
use crate::REDACTED_OUTPUT;

pub(crate) fn handle_init(args: InitArgs) -> CliResult<()> {
    // Design lock: never combine --force with --codec (create-only encrypted path).
    if args.force && args.codec.is_some() {
        return Err(CliError::Message(
            "cannot combine --force with --codec; encrypted init is create-only \
             (target path must not exist). To encrypt existing credentials use \
             `seclusor secrets rekey`; to replace with an empty encrypted skeleton, \
             remove the file first"
                .to_string(),
        ));
    }

    // Recipient channels without --codec are never silently ignored.
    if recipient_channels_present(&args.recipients) && args.codec.is_none() {
        return Err(CliError::Message(
            "recipient flags require --codec bundle on init (or omit recipients for \
             plaintext init)"
                .to_string(),
        ));
    }

    match args.codec {
        None => handle_init_plaintext(args),
        Some(StorageCodecArg::Bundle) => handle_init_bundle(args),
        Some(StorageCodecArg::Inline) => Err(CliError::Message(
            "inline encrypted documents are created by encrypting a value — run \
             `seclusor secrets init` then `set` with --recipient…, or `rekey`; \
             use --codec bundle for an empty encrypted document"
                .to_string(),
        )),
    }
}

fn handle_init_plaintext(args: InitArgs) -> CliResult<()> {
    if args.file.exists() {
        if !args.force {
            return Err(CliError::Message(format!(
                "secrets file already exists at {}; use --force to overwrite",
                args.file.display()
            )));
        }
        // Refuse overwriting a positively identified encrypted target (Slice 0).
        match probe_write_target(&args.file)? {
            WriteTargetProbe::Encrypted { source, .. } => {
                return Err(refuse_encrypted_write(&args.file, source));
            }
            WriteTargetProbe::Plaintext { .. } | WriteTargetProbe::NotEncrypted(_) => {}
        }
    }

    let mut secrets = SecretsFile::new(&args.project);
    secrets.env_prefix = args.env_prefix;
    secrets.description = normalize_description(args.description.as_deref());
    validate_strict(&secrets)?;
    write_secrets_file(&args.file, &secrets, !args.force)?;
    println!("{}", args.file.display());
    Ok(())
}

/// Encrypted init: create-only empty **bundle** skeleton (design lock A1/A2).
fn handle_init_bundle(args: InitArgs) -> CliResult<()> {
    // Existence wins — no classify/mutate of an existing path.
    if args.file.exists() {
        return Err(CliError::Message(format!(
            "encrypted init is create-only: {} already exists. To encrypt an \
             existing document use `seclusor secrets rekey`; to reset to an empty \
             encrypted skeleton, remove the file first",
            args.file.display()
        )));
    }

    // Explicit RecipientArgs only — ambient SECLUSOR_RECIPIENTS alone is insufficient.
    if !recipient_channels_present(&args.recipients) {
        return Err(CliError::Message(
            "encrypted init requires at least one explicit --recipient, \
             --recipient-file, or --recipient-env-var (ambient SECLUSOR_RECIPIENTS \
             alone is not enough)"
                .to_string(),
        ));
    }

    let recipients = resolve_recipients(&args.recipients)?;
    let as_strings = recipient_strings(&recipients);

    let mut secrets = SecretsFile::new(&args.project);
    secrets.env_prefix = args.env_prefix;
    secrets.description = normalize_description(args.description.as_deref());
    apply_establishment(&mut secrets, &as_strings)?;
    validate_strict(&secrets)?;

    let ciphertext = seclusor_codec::encrypt_bundle(&secrets, &recipients)?;

    atomic_write_ciphertext(
        &args.file,
        &ciphertext,
        AtomicWriteOptions {
            expected_prior_bytes: None,
            create_new: true,
        },
    )?;
    emit_establishment_notice(&as_strings);
    println!("{}", args.file.display());
    Ok(())
}

pub(crate) fn handle_set(args: SetArgs) -> CliResult<()> {
    if is_description_only_set(&args) {
        return handle_description_only_set(args);
    }

    match probe_write_target(&args.file)? {
        WriteTargetProbe::Plaintext { secrets, .. } => {
            let mut args = args;
            apply_plaintext_set(secrets, &mut args)?;
            Ok(())
        }
        WriteTargetProbe::NotEncrypted(bytes) => {
            let secrets = secrets_from_bytes(&bytes)?;
            let mut args = args;
            apply_plaintext_set(secrets, &mut args)?;
            Ok(())
        }
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Inline,
            bytes,
        } => handle_set_inline_encrypted(args, &bytes),
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Bundle,
            bytes,
        } => handle_set_bundle_encrypted(args, &bytes),
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Plaintext,
            ..
        } => Err(refuse_encrypted_write(
            &args.file,
            DocumentSource::Plaintext,
        )),
    }
}

fn apply_plaintext_set(mut secrets: SecretsFile, args: &mut SetArgs) -> CliResult<()> {
    let material = resolve_set_material(value_channels_from_set(args))?;
    let existing_description = get_credential(&secrets, args.project.as_deref(), &args.key)
        .ok()
        .and_then(|credential| credential.description.clone());
    let credential = credential_from_material(args, &material, existing_description)?;
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

fn handle_set_inline_encrypted(mut args: SetArgs, prior_bytes: &[u8]) -> CliResult<()> {
    // Full-load boundary: resolve identity once and decrypt-validate every field.
    let identities = resolve_identities(&args.identities, &args.passphrase, true)?;
    let secrets = load_inline_full_for_write(prior_bytes, &identities)?;
    let material = resolve_set_material(value_channels_from_set(&mut args))?;

    match &material {
        SetMaterial::Value(_) => {
            let keys_this_write = {
                let project_slug = match resolve_project_index(&secrets, args.project.as_deref()) {
                    Ok(idx) => secrets.projects[idx].project_slug.clone(),
                    Err(SeclusorError::ProjectNotFound(_)) if args.create_project => args
                        .project
                        .clone()
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| "default".to_string()),
                    Err(e) => return Err(e.into()),
                };
                vec![(project_slug, args.key.clone())]
            };
            // Establishment only when metadata absent — coverage still required then.
            let coverage_for_establish =
                inline_establishment_coverage_ok(&secrets, &keys_this_write);
            let resolved = resolve_write_recipients(
                secrets.recipients.as_deref(),
                &args.recipients,
                coverage_for_establish,
            )?;

            // Cardinality tripwire vs prior ciphertext fields (establishment
            // count-guard; meta-vs-reality when metadata present). Vacuous when
            // no prior encrypted fields (green-field first encrypt).
            ensure_inline_stanza_count_matches(&secrets, resolved.recipients.len())?;

            let mut working = secrets;
            let project_slug = ensure_project_for_write(
                &mut working,
                args.project.as_deref(),
                args.create_project,
            )?;

            let mut options = SetInlineValueOptions::default();
            options.create_if_missing = true;
            options.credential_type = &args.credential_type;
            options.description = match args.description.as_deref() {
                Some(d) => DescriptionAction::Replace(Some(d)),
                None => DescriptionAction::Preserve,
            };
            let plain = material
                .value_str()
                .ok_or_else(|| CliError::Message("internal: missing value material".to_string()))?;
            let result = set_inline_value(
                &working,
                &project_slug,
                &args.key,
                plain,
                &resolved.recipients,
                options,
            )?;
            let mut out = result.secrets;

            if resolved.established {
                apply_establishment(&mut out, &resolved.as_strings)?;
            }

            commit_inline_ciphertext_document(&args.file, prior_bytes, &out)?;
            if resolved.established {
                emit_establishment_notice(&resolved.as_strings);
            }
            println!("ok");
            Ok(())
        }
        SetMaterial::Reference(reference) => {
            // Full-load already validated decryptability. Ref writes still require
            // recipient policy when metadata/explicit channels are present.
            let mut working = secrets;
            if working.recipients.is_some()
                || crate::handlers::encrypted_write::recipient_channels_present(&args.recipients)
            {
                let resolved = resolve_write_recipients(
                    working.recipients.as_deref(),
                    &args.recipients,
                    // Ref-only does not establish (does not cover encrypted fields).
                    false,
                )?;
                if let Some(meta) = working.recipients.as_ref() {
                    ensure_inline_stanza_count_matches(&working, meta.len())?;
                }
                let _ = resolved;
            }

            let project_slug = ensure_project_for_write(
                &mut working,
                args.project.as_deref(),
                args.create_project,
            )?;
            let existing_description = get_credential(&working, Some(&project_slug), &args.key)
                .ok()
                .and_then(|c| c.description.clone());
            let description = match args.description.as_deref() {
                Some(input) => normalize_description(Some(input)),
                None => existing_description,
            };
            let mut credential = Credential::with_ref(&args.credential_type, reference);
            credential.description = description;
            let idx = resolve_project_index(&working, Some(&project_slug))?;
            working.projects[idx]
                .credentials
                .insert(args.key.clone(), credential);
            validate_strict(&working)?;
            commit_inline_ciphertext_document(&args.file, prior_bytes, &working)?;
            println!("ok");
            Ok(())
        }
    }
}

fn handle_set_bundle_encrypted(mut args: SetArgs, prior_bytes: &[u8]) -> CliResult<()> {
    refuse_scrypt_bundle_write(prior_bytes)?;
    let identities = resolve_identities(&args.identities, &args.passphrase, true)?;
    let material = resolve_set_material(value_channels_from_set(&mut args))?;

    // Peek document recipients from a Full decrypt for policy (same identities).
    let peek = seclusor_codec::resolve_runtime_document(prior_bytes, &identities)?;
    if peek.source != DocumentSource::Bundle || peek.mode != LoadMode::Full {
        return Err(refuse_encrypted_write(&args.file, peek.source));
    }
    // Bundle establishment always permitted.
    let resolved =
        resolve_write_recipients(peek.secrets.recipients.as_deref(), &args.recipients, true)?;
    drop(peek);

    commit_bundle_mutation(
        &args.file,
        prior_bytes,
        &identities,
        &resolved.recipients,
        resolved.recipients.len(),
        |secrets| {
            if resolved.established {
                apply_establishment(secrets, &resolved.as_strings)?;
            }
            let project_slug =
                ensure_project_for_write(secrets, args.project.as_deref(), args.create_project)?;
            let existing_description = get_credential(secrets, Some(&project_slug), &args.key)
                .ok()
                .and_then(|c| c.description.clone());
            let credential = credential_from_material(&args, &material, existing_description)?;
            set_credential(
                secrets,
                Some(&project_slug),
                &args.key,
                credential,
                false, // project already ensured
            )?;
            Ok(())
        },
    )?;
    if resolved.established {
        emit_establishment_notice(&resolved.as_strings);
    }
    println!("ok");
    Ok(())
}

fn value_channels_from_set(args: &mut SetArgs) -> ValueChannelArgs {
    ValueChannelArgs {
        value: args.value.take(),
        value_stdin: args.value_stdin,
        value_file: args.value_file.take(),
        value_env: args.value_env.take(),
        reference: args.reference.take(),
    }
}

fn ensure_project_for_write(
    secrets: &mut SecretsFile,
    project: Option<&str>,
    create_project: bool,
) -> CliResult<String> {
    match resolve_project_index(secrets, project) {
        Ok(idx) => Ok(secrets.projects[idx].project_slug.clone()),
        Err(SeclusorError::ProjectNotFound(slug)) if create_project => {
            if !secrets.projects.is_empty() {
                return Err(CliError::Core(SeclusorError::CannotAutoCreateProject));
            }
            let slug = if slug.is_empty() {
                "default".to_string()
            } else {
                slug
            };
            secrets.projects.push(Project {
                project_slug: slug.clone(),
                description: None,
                credentials: BTreeMap::new(),
            });
            Ok(slug)
        }
        Err(e) => Err(e.into()),
    }
}

fn credential_from_material(
    args: &SetArgs,
    material: &SetMaterial,
    existing_description: Option<String>,
) -> CliResult<Credential> {
    let description = match args.description.as_deref() {
        Some(input) => normalize_description(Some(input)),
        None => existing_description,
    };
    match material {
        SetMaterial::Value(_) => {
            let plain = material
                .value_str()
                .ok_or_else(|| CliError::Message("internal: missing value material".to_string()))?;
            let mut credential = Credential::with_value(&args.credential_type, plain);
            credential.description = description;
            Ok(credential)
        }
        SetMaterial::Reference(reference) => {
            let mut credential = Credential::with_ref(&args.credential_type, reference);
            credential.description = description;
            Ok(credential)
        }
    }
}

/// Description-only edit: `--description` with neither a value channel nor `--ref`.
///
/// - **Plaintext:** normal validated mutation (existing credential required).
/// - **Inline:** structural-only authorized path (no crypto / identity / recipients).
/// - **Bundle:** full encrypting write (recipient + identity rules).
fn handle_description_only_set(args: SetArgs) -> CliResult<()> {
    if args.create_project {
        return Err(CliError::Message(
            "description-only edit cannot create credentials or projects; \
             pass a value channel or --ref to create"
                .to_string(),
        ));
    }

    match probe_write_target(&args.file)? {
        WriteTargetProbe::Plaintext { secrets, .. } => {
            apply_plaintext_description_only(secrets, &args)?;
            Ok(())
        }
        WriteTargetProbe::NotEncrypted(bytes) => {
            let secrets = secrets_from_bytes(&bytes)?;
            apply_plaintext_description_only(secrets, &args)?;
            Ok(())
        }
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Inline,
            bytes,
        } => {
            commit_inline_structural_mutation(&args.file, &bytes, |secrets| {
                let project_slug = resolved_project_slug(secrets, args.project.as_deref())?;
                let result = set_inline_description(
                    secrets,
                    &project_slug,
                    &args.key,
                    args.description.as_deref(),
                )?;
                Ok(result.secrets)
            })?;
            emit_structural_only_write_status("set", DocumentSource::Inline);
            Ok(())
        }
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Bundle,
            bytes,
        } => {
            refuse_scrypt_bundle_write(&bytes)?;
            let identities = resolve_identities(&args.identities, &args.passphrase, true)?;
            let peek = seclusor_codec::resolve_runtime_document(&bytes, &identities)?;
            let resolved = resolve_write_recipients(
                peek.secrets.recipients.as_deref(),
                &args.recipients,
                true,
            )?;
            drop(peek);
            commit_bundle_mutation(
                &args.file,
                &bytes,
                &identities,
                &resolved.recipients,
                resolved.recipients.len(),
                |secrets| {
                    if resolved.established {
                        apply_establishment(secrets, &resolved.as_strings)?;
                    }
                    let existing = get_credential(secrets, args.project.as_deref(), &args.key)?;
                    let mut credential = existing.clone();
                    credential.description = normalize_description(args.description.as_deref());
                    set_credential(
                        secrets,
                        args.project.as_deref(),
                        &args.key,
                        credential,
                        false,
                    )?;
                    Ok(())
                },
            )?;
            if resolved.established {
                emit_establishment_notice(&resolved.as_strings);
            }
            println!("ok");
            Ok(())
        }
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Plaintext,
            ..
        } => {
            // Classification never returns Encrypted+Plaintext; defensive.
            Err(refuse_encrypted_write(
                &args.file,
                DocumentSource::Plaintext,
            ))
        }
    }
}

fn apply_plaintext_description_only(mut secrets: SecretsFile, args: &SetArgs) -> CliResult<()> {
    // Must exist — description-only never mints credentials.
    let existing = get_credential(&secrets, args.project.as_deref(), &args.key)?;
    let mut credential = existing.clone();
    credential.description = normalize_description(args.description.as_deref());
    set_credential(
        &mut secrets,
        args.project.as_deref(),
        &args.key,
        credential,
        false,
    )?;
    validate_strict(&secrets)?;
    write_secrets_file(&args.file, &secrets, false)?;
    println!("ok");
    Ok(())
}

pub(crate) fn handle_get(args: GetArgs) -> CliResult<()> {
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

pub(crate) fn handle_list(args: ListArgs) -> CliResult<()> {
    let identities = resolve_identities(&args.identities, &args.passphrase, false)?;
    let resolved = read_runtime_document_file(&args.file, &identities)?;
    let secrets = &resolved.secrets;
    if !args.verbose {
        let keys = list_credential_keys(secrets, args.project.as_deref())?;
        for key in keys {
            println!("{key}");
        }
        return Ok(());
    }

    let project_index = resolve_project_index(secrets, args.project.as_deref())?;
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

pub(crate) fn handle_unset(args: UnsetArgs) -> CliResult<()> {
    match probe_write_target(&args.file)? {
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Inline,
            bytes,
        } => {
            // Structural-only authorized path: no crypto, identity, or recipients.
            commit_inline_structural_mutation(&args.file, &bytes, |secrets| {
                let project_slug = resolved_project_slug(secrets, args.project.as_deref())?;
                // Fail closed if missing (matches plaintext unset existence check).
                let _ = get_credential(secrets, Some(&project_slug), &args.key)?;
                let result = unset_inline_value(secrets, &project_slug, &args.key)?;
                Ok(result.secrets)
            })?;
            emit_structural_only_write_status("unset", DocumentSource::Inline);
            Ok(())
        }
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Bundle,
            bytes,
        } => {
            refuse_scrypt_bundle_write(&bytes)?;
            let identities = resolve_identities(&args.identities, &args.passphrase, true)?;
            let peek = seclusor_codec::resolve_runtime_document(&bytes, &identities)?;
            let resolved = resolve_write_recipients(
                peek.secrets.recipients.as_deref(),
                &args.recipients,
                true,
            )?;
            drop(peek);
            commit_bundle_mutation(
                &args.file,
                &bytes,
                &identities,
                &resolved.recipients,
                resolved.recipients.len(),
                |secrets| {
                    if resolved.established {
                        apply_establishment(secrets, &resolved.as_strings)?;
                    }
                    unset_strict(secrets, &args)?;
                    Ok(())
                },
            )?;
            if resolved.established {
                emit_establishment_notice(&resolved.as_strings);
            }
            println!("ok");
            Ok(())
        }
        WriteTargetProbe::Encrypted { source, .. } => {
            Err(refuse_encrypted_write(&args.file, source))
        }
        WriteTargetProbe::Plaintext { mut secrets, .. } => {
            unset_strict(&mut secrets, &args)?;
            write_secrets_file(&args.file, &secrets, false)?;
            println!("ok");
            Ok(())
        }
        WriteTargetProbe::NotEncrypted(bytes) => match secrets_from_bytes(&bytes) {
            Ok(mut secrets) => {
                unset_strict(&mut secrets, &args)?;
                write_secrets_file(&args.file, &secrets, false)?;
                println!("ok");
                Ok(())
            }
            Err(err)
                if should_use_lenient_unset(&bytes, args.project.as_deref(), &args.key, &err) =>
            {
                // Same bounded bytes through eligibility and mutation (no path reopen).
                handle_unset_lenient_bytes(args, bytes)
            }
            Err(err) => Err(err),
        },
    }
}

fn unset_strict(secrets: &mut SecretsFile, args: &UnsetArgs) -> CliResult<()> {
    let _ = get_credential(secrets, args.project.as_deref(), &args.key)?;
    let removed = unset_credential(secrets, args.project.as_deref(), &args.key)?;
    if !removed {
        return Err(CliError::Message("credential was not removed".to_string()));
    }
    validate_strict(secrets)?;
    Ok(())
}

/// True when `--description` is present with no value channel and no `--ref`.
fn is_description_only_set(args: &SetArgs) -> bool {
    !has_value_or_ref_channel(args) && args.description.is_some()
}

fn has_value_or_ref_channel(args: &SetArgs) -> bool {
    args.value.is_some()
        || args.value_stdin
        || args.value_file.is_some()
        || args.value_env.is_some()
        || args.reference.is_some()
}

fn resolved_project_slug(secrets: &SecretsFile, project: Option<&str>) -> CliResult<String> {
    let idx = resolve_project_index(secrets, project)?;
    Ok(secrets.projects[idx].project_slug.clone())
}

/// Structural-only inline mutation: load without identities, mutate in memory,
/// commit encrypted JSON only via atomic writer + CAS on the original bytes.
///
/// `pub(crate)` so unit tests can exercise CAS wiring through this helper
/// (race inside the mutation closure) without production hooks.
pub(crate) fn commit_inline_structural_mutation<F>(
    path: &Path,
    prior_bytes: &[u8],
    mutate: F,
) -> CliResult<()>
where
    F: FnOnce(&SecretsFile) -> CliResult<SecretsFile>,
{
    // Empty identities → StructuralOnly for inline (shape-checked; no decrypt).
    let resolved = seclusor_codec::resolve_runtime_document(prior_bytes, &[])?;
    if resolved.source != DocumentSource::Inline {
        return Err(refuse_encrypted_write(path, resolved.source));
    }
    if resolved.mode != LoadMode::StructuralOnly {
        // Defensive: with no identities, inline must be structural-only.
        return Err(CliError::Message(
            "inline structural-only write requires a structural-only load \
             (do not pass identities for this path)"
                .to_string(),
        ));
    }

    let mutated = mutate(&resolved.secrets)?;
    validate_strict(&mutated)?;
    // Ciphertext-only writer contract: no direct plaintext values may enter an
    // orphanable temp. Refs and sec:age:v1: values are allowed.
    ensure_no_plaintext_credential_values(&mutated)?;

    let mut out = serde_json::to_vec_pretty(&mutated)?;
    // Match create_new secrets pretty-print convention (git-friendly trailing newline).
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    if out.len() > MAX_SECRETS_DOC_BYTES {
        return Err(CliError::Core(SeclusorError::DocumentTooLarge {
            actual: out.len(),
            max: MAX_SECRETS_DOC_BYTES,
        }));
    }

    atomic_write_ciphertext(
        path,
        &out,
        AtomicWriteOptions {
            expected_prior_bytes: Some(prior_bytes.to_vec()),
            create_new: false,
        },
    )?;
    Ok(())
}

/// Stdout/stderr vocabulary for structural-only authorized writes.
///
/// Mode token is library-owned ([`LoadMode::token`]); mirrors `validate`.
fn emit_structural_only_write_status(command: &str, source: DocumentSource) {
    let mode = LoadMode::StructuralOnly.token();
    println!("{mode} ok");
    eprintln!(
        "{command}: {mode} (source: {}); inline ciphertext encodings checked \
         without decryption; no identity or recipients required.",
        source.token()
    );
}

pub(crate) fn handle_validate(args: ValidateArgs) -> CliResult<()> {
    let identities = resolve_identities(&args.identities, &args.passphrase, false)?;
    let resolved = read_runtime_document_file(&args.file, &identities)?;
    // resolve_runtime_document already validates appropriately. Re-check with
    // the mode-correct policy: Full loads may be decrypted working copies
    // (plaintext values + recipients) — structure only. Structural-only keeps
    // ciphertext JSON-at-rest and uses full validate.
    match resolved.mode {
        seclusor_codec::LoadMode::StructuralOnly => {
            validate_strict(&resolved.secrets)?;
            // Encoding/shape only — not authenticity or decryptability.
            println!("structural-only valid");
            eprintln!(
                "validate: structural-only (source: {}); inline ciphertext encodings \
                 checked without decryption. Pass --identity-file or \
                 --identity-public-key for full validation.",
                resolved.source_token()
            );
        }
        seclusor_codec::LoadMode::Full => {
            seclusor_core::validate::validate_structure_strict(&resolved.secrets)?;
            println!("valid");
        }
    }
    Ok(())
}

pub(crate) fn handle_export_env(args: ExportEnvArgs) -> CliResult<()> {
    // Pure shell-safety gates first: never resolve identities, prompt for
    // passphrases, or decrypt secrets when --allow / TTY policy would refuse.
    let stdout_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    enforce_export_shell_safety_preflight(&args, stdout_is_tty)?;

    let identities = resolve_identities(&args.identities, &args.passphrase, false)?;
    let secrets = read_runtime_secrets_file(&args.file, &identities)?;
    let (output, exported_count) =
        render_export_env_output(&secrets, args.project.as_deref(), &args)?;

    // Forced-TTY warning immediately before emission (after load succeeds so
    // we do not warn about output that never happens).
    warn_export_shell_tty_force(&args, stdout_is_tty);

    println!("{output}");

    // ADR-0006: default success leaves stderr empty. Shell completion summary
    // is opt-in via --verbose only (settled for shell-export safety).
    if matches!(args.format, EnvFormatArg::Export) && args.verbose {
        let project_label = args
            .project
            .as_deref()
            .or_else(|| secrets.projects.first().map(|p| p.project_slug.as_str()))
            .unwrap_or("unknown");
        eprint!("Exported {exported_count} variables from {project_label}");
        if !args.allow.is_empty() {
            // Patterns are user-supplied and potentially sensitive; only under
            // explicit --verbose, and never on the default path.
            eprint!(" (allow: {})", args.allow.join(", "));
        }
        eprintln!();
    }

    Ok(())
}

/// Pure refusal gates for shell `--format export` (before any secret I/O).
///
/// Dotenv and JSON keep the historical default (empty `--allow` means all keys).
/// `stdout_is_tty` is injected so unit tests can cover the TTY branch without a
/// real terminal. Does **not** emit the forced-TTY warning — that runs only
/// immediately before successful emission (see [`warn_export_shell_tty_force`]).
pub(crate) fn enforce_export_shell_safety_preflight(
    args: &ExportEnvArgs,
    stdout_is_tty: bool,
) -> CliResult<()> {
    if !matches!(args.format, EnvFormatArg::Export) {
        return Ok(());
    }

    if args.allow.is_empty() {
        return Err(CliError::Message(
            "export format requires at least one --allow pattern \
             (refusing to export all secrets to the shell by default)"
                .to_string(),
        ));
    }

    if stdout_is_tty && !args.force {
        return Err(CliError::Message(
            "refusing to write shell exports to a TTY (values would be visible); \
             re-run with --force, or pipe/redirect for eval \
             (e.g. eval \"$(seclusor secrets export-env ... --format export --allow '...')\")"
                .to_string(),
        ));
    }

    Ok(())
}

/// Risk acknowledgment when deliberately writing shell exports to a TTY.
fn warn_export_shell_tty_force(args: &ExportEnvArgs, stdout_is_tty: bool) {
    if matches!(args.format, EnvFormatArg::Export) && stdout_is_tty && args.force {
        eprintln!(
            "warning: writing shell exports to a TTY; secret values may be visible on screen"
        );
    }
}

/// Combined preflight used by unit tests that only need the refusal contract.
#[cfg(test)]
pub(crate) fn enforce_export_shell_safety(
    args: &ExportEnvArgs,
    stdout_is_tty: bool,
) -> CliResult<()> {
    enforce_export_shell_safety_preflight(args, stdout_is_tty)
}

pub(crate) fn handle_import_env(args: ImportEnvArgs) -> CliResult<()> {
    match probe_write_target(&args.file)? {
        WriteTargetProbe::Plaintext { secrets, .. } => apply_import_env_plaintext(secrets, &args),
        WriteTargetProbe::NotEncrypted(bytes) => {
            let secrets = secrets_from_bytes(&bytes)?;
            apply_import_env_plaintext(secrets, &args)
        }
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Inline,
            bytes,
        } => handle_import_env_inline(args, &bytes),
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Bundle,
            bytes,
        } => handle_import_env_bundle(args, &bytes),
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Plaintext,
            ..
        } => Err(refuse_encrypted_write(
            &args.file,
            DocumentSource::Plaintext,
        )),
    }
}

fn prepare_import_pairs(
    secrets: &SecretsFile,
    args: &ImportEnvArgs,
) -> CliResult<Vec<(String, Credential)>> {
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

    let source = read_import_source(args)?;
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
    Ok(imported)
}

fn apply_import_env_plaintext(mut secrets: SecretsFile, args: &ImportEnvArgs) -> CliResult<()> {
    let imported = prepare_import_pairs(&secrets, args)?;
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

fn handle_import_env_inline(args: ImportEnvArgs, prior_bytes: &[u8]) -> CliResult<()> {
    let identities = resolve_identities(&args.identities, &args.passphrase, true)?;
    let secrets = load_inline_full_for_write(prior_bytes, &identities)?;
    let imported = prepare_import_pairs(&secrets, &args)?;

    let project_slug_hint = match resolve_project_index(&secrets, args.project.as_deref()) {
        Ok(idx) => secrets.projects[idx].project_slug.clone(),
        Err(SeclusorError::ProjectNotFound(_)) if args.create_project => args
            .project
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "default".to_string()),
        Err(e) => return Err(e.into()),
    };

    let keys_this_write: Vec<(String, String)> = imported
        .iter()
        .map(|(k, _)| (project_slug_hint.clone(), k.clone()))
        .collect();
    let coverage_for_establish = inline_establishment_coverage_ok(&secrets, &keys_this_write);
    let resolved = resolve_write_recipients(
        secrets.recipients.as_deref(),
        &args.recipients,
        coverage_for_establish,
    )?;
    // Cardinality vs prior encrypted fields (establish + meta paths).
    ensure_inline_stanza_count_matches(&secrets, resolved.recipients.len())?;

    let mut working = secrets;
    let project_slug =
        ensure_project_for_write(&mut working, args.project.as_deref(), args.create_project)?;

    let mut count = 0usize;
    for (key, credential) in &imported {
        let plaintext = credential
            .value
            .as_deref()
            .ok_or_else(|| CliError::Message(format!("imported credential {key} has no value")))?;
        // import-env replaces description with None across codecs (parity).
        let mut options = SetInlineValueOptions::default();
        options.create_if_missing = true;
        options.credential_type = &args.credential_type;
        options.description = DescriptionAction::Replace(None);
        let result = set_inline_value(
            &working,
            &project_slug,
            key,
            plaintext,
            &resolved.recipients,
            options,
        )?;
        working = result.secrets;
        count += 1;
    }

    if resolved.established {
        apply_establishment(&mut working, &resolved.as_strings)?;
    }
    commit_inline_ciphertext_document(&args.file, prior_bytes, &working)?;
    if resolved.established {
        emit_establishment_notice(&resolved.as_strings);
    }
    println!("{count}");
    Ok(())
}

fn handle_import_env_bundle(args: ImportEnvArgs, prior_bytes: &[u8]) -> CliResult<()> {
    refuse_scrypt_bundle_write(prior_bytes)?;
    let identities = resolve_identities(&args.identities, &args.passphrase, true)?;
    let peek = seclusor_codec::resolve_runtime_document(prior_bytes, &identities)?;
    let imported = prepare_import_pairs(&peek.secrets, &args)?;
    let resolved =
        resolve_write_recipients(peek.secrets.recipients.as_deref(), &args.recipients, true)?;
    drop(peek);

    let count = imported.len();
    commit_bundle_mutation(
        &args.file,
        prior_bytes,
        &identities,
        &resolved.recipients,
        resolved.recipients.len(),
        |secrets| {
            if resolved.established {
                apply_establishment(secrets, &resolved.as_strings)?;
            }
            for (key, credential) in imported {
                set_credential(
                    secrets,
                    args.project.as_deref(),
                    &key,
                    credential,
                    args.create_project,
                )?;
            }
            Ok(())
        },
    )?;
    if resolved.established {
        emit_establishment_notice(&resolved.as_strings);
    }
    println!("{count}");
    Ok(())
}

fn render_export_env_output(
    secrets: &SecretsFile,
    project_slug: Option<&str>,
    args: &ExportEnvArgs,
) -> CliResult<(String, usize)> {
    let vars = resolve_export_env_vars(
        secrets,
        project_slug,
        args.prefix.as_deref(),
        args.emit_ref,
        &args.allow,
        &args.deny,
    )?;
    let count = vars.len();
    Ok((format_env_vars(&vars, args.format.into()), count))
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

#[cfg(test)]
fn credential_from_set_args(
    args: &SetArgs,
    existing_description: Option<String>,
) -> CliResult<Credential> {
    let mut owned = args.clone();
    let material = resolve_set_material(value_channels_from_set(&mut owned))?;
    credential_from_material(args, &material, existing_description)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    use seclusor_core::SeclusorError;
    use seclusor_crypto::Identity;

    use crate::cli::*;
    use crate::error::CliError;
    use crate::handlers::bundle::handle_bundle_encrypt;
    use crate::io::{read_secrets_file, write_secrets_file};
    use crate::test_support::*;

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
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
    fn handle_unset_removes_existing_key() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.json");
        let secrets = fixture_secrets();
        write_secrets_file(&path, &secrets, true).expect("write");

        handle_unset(UnsetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
                identity_public_key: None,
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
                identity_public_key: None,
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
                identity_public_key: None,
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
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("clear description");
        let loaded = read_secrets_file(&path).unwrap();
        assert!(loaded.projects[0].credentials["VAULT"]
            .description
            .is_none());
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
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
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
            force: false,
            verbose: false,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        };

        let (output, count) =
            render_export_env_output(&secrets, Some("demo"), &args).expect("export");
        assert_eq!(output, "APP_API_KEY=sk-123");
        assert_eq!(count, 1);
    }

    #[test]
    fn export_shell_format_requires_allow_pattern() {
        let args = ExportEnvArgs {
            file: PathBuf::from("ignored.json"),
            project: Some("demo".to_string()),
            format: EnvFormatArg::Export,
            prefix: None,
            emit_ref: false,
            allow: vec![],
            deny: vec![],
            force: false,
            verbose: false,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        };
        let err = enforce_export_shell_safety(&args, false).expect_err("require allow");
        assert!(format!("{err}").contains("--allow"));
    }

    #[test]
    fn export_shell_format_refuses_tty_without_force() {
        let args = ExportEnvArgs {
            file: PathBuf::from("ignored.json"),
            project: Some("demo".to_string()),
            format: EnvFormatArg::Export,
            prefix: None,
            emit_ref: false,
            allow: vec!["APP_*".to_string()],
            deny: vec![],
            force: false,
            verbose: false,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        };
        let err = enforce_export_shell_safety(&args, true).expect_err("refuse tty");
        assert!(format!("{err}").contains("TTY"));
        // With force, TTY is allowed (warning is side-effect only).
        let forced = ExportEnvArgs {
            force: true,
            ..args
        };
        enforce_export_shell_safety(&forced, true).expect("force permits tty");
    }

    #[test]
    fn export_dotenv_and_json_skip_shell_safety_gates() {
        for format in [EnvFormatArg::Dotenv, EnvFormatArg::Json] {
            let args = ExportEnvArgs {
                file: PathBuf::from("ignored.json"),
                project: Some("demo".to_string()),
                format,
                prefix: None,
                emit_ref: false,
                allow: vec![], // empty still OK for non-export
                deny: vec![],
                force: false,
                verbose: false,
                identities: IdentityArgs::default(),
                passphrase: PassphraseArgs::default(),
            };
            enforce_export_shell_safety(&args, true).expect("non-export ignores tty/allow gates");
        }
    }

    #[test]
    fn export_shell_missing_allow_wins_before_missing_file_io() {
        // Missing allow must fail before any attempt to open the secrets file.
        let missing = PathBuf::from("/nonexistent/seclusor-export-env-no-such-file.json");
        let err = handle_export_env(ExportEnvArgs {
            file: missing,
            project: Some("demo".to_string()),
            format: EnvFormatArg::Export,
            prefix: None,
            emit_ref: false,
            allow: vec![],
            deny: vec![],
            force: false,
            verbose: false,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("must refuse on allow before I/O");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("--allow"),
            "expected allowlist error, got {rendered}"
        );
        assert!(
            !rendered.to_ascii_lowercase().contains("no such file")
                && !rendered.to_ascii_lowercase().contains("not found")
                && !rendered.to_ascii_lowercase().contains("os error"),
            "must not surface file I/O: {rendered}"
        );
    }

    #[test]
    fn export_shell_tty_refuse_wins_before_missing_file_io() {
        // TTY refuse is pure preflight; inject via unit gate (handler uses real
        // stdout isatty). Prove missing-allow already covers file-before-load.
        // TTY+allow without force still must not need a real secrets path when
        // exercised through enforce_export_shell_safety_preflight alone.
        let args = ExportEnvArgs {
            file: PathBuf::from("/nonexistent/seclusor-export-env-tty.json"),
            project: Some("demo".to_string()),
            format: EnvFormatArg::Export,
            prefix: None,
            emit_ref: false,
            allow: vec!["APP_*".to_string()],
            deny: vec![],
            force: false,
            verbose: false,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        };
        let err = enforce_export_shell_safety_preflight(&args, true).expect_err("tty refuse");
        assert!(format!("{err}").contains("TTY"));
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
            force: false,
            verbose: false,
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
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
            force: false,
            verbose: false,
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
            force: false,
            verbose: false,
            identities: IdentityArgs {
                identity_files: vec![wrong_identity_file],
                identity_public_key: None,
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
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("import env");

        let secrets = read_secrets_file(&secrets_path).expect("reload");
        let project = &secrets.projects[0];
        assert!(project.credentials.contains_key("NEW_TOKEN"));
        assert!(project.credentials.contains_key("DB_URL"));
        assert!(!project.credentials.contains_key("IGNORED"));
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
                identity_public_key: None,
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
                identity_public_key: None,
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
            force: false,
            verbose: false,
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        });
        assert!(result.is_ok(), "export-env failed: {}", result.unwrap_err());
    }

    #[test]
    fn handle_list_and_validate_accept_bundle_with_identity() {
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

        handle_list(ListArgs {
            file: bundle.clone(),
            project: Some("demo".to_string()),
            verbose: false,
            identities: IdentityArgs {
                identity_files: vec![identity_file.clone()],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("list bundle");

        handle_validate(ValidateArgs {
            file: bundle,
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("validate bundle full");
    }

    #[test]
    fn handle_list_and_validate_bundle_require_identity() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        write_secrets_file(&input, &fixture_secrets(), true).expect("write input");
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

        let list_err = handle_list(ListArgs {
            file: bundle.clone(),
            project: Some("demo".to_string()),
            verbose: false,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("list bundle without identity");
        assert!(matches!(
            list_err,
            CliError::Codec(seclusor_codec::CodecError::BundleIdentityRequired)
        ));

        let validate_err = handle_validate(ValidateArgs {
            file: bundle,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("validate bundle without identity");
        assert!(matches!(
            validate_err,
            CliError::Codec(seclusor_codec::CodecError::BundleIdentityRequired)
        ));
    }

    #[test]
    fn handle_list_inline_without_identity_lists_keys() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, _identity_file) = write_inline_encrypted_file(dir.path());

        handle_list(ListArgs {
            file: inline,
            project: Some("demo".to_string()),
            verbose: false,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("list inline structural keys");
    }

    #[test]
    fn handle_validate_inline_structural_only_without_identity() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, _identity_file) = write_inline_encrypted_file(dir.path());

        handle_validate(ValidateArgs {
            file: inline,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("structural-only validate");
    }

    #[test]
    fn handle_validate_inline_full_with_identity() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, identity_file) = write_inline_encrypted_file(dir.path());

        handle_validate(ValidateArgs {
            file: inline,
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("full validate with identity");
    }

    #[test]
    fn handle_list_via_identity_public_key() {
        let dir = tempfile::tempdir().expect("temp dir");
        let xdg = dir.path().join("xdg-config");
        let seclusor_cfg = xdg.join("seclusor");
        fs::create_dir_all(&seclusor_cfg).expect("mkdir config");
        let identity_path = seclusor_cfg.join("identity.txt");
        write_identity_file(&identity_path, TEST_IDENTITY);

        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        write_secrets_file(&input, &fixture_secrets(), true).expect("write");
        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt");

        // SAFETY: serial test env; restored on drop via scope-guard pattern below.
        let prev = std::env::var_os("XDG_CONFIG_HOME");
        // Absolute XDG_CONFIG_HOME replaces platform defaults for discovery.
        std::env::set_var("XDG_CONFIG_HOME", &xdg);
        let result = handle_list(ListArgs {
            file: bundle,
            project: Some("demo".to_string()),
            verbose: false,
            identities: IdentityArgs {
                identity_files: vec![],
                identity_public_key: Some(fixture_recipient_string()),
            },
            passphrase: PassphraseArgs::default(),
        });
        match prev {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        result.expect("list via identity public key");
    }

    // --- Encrypted write-target guard (fail-closed) ---

    fn assert_bytes_unchanged(path: &std::path::Path, before: &[u8]) {
        let after = fs::read(path).expect("re-read target");
        assert_eq!(
            after, before,
            "target file must remain byte-identical on refuse"
        );
    }

    fn assert_encrypted_write_refused(err: &CliError, expected_source: &str) {
        match err {
            CliError::EncryptedWriteUnsupported { path, source_kind } => {
                assert_eq!(*source_kind, expected_source);
                assert!(!path.is_empty());
            }
            other => panic!("expected EncryptedWriteUnsupported, got {other:?}"),
        }
        let rendered = err.to_string();
        assert!(rendered.contains("refusing to write into encrypted secrets file"));
        assert!(rendered.contains(&format!("source: {expected_source}")));
        assert!(rendered.contains("not available in this version"));
        // Error output must not include plaintext or ciphertext content.
        assert!(!rendered.contains("sk-123"));
        assert!(!rendered.contains(seclusor_core::constants::INLINE_CIPHERTEXT_PREFIX));
        assert!(!rendered.contains("age-encryption.org"));
        let debug = format!("{err:?}");
        assert!(!debug.contains("sk-123"));
        assert!(!debug.contains(seclusor_core::constants::INLINE_CIPHERTEXT_PREFIX));
    }

    #[test]
    fn set_inline_encrypted_without_recipients_refuses_and_leaves_file_unchanged() {
        let dir = tempfile::tempdir().expect("temp dir");
        // Ciphertext without document recipients metadata (pre-establishment form).
        let inline = dir.path().join("legacy-inline.json");
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        let mut secrets = fixture_secrets();
        let r = fixture_identity().to_public();
        for (_k, cred) in secrets.projects[0].credentials.iter_mut() {
            if let Some(v) = cred.value.take() {
                let ct =
                    seclusor_crypto::encrypt_inline_value(v.as_bytes(), std::slice::from_ref(&r))
                        .expect("encrypt");
                cred.value = Some(ct);
            }
        }
        // Explicitly no recipients metadata.
        secrets.recipients = None;
        secrets.schema_version = "v1.0.0".into();
        write_secrets_file(&inline, &secrets, true).expect("write");
        let before = fs::read(&inline).expect("read before");

        let err = handle_set(SetArgs {
            file: inline.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("plaintext-injection".to_string()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("must refuse without recipients");

        let msg = err.to_string();
        assert!(msg.contains("recipients") || msg.contains("rekey"), "{msg}");
        assert!(!msg.contains("plaintext-injection"));
        assert_bytes_unchanged(&inline, &before);
    }

    #[test]
    fn set_inline_encrypted_wrong_identity_refuses_byte_identical() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, _correct_id) = write_inline_encrypted_file(dir.path());
        let before = fs::read(&inline).expect("read before");
        // Wrong identity B.
        let wrong = dir.path().join("wrong.txt");
        let gen = seclusor_keyring::generate_identity_file(&wrong).expect("gen wrong");
        let _ = gen;

        let err = handle_set(SetArgs {
            file: inline.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("should-not-land".to_string()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![wrong],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("wrong identity must fail Full load");

        let msg = err.to_string();
        assert!(!msg.contains("should-not-land"));
        assert_bytes_unchanged(&inline, &before);
        assert_eq!(list_sibling_names(dir.path()).len(), 3); // inline + correct id + wrong id
    }

    #[test]
    fn set_inline_encrypted_establishes_when_covering_all_fields() {
        let dir = tempfile::tempdir().expect("temp dir");
        // Single encrypted field so establishment coverage holds.
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        let recipient = fixture_recipient_string();
        let mut secrets = SecretsFile::new("demo");
        let ct = seclusor_crypto::encrypt_inline_value(
            b"old",
            std::slice::from_ref(&fixture_identity().to_public()),
        )
        .expect("encrypt");
        secrets.projects[0]
            .credentials
            .insert("API_KEY".into(), Credential::with_value("secret", &ct));
        let inline = dir.path().join("one.json");
        write_secrets_file(&inline, &secrets, true).expect("write");

        handle_set(SetArgs {
            file: inline.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("new-secret-value".to_string()),
            reference: None,
            description: Some("rotated".to_string()),
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![recipient.clone()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("set with establishment");

        let after: SecretsFile =
            serde_json::from_slice(&fs::read(&inline).expect("read")).expect("parse");
        assert_eq!(after.schema_version, "v1.1.0");
        assert_eq!(
            after.recipients.as_deref(),
            Some(std::slice::from_ref(&recipient))
        );
        let val = after.projects[0].credentials["API_KEY"]
            .value
            .as_ref()
            .expect("value");
        assert!(val.starts_with(seclusor_core::constants::INLINE_CIPHERTEXT_PREFIX));
        assert_ne!(val, &ct);
        assert_eq!(
            after.projects[0].credentials["API_KEY"]
                .description
                .as_deref(),
            Some("rotated")
        );
        // Decryptable with identity.
        let plain = seclusor_crypto::decrypt_inline_value(val, &[fixture_identity()]).expect("dec");
        assert_eq!(plain, b"new-secret-value");
    }

    #[test]
    fn init_force_still_refuses_inline_encrypted() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, _identity) = write_inline_encrypted_file(dir.path());
        let before = fs::read(&inline).expect("read before");

        let init_err = handle_init(InitArgs {
            file: inline.clone(),
            project: "other".to_string(),
            env_prefix: None,
            description: None,
            force: true,
            codec: None,
            recipients: RecipientArgs {
                recipients: vec![],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect_err("init --force must refuse encrypted target");
        assert_encrypted_write_refused(&init_err, "inline");
        assert_bytes_unchanged(&inline, &before);
    }

    fn empty_recipient_args() -> RecipientArgs {
        RecipientArgs {
            recipients: vec![],
            recipient_file: None,
            recipient_env_var: None,
        }
    }

    #[test]
    fn init_bundle_create_only_roundtrip() {
        let dir = tempfile::tempdir().expect("temp");
        let out = dir.path().join("fresh.age");
        let id = dir.path().join("id.txt");
        write_identity_file(&id, TEST_IDENTITY);
        let recipient = fixture_recipient_string();

        handle_init(InitArgs {
            file: out.clone(),
            project: "myapp".into(),
            env_prefix: Some("APP_".into()),
            description: Some("demo".into()),
            force: false,
            codec: Some(crate::cli::StorageCodecArg::Bundle),
            recipients: RecipientArgs {
                recipients: vec![recipient.clone()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle init");

        assert!(out.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&out).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "fresh bundle must be 0600");
        }

        let identities = seclusor_keyring::load_identity_file_auto(&id, None).expect("id");
        let secrets = seclusor_codec::decrypt_bundle(&fs::read(&out).expect("read"), &identities)
            .expect("decrypt");
        assert_eq!(secrets.schema_version, "v1.1.0");
        assert_eq!(
            secrets.recipients.as_deref(),
            Some(std::slice::from_ref(&recipient))
        );
        assert_eq!(secrets.projects[0].project_slug, "myapp");
        assert_eq!(secrets.env_prefix.as_deref(), Some("APP_"));
        assert_eq!(secrets.description.as_deref(), Some("demo"));
        assert!(secrets.projects[0].credentials.is_empty());
    }

    #[test]
    fn init_bundle_refuses_existing_path_without_mutate() {
        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("exists.json");
        fs::write(&path, b"prior").expect("write");
        let before = fs::read(&path).expect("before");
        let names = list_sibling_names(dir.path());

        let err = handle_init(InitArgs {
            file: path.clone(),
            project: "default".into(),
            env_prefix: None,
            description: None,
            force: false,
            codec: Some(crate::cli::StorageCodecArg::Bundle),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect_err("existing path");
        let msg = err.to_string();
        assert!(
            msg.contains("create-only") || msg.contains("rekey"),
            "{msg}"
        );
        assert_eq!(fs::read(&path).expect("after"), before);
        assert_eq!(list_sibling_names(dir.path()), names);
    }

    #[test]
    fn init_codec_inline_refuses() {
        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("nope.json");
        let names = list_sibling_names(dir.path());
        let err = handle_init(InitArgs {
            file: path.clone(),
            project: "default".into(),
            env_prefix: None,
            description: None,
            force: false,
            codec: Some(crate::cli::StorageCodecArg::Inline),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect_err("inline codec");
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("inline"), "{msg}");
        assert!(!path.exists());
        assert_eq!(list_sibling_names(dir.path()), names);
    }

    #[test]
    fn init_force_plus_codec_refuses() {
        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("x.age");
        let err = handle_init(InitArgs {
            file: path.clone(),
            project: "default".into(),
            env_prefix: None,
            description: None,
            force: true,
            codec: Some(crate::cli::StorageCodecArg::Bundle),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect_err("force+codec");
        assert!(err.to_string().contains("--force"), "{err}");
        assert!(!path.exists());
    }

    #[test]
    fn init_recipients_without_codec_refuses() {
        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("plain.json");
        let err = handle_init(InitArgs {
            file: path.clone(),
            project: "default".into(),
            env_prefix: None,
            description: None,
            force: false,
            codec: None,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect_err("recipients need codec");
        assert!(err.to_string().contains("recipient"), "{err}");
        assert!(!path.exists());
    }

    #[test]
    fn init_bundle_requires_explicit_recipients_not_ambient_alone() {
        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("ambient.age");
        let var = "SECLUSOR_RECIPIENTS";
        // Isolate: set ambient only; no explicit channel on InitArgs.
        std::env::set_var(var, fixture_recipient_string());
        let err = handle_init(InitArgs {
            file: path.clone(),
            project: "default".into(),
            env_prefix: None,
            description: None,
            force: false,
            codec: Some(crate::cli::StorageCodecArg::Bundle),
            recipients: empty_recipient_args(),
        })
        .expect_err("ambient alone insufficient");
        std::env::remove_var(var);
        let msg = err.to_string();
        assert!(
            msg.contains("explicit") || msg.contains("recipient"),
            "{msg}"
        );
        assert!(!path.exists());
    }

    #[test]
    fn init_bundle_missing_recipients_refuses() {
        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("norec.age");
        std::env::remove_var("SECLUSOR_RECIPIENTS");
        let err = handle_init(InitArgs {
            file: path.clone(),
            project: "default".into(),
            env_prefix: None,
            description: None,
            force: false,
            codec: Some(crate::cli::StorageCodecArg::Bundle),
            recipients: empty_recipient_args(),
        })
        .expect_err("no recipients");
        assert!(!path.exists());
        assert!(err.to_string().contains("recipient"), "{err}");
    }

    #[test]
    fn a1_recipients_empty_credentials_set_refuses_plaintext_persist() {
        // End-to-end A1 regression: hand-built v1.1.0 + recipients + empty
        // credentials classifies as plaintext; set must not store plaintext.
        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("trap.json");
        let mut secrets = SecretsFile::new("demo");
        secrets
            .establish_recipients(vec![fixture_recipient_string()])
            .expect("establish");
        write_secrets_file(&path, &secrets, true).expect("write trap");
        let before = fs::read(&path).expect("before");
        let names = list_sibling_names(dir.path());

        let err = handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".into()),
            key: "API_KEY".into(),
            credential_type: "secret".into(),
            value: Some("must-not-persist-plaintext".into()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: empty_recipient_args(),
            identities: IdentityArgs {
                identity_files: vec![],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("must refuse plaintext value with recipients");

        let msg = err.to_string();
        assert!(!msg.contains("must-not-persist-plaintext"), "{msg}");
        assert_eq!(fs::read(&path).expect("after"), before);
        assert_eq!(list_sibling_names(dir.path()), names);
    }

    #[test]
    fn init_cli_rejects_passphrase_flags_as_unsupported() {
        // C7 freeze: init has no passphrase surface; clap rejects unknown flags.
        use crate::cli::Cli;
        use clap::Parser;
        let parsed = Cli::try_parse_from([
            "seclusor",
            "secrets",
            "init",
            "--codec",
            "bundle",
            "--recipient",
            &fixture_recipient_string(),
            "--passphrase",
        ]);
        assert!(parsed.is_err(), "init must not accept --passphrase");
    }

    #[test]
    fn handle_unset_inline_structural_only_preserves_untouched_ciphertext() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, _identity) = write_inline_encrypted_file(dir.path());
        let before = fs::read(&inline).expect("read before");
        let before_secrets: SecretsFile = serde_json::from_slice(&before).expect("parse before");
        let vault_ct = before_secrets.projects[0].credentials["VAULT"]
            .reference
            .clone();
        // VAULT is a ref in the fixture; use a second encrypted value if present.
        // Fixture has API_KEY (value, encrypted) and VAULT (ref, plaintext pointer).
        let api_before = before_secrets.projects[0].credentials["API_KEY"]
            .value
            .clone()
            .expect("API_KEY value");

        // Encrypt a second value so we can assert untouched ciphertext identity.
        let mut multi = before_secrets.clone();
        let recipients = vec![fixture_identity().to_public()];
        let other_ct = seclusor_crypto::encrypt_inline_value(b"other-secret", &recipients)
            .expect("encrypt OTHER");
        multi.projects[0].credentials.insert(
            "OTHER".to_string(),
            seclusor_core::Credential::with_value("secret", &other_ct),
        );
        write_secrets_file(&inline, &multi, false).expect("write multi");
        let prior = fs::read(&inline).expect("re-read multi");
        let other_before = other_ct.clone();

        handle_unset(UnsetArgs {
            file: inline.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("inline structural unset");

        let after = fs::read(&inline).expect("read after");
        assert_ne!(after, prior, "file content must change");
        let after_secrets: SecretsFile = serde_json::from_slice(&after).expect("parse after");
        assert!(!after_secrets.projects[0]
            .credentials
            .contains_key("API_KEY"));
        assert_eq!(
            after_secrets.projects[0].credentials["OTHER"]
                .value
                .as_deref(),
            Some(other_before.as_str()),
            "untouched ciphertext must be byte-identical"
        );
        // Removed key's ciphertext must not reappear as another field's value.
        for cred in after_secrets.projects[0].credentials.values() {
            if let Some(v) = &cred.value {
                assert_ne!(v, &api_before);
            }
        }
        let _ = vault_ct;
    }

    #[test]
    fn handle_set_description_only_inline_preserves_ciphertext() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, _identity) = write_inline_encrypted_file(dir.path());
        let before_secrets: SecretsFile =
            serde_json::from_slice(&fs::read(&inline).expect("read")).expect("parse");
        let api_ct = before_secrets.projects[0].credentials["API_KEY"]
            .value
            .clone()
            .expect("API_KEY ciphertext");

        handle_set(SetArgs {
            file: inline.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: None,
            reference: None,
            description: Some("  rotated note  ".to_string()),
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("description-only inline");

        let after_secrets: SecretsFile =
            serde_json::from_slice(&fs::read(&inline).expect("read after")).expect("parse after");
        assert_eq!(
            after_secrets.projects[0].credentials["API_KEY"]
                .description
                .as_deref(),
            Some("rotated note")
        );
        assert_eq!(
            after_secrets.projects[0].credentials["API_KEY"]
                .value
                .as_deref(),
            Some(api_ct.as_str()),
            "value ciphertext must be byte-identical"
        );
    }

    #[test]
    fn handle_set_description_only_plaintext() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.json");
        write_fixture_secrets(&path, &fixture_secrets());

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: None,
            reference: None,
            description: Some("plain note".to_string()),
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("plaintext description-only");

        let loaded = read_secrets_file(&path).expect("reload");
        assert_eq!(
            loaded.projects[0].credentials["API_KEY"]
                .description
                .as_deref(),
            Some("plain note")
        );
        assert_eq!(
            loaded.projects[0].credentials["API_KEY"].value.as_deref(),
            Some("sk-123")
        );
    }

    #[test]
    fn handle_set_description_only_refuses_missing_key_and_create_project() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.json");
        write_fixture_secrets(&path, &fixture_secrets());

        let missing = handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "NO_SUCH".to_string(),
            credential_type: "secret".to_string(),
            value: None,
            reference: None,
            description: Some("x".to_string()),
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("missing key");
        assert!(matches!(
            missing,
            CliError::Core(SeclusorError::CredentialNotFound { .. })
        ));

        let create = handle_set(SetArgs {
            file: path,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: None,
            reference: None,
            description: Some("x".to_string()),
            create_project: true,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("create_project");
        let msg = create.to_string();
        assert!(msg.contains("description-only"));
        assert!(msg.contains("cannot create"));
    }

    #[test]
    fn handle_set_description_only_bundle_encrypting_write() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("plain.json");
        let bundle = dir.path().join("secrets.age");
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        write_secrets_file(&input, &fixture_secrets(), true).expect("write plain");
        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt");

        handle_set(SetArgs {
            file: bundle.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: None,
            reference: None,
            description: Some("bundle note".to_string()),
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file.clone()],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("bundle description-only");

        let decrypted = seclusor_codec::decrypt_bundle(
            &fs::read(&bundle).expect("read"),
            &[fixture_identity()],
        )
        .expect("decrypt");
        assert_eq!(
            decrypted.projects[0].credentials["API_KEY"]
                .description
                .as_deref(),
            Some("bundle note")
        );
        assert_eq!(
            decrypted.projects[0].credentials["API_KEY"]
                .value
                .as_deref(),
            Some("sk-123")
        );
        assert!(decrypted.recipients.is_some());
    }

    #[test]
    fn handle_unset_bundle_encrypting_write() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("plain.json");
        let bundle = dir.path().join("secrets.age");
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        write_secrets_file(&input, &fixture_secrets(), true).expect("write plain");
        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt");

        handle_unset(UnsetArgs {
            file: bundle.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("bundle unset");

        let decrypted = seclusor_codec::decrypt_bundle(
            &fs::read(&bundle).expect("read"),
            &[fixture_identity()],
        )
        .expect("decrypt");
        assert!(!decrypted.projects[0].credentials.contains_key("API_KEY"));
    }

    #[test]
    fn commit_inline_structural_mutation_cas_uses_load_time_bytes() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, _identity) = write_inline_encrypted_file(dir.path());
        let prior = fs::read(&inline).expect("prior");
        let racing = b"racing-concurrent-bytes-v2";

        let err = commit_inline_structural_mutation(&inline, &prior, |secrets| {
            // Simulate concurrent writer between load and commit.
            fs::write(&inline, racing).expect("race write");
            let project_slug = secrets.projects[0].project_slug.clone();
            let result = unset_inline_value(secrets, &project_slug, "API_KEY").expect("mutate");
            Ok(result.secrets)
        })
        .expect_err("CAS must fail when target changed mid-mutation");

        assert!(
            matches!(err, CliError::ConcurrentModification { .. }),
            "got {err:?}"
        );
        assert_eq!(
            fs::read(&inline).expect("after race"),
            racing,
            "racing content must remain (CAS refused overwrite)"
        );
    }

    const MIXED_PLAINTEXT_SENTINEL: &str = "SECLUSOR_PLAINTEXT_SENTINEL_7f3a";

    fn write_mixed_inline_with_plaintext_sentinel(path: &std::path::Path) {
        let recipients = vec![fixture_identity().to_public()];
        let mut secrets = SecretsFile::new("demo");
        let ct = seclusor_crypto::encrypt_inline_value(b"encrypted-secret", &recipients)
            .expect("encrypt");
        secrets.projects[0].credentials.insert(
            "ENC_KEY".to_string(),
            seclusor_core::Credential::with_value("secret", &ct),
        );
        secrets.projects[0].credentials.insert(
            "PLAIN_KEY".to_string(),
            seclusor_core::Credential::with_value("secret", MIXED_PLAINTEXT_SENTINEL),
        );
        secrets.projects[0].credentials.insert(
            "REF_KEY".to_string(),
            seclusor_core::Credential::with_ref("ref", "vault://keep"),
        );
        write_secrets_file(path, &secrets, true).expect("write mixed");
    }

    #[test]
    fn handle_unset_mixed_doc_refuses_when_plaintext_remains() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("mixed.json");
        write_mixed_inline_with_plaintext_sentinel(&path);
        let before = fs::read(&path).expect("before");
        let names_before = list_sibling_names(dir.path());

        let err = handle_unset(UnsetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "ENC_KEY".to_string(),
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("must refuse plaintext residual");

        let rendered = err.to_string();
        assert!(
            rendered.contains("plaintext value") || rendered.contains("PLAIN_KEY"),
            "error={rendered}"
        );
        assert!(!rendered.contains(MIXED_PLAINTEXT_SENTINEL));
        assert!(!rendered.contains(seclusor_core::constants::INLINE_CIPHERTEXT_PREFIX));
        assert_bytes_unchanged(&path, &before);
        assert_eq!(list_sibling_names(dir.path()), names_before);
    }

    #[test]
    fn handle_set_description_only_mixed_doc_refuses_when_plaintext_remains() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("mixed.json");
        write_mixed_inline_with_plaintext_sentinel(&path);
        let before = fs::read(&path).expect("before");
        let names_before = list_sibling_names(dir.path());

        let err = handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "ENC_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: None,
            reference: None,
            description: Some("note".to_string()),
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("must refuse plaintext residual");

        let rendered = err.to_string();
        assert!(rendered.contains("plaintext value") || rendered.contains("PLAIN_KEY"));
        assert!(!rendered.contains(MIXED_PLAINTEXT_SENTINEL));
        assert_bytes_unchanged(&path, &before);
        assert_eq!(list_sibling_names(dir.path()), names_before);
    }

    #[test]
    fn handle_unset_mixed_doc_succeeds_when_last_plaintext_removed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("mixed.json");
        write_mixed_inline_with_plaintext_sentinel(&path);
        let before_secrets: SecretsFile =
            serde_json::from_slice(&fs::read(&path).expect("read")).expect("parse");
        let enc_ct = before_secrets.projects[0].credentials["ENC_KEY"]
            .value
            .clone()
            .expect("enc");

        handle_unset(UnsetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "PLAIN_KEY".to_string(),
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("removing last plaintext is allowed");

        let after: SecretsFile =
            serde_json::from_slice(&fs::read(&path).expect("after")).expect("parse after");
        assert!(!after.projects[0].credentials.contains_key("PLAIN_KEY"));
        assert_eq!(
            after.projects[0].credentials["ENC_KEY"].value.as_deref(),
            Some(enc_ct.as_str())
        );
        assert_eq!(
            after.projects[0].credentials["REF_KEY"]
                .reference
                .as_deref(),
            Some("vault://keep")
        );
        ensure_no_plaintext_credential_values(&after).expect("result is ciphertext/ref only");
    }

    #[test]
    fn handle_set_description_only_ref_credential_and_clear() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, _identity) = write_inline_encrypted_file(dir.path());
        // Fixture VAULT is a ref; description-only must not touch ref body.
        let before: SecretsFile =
            serde_json::from_slice(&fs::read(&inline).expect("read")).expect("parse");
        let ref_before = before.projects[0].credentials["VAULT"]
            .reference
            .clone()
            .expect("ref");

        handle_set(SetArgs {
            file: inline.clone(),
            project: Some("demo".to_string()),
            key: "VAULT".to_string(),
            credential_type: "ref".to_string(),
            value: None,
            reference: None,
            description: Some("  ref note  ".to_string()),
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("description on ref");

        let mid: SecretsFile =
            serde_json::from_slice(&fs::read(&inline).expect("mid")).expect("parse mid");
        assert_eq!(
            mid.projects[0].credentials["VAULT"].description.as_deref(),
            Some("ref note")
        );
        assert_eq!(
            mid.projects[0].credentials["VAULT"].reference.as_deref(),
            Some(ref_before.as_str())
        );

        handle_set(SetArgs {
            file: inline.clone(),
            project: Some("demo".to_string()),
            key: "VAULT".to_string(),
            credential_type: "ref".to_string(),
            value: None,
            reference: None,
            description: Some(String::new()),
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("clear description");

        let after: SecretsFile =
            serde_json::from_slice(&fs::read(&inline).expect("after")).expect("parse after");
        assert!(after.projects[0].credentials["VAULT"].description.is_none());
        assert_eq!(
            after.projects[0].credentials["VAULT"].reference.as_deref(),
            Some(ref_before.as_str())
        );
    }

    #[test]
    fn structural_ops_preserve_recipients_and_multi_project_ciphertext() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("multi.json");
        let recipients = vec![fixture_identity().to_public()];
        let mut secrets = SecretsFile::new("alpha");
        secrets.schema_version = seclusor_core::constants::SCHEMA_VERSION_V1_1_0.to_string();
        secrets.recipients = Some(vec![fixture_recipient_string()]);
        let a_ct =
            seclusor_crypto::encrypt_inline_value(b"alpha-secret", &recipients).expect("enc a");
        let b_ct =
            seclusor_crypto::encrypt_inline_value(b"beta-secret", &recipients).expect("enc b");
        secrets.projects[0].credentials.insert(
            "A_KEY".to_string(),
            seclusor_core::Credential::with_value("secret", &a_ct),
        );
        secrets.projects.push(seclusor_core::Project {
            project_slug: "beta".to_string(),
            description: None,
            credentials: {
                let mut m = std::collections::BTreeMap::new();
                m.insert(
                    "B_KEY".to_string(),
                    seclusor_core::Credential::with_value("secret", &b_ct),
                );
                m
            },
        });
        write_secrets_file(&path, &secrets, true).expect("write multi");

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("alpha".to_string()),
            key: "A_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: None,
            reference: None,
            description: Some("alpha note".to_string()),
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("desc multi");

        let after_desc: SecretsFile =
            serde_json::from_slice(&fs::read(&path).expect("read")).expect("parse");
        assert_eq!(
            after_desc.schema_version,
            seclusor_core::constants::SCHEMA_VERSION_V1_1_0
        );
        assert_eq!(
            after_desc.recipients.as_deref(),
            Some([fixture_recipient_string()].as_slice())
        );
        assert_eq!(
            after_desc.projects[0].credentials["A_KEY"].value.as_deref(),
            Some(a_ct.as_str())
        );
        assert_eq!(
            after_desc.projects[1].credentials["B_KEY"].value.as_deref(),
            Some(b_ct.as_str())
        );

        handle_unset(UnsetArgs {
            file: path.clone(),
            project: Some("alpha".to_string()),
            key: "A_KEY".to_string(),
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("unset multi");

        let after_unset: SecretsFile =
            serde_json::from_slice(&fs::read(&path).expect("read2")).expect("parse2");
        assert!(!after_unset.projects[0].credentials.contains_key("A_KEY"));
        assert_eq!(
            after_unset.projects[1].credentials["B_KEY"]
                .value
                .as_deref(),
            Some(b_ct.as_str())
        );
        assert_eq!(
            after_unset.recipients.as_deref(),
            Some([fixture_recipient_string()].as_slice())
        );
    }

    #[test]
    fn handle_set_description_only_refuses_ambiguous_and_missing_project() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("two.json");
        let mut secrets = fixture_secrets();
        secrets.projects.push(seclusor_core::Project {
            project_slug: "other".to_string(),
            description: None,
            credentials: std::collections::BTreeMap::new(),
        });
        // Encrypt so structural path is taken if we ever load it; plaintext multi
        // also exercises project resolution before write.
        let recipients = vec![fixture_identity().to_public()];
        let encrypted = seclusor_codec::encrypt_inline(&secrets, &recipients).expect("encrypt");
        write_secrets_file(&path, &encrypted, true).expect("write");
        let before = fs::read(&path).expect("before");

        let ambiguous = handle_set(SetArgs {
            file: path.clone(),
            project: None,
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: None,
            reference: None,
            description: Some("x".to_string()),
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("ambiguous project");
        assert!(matches!(
            ambiguous,
            CliError::Core(SeclusorError::AmbiguousProject(_))
        ));
        assert_bytes_unchanged(&path, &before);

        let missing = handle_set(SetArgs {
            file: path.clone(),
            project: Some("nope".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: None,
            reference: None,
            description: Some("x".to_string()),
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("missing project");
        assert!(
            matches!(missing, CliError::Core(SeclusorError::ProjectNotFound(_)))
                || matches!(
                    missing,
                    CliError::Codec(seclusor_codec::CodecError::ProjectNotFound(_))
                )
        );
        assert_bytes_unchanged(&path, &before);
    }

    #[test]
    fn commit_structural_refuses_when_pretty_output_exceeds_document_limit() {
        use seclusor_core::constants::{
            MAX_CREDENTIALS_PER_PROJECT, MAX_PROJECTS, MAX_SECRETS_DOC_BYTES,
        };

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("near-limit.json");
        let recipients = vec![fixture_identity().to_public()];
        // Minified valid inline document under the limit.
        let mut base = SecretsFile::new("demo");
        let ct = seclusor_crypto::encrypt_inline_value(b"seed", &recipients).expect("encrypt seed");
        base.projects[0].credentials.insert(
            "SEED".to_string(),
            seclusor_core::Credential::with_value("secret", &ct),
        );
        let compact = serde_json::to_vec(&base).expect("compact");
        assert!(compact.len() < MAX_SECRETS_DOC_BYTES);
        fs::write(&path, &compact).expect("write compact");
        let before = fs::read(&path).expect("before");

        // Grow with ref-only credentials (no plaintext values) until pretty-print
        // exceeds the document limit while still passing validate_strict.
        let err = commit_inline_structural_mutation(&path, &before, |loaded| {
            let mut out = loaded.clone();
            let pad = "P".repeat(1800);
            let mut n = 0usize;
            for p in 0..MAX_PROJECTS {
                if p >= out.projects.len() {
                    out.projects.push(seclusor_core::Project {
                        project_slug: format!("p{p}"),
                        description: None,
                        credentials: std::collections::BTreeMap::new(),
                    });
                }
                while out.projects[p].credentials.len() < MAX_CREDENTIALS_PER_PROJECT {
                    out.projects[p].credentials.insert(
                        format!("K{n}"),
                        seclusor_core::Credential {
                            credential_type: "ref".to_string(),
                            value: None,
                            reference: Some(format!("vault://{pad}/{n}")),
                            description: None,
                        },
                    );
                    n += 1;
                }
                // Probe after each full project to stop early once over limit.
                if serde_json::to_vec_pretty(&out).expect("pretty probe").len()
                    > MAX_SECRETS_DOC_BYTES
                {
                    break;
                }
            }
            let pretty_len = serde_json::to_vec_pretty(&out).expect("pretty final").len();
            assert!(
                pretty_len > MAX_SECRETS_DOC_BYTES,
                "test fixture must exceed document limit after pretty-print (got {pretty_len})"
            );
            Ok(out)
        })
        .expect_err("must refuse oversized pretty output");

        assert!(
            matches!(err, CliError::Core(SeclusorError::DocumentTooLarge { .. })),
            "got {err:?}"
        );
        assert_bytes_unchanged(&path, &before);
        assert_eq!(
            list_sibling_names(dir.path()),
            vec!["near-limit.json".to_string()]
        );
    }

    fn list_sibling_names(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn set_bundle_without_identity_refuses_and_leaves_file_unchanged() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("plain.json");
        let bundle = dir.path().join("secrets.age");
        write_secrets_file(&input, &fixture_secrets(), true).expect("write plain");
        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt bundle");
        let before = fs::read(&bundle).expect("read before");

        let err = handle_set(SetArgs {
            file: bundle.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("nope".to_string()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("must refuse without identity");

        assert!(err.to_string().contains("identity"));
        assert_bytes_unchanged(&bundle, &before);
    }

    #[test]
    fn set_bundle_encrypting_value_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("plain.json");
        let bundle = dir.path().join("secrets.age");
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        write_secrets_file(&input, &fixture_secrets(), true).expect("write plain");
        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt bundle");

        handle_set(SetArgs {
            file: bundle.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("bundle-new-value".to_string()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("bundle set");

        let decrypted = seclusor_codec::decrypt_bundle(
            &fs::read(&bundle).expect("read"),
            &[fixture_identity()],
        )
        .expect("decrypt");
        assert_eq!(
            decrypted.projects[0].credentials["API_KEY"]
                .value
                .as_deref(),
            Some("bundle-new-value")
        );
        assert!(decrypted.recipients.is_some());
    }

    #[test]
    fn set_bundle_establishment_resize_one_to_two_refuses_rekey() {
        // Value-write establishment cannot grow the set (1→2 → rekey).
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("plain.json");
        let bundle = dir.path().join("secrets.age");
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        write_secrets_file(&input, &fixture_secrets(), true).expect("write plain");
        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt to one recipient");
        let before = fs::read(&bundle).expect("before");
        let names_before = list_sibling_names(dir.path());

        let id2_path = dir.path().join("id2.txt");
        let gen2 = seclusor_keyring::generate_identity_file(&id2_path).expect("id2");
        let r2 = gen2.recipient;

        let err = handle_set(SetArgs {
            file: bundle.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("two-recipient-value".to_string()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string(), r2],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("1→2 resize must refuse");

        let msg = err.to_string();
        assert!(msg.contains("rekey") || msg.contains("resize") || msg.contains("stanza"));
        assert!(!msg.contains("two-recipient-value"));
        assert_eq!(fs::read(&bundle).expect("after"), before);
        assert_eq!(
            list_sibling_names(dir.path()).len(),
            names_before.len() + 1 // + id2
        );
    }

    #[test]
    fn set_bundle_establishment_n_to_one_refuses_team_drop() {
        // Dangerous footgun — cannot silently drop team recipients to {me}.
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("plain.json");
        let bundle = dir.path().join("secrets.age");
        let id_a = dir.path().join("id-a.txt");
        let id_b = dir.path().join("id-b.txt");
        write_identity_file(&id_a, TEST_IDENTITY);
        let gen_b = seclusor_keyring::generate_identity_file(&id_b).expect("id-b");
        write_secrets_file(&input, &fixture_secrets(), true).expect("write plain");
        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string(), gen_b.recipient.clone()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt to two");
        let before = fs::read(&bundle).expect("before");
        assert_eq!(
            seclusor_crypto::count_x25519_recipient_stanzas(&before).expect("c"),
            2
        );

        let err = handle_set(SetArgs {
            file: bundle.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("solo-value".to_string()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![id_a],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("N→1 must refuse");

        assert!(err.to_string().contains("rekey") || err.to_string().contains("stanza"));
        assert!(!err.to_string().contains("solo-value"));
        assert_eq!(fs::read(&bundle).expect("after"), before);
    }

    #[test]
    fn set_bundle_same_count_establishment_succeeds() {
        // Cardinality-preserving establishment still allowed (member-swap residual
        // is documented; count match is the enforceable guard).
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("plain.json");
        let bundle = dir.path().join("secrets.age");
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        write_secrets_file(&input, &fixture_secrets(), true).expect("write plain");
        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt");

        handle_set(SetArgs {
            file: bundle.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("same-count-value".to_string()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("same-count establish");

        let secrets = seclusor_codec::decrypt_bundle(
            &fs::read(&bundle).expect("read"),
            &[fixture_identity()],
        )
        .expect("dec");
        assert_eq!(secrets.recipients.as_ref().map(|r| r.len()), Some(1));
        assert_eq!(
            secrets.projects[0].credentials["API_KEY"].value.as_deref(),
            Some("same-count-value")
        );
    }

    #[test]
    fn set_inline_establishment_n_to_one_refuses() {
        let dir = tempfile::tempdir().expect("temp dir");
        let identity_file = dir.path().join("id.txt");
        let id_b = dir.path().join("id-b.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        let gen_b = seclusor_keyring::generate_identity_file(&id_b).expect("id-b");
        let r_a = fixture_identity().to_public();
        let r_b: seclusor_crypto::Recipient = gen_b.recipient.parse().expect("parse r_b");

        let mut secrets = SecretsFile::new("demo");
        // Two-recipient prior ciphertext, no metadata (migration surface).
        let ct = seclusor_crypto::encrypt_inline_value(b"old", &[r_a, r_b]).expect("enc");
        secrets.projects[0]
            .credentials
            .insert("API_KEY".into(), Credential::with_value("secret", &ct));
        let inline = dir.path().join("two.json");
        write_secrets_file(&inline, &secrets, true).expect("write");
        let before = fs::read(&inline).expect("before");

        let err = handle_set(SetArgs {
            file: inline.clone(),
            project: Some("demo".into()),
            key: "API_KEY".into(),
            credential_type: "secret".into(),
            value: Some("narrow".into()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("inline N→1 refuse");

        assert!(err.to_string().contains("rekey") || err.to_string().contains("stanza"));
        assert!(!err.to_string().contains("narrow"));
        assert_eq!(fs::read(&inline).expect("after"), before);
    }

    #[test]
    fn set_armored_bundle_marker_without_identity_refuses() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("armored.age");
        // Marker-only is enough (bundle marker wins even if payload is garbage).
        let armored = b"-----BEGIN AGE ENCRYPTED FILE-----\nnot-a-real-payload\n";
        fs::write(&path, armored).expect("write armored");
        let before = armored.to_vec();

        let err = handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "K".to_string(),
            credential_type: "secret".to_string(),
            value: Some("x".to_string()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("must refuse without identity / invalid payload");

        assert_bytes_unchanged(&path, &before);
        let msg = err.to_string();
        assert!(!msg.contains("AGE-SECRET"));
        assert!(!msg.contains("not-a-real-payload"));
    }

    #[test]
    fn write_guard_unset_refuses_malformed_object_inline_value_before_lenient() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("malformed-inline.json");
        // Invalid schema_version so strict parse fails; credential value still carries marker.
        // Probe classifies as encrypted inline → structural path (not lenient).
        write_raw_json(
            &path,
            r#"{
              "schema_version": "v9.9.9",
              "projects": [{
                "project_slug": "demo",
                "credentials": {
                  "API_KEY": {
                    "type": "secret",
                    "value": "sec:age:v1:dGVzdA"
                  }
                }
              }]
            }"#,
        );
        let before = fs::read(&path).expect("read before");

        let err = handle_unset(UnsetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("must fail closed before lenient path");

        // Structural load fails validation — never mutates or enters lenient recovery.
        let rendered = err.to_string();
        assert!(
            rendered.contains("schema_version") || rendered.contains("Validation"),
            "error={rendered}"
        );
        assert!(!rendered.contains("sec:age:v1:"));
        assert_bytes_unchanged(&path, &before);
    }

    #[test]
    fn write_guard_unset_refuses_bare_string_inline_credential_before_lenient() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("bare-string-inline.json");
        // Bare-string credential is malformed model shape but carries the inline marker.
        // Probe classifies as encrypted inline → structural path (not lenient).
        write_raw_json(
            &path,
            r#"{
              "schema_version": "v1.0.0",
              "projects": [{
                "project_slug": "demo",
                "credentials": {
                  "API_KEY": "sec:age:v1:dGVzdA",
                  "OTHER": {"type":"secret","value":"plain"}
                }
              }]
            }"#,
        );
        let before = fs::read(&path).expect("read before");

        let err = handle_unset(UnsetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("must fail closed on bare-string encrypted credential");

        let rendered = err.to_string();
        // Must not lenient-strip; must not echo ciphertext body.
        assert!(!rendered.contains("sec:age:v1:dGVzdA"));
        assert!(!rendered.contains("file was updated"));
        assert_bytes_unchanged(&path, &before);
    }

    #[test]
    fn write_guard_prefix_in_description_does_not_misclassify_as_encrypted() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("desc-prefix.json");
        let mut secrets = fixture_secrets();
        secrets.projects[0]
            .credentials
            .get_mut("API_KEY")
            .unwrap()
            .description = Some("mentions sec:age:v1: but is not ciphertext".to_string());
        write_secrets_file(&path, &secrets, true).expect("write");

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("updated-plain".to_string()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("description text must not trigger encrypted refuse");

        let loaded = read_secrets_file(&path).expect("reload");
        assert_eq!(
            loaded.projects[0].credentials["API_KEY"].value.as_deref(),
            Some("updated-plain")
        );
    }

    #[test]
    fn write_guard_plaintext_set_still_mutates() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.json");
        write_secrets_file(&path, &fixture_secrets(), true).expect("write");

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("new-value".to_string()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs::default(),
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("plaintext set still works");

        let loaded = read_secrets_file(&path).expect("reload");
        assert_eq!(
            loaded.projects[0].credentials["API_KEY"].value.as_deref(),
            Some("new-value")
        );
    }

    #[test]
    fn import_env_inline_batch_untouched_and_identity_refusals() {
        let dir = tempfile::tempdir().expect("temp");
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        let recipient = fixture_identity().to_public();

        // Multi-entry document with established recipients so a partial import
        // batch may leave OTHER ciphertext byte-identical.
        let mut secrets = SecretsFile::new("demo");
        secrets.env_prefix = Some("APP_".into());
        secrets
            .establish_recipients(vec![recipient.to_string()])
            .expect("establish");
        let ct_token =
            seclusor_crypto::encrypt_inline_value(b"old-token", std::slice::from_ref(&recipient))
                .expect("enc token");
        let ct_other = seclusor_crypto::encrypt_inline_value(
            b"other-secret",
            std::slice::from_ref(&recipient),
        )
        .expect("enc other");
        secrets.projects[0].credentials.insert(
            "TOKEN".into(),
            Credential {
                credential_type: "secret".into(),
                value: Some(ct_token),
                reference: None,
                description: Some("keep-me-until-import".into()),
            },
        );
        secrets.projects[0]
            .credentials
            .insert("OTHER".into(), Credential::with_value("secret", &ct_other));
        let inline = dir.path().join("multi.json");
        write_secrets_file(&inline, &secrets, true).expect("write");
        let other_ct_before = ct_other;

        // Happy path: import only TOKEN; OTHER ciphertext must stay byte-identical.
        // Use dotenv_file (not process env) to avoid parallel-test pollution.
        let dotenv = dir.path().join("import.env");
        fs::write(&dotenv, "APP_TOKEN=imported-secret\n").expect("dotenv");
        handle_import_env(ImportEnvArgs {
            file: inline.clone(),
            project: Some("demo".into()),
            credential_type: "secret".into(),
            prefix: Some("APP_".into()),
            strip_prefix: true,
            dotenv_file: Some(dotenv.clone()),
            create_project: false,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file.clone()],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("import");

        let after: SecretsFile =
            serde_json::from_slice(&fs::read(&inline).expect("read")).expect("parse");
        let val = after.projects[0].credentials["TOKEN"]
            .value
            .as_ref()
            .unwrap();
        assert!(val.starts_with("sec:age:v1:"));
        assert_eq!(
            after.projects[0].credentials["OTHER"]
                .value
                .as_deref()
                .unwrap(),
            other_ct_before,
            "untouched ciphertext must be byte-identical"
        );
        assert!(after.projects[0].credentials["TOKEN"].description.is_none());
        let plain = seclusor_crypto::decrypt_inline_value(val, &[fixture_identity()]).expect("dec");
        assert_eq!(plain, b"imported-secret");

        // Missing identity: Full-load refuse, byte-identical, no temps.
        let before = fs::read(&inline).expect("before missing");
        let names_before = list_sibling_names(dir.path());
        fs::write(&dotenv, "APP_TOKEN=no-id-secret\n").expect("dotenv");
        let missing = handle_import_env(ImportEnvArgs {
            file: inline.clone(),
            project: Some("demo".into()),
            credential_type: "secret".into(),
            prefix: Some("APP_".into()),
            strip_prefix: true,
            dotenv_file: Some(dotenv.clone()),
            create_project: false,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("missing identity");
        assert!(missing.to_string().contains("identity"));
        assert!(!missing.to_string().contains("no-id-secret"));
        assert_eq!(fs::read(&inline).expect("after missing"), before);
        assert_eq!(list_sibling_names(dir.path()), names_before);

        // Wrong identity: byte-identical refusal.
        let wrong = dir.path().join("wrong.txt");
        seclusor_keyring::generate_identity_file(&wrong).expect("wrong");
        fs::write(&dotenv, "APP_TOKEN=must-not-apply\n").expect("dotenv");
        let err = handle_import_env(ImportEnvArgs {
            file: inline.clone(),
            project: Some("demo".into()),
            credential_type: "secret".into(),
            prefix: Some("APP_".into()),
            strip_prefix: true,
            dotenv_file: Some(dotenv),
            create_project: false,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![wrong],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("wrong identity");
        assert!(!err.to_string().contains("must-not-apply"));
        assert_eq!(fs::read(&inline).expect("after wrong"), before);
        assert_eq!(list_sibling_names(dir.path()).len(), names_before.len() + 1);
        // + wrong id
    }

    #[test]
    fn import_env_bundle_happy_and_identity_refusals() {
        let dir = tempfile::tempdir().expect("temp");
        let input = dir.path().join("plain.json");
        let bundle = dir.path().join("secrets.age");
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        let mut secrets = fixture_secrets();
        secrets.env_prefix = Some("APP_".into());
        write_secrets_file(&input, &secrets, true).expect("write");
        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt");

        let dotenv = dir.path().join("bundle-import.env");
        fs::write(&dotenv, "APP_API_KEY=bundle-imported\n").expect("dotenv");
        handle_import_env(ImportEnvArgs {
            file: bundle.clone(),
            project: Some("demo".into()),
            credential_type: "secret".into(),
            prefix: Some("APP_".into()),
            strip_prefix: true,
            dotenv_file: Some(dotenv.clone()),
            create_project: false,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("import bundle");

        let dec = seclusor_codec::decrypt_bundle(
            &fs::read(&bundle).expect("read"),
            &[fixture_identity()],
        )
        .expect("dec");
        assert_eq!(
            dec.projects[0].credentials["API_KEY"].value.as_deref(),
            Some("bundle-imported")
        );
        assert!(dec.recipients.is_some());

        // Missing identity refuse, byte-identical, no residual temp.
        let before = fs::read(&bundle).expect("before missing");
        let names_before = list_sibling_names(dir.path());
        fs::write(&dotenv, "APP_API_KEY=bundle-no-id\n").expect("dotenv");
        let missing = handle_import_env(ImportEnvArgs {
            file: bundle.clone(),
            project: Some("demo".into()),
            credential_type: "secret".into(),
            prefix: Some("APP_".into()),
            strip_prefix: true,
            dotenv_file: Some(dotenv.clone()),
            create_project: false,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("missing identity");
        assert!(missing.to_string().contains("identity"));
        assert!(!missing.to_string().contains("bundle-no-id"));
        assert_eq!(fs::read(&bundle).expect("after missing"), before);
        assert_eq!(list_sibling_names(dir.path()), names_before);

        // Wrong identity refuse, byte-identical.
        let wrong = dir.path().join("wrong.txt");
        seclusor_keyring::generate_identity_file(&wrong).expect("wrong");
        fs::write(&dotenv, "APP_API_KEY=bundle-wrong\n").expect("dotenv");
        let wrong_err = handle_import_env(ImportEnvArgs {
            file: bundle.clone(),
            project: Some("demo".into()),
            credential_type: "secret".into(),
            prefix: Some("APP_".into()),
            strip_prefix: true,
            dotenv_file: Some(dotenv),
            create_project: false,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![wrong],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("wrong identity");
        assert!(!wrong_err.to_string().contains("bundle-wrong"));
        assert_eq!(fs::read(&bundle).expect("after wrong"), before);
    }

    #[test]
    fn set_inline_encrypting_cas_fault_no_residual_temp() {
        use crate::atomic_write::{inject_fault, AtomicFault};
        let dir = tempfile::tempdir().expect("temp");
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        let mut secrets = SecretsFile::new("demo");
        let ct = seclusor_crypto::encrypt_inline_value(
            b"old",
            std::slice::from_ref(&fixture_identity().to_public()),
        )
        .expect("enc");
        secrets.projects[0]
            .credentials
            .insert("API_KEY".into(), Credential::with_value("secret", &ct));
        let inline = dir.path().join("one.json");
        write_secrets_file(&inline, &secrets, true).expect("write");
        let before = fs::read(&inline).expect("before");
        let names_before = list_sibling_names(dir.path());

        inject_fault(Some(AtomicFault::ForceCasMismatch));
        let err = handle_set(SetArgs {
            file: inline.clone(),
            project: Some("demo".into()),
            key: "API_KEY".into(),
            credential_type: "secret".into(),
            value: Some("never-committed".into()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("CAS fault");
        inject_fault(None);

        assert!(matches!(err, CliError::ConcurrentModification { .. }));
        assert!(!err.to_string().contains("never-committed"));
        assert_eq!(fs::read(&inline).expect("after"), before);
        assert_eq!(list_sibling_names(dir.path()), names_before);
    }
}
