use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use seclusor_core::validate::{compare_recipient_sets, RecipientSetRelation};
use seclusor_crypto::{assert_identity_file_access, parse_recipients, Identity, Recipient};
use seclusor_keyring::{
    discover_recipients_from_file, find_identity_path_by_public_key,
    is_passphrase_protected_identity, load_identity_file_auto, KeyringError,
};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::atomic_write::{atomic_write_private_ciphertext, PrivateCiphertextPriorSnapshot};
use crate::cli::{
    BlobDecryptArgs, BlobEncryptArgs, BlobRekeyArgs, BlobSubcommand, BlobVerifyArgs,
    PriorRecipientArgs, VerifyIdentityArgs,
};
use crate::error::{CliError, CliResult};
use crate::handlers::encrypted_write::{
    recipient_channels_present, recipient_strings, render_recipient_delta,
};
use crate::handlers::rekey::{
    classify_rekey_output_with_flag, commit_recipient_refresh, emit_recipient_refresh_notice,
    paths_alias, prepare_recipient_refresh, prepare_recipient_refresh_target_with_flag,
};
use crate::resolve::{resolve_identities, resolve_identities_with_sources, resolve_recipients};

pub(crate) fn handle_blob_command_with_policy(
    command: BlobSubcommand,
    allow_recipient_mismatch: bool,
) -> CliResult<()> {
    match command {
        BlobSubcommand::Encrypt(args) => {
            if allow_recipient_mismatch {
                return Err(CliError::Message(
                    "--allow-recipient-mismatch is only valid for `blob rekey` in the `secrets blob` family"
                        .to_string(),
                ));
            }
            handle_blob_encrypt(args)
        }
        BlobSubcommand::Decrypt(args) => {
            if allow_recipient_mismatch {
                return Err(CliError::Message(
                    "--allow-recipient-mismatch is only valid for `blob rekey` in the `secrets blob` family"
                        .to_string(),
                ));
            }
            handle_blob_decrypt(args)
        }
        BlobSubcommand::Rekey(args) => {
            handle_blob_rekey_with_policy(args, allow_recipient_mismatch)
        }
        BlobSubcommand::Verify(args) => {
            if allow_recipient_mismatch {
                return Err(CliError::Message(
                    "--allow-recipient-mismatch is only valid for `blob rekey` in the `secrets blob` family"
                        .to_string(),
                ));
            }
            handle_blob_verify(args)
        }
    }
}

/// Default blob file size limit (10 MB).
const BLOB_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
/// Hard ceiling for blob plaintext under `--allow-large` (matches
/// `MAX_BUNDLE_PLAINTEXT_BYTES` / `MAX_DECRYPT_PLAINTEXT_BYTES`).
const BLOB_MAX_PLAINTEXT_HARD_BYTES: u64 =
    seclusor_core::constants::MAX_BUNDLE_PLAINTEXT_BYTES as u64;
/// Hard ceiling for blob ciphertext under `--allow-large` and existing-output
/// CAS snapshots: `24 MiB` (`16 MiB` plaintext + 4/3 base64 + line-wrap + age
/// header/tag overhead) so both binary and ASCII-armored age ciphertexts
/// produced from a valid `16 MiB` plaintext can be decrypted, verified,
/// rekeyed, and `--force` overwritten.
const BLOB_MAX_CIPHERTEXT_HARD_BYTES: u64 = 24 * 1024 * 1024;

/// Read a file with a size cap enforced at read time without `Vec` reallocation
/// growth (so `Zeroizing` never leaves unwiped intermediate heap buffers).
fn read_file_bounded_zeroizing(
    path: &Path,
    soft_limit: Option<u64>,
    hard_limit: u64,
) -> CliResult<Zeroizing<Vec<u8>>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(CliError::Message(format!(
            "input path {} must be a regular file",
            path.display()
        )));
    }
    let effective_limit = soft_limit.unwrap_or(hard_limit);
    let hint_len = meta.len();
    if hint_len > effective_limit {
        if let Some(limit) = soft_limit {
            return Err(CliError::Message(format!(
                "input file exceeds {} MB limit (size {} bytes). \
                 Use --allow-large to override.",
                limit / (1024 * 1024),
                hint_len
            )));
        }
        return Err(CliError::Message(format!(
            "input file exceeds hard maximum size of {} bytes",
            effective_limit
        )));
    }

    // Preallocate a single fixed capacity (hint_len + 1, bounded by effective_limit + 1)
    // and read via a zeroizing scratch chunk if the file grew past hint_len so `buf`
    // never reallocates while holding plaintext.
    let initial_cap = (hint_len as usize)
        .saturating_add(1)
        .min((effective_limit as usize).saturating_add(1));
    let mut buf = Zeroizing::new(vec![0u8; initial_cap]);
    let mut total = 0usize;
    while total < buf.len() {
        match file.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(err) => return Err(CliError::Io(err)),
        }
    }
    buf.truncate(total);

    if total == initial_cap {
        let mut probe = Zeroizing::new([0u8; 1]);
        if file.read(&mut probe[..])? > 0 {
            if let Some(limit) = soft_limit {
                return Err(CliError::Message(format!(
                    "input file exceeds {} MB limit (read {} bytes). \
                     Use --allow-large to override.",
                    limit / (1024 * 1024),
                    total + 1
                )));
            }
            return Err(CliError::Message(format!(
                "input file changed size during read or exceeds hard maximum size of {} bytes",
                effective_limit
            )));
        }
    }

    if (buf.len() as u64) > effective_limit {
        if let Some(limit) = soft_limit {
            return Err(CliError::Message(format!(
                "input file exceeds {} MB limit (read {} bytes). \
                 Use --allow-large to override.",
                limit / (1024 * 1024),
                buf.len()
            )));
        }
        return Err(CliError::Message(format!(
            "input file exceeds hard maximum size of {} bytes",
            effective_limit
        )));
    }

    Ok(buf)
}

/// Read an existing `--output` target for `--force` conflict detection, bounded
/// before allocation. Returns `Ok(None)` if the path does not exist yet.
fn read_existing_output_for_cas(path: &Path) -> CliResult<Option<PrivateCiphertextPriorSnapshot>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(CliError::Io(err)),
    };
    if meta.file_type().is_symlink() {
        return Err(CliError::Message(format!(
            "refusing to overwrite symlink output path {}",
            path.display()
        )));
    }
    if !meta.is_file() {
        return Err(CliError::Message(format!(
            "output path {} must be a regular file",
            path.display()
        )));
    }

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        #[cfg(unix)]
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
            return Err(CliError::Message(format!(
                "refusing to overwrite symlink output path {}",
                path.display()
            )));
        }
        Err(err) => return Err(CliError::Io(err)),
    };
    let open_meta = file.metadata().map_err(CliError::Io)?;
    if !open_meta.is_file() {
        return Err(CliError::Message(format!(
            "output path {} must be a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if open_meta.dev() != meta.dev() || open_meta.ino() != meta.ino() {
            return Err(CliError::ConcurrentModification {
                path: path.display().to_string(),
            });
        }
    }

    let hint_len = open_meta.len();
    if hint_len > BLOB_MAX_CIPHERTEXT_HARD_BYTES {
        return Err(CliError::Message(format!(
            "existing output file {} exceeds maximum size of {} bytes",
            path.display(),
            BLOB_MAX_CIPHERTEXT_HARD_BYTES
        )));
    }
    let cap = (hint_len as usize)
        .saturating_add(1)
        .min((BLOB_MAX_CIPHERTEXT_HARD_BYTES as usize).saturating_add(1));
    let mut buf = Zeroizing::new(vec![0u8; cap]);
    let mut total = 0usize;
    while total < buf.len() {
        match file.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(err) => return Err(CliError::Io(err)),
        }
    }
    buf.truncate(total);
    if total == cap || (buf.len() as u64) > BLOB_MAX_CIPHERTEXT_HARD_BYTES {
        return Err(CliError::Message(format!(
            "existing output file {} exceeds maximum size of {} bytes or changed size during read",
            path.display(),
            BLOB_MAX_CIPHERTEXT_HARD_BYTES
        )));
    }

    Ok(Some(PrivateCiphertextPriorSnapshot {
        bytes: buf,
        #[cfg(unix)]
        identity: {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            (
                open_meta.dev(),
                open_meta.ino(),
                open_meta.permissions().mode() & 0o777,
            )
        },
    }))
}

pub(crate) fn handle_blob_encrypt(args: BlobEncryptArgs) -> CliResult<()> {
    let prior_snapshot = if args.force {
        read_existing_output_for_cas(&args.output)?
    } else {
        if fs::symlink_metadata(&args.output).is_ok() {
            return Err(CliError::Message(format!(
                "refusing to create {}: path already exists (use --force to overwrite)",
                args.output.display()
            )));
        }
        None
    };

    if paths_alias(&args.output, &args.input)? {
        return Err(CliError::Message(format!(
            "--output path {} aliases --input path {}; choose a separate output path",
            args.output.display(),
            args.input.display()
        )));
    }
    for recipient_file in &args.recipients.recipient_files {
        if paths_alias(&args.output, recipient_file)? {
            return Err(CliError::Message(format!(
                "--output path {} aliases --recipient-file path {}; choose a separate output path",
                args.output.display(),
                recipient_file.display()
            )));
        }
    }

    let limit = if args.allow_large {
        None
    } else {
        Some(BLOB_MAX_FILE_BYTES)
    };
    let plaintext = read_file_bounded_zeroizing(&args.input, limit, BLOB_MAX_PLAINTEXT_HARD_BYTES)?;
    let recipients = resolve_recipients(&args.recipients)?;
    let ciphertext = seclusor_crypto::encrypt(&plaintext, &recipients)?;
    drop(plaintext);

    atomic_write_private_ciphertext(&args.output, &ciphertext, prior_snapshot)?;
    Ok(())
}

pub(crate) fn handle_blob_decrypt(args: BlobDecryptArgs) -> CliResult<()> {
    let limit = if args.allow_large {
        None
    } else {
        Some(BLOB_MAX_FILE_BYTES)
    };
    let identities = resolve_identities(&args.identities, &args.passphrase, true)?;
    let ciphertext =
        read_file_bounded_zeroizing(&args.input, limit, BLOB_MAX_CIPHERTEXT_HARD_BYTES)?;
    let plaintext = seclusor_crypto::decrypt_zeroizing(&ciphertext, &identities)?;
    drop(ciphertext);

    // Atomic write via unique temp file (create_new semantics, no symlink risk)
    let output_dir = args
        .output
        .parent()
        .filter(|part| !part.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    seclusor_crypto::acl::reject_writable_directory_acl(output_dir)?;
    let mut temp = tempfile::NamedTempFile::new_in(output_dir)?;

    // Set 0600 before writing sensitive content
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    seclusor_crypto::acl::prepare_private_file(temp.as_file(), temp.path())?;
    std::io::Write::write_all(&mut temp, &plaintext)?;
    drop(plaintext);

    // persist() replaces the target atomically on Unix; on Windows it
    // falls back to a non-atomic but correct rename-with-overwrite.
    temp.persist(&args.output)
        .map_err(|e| CliError::Io(e.error))?;
    Ok(())
}

/// Read an existing blob for in-place `blob rekey` (with CAS snapshot identity)
/// or `blob verify`, enforcing soft/hard size limits without `Vec` growth.
fn read_blob_input_for_rekey(
    path: &Path,
    soft_limit: Option<u64>,
    hard_limit: u64,
    in_place: bool,
) -> CliResult<PrivateCiphertextPriorSnapshot> {
    if in_place {
        let meta = fs::symlink_metadata(path).map_err(CliError::Io)?;
        if meta.file_type().is_symlink() {
            return Err(CliError::Message(format!(
                "refusing to overwrite symlink input path {} in place",
                path.display()
            )));
        }
        if !meta.is_file() {
            return Err(CliError::Message(format!(
                "input path {} must be a regular file",
                path.display()
            )));
        }

        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            #[cfg(unix)]
            Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
                return Err(CliError::Message(format!(
                    "refusing to overwrite symlink input path {} in place",
                    path.display()
                )));
            }
            Err(err) => return Err(CliError::Io(err)),
        };
        let open_meta = file.metadata().map_err(CliError::Io)?;
        if !open_meta.is_file() {
            return Err(CliError::Message(format!(
                "input path {} must be a regular file",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if open_meta.dev() != meta.dev() || open_meta.ino() != meta.ino() {
                return Err(CliError::ConcurrentModification {
                    path: path.display().to_string(),
                });
            }
        }

        let effective_limit = soft_limit.unwrap_or(hard_limit);
        let hint_len = open_meta.len();
        if hint_len > effective_limit {
            if let Some(limit) = soft_limit {
                return Err(CliError::Message(format!(
                    "input file exceeds {} MB limit (size {} bytes). \
                     Use --allow-large to override.",
                    limit / (1024 * 1024),
                    hint_len
                )));
            }
            return Err(CliError::Message(format!(
                "input file exceeds hard maximum size of {} bytes",
                effective_limit
            )));
        }
        let cap = (hint_len as usize)
            .saturating_add(1)
            .min((effective_limit as usize).saturating_add(1));
        let mut buf = Zeroizing::new(vec![0u8; cap]);
        let mut total = 0usize;
        while total < buf.len() {
            match file.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(err) => return Err(CliError::Io(err)),
            }
        }
        buf.truncate(total);
        if total == cap || (buf.len() as u64) > effective_limit {
            if let Some(limit) = soft_limit {
                return Err(CliError::Message(format!(
                    "input file exceeds {} MB limit (read {} bytes). \
                     Use --allow-large to override.",
                    limit / (1024 * 1024),
                    buf.len().saturating_add(1)
                )));
            }
            return Err(CliError::Message(format!(
                "input file changed size during read or exceeds hard maximum size of {} bytes",
                effective_limit
            )));
        }

        return Ok(PrivateCiphertextPriorSnapshot {
            bytes: buf,
            #[cfg(unix)]
            identity: {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                (
                    open_meta.dev(),
                    open_meta.ino(),
                    open_meta.permissions().mode() & 0o777,
                )
            },
        });
    }

    let bytes = read_file_bounded_zeroizing(path, soft_limit, hard_limit)?;
    Ok(PrivateCiphertextPriorSnapshot {
        bytes,
        #[cfg(unix)]
        identity: (0, 0, 0),
    })
}

/// Classify a blob ciphertext header: refuse scrypt (passphrase), non-age, and
/// non-X25519 recipient stanza inputs, and return the X25519 stanza count.
fn classify_blob_ciphertext_header(ciphertext: &[u8]) -> CliResult<usize> {
    match seclusor_crypto::is_scrypt_ciphertext(ciphertext) {
        Ok(true) => {
            return Err(CliError::Message(
                "passphrase-encrypted (scrypt) blobs are not supported by `blob rekey` or \
                 `blob verify`; convert to X25519 recipient mode first"
                    .to_string(),
            ));
        }
        Ok(false) => {}
        Err(_) => {
            return Err(CliError::Message(
                "input is not a valid age ciphertext blob".to_string(),
            ));
        }
    }
    let (x25519_stanzas, other_stanzas) = seclusor_crypto::count_recipient_stanzas(ciphertext)
        .map_err(|_| CliError::Message("input is not a valid age ciphertext blob".to_string()))?;
    if other_stanzas > 0 {
        return Err(CliError::Message(
            "input age header contains non-X25519 recipient stanzas; only X25519 recipient \
             blobs are supported"
                .to_string(),
        ));
    }
    if x25519_stanzas == 0 {
        return Err(CliError::Message(
            "input age header contains no X25519 recipient stanzas".to_string(),
        ));
    }
    Ok(x25519_stanzas)
}

/// Decrypt `ciphertext` by trying each loaded identity individually so the
/// exact opening identity's public key (`opened_with`) is known.
fn decrypt_blob_recording_opening_identity(
    ciphertext: &[u8],
    identities: &[Identity],
) -> CliResult<(Zeroizing<Vec<u8>>, String)> {
    for identity in identities {
        if let Ok(pt) =
            seclusor_crypto::decrypt_zeroizing(ciphertext, std::slice::from_ref(identity))
        {
            return Ok((pt, identity.to_public().to_string()));
        }
    }
    Err(CliError::Crypto(
        seclusor_crypto::CryptoError::DecryptionFailed,
    ))
}

#[derive(Clone, PartialEq, Eq)]
struct ZeroizingProbeString(Zeroizing<String>);

impl ZeroizingProbeString {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl PartialOrd for ZeroizingProbeString {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ZeroizingProbeString {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl<'de> Deserialize<'de> for ZeroizingProbeString {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ProbeStringVisitor;

        impl<'de> serde::de::Visitor<'de> for ProbeStringVisitor {
            type Value = ZeroizingProbeString;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ZeroizingProbeString(Zeroizing::new(v.to_owned())))
            }

            fn visit_string<E>(self, v: String) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ZeroizingProbeString(Zeroizing::new(v)))
            }

            fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_none<E>(self) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_seq<A>(self, _: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                Err(serde::de::Error::custom("invalid"))
            }

            fn visit_map<A>(self, _: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                Err(serde::de::Error::custom("invalid"))
            }
        }

        deserializer.deserialize_any(ProbeStringVisitor)
    }
}

struct OptionalStringProbe;

impl<'de> Deserialize<'de> for OptionalStringProbe {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct OptVisitor;

        impl<'de> serde::de::Visitor<'de> for OptVisitor {
            type Value = OptionalStringProbe;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an optional string")
            }

            fn visit_str<E>(self, _: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OptionalStringProbe)
            }

            fn visit_string<E>(self, mut v: String) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                use zeroize::Zeroize as _;
                v.zeroize();
                Ok(OptionalStringProbe)
            }

            fn visit_none<E>(self) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OptionalStringProbe)
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OptionalStringProbe)
            }

            fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_seq<A>(self, _: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                Err(serde::de::Error::custom("invalid"))
            }

            fn visit_map<A>(self, _: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                Err(serde::de::Error::custom("invalid"))
            }
        }

        deserializer.deserialize_any(OptVisitor)
    }
}

struct OptionalRecipientsProbe(bool);

impl<'de> Deserialize<'de> for OptionalRecipientsProbe {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RecipVisitor;

        impl<'de> serde::de::Visitor<'de> for RecipVisitor {
            type Value = OptionalRecipientsProbe;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an optional recipients array")
            }

            fn visit_none<E>(self) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OptionalRecipientsProbe(false))
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OptionalRecipientsProbe(false))
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                while (seq.next_element::<ZeroizingProbeString>()?).is_some() {}
                Ok(OptionalRecipientsProbe(true))
            }

            fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_str<E>(self, _: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("invalid"))
            }

            fn visit_string<E>(self, mut v: String) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                use zeroize::Zeroize as _;
                v.zeroize();
                Err(E::custom("invalid"))
            }

            fn visit_map<A>(self, _: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                Err(serde::de::Error::custom("invalid"))
            }
        }

        deserializer.deserialize_any(RecipVisitor)
    }
}

/// Refuse `blob rekey` when the decrypted payload is a seclusor `SecretsFile`
/// bundle document so inner `recipients` metadata cannot become stale.
///
/// Uses `deserialize_any` visitors with [`ZeroizingProbeString`] and
/// [`OptionalStringProbe`] so that:
/// - credential `value`, `ref`, `description`, `env_prefix`, and `recipients`
///   strings are never retained in unzeroized heap allocations,
/// - structural strings (`schema_version`, `project_slug`, credential keys, and
///   `credential_type`) are wrapped in [`Zeroizing`] immediately upon creation,
/// - mismatched JSON value types fail via static `Error::custom("invalid")`
///   before `serde_json`'s typed `peek_invalid_type` can format payload strings
///   or numbers into error messages, and
/// - duplicate credential names and duplicate credential fields match
///   `seclusor_core::model::deserialize_credentials_map` (`serde_json::Value`
///   last-value-wins semantics) so bundle documents accepted by the core
///   decoder cannot bypass bundle refusal.
fn refuse_if_secrets_bundle_document(plaintext: &[u8]) -> CliResult<()> {
    struct ZeroizingIgnoredValue;

    impl<'de> Deserialize<'de> for ZeroizingIgnoredValue {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct IgnoredVisitor;

            impl<'de> serde::de::Visitor<'de> for IgnoredVisitor {
                type Value = ZeroizingIgnoredValue;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("any JSON value")
                }

                fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E> {
                    Ok(ZeroizingIgnoredValue)
                }

                fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E> {
                    Ok(ZeroizingIgnoredValue)
                }

                fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E> {
                    Ok(ZeroizingIgnoredValue)
                }

                fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E> {
                    Ok(ZeroizingIgnoredValue)
                }

                fn visit_str<E>(self, _: &str) -> std::result::Result<Self::Value, E> {
                    Ok(ZeroizingIgnoredValue)
                }

                fn visit_string<E>(self, mut v: String) -> std::result::Result<Self::Value, E> {
                    use zeroize::Zeroize as _;
                    v.zeroize();
                    Ok(ZeroizingIgnoredValue)
                }

                fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
                    Ok(ZeroizingIgnoredValue)
                }

                fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                    Ok(ZeroizingIgnoredValue)
                }

                fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    while (seq.next_element::<ZeroizingIgnoredValue>()?).is_some() {}
                    Ok(ZeroizingIgnoredValue)
                }

                fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    while (map.next_entry::<ZeroizingProbeString, ZeroizingIgnoredValue>()?)
                        .is_some()
                    {}
                    Ok(ZeroizingIgnoredValue)
                }
            }

            deserializer.deserialize_any(IgnoredVisitor)
        }
    }

    enum FieldValueProbe {
        String(ZeroizingProbeString),
        Null,
        Other,
    }

    impl<'de> Deserialize<'de> for FieldValueProbe {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct FieldValueVisitor;

            impl<'de> serde::de::Visitor<'de> for FieldValueVisitor {
                type Value = FieldValueProbe;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("a JSON value")
                }

                fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E> {
                    Ok(FieldValueProbe::String(ZeroizingProbeString(
                        Zeroizing::new(v.to_owned()),
                    )))
                }

                fn visit_string<E>(self, v: String) -> std::result::Result<Self::Value, E> {
                    Ok(FieldValueProbe::String(ZeroizingProbeString(
                        Zeroizing::new(v),
                    )))
                }

                fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
                    Ok(FieldValueProbe::Null)
                }

                fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                    Ok(FieldValueProbe::Null)
                }

                fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E> {
                    Ok(FieldValueProbe::Other)
                }

                fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E> {
                    Ok(FieldValueProbe::Other)
                }

                fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E> {
                    Ok(FieldValueProbe::Other)
                }

                fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E> {
                    Ok(FieldValueProbe::Other)
                }

                fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    while (seq.next_element::<ZeroizingIgnoredValue>()?).is_some() {}
                    Ok(FieldValueProbe::Other)
                }

                fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    while (map.next_entry::<ZeroizingProbeString, ZeroizingIgnoredValue>()?)
                        .is_some()
                    {}
                    Ok(FieldValueProbe::Other)
                }
            }

            deserializer.deserialize_any(FieldValueVisitor)
        }
    }

    #[derive(Clone, Copy)]
    enum OptStrState {
        AbsentOrNull,
        PresentString,
        InvalidType,
    }

    #[derive(Clone, Copy)]
    enum TypeFieldState {
        Absent,
        NonEmptyString,
        Invalid,
    }

    struct CredentialEntryProbe {
        is_valid_credential_object: bool,
    }

    impl<'de> Deserialize<'de> for CredentialEntryProbe {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct CredentialEntryVisitor;

            impl<'de> serde::de::Visitor<'de> for CredentialEntryVisitor {
                type Value = CredentialEntryProbe;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("a credential entry")
                }

                fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    let mut type_state = TypeFieldState::Absent;
                    let mut value_state = OptStrState::AbsentOrNull;
                    let mut ref_state = OptStrState::AbsentOrNull;
                    let mut desc_state = OptStrState::AbsentOrNull;
                    let mut has_unknown_field = false;

                    while let Some(key) = map.next_key::<ZeroizingProbeString>()? {
                        let val = map.next_value::<FieldValueProbe>()?;
                        match key.as_str() {
                            "type" => {
                                type_state = match val {
                                    FieldValueProbe::String(s) if !s.as_str().trim().is_empty() => {
                                        TypeFieldState::NonEmptyString
                                    }
                                    _ => TypeFieldState::Invalid,
                                };
                            }
                            "value" => {
                                value_state = match val {
                                    FieldValueProbe::String(_) => OptStrState::PresentString,
                                    FieldValueProbe::Null => OptStrState::AbsentOrNull,
                                    FieldValueProbe::Other => OptStrState::InvalidType,
                                };
                            }
                            "ref" => {
                                ref_state = match val {
                                    FieldValueProbe::String(_) => OptStrState::PresentString,
                                    FieldValueProbe::Null => OptStrState::AbsentOrNull,
                                    FieldValueProbe::Other => OptStrState::InvalidType,
                                };
                            }
                            "description" => {
                                desc_state = match val {
                                    FieldValueProbe::String(_) | FieldValueProbe::Null => {
                                        OptStrState::AbsentOrNull
                                    }
                                    FieldValueProbe::Other => OptStrState::InvalidType,
                                };
                            }
                            _ => {
                                has_unknown_field = true;
                            }
                        }
                    }

                    let valid_type = matches!(type_state, TypeFieldState::NonEmptyString);
                    let valid_desc = !matches!(desc_state, OptStrState::InvalidType);
                    let valid_val_ref = matches!(
                        (value_state, ref_state),
                        (OptStrState::PresentString, OptStrState::AbsentOrNull)
                            | (OptStrState::AbsentOrNull, OptStrState::PresentString)
                    );

                    Ok(CredentialEntryProbe {
                        is_valid_credential_object: !has_unknown_field
                            && valid_type
                            && valid_desc
                            && valid_val_ref,
                    })
                }

                fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E> {
                    Ok(CredentialEntryProbe {
                        is_valid_credential_object: false,
                    })
                }

                fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E> {
                    Ok(CredentialEntryProbe {
                        is_valid_credential_object: false,
                    })
                }

                fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E> {
                    Ok(CredentialEntryProbe {
                        is_valid_credential_object: false,
                    })
                }

                fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E> {
                    Ok(CredentialEntryProbe {
                        is_valid_credential_object: false,
                    })
                }

                fn visit_str<E>(self, _: &str) -> std::result::Result<Self::Value, E> {
                    Ok(CredentialEntryProbe {
                        is_valid_credential_object: false,
                    })
                }

                fn visit_string<E>(self, mut v: String) -> std::result::Result<Self::Value, E> {
                    use zeroize::Zeroize as _;
                    v.zeroize();
                    Ok(CredentialEntryProbe {
                        is_valid_credential_object: false,
                    })
                }

                fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
                    Ok(CredentialEntryProbe {
                        is_valid_credential_object: false,
                    })
                }

                fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                    Ok(CredentialEntryProbe {
                        is_valid_credential_object: false,
                    })
                }

                fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    while (seq.next_element::<ZeroizingIgnoredValue>()?).is_some() {}
                    Ok(CredentialEntryProbe {
                        is_valid_credential_object: false,
                    })
                }
            }

            deserializer.deserialize_any(CredentialEntryVisitor)
        }
    }

    struct CredentialsMapProbe;

    impl<'de> Deserialize<'de> for CredentialsMapProbe {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct MapVisitor;

            impl<'de> serde::de::Visitor<'de> for MapVisitor {
                type Value = CredentialsMapProbe;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("a credentials map")
                }

                fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    let mut entries =
                        std::collections::BTreeMap::<ZeroizingProbeString, bool>::new();
                    while let Some(key) = map.next_key::<ZeroizingProbeString>()? {
                        let entry = map.next_value::<CredentialEntryProbe>()?;
                        let key_valid =
                            seclusor_core::validate::is_valid_credential_key(key.as_str());
                        entries.insert(key, key_valid && entry.is_valid_credential_object);
                    }
                    if entries.values().any(|&valid| !valid) {
                        return Err(serde::de::Error::custom("invalid"));
                    }
                    Ok(CredentialsMapProbe)
                }

                fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_str<E>(self, _: &str) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_string<E>(self, mut v: String) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    use zeroize::Zeroize as _;
                    v.zeroize();
                    Err(E::custom("invalid"))
                }

                fn visit_none<E>(self) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_seq<A>(self, _: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    Err(serde::de::Error::custom("invalid"))
                }
            }

            deserializer.deserialize_any(MapVisitor)
        }
    }

    struct ProjectProbe;

    impl<'de> Deserialize<'de> for ProjectProbe {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct ProjectVisitor;

            impl<'de> serde::de::Visitor<'de> for ProjectVisitor {
                type Value = ProjectProbe;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("a project object")
                }

                fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    let mut has_slug = false;
                    let mut has_credentials = false;
                    let mut seen_description = false;

                    while let Some(key) = map.next_key::<ZeroizingProbeString>()? {
                        match key.as_str() {
                            "project_slug" => {
                                if has_slug {
                                    return Err(serde::de::Error::custom("invalid"));
                                }
                                let slug = map.next_value::<ZeroizingProbeString>()?;
                                if slug.as_str().trim().is_empty() {
                                    return Err(serde::de::Error::custom("invalid"));
                                }
                                has_slug = true;
                            }
                            "description" => {
                                if seen_description {
                                    return Err(serde::de::Error::custom("invalid"));
                                }
                                seen_description = true;
                                let _ = map.next_value::<OptionalStringProbe>()?;
                            }
                            "credentials" => {
                                if has_credentials {
                                    return Err(serde::de::Error::custom("invalid"));
                                }
                                let _ = map.next_value::<CredentialsMapProbe>()?;
                                has_credentials = true;
                            }
                            _ => return Err(serde::de::Error::custom("invalid")),
                        }
                    }

                    if !has_slug || !has_credentials {
                        return Err(serde::de::Error::custom("invalid"));
                    }
                    Ok(ProjectProbe)
                }

                fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_str<E>(self, _: &str) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_string<E>(self, mut v: String) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    use zeroize::Zeroize as _;
                    v.zeroize();
                    Err(E::custom("invalid"))
                }

                fn visit_none<E>(self) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    let Some(slug) = seq.next_element::<ZeroizingProbeString>()? else {
                        return Err(serde::de::Error::custom("invalid"));
                    };
                    if slug.as_str().trim().is_empty() {
                        return Err(serde::de::Error::custom("invalid"));
                    }
                    let Some(_desc) = seq.next_element::<OptionalStringProbe>()? else {
                        return Err(serde::de::Error::custom("invalid"));
                    };
                    let Some(_creds) = seq.next_element::<CredentialsMapProbe>()? else {
                        return Err(serde::de::Error::custom("invalid"));
                    };
                    if (seq.next_element::<ZeroizingIgnoredValue>()?).is_some() {
                        return Err(serde::de::Error::custom("invalid"));
                    }
                    Ok(ProjectProbe)
                }
            }

            deserializer.deserialize_any(ProjectVisitor)
        }
    }

    struct ProjectsSeqProbe;

    impl<'de> Deserialize<'de> for ProjectsSeqProbe {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct SeqVisitor;

            impl<'de> serde::de::Visitor<'de> for SeqVisitor {
                type Value = ProjectsSeqProbe;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("a projects array")
                }

                fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    while (seq.next_element::<ProjectProbe>()?).is_some() {}
                    Ok(ProjectsSeqProbe)
                }

                fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_str<E>(self, _: &str) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_string<E>(self, mut v: String) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    use zeroize::Zeroize as _;
                    v.zeroize();
                    Err(E::custom("invalid"))
                }

                fn visit_none<E>(self) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_map<A>(self, _: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    Err(serde::de::Error::custom("invalid"))
                }
            }

            deserializer.deserialize_any(SeqVisitor)
        }
    }

    struct DocumentProbe;

    impl<'de> Deserialize<'de> for DocumentProbe {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct DocVisitor;

            impl<'de> serde::de::Visitor<'de> for DocVisitor {
                type Value = DocumentProbe;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("a bundle document")
                }

                fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    let mut schema_version: Option<ZeroizingProbeString> = None;
                    let mut has_projects = false;
                    let mut has_recipients = false;
                    let mut seen_recipients_key = false;
                    let mut seen_env_prefix = false;
                    let mut seen_description = false;

                    while let Some(key) = map.next_key::<ZeroizingProbeString>()? {
                        match key.as_str() {
                            "schema_version" => {
                                if schema_version.is_some() {
                                    return Err(serde::de::Error::custom("invalid"));
                                }
                                schema_version = Some(map.next_value::<ZeroizingProbeString>()?);
                            }
                            "env_prefix" => {
                                if seen_env_prefix {
                                    return Err(serde::de::Error::custom("invalid"));
                                }
                                seen_env_prefix = true;
                                let _ = map.next_value::<OptionalStringProbe>()?;
                            }
                            "description" => {
                                if seen_description {
                                    return Err(serde::de::Error::custom("invalid"));
                                }
                                seen_description = true;
                                let _ = map.next_value::<OptionalStringProbe>()?;
                            }
                            "recipients" => {
                                if seen_recipients_key {
                                    return Err(serde::de::Error::custom("invalid"));
                                }
                                seen_recipients_key = true;
                                let opt = map.next_value::<OptionalRecipientsProbe>()?;
                                has_recipients = opt.0;
                            }
                            "projects" => {
                                if has_projects {
                                    return Err(serde::de::Error::custom("invalid"));
                                }
                                let _ = map.next_value::<ProjectsSeqProbe>()?;
                                has_projects = true;
                            }
                            _ => return Err(serde::de::Error::custom("invalid")),
                        }
                    }

                    let Some(schema_version) = schema_version else {
                        return Err(serde::de::Error::custom("invalid"));
                    };
                    let valid_schema = schema_version.as_str()
                        == seclusor_core::constants::SCHEMA_VERSION
                        || schema_version.as_str()
                            == seclusor_core::constants::SCHEMA_VERSION_V1_1_0;
                    if !valid_schema || !has_projects {
                        return Err(serde::de::Error::custom("invalid"));
                    }
                    if has_recipients
                        && schema_version.as_str()
                            != seclusor_core::constants::SCHEMA_VERSION_V1_1_0
                    {
                        return Err(serde::de::Error::custom("invalid"));
                    }
                    Ok(DocumentProbe)
                }

                fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_str<E>(self, _: &str) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_string<E>(self, mut v: String) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    use zeroize::Zeroize as _;
                    v.zeroize();
                    Err(E::custom("invalid"))
                }

                fn visit_none<E>(self) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Err(E::custom("invalid"))
                }

                fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    let Some(schema_version) = seq.next_element::<ZeroizingProbeString>()? else {
                        return Err(serde::de::Error::custom("invalid"));
                    };
                    let Some(_env_prefix) = seq.next_element::<OptionalStringProbe>()? else {
                        return Err(serde::de::Error::custom("invalid"));
                    };
                    let Some(_description) = seq.next_element::<OptionalStringProbe>()? else {
                        return Err(serde::de::Error::custom("invalid"));
                    };
                    let Some(recipients) = seq.next_element::<OptionalRecipientsProbe>()? else {
                        return Err(serde::de::Error::custom("invalid"));
                    };
                    let Some(_projects) = seq.next_element::<ProjectsSeqProbe>()? else {
                        return Err(serde::de::Error::custom("invalid"));
                    };
                    if (seq.next_element::<ZeroizingIgnoredValue>()?).is_some() {
                        return Err(serde::de::Error::custom("invalid"));
                    }

                    let valid_schema = schema_version.as_str()
                        == seclusor_core::constants::SCHEMA_VERSION
                        || schema_version.as_str()
                            == seclusor_core::constants::SCHEMA_VERSION_V1_1_0;
                    if !valid_schema {
                        return Err(serde::de::Error::custom("invalid"));
                    }
                    if recipients.0
                        && schema_version.as_str()
                            != seclusor_core::constants::SCHEMA_VERSION_V1_1_0
                    {
                        return Err(serde::de::Error::custom("invalid"));
                    }
                    Ok(DocumentProbe)
                }
            }

            deserializer.deserialize_any(DocVisitor)
        }
    }

    let Ok(DocumentProbe) = serde_json::from_slice::<DocumentProbe>(plaintext) else {
        return Ok(());
    };
    Err(CliError::Message(
        "input is a seclusor bundle secrets document, not an opaque blob; \
         use `seclusor secrets rekey` so inner document metadata stays consistent"
            .to_string(),
    ))
}

fn resolve_prior_recipients(args: &PriorRecipientArgs) -> CliResult<Option<Vec<String>>> {
    if args.prior_recipients.is_empty() && args.prior_recipient_files.is_empty() {
        return Ok(None);
    }

    let mut recipients = Vec::new();
    if !args.prior_recipients.is_empty() {
        recipients.extend(parse_recipients(
            args.prior_recipients.iter().map(String::as_str),
        )?);
    }
    for path in &args.prior_recipient_files {
        recipients.extend(discover_recipients_from_file(path)?);
    }

    let mut seen = HashSet::new();
    recipients.retain(|recipient| seen.insert(recipient.to_string()));
    if recipients.is_empty() {
        return Err(CliError::Message(
            "asserted prior recipient set is empty".to_string(),
        ));
    }
    Ok(Some(recipient_strings(&recipients)))
}

#[derive(Debug)]
enum BlobDeltaNotice {
    Match,
    Delta {
        added: Vec<String>,
        removed: Vec<String>,
    },
    Indeterminate {
        stanzas_before: usize,
        opened_with: String,
        target: Vec<String>,
    },
}

fn evaluate_blob_rekey_delta_policy(
    prior_recipients: Option<&[String]>,
    target_recipients: &[String],
    stanzas_before: usize,
    opened_with: &str,
    allow_recipient_mismatch: bool,
) -> CliResult<BlobDeltaNotice> {
    if let Some(prior) = prior_recipients {
        if stanzas_before != prior.len() {
            return Err(CliError::Message(format!(
                "asserted prior recipient count ({}) does not match input blob age header \
                 stanza count ({stanzas_before}); refusing rekey",
                prior.len()
            )));
        }
        if !prior.iter().any(|r| r == opened_with) {
            return Err(CliError::Message(format!(
                "opening identity {opened_with} is not in the asserted prior recipient set; \
                 refusing rekey"
            )));
        }
    }

    match compare_recipient_sets(prior_recipients, target_recipients) {
        RecipientSetRelation::Match => Ok(BlobDeltaNotice::Match),
        RecipientSetRelation::Delta { added, removed } => {
            if !allow_recipient_mismatch {
                return Err(CliError::Message(format!(
                    "target recipient set differs from asserted prior recipient set; refusing \
                     blob rekey without --allow-recipient-mismatch:{}",
                    render_recipient_delta(&added, &removed)
                )));
            }
            Ok(BlobDeltaNotice::Delta { added, removed })
        }
        RecipientSetRelation::Indeterminate => {
            if !allow_recipient_mismatch {
                return Err(CliError::Message(
                    "blob carries no recipient metadata and no --prior-recipient / \
                     --prior-recipient-file was supplied; pass --prior-recipient / \
                     --prior-recipient-file to assert the current set or pass \
                     --allow-recipient-mismatch to accept indeterminate comparison"
                        .to_string(),
                ));
            }
            Ok(BlobDeltaNotice::Indeterminate {
                stanzas_before,
                opened_with: opened_with.to_string(),
                target: target_recipients.to_vec(),
            })
        }
    }
}

fn emit_blob_delta_notice(notice: &BlobDeltaNotice) {
    match notice {
        BlobDeltaNotice::Match => {}
        BlobDeltaNotice::Delta { added, removed } => {
            eprintln!(
                "recipient set change accepted:{}",
                render_recipient_delta(added, removed)
            );
        }
        BlobDeltaNotice::Indeterminate {
            stanzas_before,
            opened_with,
            target,
        } => {
            eprintln!(
                "warning: recipient-set comparison was indeterminate (input header X25519 \
                 stanzas: {stanzas_before}, opened_with: {opened_with}); age headers do not \
                 identify other recipients or detect re-grants"
            );
            eprintln!("target recipients: {}", target.join(", "));
        }
    }
}

/// Resolve optional `--verify-identity-file` / `--verify-identity-public-key`
/// identities for pre-commit self-lockout verification.
///
/// If a verify identity file is passphrase-protected, refuses with an
/// actionable remedy pointing to `--output` + `secrets blob verify` or
/// `--allow-self-lockout` (never downgrading to a public-key check).
fn resolve_verify_identities(
    args: &VerifyIdentityArgs,
) -> CliResult<(Vec<Identity>, Vec<PathBuf>)> {
    let _acl_warning_scope = seclusor_crypto::acl::warning_scope();
    if let Some(public_key) = &args.verify_identity_public_key {
        let path = find_identity_path_by_public_key(public_key)?;
        assert_identity_file_access(&path)?;
        if is_passphrase_protected_identity(&path)? {
            return Err(CliError::Message(format!(
                "--verify-identity-public-key {public_key} resolves to a passphrase-protected \
                 identity file ({}); `blob rekey` cannot unlock a separate protected verify \
                 identity in the same invocation. Write to a separate `--output` path and run \
                 `seclusor secrets blob verify` with the new identity before replacing, or \
                 pass `--allow-self-lockout`",
                path.display()
            )));
        }
        let identities = load_identity_file_auto(&path, None)?;
        let want = public_key
            .trim()
            .parse::<Recipient>()
            .map_err(|_| CliError::Keyring(KeyringError::InvalidIdentityPublicKey))?
            .to_string();
        if !identities
            .iter()
            .any(|identity| identity.to_public().to_string() == want)
        {
            return Err(CliError::Keyring(KeyringError::IdentityPublicKeyMismatch {
                path,
            }));
        }
        return Ok((identities, vec![path]));
    }

    let mut identities = Vec::new();
    for path in &args.verify_identity_files {
        assert_identity_file_access(path)?;
        if is_passphrase_protected_identity(path)? {
            return Err(CliError::Message(format!(
                "--verify-identity-file {} is passphrase-protected; `blob rekey` cannot \
                 unlock a separate protected verify identity in the same invocation. Write to \
                 a separate `--output` path and run `seclusor secrets blob verify` with the \
                 new identity before replacing, or pass `--allow-self-lockout`",
                path.display()
            )));
        }
        identities.extend(load_identity_file_auto(path, None)?);
    }
    Ok((identities, args.verify_identity_files.clone()))
}

#[cfg(test)]
pub(crate) fn handle_blob_rekey(args: BlobRekeyArgs) -> CliResult<()> {
    handle_blob_rekey_with_policy(args, false)
}

pub(crate) fn handle_blob_rekey_with_policy(
    args: BlobRekeyArgs,
    allow_recipient_mismatch: bool,
) -> CliResult<()> {
    // 1. Explicit recipient channel required (never fall back to SECLUSOR_RECIPIENTS).
    if !recipient_channels_present(&args.recipients) {
        return Err(CliError::Message(
            "blob rekey requires at least one of --recipient, --recipient-file, or \
             --recipient-env-var (implicit SECLUSOR_RECIPIENTS fallback is not used for rekey)"
                .to_string(),
        ));
    }

    let output_path = args.output.clone().unwrap_or_else(|| args.input.clone());
    let in_place = classify_rekey_output_with_flag(&args.input, args.output.as_deref(), "--input")?;
    let input_path = if in_place {
        fs::canonicalize(&args.input).map_err(CliError::Io)?
    } else {
        args.input.clone()
    };
    if !in_place && fs::symlink_metadata(&output_path).is_ok() {
        return Err(CliError::Message(format!(
            "refusing to create {}: path already exists",
            output_path.display()
        )));
    }
    for recipient_file in &args.recipients.recipient_files {
        if paths_alias(&output_path, recipient_file)? {
            return Err(CliError::Message(format!(
                "--output path {} aliases --recipient-file path {}; choose a separate output path",
                output_path.display(),
                recipient_file.display()
            )));
        }
    }
    for prior_file in &args.prior_recipients.prior_recipient_files {
        if paths_alias(&output_path, prior_file)? {
            return Err(CliError::Message(format!(
                "--output path {} aliases --prior-recipient-file path {}; choose a separate output path",
                output_path.display(),
                prior_file.display()
            )));
        }
    }

    let limit = if args.allow_large {
        None
    } else {
        Some(BLOB_MAX_FILE_BYTES)
    };
    let prior_snapshot =
        read_blob_input_for_rekey(&input_path, limit, BLOB_MAX_CIPHERTEXT_HARD_BYTES, in_place)?;
    let stanzas_before = classify_blob_ciphertext_header(&prior_snapshot.bytes)?;

    let (identities, mut identity_paths) =
        resolve_identities_with_sources(&args.identities, &args.passphrase, true)?;
    let (verify_identities, verify_paths) = resolve_verify_identities(&args.verify_identities)?;
    identity_paths.extend(verify_paths);

    for id_path in &identity_paths {
        if paths_alias(&output_path, id_path)? {
            return Err(CliError::Message(format!(
                "--output path {} aliases identity source path {}; choose a separate output path",
                output_path.display(),
                id_path.display()
            )));
        }
    }
    if let Some(pp_file) = &args.passphrase.passphrase_file {
        if paths_alias(&output_path, pp_file)? {
            return Err(CliError::Message(format!(
                "--output path {} aliases --passphrase-file path {}; choose a separate output path",
                output_path.display(),
                pp_file.display()
            )));
        }
    }

    let recipient_refresh_target = prepare_recipient_refresh_target_with_flag(
        args.write_recipients.as_deref(),
        &args.input,
        "--input",
        &output_path,
        &identity_paths,
        args.passphrase.passphrase_file.as_deref(),
        &args.recipients.recipient_files,
        &args.prior_recipients.prior_recipient_files,
    )?;

    let (plaintext, opened_with) =
        decrypt_blob_recording_opening_identity(&prior_snapshot.bytes, &identities)?;
    refuse_if_secrets_bundle_document(&plaintext)?;

    let target_recipients = resolve_recipients(&args.recipients)?;
    let target_strings = recipient_strings(&target_recipients);
    let prior_strings = resolve_prior_recipients(&args.prior_recipients)?;
    let delta_notice = evaluate_blob_rekey_delta_policy(
        prior_strings.as_deref(),
        &target_strings,
        stanzas_before,
        &opened_with,
        allow_recipient_mismatch,
    )?;
    let recipient_refresh = prepare_recipient_refresh(recipient_refresh_target, &target_strings)?;

    // Self-lockout candidate selection: any loaded or verify identity whose
    // derived public key is in the target recipient set.
    let mut target_verify_candidates: Vec<Identity> = Vec::new();
    for id in identities.iter().chain(verify_identities.iter()) {
        let pubkey = id.to_public().to_string();
        if target_strings.iter().any(|r| r == &pubkey) {
            target_verify_candidates.push(id.clone());
        }
    }
    if target_verify_candidates.is_empty() && !args.allow_self_lockout {
        return Err(CliError::Message(
            "none of the loaded or --verify-identity-* private keys belongs to the target \
             recipient set; refusing blob rekey to prevent self-lockout. Supply \
             --verify-identity-file / --verify-identity-public-key for a target recipient \
             or pass --allow-self-lockout"
                .to_string(),
        ));
    }

    // Encrypt with a fresh file key and run pre-commit verification in memory
    // before dropping `plaintext`.
    let new_ciphertext = seclusor_crypto::encrypt(&plaintext, &target_recipients)?;

    if seclusor_crypto::is_scrypt_ciphertext(&new_ciphertext)? {
        return Err(CliError::Message(
            "internal error: rekeyed blob unexpectedly produced scrypt header".to_string(),
        ));
    }
    let stanzas_after = seclusor_crypto::count_x25519_recipient_stanzas(&new_ciphertext)?;
    if stanzas_after != target_recipients.len() {
        return Err(CliError::Message(format!(
            "internal error: rekeyed blob stanza count ({stanzas_after}) does not match \
             target recipient count ({})",
            target_recipients.len()
        )));
    }

    if !target_verify_candidates.is_empty() {
        use sha2::Digest as _;
        let mut expected_hasher = sha2::Sha256::new();
        expected_hasher.update(plaintext.as_slice());
        let expected_digest: Zeroizing<[u8; 32]> =
            Zeroizing::new(expected_hasher.finalize().into());

        let verified_pt =
            seclusor_crypto::decrypt_zeroizing(&new_ciphertext, &target_verify_candidates)
                .map_err(|_| {
                    CliError::Message(
                        "pre-commit verification failed: target identity could not decrypt the \
                         newly encrypted blob"
                            .to_string(),
                    )
                })?;

        let mut actual_hasher = sha2::Sha256::new();
        actual_hasher.update(verified_pt.as_slice());
        let actual_digest: Zeroizing<[u8; 32]> = Zeroizing::new(actual_hasher.finalize().into());

        if verified_pt.len() != plaintext.len()
            || actual_digest
                .as_slice()
                .ct_eq(expected_digest.as_slice())
                .unwrap_u8()
                != 1
            || verified_pt
                .as_slice()
                .ct_eq(plaintext.as_slice())
                .unwrap_u8()
                != 1
        {
            return Err(CliError::Message(
                "pre-commit verification failed: decrypted payload mismatch".to_string(),
            ));
        }
    } else {
        eprintln!(
            "warning: proceeding with --allow-self-lockout; no target-set private identity \
             was available to decrypt and verify the rekeyed blob before commit"
        );
    }
    drop(plaintext);

    let commit_target = if in_place { &input_path } else { &output_path };
    if in_place {
        eprintln!("warning: overwriting {} in place", args.input.display());
        atomic_write_private_ciphertext(commit_target, &new_ciphertext, Some(prior_snapshot))?;
    } else {
        atomic_write_private_ciphertext(commit_target, &new_ciphertext, None)?;
    }

    // Post-commit check: fresh-open re-read must equal the bytes written.
    let post_commit_bytes =
        read_file_bounded_zeroizing(commit_target, None, BLOB_MAX_CIPHERTEXT_HARD_BYTES).map_err(
            |err| CliError::PostCommitFailure {
                path: output_path.display().to_string(),
                step: "re-read verification",
                source: Box::new(err),
            },
        )?;
    if post_commit_bytes.as_slice() != new_ciphertext.as_slice() {
        return Err(CliError::PostCommitFailure {
            path: output_path.display().to_string(),
            step: "re-read byte comparison",
            source: Box::new(CliError::Message(
                "on-disk bytes after commit did not match written ciphertext".to_string(),
            )),
        });
    }
    drop(post_commit_bytes);

    commit_recipient_refresh(recipient_refresh.as_ref(), &output_path)?;

    if recipient_refresh.is_some() {
        let post_refresh_bytes =
            read_file_bounded_zeroizing(commit_target, None, BLOB_MAX_CIPHERTEXT_HARD_BYTES)
                .map_err(|err| CliError::PostCommitFailure {
                    path: output_path.display().to_string(),
                    step: "post-refresh output re-read verification",
                    source: Box::new(err),
                })?;
        if post_refresh_bytes.as_slice() != new_ciphertext.as_slice() {
            return Err(CliError::PostCommitFailure {
                path: output_path.display().to_string(),
                step: "post-refresh output byte comparison",
                source: Box::new(CliError::Message(
                    "blob output changed concurrently while --write-recipients was being updated"
                        .to_string(),
                )),
            });
        }
    }

    emit_blob_delta_notice(&delta_notice);
    eprintln!("rekeyed blob (opened_with: {opened_with})");
    emit_recipient_refresh_notice(recipient_refresh.as_ref());
    println!("{}", output_path.display());
    Ok(())
}

pub(crate) fn handle_blob_verify(args: BlobVerifyArgs) -> CliResult<()> {
    let limit = if args.allow_large {
        None
    } else {
        Some(BLOB_MAX_FILE_BYTES)
    };
    let ciphertext =
        read_file_bounded_zeroizing(&args.input, limit, BLOB_MAX_CIPHERTEXT_HARD_BYTES)?;
    let _stanzas = classify_blob_ciphertext_header(&ciphertext)?;
    let identities = resolve_identities(&args.identities, &args.passphrase, true)?;
    let (plaintext, opened_with) =
        decrypt_blob_recording_opening_identity(&ciphertext, &identities)?;
    drop(plaintext);
    println!("{opened_with}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use crate::cli::*;
    use crate::test_support::*;

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
            force: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
        })
        .expect("blob encrypt");

        assert!(encrypted.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&encrypted)
                .expect("encrypted metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        // Ciphertext must not contain plaintext
        let ct = fs::read(&encrypted).expect("read ciphertext");
        assert!(!ct.windows(6).any(|w| w == b"secret"));

        handle_blob_decrypt(BlobDecryptArgs {
            input: encrypted,
            output: decrypted.clone(),
            allow_large: false,
            identities: IdentityArgs {
                identity_files: vec![identity_path],
                identity_public_key: None,
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
            force: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
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
                identity_public_key: None,
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
            force: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
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
                identity_public_key: None,
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
            force: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
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
            force: false,
            allow_large: true,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
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
            force: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
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
                identity_public_key: None,
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
            force: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![r1.to_string(), r2.to_string()],
                recipient_files: vec![],
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
                identity_public_key: None,
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
                identity_public_key: None,
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
            force: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
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
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("wrong identity must fail");

        // Error must not contain plaintext
        let msg = err.to_string();
        assert!(!msg.contains("secret data"));
    }

    #[test]
    fn blob_encrypt_refuses_existing_output_without_force_and_overwrites_with_force() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (identity_path, recipient) = blob_fixture_identity_and_recipient(dir.path());

        let input = dir.path().join("input.txt");
        fs::write(&input, "updated payload").expect("write input");
        let output = dir.path().join("out.age");
        fs::write(&output, b"existing-ciphertext").expect("seed existing");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&output, fs::Permissions::from_mode(0o644)).expect("set 0644");
        }

        let err = handle_blob_encrypt(BlobEncryptArgs {
            input: input.clone(),
            output: output.clone(),
            force: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
        })
        .expect_err("must refuse existing output without --force");
        assert!(err.to_string().contains("already exists"));
        assert_eq!(
            fs::read(&output).expect("unchanged"),
            b"existing-ciphertext"
        );

        handle_blob_encrypt(BlobEncryptArgs {
            input,
            output: output.clone(),
            force: true,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
        })
        .expect("--force must overwrite atomically");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&output).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "existing 0644 output must tighten to 0600");
        }

        let decrypted = dir.path().join("restored.txt");
        handle_blob_decrypt(BlobDecryptArgs {
            input: output,
            output: decrypted.clone(),
            allow_large: false,
            identities: IdentityArgs {
                identity_files: vec![identity_path],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("decrypt overwritten blob");
        assert_eq!(
            fs::read_to_string(&decrypted).expect("read"),
            "updated payload"
        );
    }

    #[test]
    fn blob_encrypt_rejects_input_and_recipient_file_aliasing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (_, recipient) = blob_fixture_identity_and_recipient(dir.path());

        let input = dir.path().join("input.txt");
        fs::write(&input, "secret").expect("write input");
        let recipients_file = dir.path().join("recipients.txt");
        fs::write(&recipients_file, format!("{recipient}\n")).expect("write recipients");

        let alias_input_err = handle_blob_encrypt(BlobEncryptArgs {
            input: input.clone(),
            output: input.clone(),
            force: true,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
        })
        .expect_err("must reject output aliasing input");
        assert!(alias_input_err.to_string().contains("aliases --input"));
        assert_eq!(fs::read_to_string(&input).expect("input intact"), "secret");

        let alias_recip_err = handle_blob_encrypt(BlobEncryptArgs {
            input,
            output: recipients_file.clone(),
            force: true,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![],
                recipient_files: vec![recipients_file.clone()],
                recipient_env_var: None,
            },
        })
        .expect_err("must reject output aliasing recipient-file");
        assert!(alias_recip_err
            .to_string()
            .contains("aliases --recipient-file"));
        assert_eq!(
            fs::read_to_string(&recipients_file).expect("recipients intact"),
            format!("{recipient}\n")
        );
    }

    #[cfg(unix)]
    #[test]
    fn blob_encrypt_force_preserves_stricter_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let (_, recipient) = blob_fixture_identity_and_recipient(dir.path());

        let input = dir.path().join("input.txt");
        fs::write(&input, "payload").expect("write input");
        let output = dir.path().join("strict.age");
        fs::write(&output, b"seed").expect("seed");
        fs::set_permissions(&output, fs::Permissions::from_mode(0o400)).expect("set 0400");

        handle_blob_encrypt(BlobEncryptArgs {
            input,
            output: output.clone(),
            force: true,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
        })
        .expect("force overwrite of 0400");

        let mode = fs::metadata(&output).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o400, "stricter owner-only mode must not be widened");
    }

    #[cfg(unix)]
    #[test]
    fn blob_encrypt_refuses_live_and_dangling_symlinks_with_and_without_force() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("temp dir");
        let (_, recipient) = blob_fixture_identity_and_recipient(dir.path());

        let input = dir.path().join("input.txt");
        fs::write(&input, "payload").expect("write input");

        let target = dir.path().join("real-target.age");
        fs::write(&target, b"keep-me").expect("seed target");
        let live_link = dir.path().join("live-link.age");
        symlink(&target, &live_link).expect("create live symlink");

        let dangling_link = dir.path().join("dangling-link.age");
        symlink(dir.path().join("missing-target.age"), &dangling_link)
            .expect("create dangling symlink");

        for (link, label) in [(&live_link, "live"), (&dangling_link, "dangling")] {
            let err_no_force = handle_blob_encrypt(BlobEncryptArgs {
                input: input.clone(),
                output: link.clone(),
                force: false,
                allow_large: false,
                recipients: RecipientArgs {
                    recipients: vec![recipient.to_string()],
                    recipient_files: vec![],
                    recipient_env_var: None,
                },
            })
            .expect_err(&format!("{label} symlink must fail without --force"));
            assert!(err_no_force.to_string().contains("already exists"));

            let err_force = handle_blob_encrypt(BlobEncryptArgs {
                input: input.clone(),
                output: link.clone(),
                force: true,
                allow_large: false,
                recipients: RecipientArgs {
                    recipients: vec![recipient.to_string()],
                    recipient_files: vec![],
                    recipient_env_var: None,
                },
            })
            .expect_err(&format!("{label} symlink must fail with --force"));
            assert!(err_force.to_string().contains("symlink"));
        }

        assert_eq!(fs::read(&target).expect("target intact"), b"keep-me");
    }

    #[cfg(unix)]
    #[test]
    fn blob_encrypt_refuses_fifo_output_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let (_, recipient) = blob_fixture_identity_and_recipient(dir.path());

        let input = dir.path().join("input.txt");
        fs::write(&input, "payload").expect("write input");

        let fifo = dir.path().join("pipe.age");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect("cstring");
        let rc = unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo must succeed");

        let err_no_force = handle_blob_encrypt(BlobEncryptArgs {
            input: input.clone(),
            output: fifo.clone(),
            force: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
        })
        .expect_err("FIFO output must fail without blocking when --force is false");
        assert!(err_no_force.to_string().contains("already exists"));

        let err_force = handle_blob_encrypt(BlobEncryptArgs {
            input,
            output: fifo,
            force: true,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
        })
        .expect_err("FIFO output must fail without blocking when --force is true");
        assert!(err_force.to_string().contains("regular file"));
    }

    #[test]
    fn blob_encrypt_decrypt_and_force_overwrite_at_max_16mib_plaintext() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (identity_path, recipient) = blob_fixture_identity_and_recipient(dir.path());

        let max_plaintext_len = seclusor_core::constants::MAX_BUNDLE_PLAINTEXT_BYTES;
        let input = dir.path().join("max-16mib.bin");
        fs::write(&input, vec![0xA5u8; max_plaintext_len]).expect("write 16 MiB input");
        let encrypted = dir.path().join("max-16mib.age");
        let decrypted = dir.path().join("max-16mib-restored.bin");

        handle_blob_encrypt(BlobEncryptArgs {
            input: input.clone(),
            output: encrypted.clone(),
            force: false,
            allow_large: true,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
        })
        .expect("encrypt 16 MiB blob");

        assert!(
            fs::metadata(&encrypted).expect("meta").len() > max_plaintext_len as u64,
            "age framing overhead makes ciphertext exceed 16 MiB"
        );

        handle_blob_encrypt(BlobEncryptArgs {
            input,
            output: encrypted.clone(),
            force: true,
            allow_large: true,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
        })
        .expect("force overwrite of 16 MiB ciphertext must succeed");

        handle_blob_decrypt(BlobDecryptArgs {
            input: encrypted,
            output: decrypted.clone(),
            allow_large: true,
            identities: IdentityArgs {
                identity_files: vec![identity_path],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("decrypt 16 MiB blob with --allow-large");

        let restored = fs::read(&decrypted).expect("read restored");
        assert_eq!(restored.len(), max_plaintext_len);
        assert!(restored.iter().all(|&b| b == 0xA5));
    }

    const BLOB_REKEY_SENTINEL: &str = "SECLUSOR_BLOB_REKEY_SENTINEL_9c4e";

    fn assert_no_blob_sentinel_in_dir(dir: &Path) {
        for entry in fs::read_dir(dir).expect("read dir").flatten() {
            let data = fs::read(entry.path()).unwrap_or_default();
            assert!(
                !data
                    .windows(BLOB_REKEY_SENTINEL.len())
                    .any(|w| w == BLOB_REKEY_SENTINEL.as_bytes()),
                "sentinel found in {}",
                entry.path().display()
            );
        }
    }

    #[test]
    fn blob_rekey_roundtrip_rotates_recipients_and_generates_fresh_file_key() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (old_id_path, old_r) = blob_fixture_identity_and_recipient(dir.path());
        let keep_id_path = dir.path().join("keep-identity.txt");
        let keep_gen = seclusor_keyring::generate_identity_file(&keep_id_path).expect("gen keep");
        let new_id_path = dir.path().join("new-identity.txt");
        let new_gen = seclusor_keyring::generate_identity_file(&new_id_path).expect("gen new");

        let blob_path = dir.path().join("pack.age");
        let initial_ct = seclusor_crypto::encrypt(
            BLOB_REKEY_SENTINEL.as_bytes(),
            &[
                old_r.clone(),
                keep_gen.recipient.parse().expect("parse keep"),
            ],
        )
        .expect("encrypt initial");
        fs::write(&blob_path, &initial_ct).expect("write blob");
        assert_no_blob_sentinel_in_dir(dir.path());

        // T2: Re-randomizing with the exact same recipient set produces a fresh file key / ciphertext.
        handle_blob_rekey(BlobRekeyArgs {
            input: blob_path.clone(),
            output: None,
            write_recipients: None,
            allow_self_lockout: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![old_r.to_string(), keep_gen.recipient.clone()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
            prior_recipients: PriorRecipientArgs {
                prior_recipients: vec![old_r.to_string(), keep_gen.recipient.clone()],
                prior_recipient_files: vec![],
            },
            identities: IdentityArgs {
                identity_files: vec![old_id_path.clone()],
                identity_public_key: None,
            },
            verify_identities: VerifyIdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("re-randomize same set");
        let rerandomized_ct = fs::read(&blob_path).expect("read rerandomized");
        assert_ne!(
            rerandomized_ct, initial_ct,
            "fresh file key must produce distinct ciphertext"
        );
        assert_no_blob_sentinel_in_dir(dir.path());

        // T1: Rotate {old, keep} -> {new, keep} using --verify-identity-file for pre-commit proof.
        let recipients_out = dir.path().join("recipients.txt");
        handle_blob_rekey_with_policy(
            BlobRekeyArgs {
                input: blob_path.clone(),
                output: None,
                write_recipients: Some(recipients_out.clone()),
                allow_self_lockout: false,
                allow_large: false,
                recipients: RecipientArgs {
                    recipients: vec![new_gen.recipient.clone(), keep_gen.recipient.clone()],
                    recipient_files: vec![],
                    recipient_env_var: None,
                },
                prior_recipients: PriorRecipientArgs {
                    prior_recipients: vec![old_r.to_string(), keep_gen.recipient.clone()],
                    prior_recipient_files: vec![],
                },
                identities: IdentityArgs {
                    identity_files: vec![old_id_path.clone()],
                    identity_public_key: None,
                },
                verify_identities: VerifyIdentityArgs {
                    verify_identity_files: vec![new_id_path.clone()],
                    verify_identity_public_key: None,
                },
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect("rotate {old, keep} -> {new, keep}");
        assert_no_blob_sentinel_in_dir(dir.path());
        assert!(recipients_out.exists());

        // Verify with new identity succeeds; old identity fails.
        handle_blob_verify(BlobVerifyArgs {
            input: blob_path.clone(),
            allow_large: false,
            identities: IdentityArgs {
                identity_files: vec![new_id_path.clone()],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("verify with new identity");

        let err_old = handle_blob_verify(BlobVerifyArgs {
            input: blob_path.clone(),
            allow_large: false,
            identities: IdentityArgs {
                identity_files: vec![old_id_path],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("retired identity must not verify");
        assert!(!err_old.to_string().contains(BLOB_REKEY_SENTINEL));

        let new_id: seclusor_crypto::Identity = new_gen.identity.parse().expect("parse new id");
        let restored = seclusor_crypto::decrypt(&fs::read(&blob_path).unwrap(), &[new_id])
            .expect("decrypt rotated");
        assert_eq!(restored, BLOB_REKEY_SENTINEL.as_bytes());
    }

    #[test]
    fn blob_rekey_delta_and_tripwire_policies_enforce_fail_closed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (old_id_path, old_r) = blob_fixture_identity_and_recipient(dir.path());
        let other_id_path = dir.path().join("other-identity.txt");
        let other_gen = seclusor_keyring::generate_identity_file(&other_id_path).expect("gen");
        let third_id_path = dir.path().join("third-identity.txt");
        let third_gen = seclusor_keyring::generate_identity_file(&third_id_path).expect("gen3");

        let blob_path = dir.path().join("pack.age");
        let ct = seclusor_crypto::encrypt(
            b"payload",
            &[
                old_r.clone(),
                other_gen.recipient.parse().expect("parse other"),
            ],
        )
        .expect("encrypt");
        fs::write(&blob_path, &ct).expect("write");

        // 1. No --prior-* without --allow-recipient-mismatch refuses (Indeterminate is strict on blobs).
        let err_indet = handle_blob_rekey(BlobRekeyArgs {
            input: blob_path.clone(),
            output: None,
            write_recipients: None,
            allow_self_lockout: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![old_r.to_string(), other_gen.recipient.clone()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
            prior_recipients: PriorRecipientArgs::default(),
            identities: IdentityArgs {
                identity_files: vec![old_id_path.clone()],
                identity_public_key: None,
            },
            verify_identities: VerifyIdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("indeterminate without --allow-recipient-mismatch must fail");
        assert!(err_indet.to_string().contains("--allow-recipient-mismatch"));
        assert_eq!(fs::read(&blob_path).unwrap(), ct);

        // 2. Stanza-count tripwire refuses even with --allow-recipient-mismatch.
        let err_count = handle_blob_rekey_with_policy(
            BlobRekeyArgs {
                input: blob_path.clone(),
                output: None,
                write_recipients: None,
                allow_self_lockout: false,
                allow_large: false,
                recipients: RecipientArgs {
                    recipients: vec![old_r.to_string()],
                    recipient_files: vec![],
                    recipient_env_var: None,
                },
                prior_recipients: PriorRecipientArgs {
                    prior_recipients: vec![old_r.to_string()],
                    prior_recipient_files: vec![],
                },
                identities: IdentityArgs {
                    identity_files: vec![old_id_path.clone()],
                    identity_public_key: None,
                },
                verify_identities: VerifyIdentityArgs::default(),
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect_err("stanza count mismatch against prior must refuse");
        assert!(err_count.to_string().contains("stanza count"));

        // 3. opened_with not in asserted prior set refuses even when stanza count matches.
        let err_opened = handle_blob_rekey_with_policy(
            BlobRekeyArgs {
                input: blob_path.clone(),
                output: None,
                write_recipients: None,
                allow_self_lockout: false,
                allow_large: false,
                recipients: RecipientArgs {
                    recipients: vec![old_r.to_string(), third_gen.recipient.clone()],
                    recipient_files: vec![],
                    recipient_env_var: None,
                },
                prior_recipients: PriorRecipientArgs {
                    prior_recipients: vec![
                        other_gen.recipient.clone(),
                        third_gen.recipient.clone(),
                    ],
                    prior_recipient_files: vec![],
                },
                identities: IdentityArgs {
                    identity_files: vec![old_id_path.clone()],
                    identity_public_key: None,
                },
                verify_identities: VerifyIdentityArgs::default(),
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect_err("opened_with missing from prior set must refuse");
        assert!(err_opened
            .to_string()
            .contains("not in the asserted prior recipient set"));

        // 4. Delta without --allow-recipient-mismatch refuses and renders +/- diff.
        let err_delta = handle_blob_rekey(BlobRekeyArgs {
            input: blob_path.clone(),
            output: None,
            write_recipients: None,
            allow_self_lockout: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![old_r.to_string(), third_gen.recipient.clone()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
            prior_recipients: PriorRecipientArgs {
                prior_recipients: vec![old_r.to_string(), other_gen.recipient.clone()],
                prior_recipient_files: vec![],
            },
            identities: IdentityArgs {
                identity_files: vec![old_id_path],
                identity_public_key: None,
            },
            verify_identities: VerifyIdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("delta without flag must refuse");
        assert!(err_delta
            .to_string()
            .contains(&format!("+{}", third_gen.recipient)));
        assert!(err_delta
            .to_string()
            .contains(&format!("-{}", other_gen.recipient)));
        assert_eq!(fs::read(&blob_path).unwrap(), ct);
    }

    #[test]
    fn blob_rekey_self_lockout_and_protected_verify_identity_refuse_unless_overridden() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (old_id_path, old_r) = blob_fixture_identity_and_recipient(dir.path());
        let new_id_path = dir.path().join("new-identity.txt");
        let new_gen = seclusor_keyring::generate_identity_file(&new_id_path).expect("gen new");

        let blob_path = dir.path().join("pack.age");
        let ct = seclusor_crypto::encrypt(b"payload", std::slice::from_ref(&old_r)).expect("enc");
        fs::write(&blob_path, &ct).expect("write");

        // Rotating to {new} with only old_id loaded and no --verify-identity-* or --allow-self-lockout refuses.
        let err_lockout = handle_blob_rekey_with_policy(
            BlobRekeyArgs {
                input: blob_path.clone(),
                output: None,
                write_recipients: None,
                allow_self_lockout: false,
                allow_large: false,
                recipients: RecipientArgs {
                    recipients: vec![new_gen.recipient.clone()],
                    recipient_files: vec![],
                    recipient_env_var: None,
                },
                prior_recipients: PriorRecipientArgs {
                    prior_recipients: vec![old_r.to_string()],
                    prior_recipient_files: vec![],
                },
                identities: IdentityArgs {
                    identity_files: vec![old_id_path.clone()],
                    identity_public_key: None,
                },
                verify_identities: VerifyIdentityArgs::default(),
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect_err("self-lockout without verify identity or flag must refuse");
        assert!(err_lockout.to_string().contains("--allow-self-lockout"));
        assert_eq!(fs::read(&blob_path).unwrap(), ct);

        // Passphrase-protected verify identity refuses with actionable remedy.
        let protected_verify_path = dir.path().join("protected-verify.txt");
        let pp = secrecy::SecretString::from("test-passphrase-123".to_owned());
        let prot_gen =
            seclusor_keyring::generate_identity_file_with_passphrase(&protected_verify_path, &pp)
                .expect("gen protected");
        let err_prot = handle_blob_rekey_with_policy(
            BlobRekeyArgs {
                input: blob_path.clone(),
                output: None,
                write_recipients: None,
                allow_self_lockout: false,
                allow_large: false,
                recipients: RecipientArgs {
                    recipients: vec![prot_gen.recipient],
                    recipient_files: vec![],
                    recipient_env_var: None,
                },
                prior_recipients: PriorRecipientArgs {
                    prior_recipients: vec![old_r.to_string()],
                    prior_recipient_files: vec![],
                },
                identities: IdentityArgs {
                    identity_files: vec![old_id_path.clone()],
                    identity_public_key: None,
                },
                verify_identities: VerifyIdentityArgs {
                    verify_identity_files: vec![protected_verify_path],
                    verify_identity_public_key: None,
                },
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect_err("protected verify identity must refuse with remedy");
        assert!(err_prot.to_string().contains("secrets blob verify"));
        assert_eq!(fs::read(&blob_path).unwrap(), ct);

        // Passing --allow-self-lockout succeeds.
        handle_blob_rekey_with_policy(
            BlobRekeyArgs {
                input: blob_path.clone(),
                output: None,
                write_recipients: None,
                allow_self_lockout: true,
                allow_large: false,
                recipients: RecipientArgs {
                    recipients: vec![new_gen.recipient],
                    recipient_files: vec![],
                    recipient_env_var: None,
                },
                prior_recipients: PriorRecipientArgs {
                    prior_recipients: vec![old_r.to_string()],
                    prior_recipient_files: vec![],
                },
                identities: IdentityArgs {
                    identity_files: vec![old_id_path],
                    identity_public_key: None,
                },
                verify_identities: VerifyIdentityArgs::default(),
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect("--allow-self-lockout must permit rotation");
    }

    #[test]
    fn blob_rekey_refuses_bundle_documents_scrypt_non_age_and_implicit_env_fallback() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (id_path, recipient) = blob_fixture_identity_and_recipient(dir.path());

        // 1. Bundle document refused with pointer to `secrets rekey`.
        let bundle_path = dir.path().join("bundle.age");
        let secrets = fixture_secrets();
        seclusor_codec::encrypt_bundle_to_file(
            &secrets,
            std::slice::from_ref(&recipient),
            &bundle_path,
        )
        .expect("write bundle");
        let err_bundle = handle_blob_rekey_with_policy(
            BlobRekeyArgs {
                input: bundle_path,
                output: None,
                write_recipients: None,
                allow_self_lockout: false,
                allow_large: false,
                recipients: RecipientArgs {
                    recipients: vec![recipient.to_string()],
                    recipient_files: vec![],
                    recipient_env_var: None,
                },
                prior_recipients: PriorRecipientArgs::default(),
                identities: IdentityArgs {
                    identity_files: vec![id_path.clone()],
                    identity_public_key: None,
                },
                verify_identities: VerifyIdentityArgs::default(),
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect_err("bundle document must be refused by blob rekey");
        assert!(err_bundle.to_string().contains("seclusor secrets rekey"));

        // 2. Scrypt blob refused.
        let scrypt_path = dir.path().join("scrypt.age");
        let scrypt_ct =
            seclusor_crypto::encrypt_with_passphrase(b"blob", "test-passphrase").expect("scrypt");
        fs::write(&scrypt_path, scrypt_ct).expect("write scrypt");
        let err_scrypt = handle_blob_rekey_with_policy(
            BlobRekeyArgs {
                input: scrypt_path,
                output: None,
                write_recipients: None,
                allow_self_lockout: false,
                allow_large: false,
                recipients: RecipientArgs {
                    recipients: vec![recipient.to_string()],
                    recipient_files: vec![],
                    recipient_env_var: None,
                },
                prior_recipients: PriorRecipientArgs::default(),
                identities: IdentityArgs {
                    identity_files: vec![id_path.clone()],
                    identity_public_key: None,
                },
                verify_identities: VerifyIdentityArgs::default(),
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect_err("scrypt blob must be refused");
        assert!(err_scrypt.to_string().contains("scrypt"));

        // 3. Non-age input refused.
        let non_age_path = dir.path().join("plain.txt");
        fs::write(&non_age_path, b"not-age-ciphertext").expect("write non-age");
        let err_non_age = handle_blob_verify(BlobVerifyArgs {
            input: non_age_path,
            allow_large: false,
            identities: IdentityArgs {
                identity_files: vec![id_path.clone()],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("non-age input must fail verify");
        assert!(err_non_age.to_string().contains("not a valid age"));

        // 4. Implicit SECLUSOR_RECIPIENTS fallback without explicit flag refused.
        let blob_path = dir.path().join("valid.age");
        fs::write(
            &blob_path,
            seclusor_crypto::encrypt(b"ok", std::slice::from_ref(&recipient)).unwrap(),
        )
        .unwrap();
        let err_no_explicit = handle_blob_rekey(BlobRekeyArgs {
            input: blob_path,
            output: None,
            write_recipients: None,
            allow_self_lockout: false,
            allow_large: false,
            recipients: RecipientArgs::default(),
            prior_recipients: PriorRecipientArgs::default(),
            identities: IdentityArgs {
                identity_files: vec![id_path],
                identity_public_key: None,
            },
            verify_identities: VerifyIdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("missing explicit recipient channel must fail");
        assert!(err_no_explicit.to_string().contains("SECLUSOR_RECIPIENTS"));
    }

    #[test]
    fn blob_rekey_faults_and_aliasing_enforce_three_state_contract() {
        use crate::atomic_write::{inject_fault, AtomicFault};

        let dir = tempfile::tempdir().expect("temp dir");
        let (id_path, recipient) = blob_fixture_identity_and_recipient(dir.path());
        let blob_path = dir.path().join("pack.age");
        let initial_ct =
            seclusor_crypto::encrypt(b"payload", std::slice::from_ref(&recipient)).expect("enc");
        fs::write(&blob_path, &initial_ct).expect("write");

        let prior_file = dir.path().join("prior.txt");
        fs::write(&prior_file, format!("{recipient}\n")).expect("write prior");

        // Aliasing --write-recipients against --prior-recipient-file must fail before write.
        let err_alias = handle_blob_rekey(BlobRekeyArgs {
            input: blob_path.clone(),
            output: None,
            write_recipients: Some(prior_file.clone()),
            allow_self_lockout: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
            prior_recipients: PriorRecipientArgs {
                prior_recipients: vec![],
                prior_recipient_files: vec![prior_file.clone()],
            },
            identities: IdentityArgs {
                identity_files: vec![id_path.clone()],
                identity_public_key: None,
            },
            verify_identities: VerifyIdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("write-recipients aliasing prior-recipient-file must fail");
        assert!(err_alias.to_string().contains("--prior-recipient-file"));
        assert_eq!(fs::read(&blob_path).unwrap(), initial_ct);

        // State 1 (Not committed): pre-replace fault leaves original intact.
        for fault in [
            AtomicFault::BeforeWrite,
            AtomicFault::AfterWriteBeforeSync,
            AtomicFault::AfterSyncBeforeReplace,
            AtomicFault::ForceCasMismatch,
            AtomicFault::ReplaceFail,
        ] {
            inject_fault(Some(fault));
            let err = handle_blob_rekey(BlobRekeyArgs {
                input: blob_path.clone(),
                output: None,
                write_recipients: None,
                allow_self_lockout: false,
                allow_large: false,
                recipients: RecipientArgs {
                    recipients: vec![recipient.to_string()],
                    recipient_files: vec![],
                    recipient_env_var: None,
                },
                prior_recipients: PriorRecipientArgs {
                    prior_recipients: vec![recipient.to_string()],
                    prior_recipient_files: vec![],
                },
                identities: IdentityArgs {
                    identity_files: vec![id_path.clone()],
                    identity_public_key: None,
                },
                verify_identities: VerifyIdentityArgs::default(),
                passphrase: PassphraseArgs::default(),
            })
            .expect_err("pre-commit fault must fail");
            inject_fault(None);
            assert!(!matches!(err, CliError::PostCommitFailure { .. }));
            assert_eq!(fs::read(&blob_path).unwrap(), initial_ct);
        }

        // State 2 (Committed, post-step failed): DirSyncFail on Unix reports PostCommitFailure
        // stating output was committed.
        #[cfg(unix)]
        {
            inject_fault(Some(AtomicFault::DirSyncFail));
            let err_dir_sync = handle_blob_rekey(BlobRekeyArgs {
                input: blob_path.clone(),
                output: None,
                write_recipients: None,
                allow_self_lockout: false,
                allow_large: false,
                recipients: RecipientArgs {
                    recipients: vec![recipient.to_string()],
                    recipient_files: vec![],
                    recipient_env_var: None,
                },
                prior_recipients: PriorRecipientArgs {
                    prior_recipients: vec![recipient.to_string()],
                    prior_recipient_files: vec![],
                },
                identities: IdentityArgs {
                    identity_files: vec![id_path],
                    identity_public_key: None,
                },
                verify_identities: VerifyIdentityArgs::default(),
                passphrase: PassphraseArgs::default(),
            })
            .expect_err("DirSyncFail must surface");
            inject_fault(None);
            assert!(matches!(err_dir_sync, CliError::PostCommitFailure { .. }));
            assert!(err_dir_sync.to_string().contains("output was committed"));
            assert_ne!(
                fs::read(&blob_path).unwrap(),
                initial_ct,
                "new ciphertext is already live on disk after commit_replace"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn blob_rekey_in_place_preserves_input_symlink_and_rewrites_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("temp dir");
        let (id_path, recipient) = blob_fixture_identity_and_recipient(dir.path());
        let real_blob = dir.path().join("real-pack.age");
        let initial_ct =
            seclusor_crypto::encrypt(b"symlink-payload", std::slice::from_ref(&recipient))
                .expect("enc");
        fs::write(&real_blob, &initial_ct).expect("write");

        let link_blob = dir.path().join("link-pack.age");
        symlink(&real_blob, &link_blob).expect("symlink");

        handle_blob_rekey(BlobRekeyArgs {
            input: link_blob.clone(),
            output: None,
            write_recipients: None,
            allow_self_lockout: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
            prior_recipients: PriorRecipientArgs {
                prior_recipients: vec![recipient.to_string()],
                prior_recipient_files: vec![],
            },
            identities: IdentityArgs {
                identity_files: vec![id_path],
                identity_public_key: None,
            },
            verify_identities: VerifyIdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("in-place blob rekey through symlink must succeed");

        assert!(
            fs::symlink_metadata(&link_blob)
                .expect("link meta")
                .file_type()
                .is_symlink(),
            "input symlink must remain a symlink"
        );
        assert_ne!(
            fs::read(&real_blob).expect("read real"),
            initial_ct,
            "canonical target must be updated"
        );
    }

    #[cfg(unix)]
    #[test]
    fn blob_rekey_symlink_parent_dotdot_does_not_misclassify_distinct_output_as_in_place() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("temp dir");
        let (id_path, recipient) = blob_fixture_identity_and_recipient(dir.path());
        let vault_dir = dir.path().join("vault");
        let vault_sub = vault_dir.join("subdir");
        let work_dir = dir.path().join("work");
        fs::create_dir_all(&vault_sub).expect("mkdir vault/subdir");
        fs::create_dir_all(&work_dir).expect("mkdir work");
        symlink(&vault_sub, work_dir.join("link")).expect("symlink work/link -> vault/subdir");

        let vault_blob = vault_dir.join("blob.age");
        let initial_ct =
            seclusor_crypto::encrypt(b"vault-payload", std::slice::from_ref(&recipient))
                .expect("enc");
        fs::write(&vault_blob, &initial_ct).expect("seed vault/blob.age");

        let input_via_link_parent = work_dir.join("link").join("..").join("blob.age");
        let requested_output = work_dir.join("blob.age");

        handle_blob_rekey(BlobRekeyArgs {
            input: input_via_link_parent,
            output: Some(requested_output.clone()),
            write_recipients: None,
            allow_self_lockout: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
            prior_recipients: PriorRecipientArgs {
                prior_recipients: vec![recipient.to_string()],
                prior_recipient_files: vec![],
            },
            identities: IdentityArgs {
                identity_files: vec![id_path],
                identity_public_key: None,
            },
            verify_identities: VerifyIdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("distinct output must be created, not treated as in-place overwrite of vault");

        assert_eq!(
            fs::read(&vault_blob).expect("vault unchanged"),
            initial_ct,
            "original vault/blob.age must not be overwritten"
        );
        assert!(
            requested_output.exists(),
            "requested output work/blob.age must be created"
        );
    }

    #[test]
    fn blob_verify_and_rekey_accept_ascii_armored_x25519_and_refuse_mixed_non_x25519_stanzas() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (id_path, recipient) = blob_fixture_identity_and_recipient(dir.path());
        let id: seclusor_crypto::Identity = fs::read_to_string(&id_path)
            .expect("read id")
            .lines()
            .find(|l| l.starts_with("AGE-SECRET-KEY-"))
            .expect("key line")
            .parse()
            .expect("parse id");

        // Construct an ASCII-armored X25519 ciphertext using age::armor::ArmoredWriter
        // via generate_identity_file_with_passphrase's underlying age crate Pattern, or
        // base64-encode a binary age ciphertext inside standard age ASCII armor framing.
        let binary_ct =
            seclusor_crypto::encrypt(b"armored-blob-payload", std::slice::from_ref(&recipient))
                .expect("encrypt binary");
        // Wrap binary_ct in standard PEM-style age armor (64-col base64).
        let mut armored = String::from("-----BEGIN AGE ENCRYPTED FILE-----\n");
        let b64 = {
            // Encode binary_ct using standard base64 via a small inline encoder.
            const TABLE: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for chunk in binary_ct.chunks(3) {
                let b0 = chunk[0] as u32;
                let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
                let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
                let n = (b0 << 16) | (b1 << 8) | b2;
                out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
                out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
                if chunk.len() > 1 {
                    out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
                } else {
                    out.push('=');
                }
                if chunk.len() > 2 {
                    out.push(TABLE[(n & 0x3f) as usize] as char);
                } else {
                    out.push('=');
                }
            }
            out
        };
        for line in b64.as_bytes().chunks(64) {
            armored.push_str(std::str::from_utf8(line).unwrap());
            armored.push('\n');
        }
        armored.push_str("-----END AGE ENCRYPTED FILE-----\n");

        let armored_path = dir.path().join("armored.age");
        fs::write(&armored_path, armored.as_bytes()).expect("write armored");

        handle_blob_verify(BlobVerifyArgs {
            input: armored_path.clone(),
            allow_large: false,
            identities: IdentityArgs {
                identity_files: vec![id_path.clone()],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("verify must accept ASCII-armored X25519 blob");

        handle_blob_rekey(BlobRekeyArgs {
            input: armored_path.clone(),
            output: None,
            write_recipients: None,
            allow_self_lockout: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
            prior_recipients: PriorRecipientArgs {
                prior_recipients: vec![recipient.to_string()],
                prior_recipient_files: vec![],
            },
            identities: IdentityArgs {
                identity_files: vec![id_path.clone()],
                identity_public_key: None,
            },
            verify_identities: VerifyIdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("rekey must accept ASCII-armored X25519 blob");

        let restored = seclusor_crypto::decrypt(&fs::read(&armored_path).unwrap(), &[id])
            .expect("decrypt rekeyed");
        assert_eq!(restored, b"armored-blob-payload");

        // Mixed header with a non-X25519 stanza must be refused by classify_blob_ciphertext_header.
        let mut mixed_header = Vec::new();
        let header_end = binary_ct
            .windows(4)
            .position(|w| w == b"\n---")
            .expect("find MAC line");
        mixed_header.extend_from_slice(&binary_ct[..header_end]);
        mixed_header.extend_from_slice(b"\n-> ssh-ed25519 AAAA fake-stanza\ndGVzdA");
        mixed_header.extend_from_slice(&binary_ct[header_end..]);
        let mixed_path = dir.path().join("mixed.age");
        fs::write(&mixed_path, &mixed_header).expect("write mixed");

        let err_mixed = handle_blob_verify(BlobVerifyArgs {
            input: mixed_path,
            allow_large: false,
            identities: IdentityArgs {
                identity_files: vec![id_path],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("mixed non-X25519 recipient stanza must be refused");
        assert!(err_mixed.to_string().contains("non-X25519"));

        // Direct unit checks on refuse_if_secrets_bundle_document for partial/malformed/unknown/wrong-type JSON inputs:
        // None of these are valid seclusor bundle documents, so they must return Ok(()) cleanly.
        for non_bundle_json in [
            b"\"TOP_SECRET\"" as &[u8],
            b"{\"schema_version\":\"TOP_SECRET\"}",
            b"{\"schema_version\":\"v1.0.0\",\"projects\":\"TOP_SECRET\"}",
            b"{\"schema_version\":\"v1.0.0\",\"unknown_field\":\"SECRET\",\"projects\":[]}",
            b"{\"schema_version\":\"v1.0.0\",\"schema_version\":\"v1.0.0\",\"projects\":[]}",
            b"{\"schema_version\":123,\"projects\":[]}",
            b"{\"schema_version\":\"v1.1.0\",\"recipients\":[],\"projects\":[{\"project_slug\":\"demo\",\"credentials\":{\"API_KEY\":{\"type\":\"secret\",\"value\":\"s1\"},\"API_KEY\":null}}]}",
            b"{\"schema_version\":\"v1.1.0\",\"recipients\":[],\"projects\":[{\"project_slug\":\"demo\",\"credentials\":{\"API_KEY\":{\"type\":\"secret\",\"value\":\"s1\",\"value\":123}}}]}",
        ] {
            refuse_if_secrets_bundle_document(non_bundle_json)
                .expect("non-bundle JSON must be accepted as opaque blob payload");
        }
        // Valid minimal bundle JSON — including duplicate credential names and duplicate credential fields
        // (even when an earlier duplicate occurrence is invalid/non-object/wrong-type before being overwritten)
        // accepted by seclusor_core::model::deserialize_credentials_map (last-value-wins) — must be refused.
        for valid_bundle_json in [
            br#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","value":"s1"}}}]}"#
                as &[u8],
            br#"{"schema_version":"v1.1.0","recipients":[],"projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","value":"s1"},"API_KEY":{"type":"secret","value":"s2"}}}]}"#,
            br#"{"schema_version":"v1.1.0","recipients":[],"projects":[{"project_slug":"demo","credentials":{"API_KEY":null,"API_KEY":{"type":"secret","value":"s2"}}}]}"#,
            br#"{"schema_version":"v1.1.0","recipients":[],"projects":[{"project_slug":"demo","credentials":{"API_KEY":{"unknown":"x"},"API_KEY":{"type":"secret","value":"s2"}}}]}"#,
            br#"{"schema_version":"v1.1.0","recipients":[],"projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","type":"secret","value":"s1","value":"s2"}}}]}"#,
            br#"{"schema_version":"v1.1.0","recipients":[],"projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":123,"type":"secret","value":false,"value":"s2","description":99,"description":null}}}]}"#,
            br#"{"schema_version":"v1.1.0","recipients":[],"projects":[["demo",null,{"API_KEY":{"type":"secret","value":"s2"}}]]}"#,
            br#"["v1.1.0",null,null,[],[["demo",null,{"API_KEY":{"type":"secret","value":"s2"}}]]]"#,
        ] {
            let err_valid_bundle = refuse_if_secrets_bundle_document(valid_bundle_json)
                .expect_err("valid or duplicate-member bundle JSON must be refused");
            assert!(err_valid_bundle
                .to_string()
                .contains("seclusor secrets rekey"));
        }
    }
}
