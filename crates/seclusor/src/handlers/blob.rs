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
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::atomic_write::{atomic_write_private_ciphertext, PrivateCiphertextPriorSnapshot};
use crate::cli::{
    BlobDecryptArgs, BlobEncryptArgs, BlobRekeyArgs, BlobRekeyBatchArgs, BlobSubcommand,
    BlobVerifyArgs, PriorRecipientArgs, VerifyIdentityArgs,
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
                    "--allow-recipient-mismatch is only valid for `blob rekey` and `blob rekey-batch` in the `secrets blob` family"
                        .to_string(),
                ));
            }
            handle_blob_encrypt(args)
        }
        BlobSubcommand::Decrypt(args) => {
            if allow_recipient_mismatch {
                return Err(CliError::Message(
                    "--allow-recipient-mismatch is only valid for `blob rekey` and `blob rekey-batch` in the `secrets blob` family"
                        .to_string(),
                ));
            }
            handle_blob_decrypt(args)
        }
        BlobSubcommand::Rekey(args) => {
            handle_blob_rekey_with_policy(args, allow_recipient_mismatch)
        }
        BlobSubcommand::RekeyBatch(args) => {
            handle_blob_rekey_batch_with_policy(args, allow_recipient_mismatch)
        }
        BlobSubcommand::Verify(args) => {
            if allow_recipient_mismatch {
                return Err(CliError::Message(
                    "--allow-recipient-mismatch is only valid for `blob rekey` and `blob rekey-batch` in the `secrets blob` family"
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

    let (pre_id, _) = path_identity_and_nlink_nofollow(path).map_err(CliError::Io)?;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
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
    if !open_meta.is_file() || is_symlink_or_reparse_point(&open_meta) {
        return Err(CliError::Message(format!(
            "output path {} must be a regular file",
            path.display()
        )));
    }
    let (open_id, _) = file_identity_and_nlink(&file).map_err(CliError::Io)?;
    if open_id != pre_id {
        return Err(CliError::ConcurrentModification {
            path: path.display().to_string(),
        });
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
            use std::os::unix::fs::PermissionsExt;
            (open_id.0, open_id.1, open_meta.permissions().mode() & 0o777)
        },
        #[cfg(windows)]
        file_id: open_id,
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

#[derive(Debug)]
enum BlobReadForRekeyError {
    TooLarge(String),
    Other(CliError),
}

impl From<BlobReadForRekeyError> for CliError {
    fn from(err: BlobReadForRekeyError) -> Self {
        match err {
            BlobReadForRekeyError::TooLarge(msg) => CliError::Message(msg),
            BlobReadForRekeyError::Other(e) => e,
        }
    }
}

/// Read an existing blob for in-place `blob rekey` / `blob rekey-batch` (with
/// cross-platform `(dev, ino)` / `(volume_serial, file_index)` identity and
/// `nlink == 1` verification) or `blob verify`, enforcing soft/hard size limits
/// without `Vec` growth and distinguishing size-limit refusals by type.
fn read_blob_input_for_rekey_with_id(
    path: &Path,
    soft_limit: Option<u64>,
    hard_limit: u64,
    in_place: bool,
) -> std::result::Result<(PrivateCiphertextPriorSnapshot, (u64, u64)), BlobReadForRekeyError> {
    if in_place {
        let meta = fs::symlink_metadata(path)
            .map_err(|e| BlobReadForRekeyError::Other(CliError::Io(e)))?;
        if is_symlink_or_reparse_point(&meta) {
            return Err(BlobReadForRekeyError::Other(CliError::Message(format!(
                "refusing to overwrite symlink input path {} in place",
                path.display()
            ))));
        }
        if !meta.is_file() {
            return Err(BlobReadForRekeyError::Other(CliError::Message(format!(
                "input path {} must be a regular file",
                path.display()
            ))));
        }
        let (pre_id, pre_nlink) = path_identity_and_nlink_nofollow(path)
            .map_err(|e| BlobReadForRekeyError::Other(CliError::Io(e)))?;
        if pre_nlink != 1 {
            return Err(BlobReadForRekeyError::Other(CliError::Message(format!(
                "refusing in-place rekey of hardlinked input path {} (nlink = {pre_nlink}); \
                 remove extra hardlinks before rekeying in place",
                path.display()
            ))));
        }

        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            #[cfg(unix)]
            Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
                return Err(BlobReadForRekeyError::Other(CliError::Message(format!(
                    "refusing to overwrite symlink input path {} in place",
                    path.display()
                ))));
            }
            Err(err) => return Err(BlobReadForRekeyError::Other(CliError::Io(err))),
        };
        let open_meta = file
            .metadata()
            .map_err(|e| BlobReadForRekeyError::Other(CliError::Io(e)))?;
        if is_symlink_or_reparse_point(&open_meta) {
            return Err(BlobReadForRekeyError::Other(CliError::Message(format!(
                "refusing to overwrite symlink input path {} in place",
                path.display()
            ))));
        }
        if !open_meta.is_file() {
            return Err(BlobReadForRekeyError::Other(CliError::Message(format!(
                "input path {} must be a regular file",
                path.display()
            ))));
        }
        let (open_id, open_nlink) = file_identity_and_nlink(&file)
            .map_err(|e| BlobReadForRekeyError::Other(CliError::Io(e)))?;
        if open_id != pre_id {
            return Err(BlobReadForRekeyError::Other(
                CliError::ConcurrentModification {
                    path: path.display().to_string(),
                },
            ));
        }
        if open_nlink != 1 {
            return Err(BlobReadForRekeyError::Other(CliError::Message(format!(
                "refusing in-place rekey of hardlinked input path {} (nlink = {open_nlink}); \
                 remove extra hardlinks before rekeying in place",
                path.display()
            ))));
        }

        let effective_limit = soft_limit.unwrap_or(hard_limit);
        let hint_len = open_meta.len();
        if hint_len > effective_limit {
            if let Some(limit) = soft_limit {
                return Err(BlobReadForRekeyError::TooLarge(format!(
                    "input file exceeds {} MB limit (size {} bytes). \
                     Use --allow-large to override.",
                    limit / (1024 * 1024),
                    hint_len
                )));
            }
            return Err(BlobReadForRekeyError::TooLarge(format!(
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
                Err(err) => return Err(BlobReadForRekeyError::Other(CliError::Io(err))),
            }
        }
        buf.truncate(total);
        if total == cap || (buf.len() as u64) > effective_limit {
            if let Some(limit) = soft_limit {
                return Err(BlobReadForRekeyError::TooLarge(format!(
                    "input file exceeds {} MB limit (read {} bytes). \
                     Use --allow-large to override.",
                    limit / (1024 * 1024),
                    buf.len().saturating_add(1)
                )));
            }
            return Err(BlobReadForRekeyError::TooLarge(format!(
                "input file changed size during read or exceeds hard maximum size of {} bytes",
                effective_limit
            )));
        }

        return Ok((
            PrivateCiphertextPriorSnapshot {
                bytes: buf,
                #[cfg(unix)]
                identity: {
                    use std::os::unix::fs::PermissionsExt;
                    (open_id.0, open_id.1, open_meta.permissions().mode() & 0o777)
                },
                #[cfg(windows)]
                file_id: open_id,
            },
            open_id,
        ));
    }

    let bytes = read_file_bounded_zeroizing(path, soft_limit, hard_limit)
        .map_err(BlobReadForRekeyError::Other)?;
    Ok((
        PrivateCiphertextPriorSnapshot {
            bytes,
            #[cfg(unix)]
            identity: (0, 0, 0),
            #[cfg(windows)]
            file_id: (0, 0),
        },
        (0, 0),
    ))
}

fn read_blob_input_for_rekey(
    path: &Path,
    soft_limit: Option<u64>,
    hard_limit: u64,
    in_place: bool,
) -> CliResult<PrivateCiphertextPriorSnapshot> {
    read_blob_input_for_rekey_with_id(path, soft_limit, hard_limit, in_place)
        .map(|(snap, _)| snap)
        .map_err(CliError::from)
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

const MAX_STATE_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
const STATE_JOURNAL_SCHEMA: &str = "seclusor.blob-rekey-state.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchStateJournal {
    schema: String,
    operation: String,
    target_recipients: Vec<String>,
    prior_recipients: Option<Vec<String>>,
    allow_recipient_mismatch: bool,
    allow_self_lockout: bool,
    allow_large: bool,
    #[serde(default)]
    auth_tag: String,
    records: std::collections::BTreeMap<String, BatchJournalRecord>,
}

#[derive(Debug, Clone)]
struct StateJournalSnapshot {
    prior: PrivateCiphertextPriorSnapshot,
    file_id: (u64, u64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchJournalRecord {
    path: String,
    sha256_before: String,
    sha256_after: String,
    status: String,
    #[serde(default)]
    displaced_verified: bool,
    ts: String,
    opened_with: String,
    stanzas_before: usize,
    stanzas_after: usize,
    delta: Option<BatchReportDelta>,
    mode_before: Option<String>,
    mode_after: Option<String>,
    backup: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchReportDelta {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchReportFileEntry {
    pub path: String,
    pub status: String,
    pub opened_with: Option<String>,
    pub stanzas_before: Option<usize>,
    pub stanzas_after: Option<usize>,
    pub delta: Option<BatchReportDelta>,
    pub mode_before: Option<String>,
    pub mode_after: Option<String>,
    pub backup: Option<String>,
    pub sha256_before: Option<String>,
    pub sha256_after: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchReportSummary {
    pub selected: usize,
    pub affected: usize,
    pub rekeyed: usize,
    pub already_done: usize,
    pub not_openable: usize,
    pub skipped: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchReport {
    pub version: u32,
    pub mode: String,
    pub target_recipients: Vec<String>,
    pub files: Vec<BatchReportFileEntry>,
    pub summary: BatchReportSummary,
}

#[cfg(test)]
thread_local! {
    static BATCH_FAIL_AFTER_COMMITS: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
    static BATCH_ABORT_AFTER_PLANNED_JOURNAL: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_batch_fail_after_commits(limit: Option<usize>) {
    BATCH_FAIL_AFTER_COMMITS.with(|c| c.set(limit));
}

#[cfg(test)]
pub(crate) fn set_batch_abort_after_planned_journal(abort: bool) {
    BATCH_ABORT_AFTER_PLANNED_JOURNAL.with(|c| c.set(abort));
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn utc_compact_timestamp_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_utc_compact(secs)
}

fn format_utc_compact(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let rem = epoch_secs % 86_400;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;

    // Howard Hinnant's civil_from_days algorithm (proleptic Gregorian UTC).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}{m:02}{d:02}T{hour:02}{minute:02}{second:02}Z")
}

fn filename_glob_matches(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = name.chars().collect();
    let mut dp = vec![false; t.len() + 1];
    dp[0] = true;
    for &pc in &p {
        if pc == '*' {
            for j in 1..=t.len() {
                dp[j] = dp[j] || dp[j - 1];
            }
        } else {
            for j in (1..=t.len()).rev() {
                dp[j] = dp[j - 1] && (pc == '?' || pc == t[j - 1]);
            }
            dp[0] = false;
        }
    }
    dp[t.len()]
}

fn is_skipped_dir_entry_name(name: &str) -> bool {
    name.starts_with('.') || name.starts_with(".seclusor-") || name.contains(".bak-")
}

fn is_symlink_or_reparse_point(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn is_macos_system_root_symlink(cur: &Path, meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    if meta.uid() != 0 {
        return false;
    }
    let expected_target = if cur == Path::new("/var") {
        Some(Path::new("private/var"))
    } else if cur == Path::new("/tmp") {
        Some(Path::new("private/tmp"))
    } else if cur == Path::new("/etc") {
        Some(Path::new("private/etc"))
    } else {
        None
    };
    match (expected_target, fs::read_link(cur)) {
        (Some(expected), Ok(target)) => target == expected,
        _ => false,
    }
}

/// Reject any path that traverses a symlink or Windows reparse point/junction
/// in any ancestor or leaf component (whether relative or absolute).
fn reject_symlink_traversal_in_path(
    path: &Path,
    flag_label: &str,
    allow_missing_leaf: bool,
) -> CliResult<()> {
    use std::path::Component;
    let components: Vec<Component<'_>> = path.components().collect();
    if components.is_empty() {
        return Err(CliError::Message(format!(
            "invalid empty {flag_label} path"
        )));
    }

    let mut cur = if path.is_relative() {
        std::env::current_dir().map_err(CliError::Io)?
    } else {
        PathBuf::new()
    };

    for (idx, comp) in components.iter().enumerate() {
        let is_last = idx + 1 == components.len();
        match comp {
            Component::Prefix(prefix) => {
                cur.push(prefix.as_os_str());
            }
            Component::RootDir => {
                cur.push(comp.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                cur.pop();
            }
            Component::Normal(part) => {
                cur.push(part);
                let meta = match fs::symlink_metadata(&cur) {
                    Ok(m) => m,
                    Err(err)
                        if is_last
                            && allow_missing_leaf
                            && err.kind() == std::io::ErrorKind::NotFound =>
                    {
                        return Ok(());
                    }
                    Err(err) => {
                        return Err(CliError::Message(format!(
                            "cannot inspect {flag_label} path {}: {err}",
                            path.display()
                        )));
                    }
                };
                if is_symlink_or_reparse_point(&meta) {
                    #[cfg(target_os = "macos")]
                    if !is_last && is_macos_system_root_symlink(&cur, &meta) {
                        continue;
                    }
                    return Err(CliError::Message(format!(
                        "refusing symlink in {flag_label} path {}; symlinks are not followed",
                        path.display()
                    )));
                }
            }
        }
    }

    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if is_symlink_or_reparse_point(&meta) {
                return Err(CliError::Message(format!(
                    "refusing symlink in {flag_label} path {}; symlinks are not followed",
                    path.display()
                )));
            }
        }
        Err(err) if allow_missing_leaf && err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(CliError::Message(format!(
                "cannot inspect {flag_label} path {}: {err}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn reject_symlink_traversal_in_user_path(path: &Path, flag_label: &str) -> CliResult<()> {
    reject_symlink_traversal_in_path(path, flag_label, false)
}

fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn file_identity_and_nlink(file: &fs::File) -> std::io::Result<((u64, u64), u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata()?;
        Ok(((meta.dev(), meta.ino()), meta.nlink()))
    }
    #[cfg(windows)]
    {
        windows_dacl::file_identity_and_nlink(file)
    }
}

fn path_identity_and_nlink_nofollow(path: &Path) -> std::io::Result<((u64, u64), u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(path)?;
        Ok(((meta.dev(), meta.ino()), meta.nlink()))
    }
    #[cfg(windows)]
    {
        windows_dacl::path_identity_and_nlink_nofollow(path)
    }
}

#[derive(Debug, Clone)]
struct SelectedBatchFile {
    path: PathBuf,
    user_path: PathBuf,
    identity: (u64, u64),
}

fn collect_dir_candidates(
    dir: &Path,
    glob_pattern: &str,
    recursive: bool,
    out: &mut Vec<PathBuf>,
) -> CliResult<()> {
    let meta = fs::symlink_metadata(dir).map_err(CliError::Io)?;
    if is_symlink_or_reparse_point(&meta) {
        return Err(CliError::Message(format!(
            "--dir path {} must not be a symlink",
            dir.display()
        )));
    }
    if !meta.is_dir() {
        return Err(CliError::Message(format!(
            "--dir path {} is not a directory",
            dir.display()
        )));
    }
    let (pre_dir_id, _) = path_identity_and_nlink_nofollow(dir).map_err(CliError::Io)?;
    let canon_dir = fs::canonicalize(dir).map_err(CliError::Io)?;
    if canon_dir.to_str().is_none() {
        return Err(CliError::Message(format!(
            "refusing non-UTF-8 --dir path {}; batch paths must be valid UTF-8",
            canon_dir.display()
        )));
    }
    reject_symlink_traversal_in_user_path(&canon_dir, "--dir")?;
    let (canon_dir_id, _) = path_identity_and_nlink_nofollow(&canon_dir).map_err(CliError::Io)?;
    if canon_dir_id != pre_dir_id {
        return Err(CliError::ConcurrentModification {
            path: dir.display().to_string(),
        });
    }

    let mut entries: Vec<fs::DirEntry> = fs::read_dir(&canon_dir)
        .map_err(CliError::Io)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(CliError::Io)?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let file_name = entry.file_name();
        let Some(name_str) = file_name.to_str() else {
            return Err(CliError::Message(format!(
                "refusing non-UTF-8 directory entry {}; batch paths must be valid UTF-8",
                entry.path().display()
            )));
        };
        if is_skipped_dir_entry_name(name_str) {
            continue;
        }
        let path = entry.path();
        let entry_meta = fs::symlink_metadata(&path).map_err(CliError::Io)?;
        if is_symlink_or_reparse_point(&entry_meta) {
            continue;
        }
        let file_type = entry_meta.file_type();
        if file_type.is_dir() {
            if recursive {
                collect_dir_candidates(&path, glob_pattern, true, out)?;
            }
            continue;
        }
        if file_type.is_file() && filename_glob_matches(glob_pattern, name_str) {
            out.push(path);
        }
    }
    Ok(())
}

fn collect_batch_files(args: &BlobRekeyBatchArgs) -> CliResult<Vec<SelectedBatchFile>> {
    if args.files.is_empty() && args.dir.is_none() {
        return Err(CliError::Message(
            "blob rekey-batch requires at least one FILE or --dir <DIR>".to_string(),
        ));
    }
    if args.recursive && args.dir.is_none() {
        return Err(CliError::Message(
            "--recursive requires --dir <DIR>".to_string(),
        ));
    }
    if args.glob.trim().is_empty() {
        return Err(CliError::Message(
            "--glob pattern must not be empty".to_string(),
        ));
    }

    let mut raw_candidates: Vec<PathBuf> = Vec::new();
    for file in &args.files {
        if file.to_str().is_none() {
            return Err(CliError::Message(format!(
                "refusing non-UTF-8 input path {}; batch paths must be valid UTF-8",
                file.display()
            )));
        }
        reject_symlink_traversal_in_user_path(file, "input")?;
        let meta = fs::symlink_metadata(file).map_err(|err| {
            CliError::Message(format!(
                "cannot inspect input path {}: {err}",
                file.display()
            ))
        })?;
        if is_symlink_or_reparse_point(&meta) {
            return Err(CliError::Message(format!(
                "refusing symlink input path {} in blob rekey-batch; symlinks are not followed",
                file.display()
            )));
        }
        if !meta.is_file() {
            return Err(CliError::Message(format!(
                "input path {} must be a regular file",
                file.display()
            )));
        }
        raw_candidates.push(file.clone());
    }

    if let Some(dir) = &args.dir {
        if dir.to_str().is_none() {
            return Err(CliError::Message(format!(
                "refusing non-UTF-8 --dir path {}; batch paths must be valid UTF-8",
                dir.display()
            )));
        }
        reject_symlink_traversal_in_user_path(dir, "--dir")?;
        collect_dir_candidates(dir, &args.glob, args.recursive, &mut raw_candidates)?;
    }

    let mut selected_files: Vec<SelectedBatchFile> = Vec::with_capacity(raw_candidates.len());
    for candidate in raw_candidates {
        if candidate.to_str().is_none() {
            return Err(CliError::Message(format!(
                "refusing non-UTF-8 input path {}; batch paths must be valid UTF-8",
                candidate.display()
            )));
        }
        reject_symlink_traversal_in_user_path(&candidate, "input")?;
        let pre_meta = fs::symlink_metadata(&candidate).map_err(CliError::Io)?;
        if is_symlink_or_reparse_point(&pre_meta) || !pre_meta.is_file() {
            return Err(CliError::Message(format!(
                "refusing symlink or non-regular input path {}",
                candidate.display()
            )));
        }
        let (pre_id, pre_nlink) =
            path_identity_and_nlink_nofollow(&candidate).map_err(CliError::Io)?;
        if pre_nlink != 1 {
            return Err(CliError::Message(format!(
                "refusing hardlinked input path {} (nlink = {pre_nlink}); \
                 remove extra hardlinks before running blob rekey-batch",
                candidate.display()
            )));
        }
        let canon = fs::canonicalize(&candidate).map_err(CliError::Io)?;
        if canon.to_str().is_none() {
            return Err(CliError::Message(format!(
                "refusing non-UTF-8 canonical input path {}; batch paths must be valid UTF-8",
                canon.display()
            )));
        }
        reject_symlink_traversal_in_user_path(&canon, "input")?;
        let post_meta = fs::symlink_metadata(&candidate).map_err(CliError::Io)?;
        let canon_meta = fs::symlink_metadata(&canon).map_err(CliError::Io)?;
        if is_symlink_or_reparse_point(&post_meta)
            || !post_meta.is_file()
            || is_symlink_or_reparse_point(&canon_meta)
            || !canon_meta.is_file()
        {
            return Err(CliError::ConcurrentModification {
                path: candidate.display().to_string(),
            });
        }
        let (post_id, post_nlink) =
            path_identity_and_nlink_nofollow(&candidate).map_err(CliError::Io)?;
        let (canon_id, canon_nlink) =
            path_identity_and_nlink_nofollow(&canon).map_err(CliError::Io)?;
        if pre_id != post_id || pre_id != canon_id {
            return Err(CliError::ConcurrentModification {
                path: candidate.display().to_string(),
            });
        }
        if post_nlink != 1 || canon_nlink != 1 {
            return Err(CliError::Message(format!(
                "refusing hardlinked input path {} (nlink = {canon_nlink}); \
                 remove extra hardlinks before running blob rekey-batch",
                candidate.display()
            )));
        }
        selected_files.push(SelectedBatchFile {
            path: canon,
            user_path: candidate,
            identity: pre_id,
        });
    }
    selected_files.sort_by(|a, b| a.path.cmp(&b.path));
    selected_files.dedup_by(|a, b| a.path == b.path);

    // Reject distinct canonical paths that alias the same underlying inode (hardlinks).
    for i in 0..selected_files.len() {
        for j in (i + 1)..selected_files.len() {
            if selected_files[i].identity == selected_files[j].identity
                || paths_alias(&selected_files[i].path, &selected_files[j].path)?
            {
                return Err(CliError::Message(format!(
                    "selected blob path {} aliases selected blob path {} (hardlink to the same file); \
                     refusing batch rekey with hardlinked inputs",
                    selected_files[i].path.display(),
                    selected_files[j].path.display()
                )));
            }
        }
    }

    Ok(selected_files)
}

#[cfg(any(windows, test))]
const WINDOWS_SE_DACL_PRESENT: u16 = 0x0004;
#[cfg(any(windows, test))]
const WINDOWS_SE_DACL_PROTECTED: u16 = 0x1000;
#[cfg(any(windows, test))]
const WINDOWS_ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
#[cfg(any(windows, test))]
const WINDOWS_MIN_ACCESS_ALLOWED_ACE_SIZE: u16 = 12;

/// Validate an individual Windows ACE header before casting its pointer to
/// `AccessAllowedAcePrefix` or reading the embedded SID.
#[cfg(any(windows, test))]
fn validate_windows_ace_header(
    ace_type: u8,
    ace_size: u16,
    sid_len: Option<usize>,
) -> std::io::Result<()> {
    if ace_type != WINDOWS_ACCESS_ALLOWED_ACE_TYPE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private file on Windows contains unexpected ACE type in DACL",
        ));
    }
    if ace_size < WINDOWS_MIN_ACCESS_ALLOWED_ACE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private file on Windows contains truncated ACE in DACL",
        ));
    }
    if let Some(slen) = sid_len {
        if slen < 8 || 8usize.saturating_add(slen) > (ace_size as usize) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private file on Windows contains ACE with out-of-bounds SID length",
            ));
        }
    }
    Ok(())
}

/// Validate that a Windows security descriptor has an owner SID equal to the
/// current process user SID, a present and protected DACL (`SE_DACL_PROTECTED`,
/// blocking inherited parent ACEs), and at least one ACE where every ACE is an
/// `ACCESS_ALLOWED_ACE_TYPE` granting access solely to `expected_user_sid`.
#[cfg(any(windows, test))]
fn validate_windows_owner_and_dacl_sids(
    expected_user_sid: &[u8],
    file_owner_sid: Option<&[u8]>,
    control: u16,
    aces: &[(u8, &[u8])],
) -> std::io::Result<()> {
    if expected_user_sid.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "invalid empty Windows process user SID",
        ));
    }
    if file_owner_sid != Some(expected_user_sid) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private file on Windows is not owned by the current user SID",
        ));
    }
    if (control & WINDOWS_SE_DACL_PRESENT) == 0 || (control & WINDOWS_SE_DACL_PROTECTED) == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private file on Windows does not have a protected owner-only DACL",
        ));
    }
    if aces.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private file on Windows has an empty DACL",
        ));
    }
    for (ace_type, ace_sid) in aces {
        if *ace_type != WINDOWS_ACCESS_ALLOWED_ACE_TYPE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private file on Windows contains unexpected ACE type in DACL",
            ));
        }
        if *ace_sid != expected_user_sid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private file on Windows grants DACL access to a non-owner SID",
            ));
        }
    }
    Ok(())
}

#[cfg(any(windows, test))]
const WINDOWS_DANGEROUS_DIR_WRITE_MASK: u32 =
    0x0002 | 0x0004 | 0x0040 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x4000_0000 | 0x1000_0000;

/// Validate a Windows parent directory's ownership and DACL entries.
///
/// - The directory owner (`owner_is_trusted`) must be a trusted principal
///   (current user SID, `SYSTEM`, or `Administrators`); a foreign unprivileged
///   owner has implicit `WRITE_DAC` and could grant itself directory write
///   rights after inspection.
/// - Every ACE in the DACL must be a standard `ACCESS_ALLOWED_ACE_TYPE` (`0x00`);
///   non-basic ACE types (such as callback or object ACEs) are rejected
///   fail-closed.
/// - Any ACE whose access mask overlaps `WINDOWS_DANGEROUS_DIR_WRITE_MASK`
///   (`FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY`, `FILE_DELETE_CHILD`, `DELETE`,
///   `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_WRITE`, `GENERIC_ALL`) must be bound
///   to a trusted principal (`sid_is_trusted`).
#[cfg(any(windows, test))]
fn validate_windows_directory_owner_and_dacl(
    owner_is_trusted: bool,
    control: u16,
    aces: &[(u8, u32, bool)],
) -> std::io::Result<()> {
    if !owner_is_trusted {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private file directory on Windows is not owned by a trusted principal (current user, SYSTEM, or Administrators)",
        ));
    }
    if (control & WINDOWS_SE_DACL_PRESENT) == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private file directory on Windows has no DACL (unrestricted access)",
        ));
    }
    for (ace_type, mask, sid_is_trusted) in aces {
        if *ace_type != WINDOWS_ACCESS_ALLOWED_ACE_TYPE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private file directory DACL on Windows contains unsupported ACE type; only standard ACCESS_ALLOWED_ACE entries are permitted",
            ));
        }
        if (*mask & WINDOWS_DANGEROUS_DIR_WRITE_MASK) != 0 && !*sid_is_trusted {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private file directory DACL on Windows grants non-owner write, delete, or ACL-edit access",
            ));
        }
    }
    Ok(())
}

#[cfg(any(windows, test))]
#[repr(C)]
struct WindowsFileRenameInfoPrefix {
    replace_if_exists: u8,
    _pad: [u8; 7],
    root_directory: *mut core::ffi::c_void,
    file_name_length: u32,
    file_name: [u16; 1],
}

#[cfg(any(windows, test))]
const fn windows_file_rename_info_filename_offset() -> usize {
    core::mem::offset_of!(WindowsFileRenameInfoPrefix, file_name)
}

#[cfg(any(windows, test))]
fn build_windows_file_rename_info_buffer(
    root_directory: *mut core::ffi::c_void,
    leaf_wide: &[u16],
    replace_if_exists: bool,
) -> std::io::Result<(Vec<u64>, usize)> {
    if root_directory.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "FILE_RENAME_INFO requires a non-null parent RootDirectory handle",
        ));
    }
    const DOT: u16 = b'.' as u16;
    const SLASH: u16 = b'/' as u16;
    const BACKSLASH: u16 = b'\\' as u16;
    const COLON: u16 = b':' as u16;
    if leaf_wide.is_empty()
        || leaf_wide == [DOT]
        || leaf_wide == [DOT, DOT]
        || leaf_wide
            .iter()
            .any(|&ch| ch == 0 || ch == SLASH || ch == BACKSLASH || ch == COLON)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "FILE_RENAME_INFO FileName must be a relative leaf name without path separators",
        ));
    }
    let name_bytes_len = leaf_wide
        .len()
        .checked_mul(2)
        .filter(|&len| len <= u16::MAX as usize)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "leaf name too long")
        })?;
    let filename_offset = windows_file_rename_info_filename_offset();
    let total_bytes = filename_offset + name_bytes_len + 2;
    let mut aligned_buf = vec![0u64; total_bytes.div_ceil(8)];
    let buf_ptr = aligned_buf.as_mut_ptr().cast::<u8>();
    let prefix = WindowsFileRenameInfoPrefix {
        replace_if_exists: u8::from(replace_if_exists),
        _pad: [0; 7],
        root_directory,
        file_name_length: name_bytes_len as u32,
        file_name: [0u16; 1],
    };
    // SAFETY: `aligned_buf` is 8-byte aligned and holds at least `total_bytes` bytes;
    // `filename_offset` is `offset_of!(WindowsFileRenameInfoPrefix, file_name)` (20 on 64-bit).
    unsafe {
        core::ptr::write(buf_ptr.cast::<WindowsFileRenameInfoPrefix>(), prefix);
        let name_dst = buf_ptr.add(filename_offset).cast::<u16>();
        core::ptr::copy_nonoverlapping(leaf_wide.as_ptr(), name_dst, leaf_wide.len());
        core::ptr::write(name_dst.add(leaf_wide.len()), 0u16);
    }
    Ok((aligned_buf, total_bytes))
}

#[cfg(windows)]
mod windows_dacl {
    use std::fs::{self, File};
    use std::io::{self, Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;

    use zeroize::Zeroizing;

    use crate::error::{CliError, CliResult};

    use super::{
        build_windows_file_rename_info_buffer, is_symlink_or_reparse_point,
        validate_windows_ace_header, validate_windows_directory_owner_and_dacl,
        validate_windows_owner_and_dacl_sids, StateJournalSnapshot, MAX_STATE_JOURNAL_BYTES,
        WINDOWS_SE_DACL_PRESENT, WINDOWS_SE_DACL_PROTECTED,
    };

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut core::ffi::c_void,
        attributes: u32,
    }

    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[repr(C)]
    struct AclHeader {
        acl_revision: u8,
        sbz1: u8,
        acl_size: u16,
        ace_count: u16,
        sbz2: u16,
    }

    #[repr(C)]
    struct AceHeader {
        ace_type: u8,
        ace_flags: u8,
        ace_size: u16,
    }

    #[repr(C)]
    struct AccessAllowedAcePrefix {
        header: AceHeader,
        mask: u32,
        sid_start: u32,
    }

    #[repr(C)]
    struct SecurityDescriptor {
        revision: u8,
        sbz1: u8,
        control: u16,
        owner: *mut core::ffi::c_void,
        group: *mut core::ffi::c_void,
        sacl: *mut AclHeader,
        dacl: *mut AclHeader,
    }

    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut core::ffi::c_void,
        b_inherit_handle: i32,
    }

    #[repr(C)]
    struct FileTime {
        dw_low_date_time: u32,
        dw_high_date_time: u32,
    }

    #[repr(C)]
    struct ByHandleFileInformation {
        dw_file_attributes: u32,
        ft_creation_time: FileTime,
        ft_last_access_time: FileTime,
        ft_last_write_time: FileTime,
        dw_volume_serial_number: u32,
        n_file_size_high: u32,
        n_file_size_low: u32,
        n_number_of_links: u32,
        n_file_index_high: u32,
        n_file_index_low: u32,
    }

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: *mut core::ffi::c_void,
    }

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: *mut core::ffi::c_void,
        object_name: *mut UnicodeString,
        attributes: u32,
        security_descriptor: *mut core::ffi::c_void,
        security_quality_of_service: *mut core::ffi::c_void,
    }

    #[repr(C)]
    struct IoStatusBlock {
        status_or_pointer: *mut core::ffi::c_void,
        information: usize,
    }

    #[repr(C)]
    struct FileDispositionInfo {
        delete_file: u8,
    }

    struct HandleGuard(*mut core::ffi::c_void);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is an open Win32 handle owned by this guard.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    struct LocalMemGuard(*mut core::ffi::c_void);
    impl Drop for LocalMemGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was allocated by `GetSecurityInfo` via LocalAlloc.
                unsafe {
                    let _ = LocalFree(self.0);
                }
            }
        }
    }

    struct LockedJournalTargetGuard {
        file: File,
    }

    impl Drop for LockedJournalTargetGuard {
        fn drop(&mut self) {
            let mut overlapped = Overlapped {
                internal: 0,
                internal_high: 0,
                offset: u32::MAX,
                offset_high: u32::MAX,
                event: core::ptr::null_mut(),
            };
            // SAFETY: `self.file` is an open handle owned by this guard.
            unsafe {
                let _ = UnlockFileEx(self.file.as_raw_handle(), 0, 1, 0, &mut overlapped);
            }
        }
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn CloseHandle(hObject: *mut core::ffi::c_void) -> i32;
        fn LocalFree(hMem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
        fn GetFileInformationByHandle(
            hFile: *mut core::ffi::c_void,
            lpFileInformation: *mut ByHandleFileInformation,
        ) -> i32;
        fn LockFileEx(
            hFile: *mut core::ffi::c_void,
            dwFlags: u32,
            dwReserved: u32,
            nNumberOfBytesToLockLow: u32,
            nNumberOfBytesToLockHigh: u32,
            lpOverlapped: *mut Overlapped,
        ) -> i32;
        fn UnlockFileEx(
            hFile: *mut core::ffi::c_void,
            dwReserved: u32,
            nNumberOfBytesToUnlockLow: u32,
            nNumberOfBytesToUnlockHigh: u32,
            lpOverlapped: *mut Overlapped,
        ) -> i32;
        fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *mut SecurityAttributes,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: *mut core::ffi::c_void,
        ) -> *mut core::ffi::c_void;
        fn SetFileInformationByHandle(
            hFile: *mut core::ffi::c_void,
            FileInformationClass: u32,
            lpFileInformation: *const core::ffi::c_void,
            dwBufferSize: u32,
        ) -> i32;
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtCreateFile(
            FileHandle: *mut *mut core::ffi::c_void,
            DesiredAccess: u32,
            ObjectAttributes: *mut ObjectAttributes,
            IoStatusBlock: *mut IoStatusBlock,
            AllocationSize: *mut i64,
            FileAttributes: u32,
            ShareAccess: u32,
            CreateDisposition: u32,
            CreateOptions: u32,
            EaBuffer: *mut core::ffi::c_void,
            EaLength: u32,
        ) -> i32;
        fn RtlNtStatusToDosError(Status: i32) -> u32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            ProcessHandle: *mut core::ffi::c_void,
            DesiredAccess: u32,
            TokenHandle: *mut *mut core::ffi::c_void,
        ) -> i32;
        fn GetTokenInformation(
            TokenHandle: *mut core::ffi::c_void,
            TokenInformationClass: u32,
            TokenInformation: *mut core::ffi::c_void,
            TokenInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;
        fn IsValidSid(pSid: *mut core::ffi::c_void) -> i32;
        fn GetLengthSid(pSid: *mut core::ffi::c_void) -> u32;
        fn EqualSid(pSid1: *mut core::ffi::c_void, pSid2: *mut core::ffi::c_void) -> i32;
        fn IsWellKnownSid(pSid: *mut core::ffi::c_void, WellKnownSidType: u32) -> i32;
        fn InitializeAcl(pAcl: *mut AclHeader, nAclLength: u32, dwAclRevision: u32) -> i32;
        fn AddAccessAllowedAce(
            pAcl: *mut AclHeader,
            dwAceRevision: u32,
            AccessMask: u32,
            pSid: *mut core::ffi::c_void,
        ) -> i32;
        fn InitializeSecurityDescriptor(
            pSecurityDescriptor: *mut SecurityDescriptor,
            dwRevision: u32,
        ) -> i32;
        fn SetSecurityDescriptorOwner(
            pSecurityDescriptor: *mut SecurityDescriptor,
            pOwner: *mut core::ffi::c_void,
            bOwnerDefaulted: i32,
        ) -> i32;
        fn SetSecurityDescriptorDacl(
            pSecurityDescriptor: *mut SecurityDescriptor,
            bDaclPresent: i32,
            pDacl: *mut AclHeader,
            bDaclDefaulted: i32,
        ) -> i32;
        fn SetSecurityDescriptorControl(
            pSecurityDescriptor: *mut SecurityDescriptor,
            wControlBitsOfInterest: u16,
            wControlBitsToSet: u16,
        ) -> i32;
        fn SetSecurityInfo(
            handle: *mut core::ffi::c_void,
            ObjectType: u32,
            SecurityInfo: u32,
            psidOwner: *mut core::ffi::c_void,
            psidGroup: *mut core::ffi::c_void,
            pDacl: *mut AclHeader,
            pSacl: *mut AclHeader,
        ) -> u32;
        fn GetSecurityInfo(
            handle: *mut core::ffi::c_void,
            ObjectType: u32,
            SecurityInfo: u32,
            ppsidOwner: *mut *mut core::ffi::c_void,
            ppsidGroup: *mut *mut core::ffi::c_void,
            ppDacl: *mut *mut AclHeader,
            ppSacl: *mut *mut AclHeader,
            ppSecurityDescriptor: *mut *mut core::ffi::c_void,
        ) -> u32;
        fn GetSecurityDescriptorControl(
            pSecurityDescriptor: *mut core::ffi::c_void,
            pControl: *mut u16,
            lpdwRevision: *mut u32,
        ) -> i32;
        fn GetAce(pAcl: *mut AclHeader, dwAceIndex: u32, pAce: *mut *mut AceHeader) -> i32;
    }

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;
    const ACL_REVISION: u32 = 2;
    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
    const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const DELETE: u32 = 0x0001_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_LIST_DIRECTORY: u32 = 0x0001;
    const FILE_TRAVERSE: u32 = 0x0020;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_RENAME_INFO_CLASS: u32 = 3;
    const FILE_DISPOSITION_INFO_CLASS: u32 = 4;
    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const CREATE_NEW: u32 = 1;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
    const SE_FILE_OBJECT: u32 = 1;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
    const WIN_CREATOR_OWNER_SID: u32 = 3;
    const WIN_LOCAL_SYSTEM_SID: u32 = 22;
    const WIN_BUILTIN_ADMINISTRATORS_SID: u32 = 26;

    pub(super) fn file_identity_and_nlink(file: &File) -> io::Result<((u64, u64), u64)> {
        let mut info = ByHandleFileInformation {
            dw_file_attributes: 0,
            ft_creation_time: FileTime {
                dw_low_date_time: 0,
                dw_high_date_time: 0,
            },
            ft_last_access_time: FileTime {
                dw_low_date_time: 0,
                dw_high_date_time: 0,
            },
            ft_last_write_time: FileTime {
                dw_low_date_time: 0,
                dw_high_date_time: 0,
            },
            dw_volume_serial_number: 0,
            n_file_size_high: 0,
            n_file_size_low: 0,
            n_number_of_links: 0,
            n_file_index_high: 0,
            n_file_index_low: 0,
        };
        // SAFETY: `file` is a valid open file handle and `info` is stack-allocated.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let vol = info.dw_volume_serial_number as u64;
        let idx = ((info.n_file_index_high as u64) << 32) | (info.n_file_index_low as u64);
        Ok(((vol, idx), info.n_number_of_links as u64))
    }

    pub(super) fn path_identity_and_nlink_nofollow(path: &Path) -> io::Result<((u64, u64), u64)> {
        use std::os::windows::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        let meta = file.metadata()?;
        if is_symlink_or_reparse_point(&meta) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refusing symlink or reparse point",
            ));
        }
        file_identity_and_nlink(&file)
    }

    fn encode_wide_null(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(core::iter::once(0))
            .collect()
    }

    fn current_process_user_token_buf() -> io::Result<Vec<u64>> {
        let mut token: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: `GetCurrentProcess()` returns a pseudo-handle; `token` is valid on success.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let _token_guard = HandleGuard(token);

        let mut needed: u32 = 0;
        // SAFETY: probing required buffer size with null buffer and zero length.
        unsafe {
            let _ = GetTokenInformation(
                token,
                TOKEN_USER_CLASS,
                core::ptr::null_mut(),
                0,
                &mut needed,
            );
        }
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        let byte_len = (buf.len() * 8) as u32;
        // SAFETY: `buf` is 8-byte aligned and holds at least `needed` bytes.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TOKEN_USER_CLASS,
                buf.as_mut_ptr().cast(),
                byte_len,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let token_user = buf.as_ptr().cast::<TokenUser>();
        // SAFETY: `GetTokenInformation` initialized `TokenUser` inside `buf`.
        let sid = unsafe { (*token_user).user.sid };
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid Windows process user SID",
            ));
        }
        Ok(buf)
    }

    fn build_owner_only_acl_buf(user_sid: *mut core::ffi::c_void) -> io::Result<Vec<u64>> {
        // SAFETY: `user_sid` was validated by `IsValidSid`.
        let sid_len = unsafe { GetLengthSid(user_sid) } as usize;
        let acl_bytes_len = (core::mem::size_of::<AclHeader>() + 8 + sid_len + 3) & !3;
        let mut acl_buf = vec![0u64; acl_bytes_len.div_ceil(8)];
        let acl_ptr = acl_buf.as_mut_ptr().cast::<AclHeader>();

        // SAFETY: `acl_buf` has at least `acl_bytes_len` bytes and is 8-byte aligned.
        if unsafe { InitializeAcl(acl_ptr, acl_bytes_len as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `acl_ptr` is initialized and `user_sid` is valid.
        if unsafe { AddAccessAllowedAce(acl_ptr, ACL_REVISION, FILE_ALL_ACCESS, user_sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(acl_buf)
    }

    unsafe fn sid_bytes<'a>(sid: *mut core::ffi::c_void) -> Option<&'a [u8]> {
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return None;
        }
        let len = unsafe { GetLengthSid(sid) } as usize;
        if len == 0 {
            return None;
        }
        Some(unsafe { core::slice::from_raw_parts(sid.cast::<u8>(), len) })
    }

    pub(super) fn validate_directory_handle_dacl(dir_file: &File) -> io::Result<()> {
        let dir_meta = dir_file.metadata()?;
        if is_symlink_or_reparse_point(&dir_meta) || !dir_meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private file parent directory on Windows must be a non-reparse directory",
            ));
        }

        let user_buf = current_process_user_token_buf()?;
        let token_user = user_buf.as_ptr().cast::<TokenUser>();
        // SAFETY: `user_buf` holds a valid `TokenUser`.
        let user_sid = unsafe { (*token_user).user.sid };

        let mut owner_sid: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut dacl: *mut AclHeader = core::ptr::null_mut();
        let mut sd: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: `dir_file` is an open directory handle; `sd` is freed by `LocalMemGuard`.
        let rc = unsafe {
            GetSecurityInfo(
                dir_file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner_sid,
                core::ptr::null_mut(),
                &mut dacl,
                core::ptr::null_mut(),
                &mut sd,
            )
        };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let _sd_guard = LocalMemGuard(sd);

        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        // SAFETY: `sd` was returned by `GetSecurityInfo`.
        if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if (control & WINDOWS_SE_DACL_PRESENT) == 0 || dacl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private file directory on Windows has no DACL (unrestricted access)",
            ));
        }
        let owner_is_trusted = !owner_sid.is_null()
            && unsafe {
                IsValidSid(owner_sid) != 0
                    && (EqualSid(owner_sid, user_sid) != 0
                        || IsWellKnownSid(owner_sid, WIN_LOCAL_SYSTEM_SID) != 0
                        || IsWellKnownSid(owner_sid, WIN_BUILTIN_ADMINISTRATORS_SID) != 0)
            };

        // SAFETY: `dacl` is non-null and points into `sd`.
        let ace_count = unsafe { (*dacl).ace_count };
        let mut parsed_aces: Vec<(u8, u32, bool)> = Vec::with_capacity(ace_count as usize);
        for idx in 0..(ace_count as u32) {
            let mut ace_ptr: *mut AceHeader = core::ptr::null_mut();
            // SAFETY: `dacl` is valid and `idx < ace_count`.
            if unsafe { GetAce(dacl, idx, &mut ace_ptr) } == 0 || ace_ptr.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `ace_ptr` points to a valid `AceHeader`.
            let ace_type = unsafe { (*ace_ptr).ace_type };
            let ace_size = unsafe { (*ace_ptr).ace_size };
            validate_windows_ace_header(ace_type, ace_size, None)?;
            let allowed_ptr = ace_ptr.cast::<AccessAllowedAcePrefix>();
            // SAFETY: `ace_size >= 12` and `ace_type == WINDOWS_ACCESS_ALLOWED_ACE_TYPE` were validated above.
            let mask = unsafe { (*allowed_ptr).mask };
            let ace_sid = unsafe { core::ptr::addr_of_mut!((*allowed_ptr).sid_start).cast() };
            if unsafe { IsValidSid(ace_sid) } == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private file directory on Windows contains an invalid SID in DACL",
                ));
            }
            let sid_len = unsafe { GetLengthSid(ace_sid) } as usize;
            validate_windows_ace_header(ace_type, ace_size, Some(sid_len))?;
            let is_trusted = unsafe {
                EqualSid(ace_sid, user_sid) != 0
                    || IsWellKnownSid(ace_sid, WIN_LOCAL_SYSTEM_SID) != 0
                    || IsWellKnownSid(ace_sid, WIN_BUILTIN_ADMINISTRATORS_SID) != 0
                    || IsWellKnownSid(ace_sid, WIN_CREATOR_OWNER_SID) != 0
            };
            parsed_aces.push((ace_type, mask, is_trusted));
        }
        validate_windows_directory_owner_and_dacl(owner_is_trusted, control, &parsed_aces)
    }

    /// Reject a Windows parent directory whose DACL grants write, file-add,
    /// child-delete, or ACL/owner-modification access to any principal other
    /// than the current user SID, `SYSTEM`, `Administrators`, or `CREATOR OWNER`.
    pub(super) fn reject_writable_directory_dacl(dir_path: &Path) -> io::Result<()> {
        use std::os::windows::fs::OpenOptionsExt;
        let dir_file = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir_path)?;
        validate_directory_handle_dacl(&dir_file)
    }

    /// Create a brand-new private file atomically bound to a protected
    /// current-user-only security descriptor (`owner = user_sid`,
    /// `SE_DACL_PROTECTED`, single `FILE_ALL_ACCESS` ACE for `user_sid`) and
    /// `dwShareMode = 0` (exclusive) at `CreateFileW` time so no other user can
    /// open or retain a handle during creation.
    pub(super) fn create_new_private_file(path: &Path) -> io::Result<File> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        reject_writable_directory_dacl(parent)?;

        let user_buf = current_process_user_token_buf()?;
        let token_user = user_buf.as_ptr().cast::<TokenUser>();
        // SAFETY: `user_buf` lives for this function and holds a valid `TokenUser`.
        let user_sid = unsafe { (*token_user).user.sid };
        let mut acl_buf = build_owner_only_acl_buf(user_sid)?;
        let acl_ptr = acl_buf.as_mut_ptr().cast::<AclHeader>();

        let mut sd = SecurityDescriptor {
            revision: 0,
            sbz1: 0,
            control: 0,
            owner: core::ptr::null_mut(),
            group: core::ptr::null_mut(),
            sacl: core::ptr::null_mut(),
            dacl: core::ptr::null_mut(),
        };
        // SAFETY: `sd` is stack-allocated and lives across `CreateFileW`.
        if unsafe { InitializeSecurityDescriptor(&mut sd, SECURITY_DESCRIPTOR_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `sd` is initialized and `user_sid` is valid.
        if unsafe { SetSecurityDescriptorOwner(&mut sd, user_sid, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `sd` is initialized and `acl_ptr` is valid.
        if unsafe { SetSecurityDescriptorDacl(&mut sd, 1, acl_ptr, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: mark DACL as protected (`SE_DACL_PROTECTED`) so parent ACEs are not inherited.
        if unsafe {
            SetSecurityDescriptorControl(
                &mut sd,
                WINDOWS_SE_DACL_PROTECTED,
                WINDOWS_SE_DACL_PROTECTED,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut sa = SecurityAttributes {
            n_length: core::mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: (&mut sd as *mut SecurityDescriptor).cast(),
            b_inherit_handle: 0,
        };
        let wide_path = encode_wide_null(path);
        // SAFETY: `wide_path` is null-terminated and `sa` points to `sd` which is live.
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER,
                0, // dwShareMode = 0 (exclusive; no concurrent handles permitted)
                &mut sa,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                core::ptr::null_mut(),
            )
        };
        let invalid = (-1isize) as *mut core::ffi::c_void;
        if handle.is_null() || handle == invalid {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `handle` is a valid newly opened Win32 file handle.
        let file = unsafe { File::from_raw_handle(handle) };
        if let Err(err) =
            restrict_private_file_dacl(&file).and_then(|()| verify_private_file_dacl(&file))
        {
            delete_open_handle_on_close(&file);
            drop(file);
            return Err(err);
        }
        Ok(file)
    }

    pub(super) fn restrict_private_file_dacl(file: &File) -> io::Result<()> {
        let user_buf = current_process_user_token_buf()?;
        let token_user = user_buf.as_ptr().cast::<TokenUser>();
        // SAFETY: `user_buf` lives for this function and holds a valid `TokenUser`.
        let user_sid = unsafe { (*token_user).user.sid };
        let mut acl_buf = build_owner_only_acl_buf(user_sid)?;
        let acl_ptr = acl_buf.as_mut_ptr().cast::<AclHeader>();

        // Attempt to set both owner SID and protected owner-only DACL first; if
        // setting owner is not permitted because the handle was opened with
        // WRITE_DAC only, fall back to setting the protected DACL and require
        // `verify_private_file_dacl` to confirm `owner_sid == user_sid`.
        // SAFETY: `file` is an open file handle and `user_sid` / `acl_ptr` are valid.
        let rc_owner = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                user_sid,
                core::ptr::null_mut(),
                acl_ptr,
                core::ptr::null_mut(),
            )
        };
        if rc_owner != 0 {
            // SAFETY: `file` is an open file handle and `acl_ptr` is a valid ACL.
            let rc_dacl = unsafe {
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    acl_ptr,
                    core::ptr::null_mut(),
                )
            };
            if rc_dacl != 0 {
                return Err(io::Error::from_raw_os_error(rc_dacl as i32));
            }
        }
        verify_private_file_dacl(file)
    }

    pub(super) fn verify_private_file_dacl(file: &File) -> io::Result<()> {
        let user_buf = current_process_user_token_buf()?;
        let token_user = user_buf.as_ptr().cast::<TokenUser>();
        // SAFETY: `user_buf` lives for this function and holds a valid `TokenUser`.
        let user_sid = unsafe { (*token_user).user.sid };
        let expected_user_bytes = unsafe { sid_bytes(user_sid) }.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid Windows process user SID",
            )
        })?;

        let mut owner_sid: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut dacl: *mut AclHeader = core::ptr::null_mut();
        let mut sd: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: `file` is an open file handle; `sd` is freed by `LocalMemGuard`.
        let rc = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner_sid,
                core::ptr::null_mut(),
                &mut dacl,
                core::ptr::null_mut(),
                &mut sd,
            )
        };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let _sd_guard = LocalMemGuard(sd);

        let file_owner_bytes = unsafe { sid_bytes(owner_sid) };
        if file_owner_bytes.is_none() || unsafe { EqualSid(owner_sid, user_sid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private file on Windows is not owned by the current user SID",
            ));
        }

        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        // SAFETY: `sd` was returned by `GetSecurityInfo`.
        if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if (control & WINDOWS_SE_DACL_PRESENT) == 0
            || (control & WINDOWS_SE_DACL_PROTECTED) == 0
            || dacl.is_null()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private file on Windows does not have a protected owner-only DACL",
            ));
        }

        // SAFETY: `dacl` is non-null and points into `sd`.
        let ace_count = unsafe { (*dacl).ace_count };
        let mut aces: Vec<(u8, &[u8])> = Vec::with_capacity(ace_count as usize);
        for idx in 0..(ace_count as u32) {
            let mut ace_ptr: *mut AceHeader = core::ptr::null_mut();
            // SAFETY: `dacl` is valid and `idx < ace_count`.
            if unsafe { GetAce(dacl, idx, &mut ace_ptr) } == 0 || ace_ptr.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `ace_ptr` points to a valid `AceHeader` inside `dacl`.
            // Validate `ace_type` and `ace_size >= 12` BEFORE casting to `AccessAllowedAcePrefix`.
            let ace_type = unsafe { (*ace_ptr).ace_type };
            let ace_size = unsafe { (*ace_ptr).ace_size };
            validate_windows_ace_header(ace_type, ace_size, None)?;

            let allowed_ptr = ace_ptr.cast::<AccessAllowedAcePrefix>();
            // SAFETY: `ace_type == ACCESS_ALLOWED_ACE_TYPE` and `ace_size >= 12` were validated above.
            let ace_sid = unsafe { core::ptr::addr_of_mut!((*allowed_ptr).sid_start).cast() };
            if unsafe { IsValidSid(ace_sid) } == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private file on Windows contains invalid SID in DACL",
                ));
            }
            let sid_len = unsafe { GetLengthSid(ace_sid) } as usize;
            validate_windows_ace_header(ace_type, ace_size, Some(sid_len))?;
            let ace_sid_slice = unsafe { sid_bytes(ace_sid) }.unwrap_or(&[]);
            if unsafe { EqualSid(ace_sid, user_sid) } == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private file on Windows grants DACL access to a non-owner SID",
                ));
            }
            aces.push((ace_type, ace_sid_slice));
        }
        validate_windows_owner_and_dacl_sids(expected_user_bytes, file_owner_bytes, control, &aces)
    }

    fn lock_target_handle(file: File) -> CliResult<LockedJournalTargetGuard> {
        let mut overlapped = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: u32::MAX,
            offset_high: u32::MAX,
            event: core::ptr::null_mut(),
        };
        // SAFETY: `file` is a valid open handle and `overlapped` lives for the call.
        let ok = unsafe {
            LockFileEx(
                file.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlapped,
            )
        };
        if ok == 0 {
            return Err(CliError::ConcurrentModification {
                path: "<state-journal>".to_string(),
            });
        }
        Ok(LockedJournalTargetGuard { file })
    }

    /// Atomically write `--state` on Windows:
    /// - Validates parent directory DACL (`open_dir_nofollow_anchored_windows`).
    /// - Recovers any interrupted prior displacement (`.seclusor-displaced-<leaf>`).
    /// - Creates the temporary file via `create_new_private_file` (`CreateFileW`
    ///   with `CREATE_NEW`, `dwShareMode = 0`, `DELETE` access, and protected
    ///   owner-only `SECURITY_ATTRIBUTES`) and keeps `temp_file` open (`ShareAccess = 0`)
    ///   across publication so staged-source substitution is rejected by the kernel.
    /// - When replacing an existing journal, opens `leaf_name` relative to `parent_dir`
    ///   with `GENERIC_READ | DELETE` and `ShareAccess = 0` (excluding ALL concurrent
    ///   opens and preventing any other process from renaming or deleting `leaf_name`
    ///   because `FILE_SHARE_DELETE` is omitted), verifies `(volume_serial, file_index)`
    ///   + `nlink == 1` + owner/DACL + bounded content, displaces `guard.file` by handle
    ///   to `.seclusor-displaced-<leaf>` (`ReplaceIfExists = false`), publishes `temp_file`
    ///   by handle to `leaf_name` (`ReplaceIfExists = false`), and deletes the displaced
    ///   `guard.file` by handle (`delete_open_handle_on_close`).
    pub(super) fn atomic_write_private_journal(
        state_path: &Path,
        content: &[u8],
        prior: Option<&StateJournalSnapshot>,
    ) -> CliResult<()> {
        let parent = state_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let leaf_os = state_path
            .file_name()
            .filter(|n| !n.is_empty() && *n != "." && *n != "..")
            .ok_or_else(|| {
                CliError::Message(format!(
                    "--state journal path {} must name a regular file",
                    state_path.display()
                ))
            })?;
        let parent_dir = open_dir_nofollow_anchored_windows(parent, "--state")?;
        recover_displaced_windows_entry_in_dir(&parent_dir, leaf_os).map_err(CliError::Io)?;

        if prior.is_none() && stat_relative_nofollow(&parent_dir, leaf_os).is_ok() {
            return Err(CliError::Message(format!(
                "refusing to create {}: path already exists",
                state_path.display()
            )));
        }

        let pid = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut temp_name = None;
        let mut temp_path = None;
        let mut temp_file = None;
        for attempt in 0..64u32 {
            let candidate_name =
                std::ffi::OsString::from(format!(".seclusor-state-{pid}-{ts}-{attempt}.tmp"));
            let candidate = parent.join(&candidate_name);
            match create_new_private_file(&candidate) {
                Ok(f) => {
                    temp_name = Some(candidate_name);
                    temp_path = Some(candidate);
                    temp_file = Some(f);
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(CliError::Io(err)),
            }
        }
        let temp_name = temp_name.ok_or_else(|| {
            CliError::Message("failed to allocate unique temporary state journal path".to_string())
        })?;
        let temp_path = temp_path.expect("temp_path set with temp_name");
        let mut temp_file = temp_file.expect("temp_file set with temp_path");

        let (temp_id, temp_nlink) = match file_identity_and_nlink(&temp_file) {
            Ok(v) => v,
            Err(err) => {
                delete_open_handle_on_close(&temp_file);
                drop(temp_file);
                return Err(CliError::Io(err));
            }
        };
        if temp_nlink != 1 {
            delete_open_handle_on_close(&temp_file);
            drop(temp_file);
            return Err(CliError::ConcurrentModification {
                path: temp_path.display().to_string(),
            });
        }

        if let Err(err) = temp_file
            .write_all(content)
            .and_then(|()| temp_file.sync_all())
            .and_then(|()| verify_private_file_dacl(&temp_file))
        {
            delete_open_handle_on_close(&temp_file);
            drop(temp_file);
            return Err(CliError::Io(err));
        }

        // Keep `temp_file` open (`dwShareMode = 0`, `DELETE` access) across CAS verification
        // and handle-bound publication so no process can open, modify, or substitute the
        // staged temporary journal.
        let mut cas_guard = if let Some(expected_snap) = prior {
            // Open `leaf_os` directly relative to `parent_dir` with `GENERIC_READ | DELETE`
            // and `ShareAccess = 0` (excluding `FILE_SHARE_DELETE` as well as read/write),
            // so the Windows kernel blocks any concurrent open, rename, or deletion of
            // `leaf_os` with `STATUS_SHARING_VIOLATION` while `guard` is held.
            let existing = match open_relative_entry_nofollow(
                &parent_dir,
                leaf_os,
                GENERIC_READ | DELETE,
                0,
                FILE_OPEN,
                false,
            ) {
                Ok(f) => f,
                Err(err) => {
                    delete_open_handle_on_close(&temp_file);
                    drop(temp_file);
                    if err.kind() == io::ErrorKind::NotFound
                        || err.kind() == io::ErrorKind::InvalidInput
                    {
                        return Err(CliError::ConcurrentModification {
                            path: state_path.display().to_string(),
                        });
                    }
                    return Err(CliError::Io(err));
                }
            };
            let mut guard = match lock_target_handle(existing) {
                Ok(g) => g,
                Err(_) => {
                    delete_open_handle_on_close(&temp_file);
                    drop(temp_file);
                    return Err(CliError::ConcurrentModification {
                        path: state_path.display().to_string(),
                    });
                }
            };

            let check_res: CliResult<()> = (|| {
                let open_meta = guard.file.metadata().map_err(CliError::Io)?;
                if !open_meta.is_file() || is_symlink_or_reparse_point(&open_meta) {
                    return Err(CliError::ConcurrentModification {
                        path: state_path.display().to_string(),
                    });
                }
                let (open_id, open_nlink) =
                    file_identity_and_nlink(&guard.file).map_err(CliError::Io)?;
                let (rel_id, rel_nlink) =
                    stat_relative_nofollow(&parent_dir, leaf_os).map_err(CliError::Io)?;
                if open_id != expected_snap.file_id
                    || rel_id != expected_snap.file_id
                    || open_nlink != 1
                    || rel_nlink != 1
                {
                    return Err(CliError::ConcurrentModification {
                        path: state_path.display().to_string(),
                    });
                }
                verify_private_file_dacl(&guard.file).map_err(CliError::Io)?;

                let expected_bytes = expected_snap.prior.bytes.as_slice();
                if open_meta.len() > MAX_STATE_JOURNAL_BYTES
                    || open_meta.len() != expected_bytes.len() as u64
                {
                    return Err(CliError::ConcurrentModification {
                        path: state_path.display().to_string(),
                    });
                }
                let cap = expected_bytes
                    .len()
                    .min(MAX_STATE_JOURNAL_BYTES as usize)
                    .saturating_add(1);
                let mut current_bytes = Zeroizing::new(vec![0u8; cap]);
                let mut total = 0usize;
                while total < current_bytes.len() {
                    match guard.file.read(&mut current_bytes[total..]) {
                        Ok(0) => break,
                        Ok(n) => total += n,
                        Err(err) => return Err(CliError::Io(err)),
                    }
                }
                if total == cap || &current_bytes[..total] != expected_bytes {
                    return Err(CliError::ConcurrentModification {
                        path: state_path.display().to_string(),
                    });
                }
                Ok(())
            })();
            if let Err(err) = check_res {
                drop(guard);
                delete_open_handle_on_close(&temp_file);
                drop(temp_file);
                return Err(err);
            }
            Some(guard)
        } else {
            None
        };

        let (still_temp_id, still_temp_nlink) = match file_identity_and_nlink(&temp_file) {
            Ok(v) => v,
            Err(err) => {
                drop(cas_guard);
                delete_open_handle_on_close(&temp_file);
                drop(temp_file);
                return Err(CliError::Io(err));
            }
        };
        let (rel_temp_id, rel_temp_nlink) = match stat_relative_nofollow(&parent_dir, &temp_name) {
            Ok(v) => v,
            Err(_) => {
                drop(cas_guard);
                delete_open_handle_on_close(&temp_file);
                drop(temp_file);
                return Err(CliError::ConcurrentModification {
                    path: temp_path.display().to_string(),
                });
            }
        };
        if still_temp_id != temp_id
            || still_temp_nlink != 1
            || rel_temp_id != temp_id
            || rel_temp_nlink != 1
        {
            drop(cas_guard);
            delete_open_handle_on_close(&temp_file);
            drop(temp_file);
            return Err(CliError::ConcurrentModification {
                path: temp_path.display().to_string(),
            });
        }

        if let Some(ref mut guard) = cas_guard {
            let displaced_name = displaced_windows_leaf_name(leaf_os);
            if let Err(err) =
                rename_open_handle_in_dir(&guard.file, &parent_dir, &displaced_name, false)
            {
                drop(cas_guard);
                delete_open_handle_on_close(&temp_file);
                drop(temp_file);
                if err.kind() == io::ErrorKind::AlreadyExists {
                    return Err(CliError::ConcurrentModification {
                        path: state_path.display().to_string(),
                    });
                }
                return Err(CliError::Io(err));
            }
            if let Err(err) = rename_open_handle_in_dir(&temp_file, &parent_dir, leaf_os, false) {
                let _ = rename_open_handle_in_dir(&guard.file, &parent_dir, leaf_os, false);
                drop(cas_guard);
                delete_open_handle_on_close(&temp_file);
                drop(temp_file);
                if err.kind() == io::ErrorKind::AlreadyExists {
                    return Err(CliError::ConcurrentModification {
                        path: state_path.display().to_string(),
                    });
                }
                return Err(CliError::Io(err));
            }
            delete_open_handle_on_close(&guard.file);
        } else if let Err(err) = rename_open_handle_in_dir(&temp_file, &parent_dir, leaf_os, false)
        {
            delete_open_handle_on_close(&temp_file);
            drop(temp_file);
            if err.kind() == io::ErrorKind::AlreadyExists {
                return Err(CliError::ConcurrentModification {
                    path: state_path.display().to_string(),
                });
            }
            return Err(CliError::Io(err));
        }

        let (post_handle_id, post_handle_nlink) =
            file_identity_and_nlink(&temp_file).map_err(CliError::Io)?;
        drop(temp_file);
        drop(cas_guard);

        let (published_id, published_nlink) =
            stat_relative_nofollow(&parent_dir, leaf_os).map_err(CliError::Io)?;
        if post_handle_id != temp_id
            || post_handle_nlink != 1
            || published_id != temp_id
            || published_nlink != 1
        {
            return Err(CliError::ConcurrentModification {
                path: state_path.display().to_string(),
            });
        }
        Ok(())
    }

    /// Open or create a child entry (`leaf_name`) directly relative to an open
    /// `parent_dir` handle via `NtCreateFile` with `FILE_OPEN_REPARSE_POINT`
    /// so the Windows kernel resolves `leaf_name` inside `parent_dir` without
    /// re-resolving or traversing any ancestor directory path.
    pub(super) fn open_relative_entry_nofollow(
        parent_dir: &File,
        leaf_name: &std::ffi::OsStr,
        desired_access: u32,
        share_access: u32,
        create_disposition: u32,
        is_directory: bool,
    ) -> io::Result<File> {
        let mut wide: Vec<u16> = leaf_name.encode_wide().collect();
        const DOT: u16 = b'.' as u16;
        const SLASH: u16 = b'/' as u16;
        const BACKSLASH: u16 = b'\\' as u16;
        const COLON: u16 = b':' as u16;
        if wide.is_empty()
            || wide == [DOT]
            || wide == [DOT, DOT]
            || wide
                .iter()
                .any(|&ch| ch == 0 || ch == SLASH || ch == BACKSLASH || ch == COLON)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "handle-relative Windows open requires a single leaf name without path separators",
            ));
        }
        let byte_len = wide
            .len()
            .checked_mul(2)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "leaf name too long"))?;
        let mut ustr = UnicodeString {
            length: byte_len,
            maximum_length: byte_len,
            buffer: wide.as_mut_ptr(),
        };
        let mut oa = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: parent_dir.as_raw_handle(),
            object_name: &mut ustr,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: core::ptr::null_mut(),
            security_quality_of_service: core::ptr::null_mut(),
        };
        let mut iosb = IoStatusBlock {
            status_or_pointer: core::ptr::null_mut(),
            information: 0,
        };
        let create_options = FILE_OPEN_REPARSE_POINT
            | FILE_SYNCHRONOUS_IO_NONALERT
            | if is_directory {
                FILE_DIRECTORY_FILE
            } else {
                FILE_NON_DIRECTORY_FILE
            };
        let mut handle: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: `parent_dir` is an open directory handle, `ustr` and `oa` are
        // stack-allocated and valid for the duration of `NtCreateFile`.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                desired_access | SYNCHRONIZE,
                &mut oa,
                &mut iosb,
                core::ptr::null_mut(),
                FILE_ATTRIBUTE_NORMAL,
                share_access,
                create_disposition,
                create_options,
                core::ptr::null_mut(),
                0,
            )
        };
        if status < 0 {
            // SAFETY: `RtlNtStatusToDosError` converts any NTSTATUS to a Win32 error code.
            let win_err = unsafe { RtlNtStatusToDosError(status) } as i32;
            return Err(io::Error::from_raw_os_error(win_err));
        }
        // SAFETY: `handle` is a newly opened kernel file/directory handle.
        let file = unsafe { File::from_raw_handle(handle) };
        let meta = file.metadata()?;
        if is_symlink_or_reparse_point(&meta) {
            if create_disposition == FILE_CREATE {
                delete_open_handle_on_close(&file);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing symlink or reparse point",
            ));
        }
        Ok(file)
    }

    pub(super) fn stat_relative_nofollow(
        parent_dir: &File,
        leaf_name: &std::ffi::OsStr,
    ) -> io::Result<((u64, u64), u64)> {
        let f = open_relative_entry_nofollow(
            parent_dir,
            leaf_name,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            false,
        )?;
        file_identity_and_nlink(&f)
    }

    pub(super) fn delete_open_handle_on_close(file: &File) {
        let info = FileDispositionInfo { delete_file: 1 };
        // SAFETY: `file` is an open handle with `DELETE` access and `info` is valid.
        unsafe {
            let _ = SetFileInformationByHandle(
                file.as_raw_handle(),
                FILE_DISPOSITION_INFO_CLASS,
                (&info as *const FileDispositionInfo).cast(),
                core::mem::size_of::<FileDispositionInfo>() as u32,
            );
        }
    }

    pub(super) fn displaced_windows_leaf_name(leaf_name: &std::ffi::OsStr) -> std::ffi::OsString {
        let mut s = std::ffi::OsString::from(".seclusor-displaced-");
        s.push(leaf_name);
        s
    }

    /// If a prior Windows handle-bound replacement crashed after displacing `leaf_name`
    /// to `.seclusor-displaced-<leaf_name>` before publishing the new file to `leaf_name`,
    /// automatically restore `.seclusor-displaced-<leaf_name>` to `leaf_name` by handle.
    pub(super) fn recover_displaced_windows_entry_in_dir(
        parent_dir: &File,
        leaf_name: &std::ffi::OsStr,
    ) -> io::Result<()> {
        let displaced_name = displaced_windows_leaf_name(leaf_name);
        match open_relative_entry_nofollow(
            parent_dir,
            &displaced_name,
            GENERIC_READ | DELETE,
            0,
            FILE_OPEN,
            false,
        ) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
            Ok(displaced_file) => {
                if stat_relative_nofollow(parent_dir, leaf_name).is_err() {
                    rename_open_handle_in_dir(&displaced_file, parent_dir, leaf_name, false)?;
                }
                Ok(())
            }
        }
    }

    pub(super) fn open_dir_nofollow_anchored_windows(
        dir_path: &Path,
        flag_label: &str,
    ) -> CliResult<File> {
        use std::os::windows::fs::OpenOptionsExt;
        use std::path::{Component, PathBuf};

        let base_path = if dir_path.is_relative() {
            let cwd = std::env::current_dir().map_err(CliError::Io)?;
            super::reject_symlink_traversal_in_user_path(&cwd, flag_label)?;
            cwd.join(dir_path)
        } else {
            dir_path.to_path_buf()
        };

        let mut root_path = PathBuf::new();
        let mut normal_parts = Vec::new();
        for comp in base_path.components() {
            match comp {
                Component::Prefix(p) => root_path.push(p.as_os_str()),
                Component::RootDir => root_path.push(comp.as_os_str()),
                Component::CurDir => {}
                Component::ParentDir => {
                    normal_parts.pop();
                }
                Component::Normal(part) => normal_parts.push(part.to_os_string()),
            }
        }
        if root_path.as_os_str().is_empty() {
            root_path.push(".");
        }

        let dir_access =
            FILE_READ_ATTRIBUTES | READ_CONTROL | FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE;
        let mut cur_dir = fs::OpenOptions::new()
            .access_mode(dir_access)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&root_path)
            .map_err(CliError::Io)?;
        validate_directory_handle_dacl(&cur_dir).map_err(CliError::Io)?;

        for part in normal_parts {
            cur_dir = open_relative_entry_nofollow(
                &cur_dir,
                &part,
                dir_access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                true,
            )
            .map_err(|err| {
                if err.kind() == io::ErrorKind::InvalidInput {
                    CliError::Message(format!(
                        "refusing symlink or reparse point in {flag_label} path {}",
                        dir_path.display()
                    ))
                } else {
                    CliError::Io(err)
                }
            })?;
            validate_directory_handle_dacl(&cur_dir).map_err(CliError::Io)?;
        }
        Ok(cur_dir)
    }

    /// Rename an open `source_file` handle (`DELETE` access) directly to
    /// `leaf_name` inside `parent_dir` via `SetFileInformationByHandle(FileRenameInfo)`
    /// with `RootDirectory = parent_dir.as_raw_handle()` so neither the source
    /// nor the destination ancestor path is ever re-resolved by path.
    fn rename_open_handle_in_dir(
        source_file: &File,
        parent_dir: &File,
        leaf_name: &std::ffi::OsStr,
        replace_if_exists: bool,
    ) -> io::Result<()> {
        let wide_leaf: Vec<u16> = leaf_name.encode_wide().collect();
        let (aligned_buf, total_bytes) = build_windows_file_rename_info_buffer(
            parent_dir.as_raw_handle(),
            &wide_leaf,
            replace_if_exists,
        )?;
        let buf_ptr = aligned_buf.as_ptr().cast::<core::ffi::c_void>();
        // SAFETY: `source_file` is an open handle with `DELETE` access, `parent_dir`
        // is an open directory handle, and `buf_ptr` points to a valid
        // `FILE_RENAME_INFO` buffer of `total_bytes` bytes.
        let ok = unsafe {
            SetFileInformationByHandle(
                source_file.as_raw_handle(),
                FILE_RENAME_INFO_CLASS,
                buf_ptr,
                total_bytes as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn commit_batch_recipient_refresh_windows(
        parent_dir: &File,
        canon_parent: &Path,
        expected_parent_id: (u64, u64),
        leaf_name: &std::ffi::OsStr,
        content: &[u8],
        expected_file_id: Option<(u64, u64)>,
        expected_prior_bytes: Option<&[u8]>,
    ) -> CliResult<()> {
        validate_directory_handle_dacl(parent_dir).map_err(CliError::Io)?;
        let (handle_parent_id, _) = file_identity_and_nlink(parent_dir).map_err(CliError::Io)?;
        let (named_parent_id, _) =
            path_identity_and_nlink_nofollow(canon_parent).map_err(CliError::Io)?;
        if handle_parent_id != expected_parent_id || named_parent_id != expected_parent_id {
            return Err(CliError::ConcurrentModification {
                path: canon_parent.display().to_string(),
            });
        }
        recover_displaced_windows_entry_in_dir(parent_dir, leaf_name).map_err(CliError::Io)?;

        let target_display = canon_parent.join(leaf_name).display().to_string();
        if expected_file_id.is_none() && stat_relative_nofollow(parent_dir, leaf_name).is_ok() {
            return Err(CliError::ConcurrentModification {
                path: target_display,
            });
        }

        let pid = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut temp_name_opt = None;
        let mut temp_file_opt = None;
        for attempt in 0..64u32 {
            let candidate_name =
                std::ffi::OsString::from(format!(".seclusor-rcpt-{pid}-{ts}-{attempt}.tmp"));
            match open_relative_entry_nofollow(
                parent_dir,
                &candidate_name,
                GENERIC_READ | GENERIC_WRITE | DELETE,
                0,
                FILE_CREATE,
                false,
            ) {
                Ok(file) => {
                    temp_name_opt = Some(candidate_name);
                    temp_file_opt = Some(file);
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(CliError::Io(err)),
            }
        }
        let temp_name = temp_name_opt.ok_or_else(|| {
            CliError::Message("failed to allocate unique temporary recipient file path".to_string())
        })?;
        let mut temp_file = temp_file_opt.expect("temp_file set with temp_name");

        let (temp_id, temp_nlink) = match file_identity_and_nlink(&temp_file) {
            Ok(v) => v,
            Err(err) => {
                delete_open_handle_on_close(&temp_file);
                drop(temp_file);
                return Err(CliError::Io(err));
            }
        };
        if temp_nlink != 1 {
            delete_open_handle_on_close(&temp_file);
            drop(temp_file);
            return Err(CliError::ConcurrentModification {
                path: target_display,
            });
        }
        if let Err(err) = temp_file
            .write_all(content)
            .and_then(|()| temp_file.sync_all())
        {
            delete_open_handle_on_close(&temp_file);
            drop(temp_file);
            return Err(CliError::Io(err));
        }

        // Keep `temp_file` open (`ShareAccess = 0`, `DELETE` access) across `cas_guard`
        // acquisition and handle-bound publication so the staged file cannot be opened,
        // swapped, or modified before or during publication inside `parent_dir`.
        let mut cas_guard = if let Some(expected_id) = expected_file_id {
            let expected_bytes = expected_prior_bytes.unwrap_or(&[]);
            // Open `leaf_name` directly relative to `parent_dir` with `GENERIC_READ | DELETE`
            // and `ShareAccess = 0` (excluding `FILE_SHARE_DELETE` as well as read/write),
            // so the Windows kernel blocks any concurrent open, rename, or deletion of
            // `leaf_name` with `STATUS_SHARING_VIOLATION` while `guard` is held.
            let existing = match open_relative_entry_nofollow(
                parent_dir,
                leaf_name,
                GENERIC_READ | DELETE,
                0,
                FILE_OPEN,
                false,
            ) {
                Ok(f) => f,
                Err(err) => {
                    delete_open_handle_on_close(&temp_file);
                    drop(temp_file);
                    if err.kind() == io::ErrorKind::NotFound
                        || err.kind() == io::ErrorKind::InvalidInput
                    {
                        return Err(CliError::ConcurrentModification {
                            path: target_display,
                        });
                    }
                    return Err(CliError::Io(err));
                }
            };
            let mut guard = match lock_target_handle(existing) {
                Ok(g) => g,
                Err(_) => {
                    delete_open_handle_on_close(&temp_file);
                    drop(temp_file);
                    return Err(CliError::ConcurrentModification {
                        path: target_display,
                    });
                }
            };
            let check_res: CliResult<()> = (|| {
                let open_meta = guard.file.metadata().map_err(CliError::Io)?;
                if !open_meta.is_file() || is_symlink_or_reparse_point(&open_meta) {
                    return Err(CliError::ConcurrentModification {
                        path: target_display.clone(),
                    });
                }
                let (open_id, open_nlink) =
                    file_identity_and_nlink(&guard.file).map_err(CliError::Io)?;
                let (rel_id, rel_nlink) =
                    stat_relative_nofollow(parent_dir, leaf_name).map_err(CliError::Io)?;
                if open_id != expected_id
                    || rel_id != expected_id
                    || open_nlink != 1
                    || rel_nlink != 1
                    || open_meta.len() != expected_bytes.len() as u64
                {
                    return Err(CliError::ConcurrentModification {
                        path: target_display.clone(),
                    });
                }
                let cap = expected_bytes.len().saturating_add(1);
                let mut current_bytes = vec![0u8; cap];
                let mut total = 0usize;
                while total < current_bytes.len() {
                    match guard.file.read(&mut current_bytes[total..]) {
                        Ok(0) => break,
                        Ok(n) => total += n,
                        Err(err) => return Err(CliError::Io(err)),
                    }
                }
                if total == cap || &current_bytes[..total] != expected_bytes {
                    return Err(CliError::ConcurrentModification {
                        path: target_display.clone(),
                    });
                }
                Ok(())
            })();
            if let Err(err) = check_res {
                drop(guard);
                delete_open_handle_on_close(&temp_file);
                drop(temp_file);
                return Err(err);
            }
            Some(guard)
        } else {
            None
        };

        let (still_temp_id, still_temp_nlink) = match file_identity_and_nlink(&temp_file) {
            Ok(v) => v,
            Err(err) => {
                drop(cas_guard);
                delete_open_handle_on_close(&temp_file);
                drop(temp_file);
                return Err(CliError::Io(err));
            }
        };
        let (rel_temp_id, rel_temp_nlink) = match stat_relative_nofollow(parent_dir, &temp_name) {
            Ok(v) => v,
            Err(_) => {
                drop(cas_guard);
                delete_open_handle_on_close(&temp_file);
                drop(temp_file);
                return Err(CliError::ConcurrentModification {
                    path: target_display,
                });
            }
        };
        if still_temp_id != temp_id
            || still_temp_nlink != 1
            || rel_temp_id != temp_id
            || rel_temp_nlink != 1
        {
            drop(cas_guard);
            delete_open_handle_on_close(&temp_file);
            drop(temp_file);
            return Err(CliError::ConcurrentModification {
                path: target_display,
            });
        }

        if let Some(ref mut guard) = cas_guard {
            let displaced_name = displaced_windows_leaf_name(leaf_name);
            if let Err(err) =
                rename_open_handle_in_dir(&guard.file, parent_dir, &displaced_name, false)
            {
                drop(cas_guard);
                delete_open_handle_on_close(&temp_file);
                drop(temp_file);
                if err.kind() == io::ErrorKind::AlreadyExists {
                    return Err(CliError::ConcurrentModification {
                        path: target_display,
                    });
                }
                return Err(CliError::Io(err));
            }
            if let Err(err) = rename_open_handle_in_dir(&temp_file, parent_dir, leaf_name, false) {
                let _ = rename_open_handle_in_dir(&guard.file, parent_dir, leaf_name, false);
                drop(cas_guard);
                delete_open_handle_on_close(&temp_file);
                drop(temp_file);
                if err.kind() == io::ErrorKind::AlreadyExists {
                    return Err(CliError::ConcurrentModification {
                        path: target_display,
                    });
                }
                return Err(CliError::Io(err));
            }
            delete_open_handle_on_close(&guard.file);
        } else if let Err(err) = rename_open_handle_in_dir(&temp_file, parent_dir, leaf_name, false)
        {
            delete_open_handle_on_close(&temp_file);
            drop(temp_file);
            if err.kind() == io::ErrorKind::AlreadyExists {
                return Err(CliError::ConcurrentModification {
                    path: target_display,
                });
            }
            return Err(CliError::Io(err));
        }

        let (post_handle_id, post_handle_nlink) =
            file_identity_and_nlink(&temp_file).map_err(CliError::Io)?;
        drop(temp_file);
        drop(cas_guard);

        let (published_id, published_nlink) =
            stat_relative_nofollow(parent_dir, leaf_name).map_err(CliError::Io)?;
        if post_handle_id != temp_id
            || post_handle_nlink != 1
            || published_id != temp_id
            || published_nlink != 1
        {
            return Err(CliError::ConcurrentModification {
                path: target_display,
            });
        }
        Ok(())
    }
}

fn derive_journal_auth_key(target_verify_candidates: &[Identity]) -> Zeroizing<[u8; 32]> {
    use sha2::Digest as _;
    let mut secret_material: Vec<Zeroizing<String>> = target_verify_candidates
        .iter()
        .map(|id| Zeroizing::new(seclusor_crypto::identity_to_string(id)))
        .collect();
    secret_material.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    secret_material.dedup_by(|a, b| a.as_str() == b.as_str());

    let mut hasher = sha2::Sha256::new();
    hasher.update(b"seclusor.v1.blob-rekey-batch.journal-hmac-key\0");
    for s in &secret_material {
        hasher.update((s.len() as u64).to_le_bytes());
        hasher.update(s.as_bytes());
    }
    Zeroizing::new(hasher.finalize().into())
}

fn hmac_sha256_hex(key: &[u8; 32], message: &[u8]) -> String {
    use sha2::Digest as _;
    let mut ipad = Zeroizing::new([0x36u8; 64]);
    let mut opad = Zeroizing::new([0x5cu8; 64]);
    for i in 0..32 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = sha2::Sha256::new();
    inner.update(&ipad[..]);
    inner.update(message);
    let inner_digest: Zeroizing<[u8; 32]> = Zeroizing::new(inner.finalize().into());

    let mut outer = sha2::Sha256::new();
    outer.update(&opad[..]);
    outer.update(&inner_digest[..]);
    let tag: Zeroizing<[u8; 32]> = Zeroizing::new(outer.finalize().into());

    let mut out = String::with_capacity(64);
    for b in tag.iter() {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn compute_journal_auth_tag(journal: &BatchStateJournal, auth_key: &[u8; 32]) -> CliResult<String> {
    let mut canonical = journal.clone();
    canonical.auth_tag.clear();
    let canonical_bytes =
        serialize_state_journal_bounded(&canonical, MAX_STATE_JOURNAL_BYTES as usize)?;
    Ok(hmac_sha256_hex(auth_key, &canonical_bytes))
}

/// Read an existing `--state` journal with file-descriptor-bound ownership,
/// `0600` permission, single-hardlink (`nlink == 1`), and strict non-owner
/// ACL rejection. Returns `Ok(None)` if `state_path` does not exist yet.
fn read_existing_state_journal_for_cas(
    state_path: &Path,
) -> CliResult<Option<StateJournalSnapshot>> {
    reject_symlink_traversal_in_path(state_path, "--state", true)?;
    let parent = state_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    seclusor_crypto::acl::reject_writable_directory_acl(parent)?;
    #[cfg(windows)]
    {
        let parent_dir = windows_dacl::open_dir_nofollow_anchored_windows(parent, "--state")?;
        if let Some(leaf_os) = state_path
            .file_name()
            .filter(|n| !n.is_empty() && *n != "." && *n != "..")
        {
            windows_dacl::recover_displaced_windows_entry_in_dir(&parent_dir, leaf_os)
                .map_err(CliError::Io)?;
        }
    }

    let pre_meta = match fs::symlink_metadata(state_path) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(CliError::Io(err)),
    };
    if is_symlink_or_reparse_point(&pre_meta) {
        return Err(CliError::Message(format!(
            "refusing symlink --state journal path {}",
            state_path.display()
        )));
    }
    if !pre_meta.is_file() {
        return Err(CliError::Message(format!(
            "--state journal path {} must be a regular file",
            state_path.display()
        )));
    }
    let (pre_id, pre_nlink) = path_identity_and_nlink_nofollow(state_path).map_err(CliError::Io)?;
    if pre_nlink != 1 {
        return Err(CliError::Message(format!(
            "refusing hardlinked --state journal path {} (nlink = {pre_nlink})",
            state_path.display()
        )));
    }

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        // `share_mode(0)` is exclusive: if any other process retains an open
        // data handle to `--state`, `CreateFileW` fails closed with
        // `ERROR_SHARING_VIOLATION`.
        options
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = match options.open(state_path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(CliError::ConcurrentModification {
                path: state_path.display().to_string(),
            });
        }
        #[cfg(unix)]
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
            return Err(CliError::Message(format!(
                "refusing symlink --state journal path {}",
                state_path.display()
            )));
        }
        Err(err) => return Err(CliError::Io(err)),
    };

    let open_meta = file.metadata().map_err(CliError::Io)?;
    if is_symlink_or_reparse_point(&open_meta) {
        return Err(CliError::Message(format!(
            "refusing symlink --state journal path {}",
            state_path.display()
        )));
    }
    if !open_meta.is_file() {
        return Err(CliError::Message(format!(
            "--state journal path {} must be a regular file",
            state_path.display()
        )));
    }
    let (open_id, open_nlink) = file_identity_and_nlink(&file).map_err(CliError::Io)?;
    if open_id != pre_id {
        return Err(CliError::ConcurrentModification {
            path: state_path.display().to_string(),
        });
    }
    if open_nlink != 1 {
        return Err(CliError::Message(format!(
            "refusing hardlinked --state journal path {} (nlink = {open_nlink})",
            state_path.display()
        )));
    }

    #[cfg(unix)]
    let open_identity = {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let file_uid = open_meta.uid();
        // SAFETY: `getuid` has no memory-safety preconditions and cannot fail.
        let current_uid = unsafe { libc::getuid() };
        if file_uid != current_uid {
            return Err(CliError::Crypto(
                seclusor_crypto::CryptoError::IdentityFileNotOwnedByCurrentUser {
                    file_uid,
                    current_uid,
                },
            ));
        }
        let mode = open_meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(CliError::Crypto(
                seclusor_crypto::CryptoError::InsecureIdentityFilePermissions { actual: mode },
            ));
        }
        (open_id.0, open_id.1, mode)
    };

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        let has_non_owner_acl = seclusor_crypto::acl::has_non_owner_file_acl(state_path)?;
        let post_acl_meta = fs::symlink_metadata(state_path).map_err(CliError::Io)?;
        if is_symlink_or_reparse_point(&post_acl_meta)
            || !post_acl_meta.is_file()
            || post_acl_meta.dev() != open_identity.0
            || post_acl_meta.ino() != open_identity.1
        {
            return Err(CliError::ConcurrentModification {
                path: state_path.display().to_string(),
            });
        }
        if has_non_owner_acl {
            return Err(CliError::Message(format!(
                "--state journal {} has a non-owner extended ACL grant; inspect with ls -le and remove with chmod -N",
                state_path.display()
            )));
        }
    }

    #[cfg(windows)]
    {
        windows_dacl::verify_private_file_dacl(&file).map_err(CliError::Io)?;
    }

    let hint_len = open_meta.len();
    if hint_len > MAX_STATE_JOURNAL_BYTES {
        return Err(CliError::Message(format!(
            "--state journal {} exceeds maximum size of {} bytes",
            state_path.display(),
            MAX_STATE_JOURNAL_BYTES
        )));
    }
    let cap = (hint_len as usize)
        .saturating_add(1)
        .min((MAX_STATE_JOURNAL_BYTES as usize).saturating_add(1));
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
    if total == cap || (buf.len() as u64) > MAX_STATE_JOURNAL_BYTES {
        return Err(CliError::Message(format!(
            "--state journal {} exceeds maximum size of {} bytes or changed size during read",
            state_path.display(),
            MAX_STATE_JOURNAL_BYTES
        )));
    }

    let (after_id, after_nlink) = file_identity_and_nlink(&file).map_err(CliError::Io)?;
    if after_id != open_id || after_nlink != 1 {
        return Err(CliError::ConcurrentModification {
            path: state_path.display().to_string(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let after_read_meta = file.metadata().map_err(CliError::Io)?;
        if (after_read_meta.permissions().mode() & 0o777) != 0o600 {
            return Err(CliError::ConcurrentModification {
                path: state_path.display().to_string(),
            });
        }
    }

    Ok(Some(StateJournalSnapshot {
        prior: PrivateCiphertextPriorSnapshot {
            bytes: buf,
            #[cfg(unix)]
            identity: open_identity,
            #[cfg(windows)]
            file_id: open_id,
        },
        file_id: open_id,
    }))
}

fn load_or_init_state_journal(
    state_path: &Path,
    target_recipients: &[String],
    prior_recipients: Option<&[String]>,
    allow_recipient_mismatch: bool,
    allow_self_lockout: bool,
    allow_large: bool,
    auth_key: &[u8; 32],
) -> CliResult<(BatchStateJournal, Option<StateJournalSnapshot>)> {
    let prior_snapshot = read_existing_state_journal_for_cas(state_path)?;
    if let Some(snapshot) = prior_snapshot {
        let journal: BatchStateJournal =
            serde_json::from_slice(&snapshot.prior.bytes).map_err(|err| {
                CliError::Message(format!(
                    "invalid --state journal at {}: {}",
                    state_path.display(),
                    CliError::from(err)
                ))
            })?;
        if journal.schema != STATE_JOURNAL_SCHEMA || journal.operation != "blob-rekey-batch" {
            return Err(CliError::Message(format!(
                "--state journal at {} has unsupported schema or operation",
                state_path.display()
            )));
        }
        let expected_prior = prior_recipients.map(|s| s.to_vec());
        if journal.target_recipients != target_recipients
            || journal.prior_recipients != expected_prior
            || journal.allow_recipient_mismatch != allow_recipient_mismatch
            || journal.allow_self_lockout != allow_self_lockout
            || journal.allow_large != allow_large
        {
            return Err(CliError::Message(format!(
                "--state journal at {} is bound to different target recipients or policy flags; \
                 refusing to mix batch state across mismatched parameters",
                state_path.display()
            )));
        }
        if !is_valid_sha256_hex(&journal.auth_tag) {
            return Err(CliError::Message(format!(
                "--state journal at {} is missing a valid cryptographic auth_tag",
                state_path.display()
            )));
        }
        let expected_tag = compute_journal_auth_tag(&journal, auth_key)?;
        if journal
            .auth_tag
            .as_bytes()
            .ct_eq(expected_tag.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(CliError::Message(format!(
                "--state journal at {} failed cryptographic authenticity verification \
                 (journal was modified outside seclusor or bound to different identity keys)",
                state_path.display()
            )));
        }
        for (key, rec) in &journal.records {
            if key != &rec.path
                || !matches!(rec.status.as_str(), "in_progress" | "rekeyed")
                || !is_valid_sha256_hex(&rec.sha256_before)
                || !is_valid_sha256_hex(&rec.sha256_after)
                || rec.sha256_before == rec.sha256_after
            {
                return Err(CliError::Message(format!(
                    "--state journal at {} contains malformed record for {}",
                    state_path.display(),
                    key
                )));
            }
        }
        return Ok((journal, Some(snapshot)));
    }

    let mut journal = BatchStateJournal {
        schema: STATE_JOURNAL_SCHEMA.to_string(),
        operation: "blob-rekey-batch".to_string(),
        target_recipients: target_recipients.to_vec(),
        prior_recipients: prior_recipients.map(|s| s.to_vec()),
        allow_recipient_mismatch,
        allow_self_lockout,
        allow_large,
        auth_tag: String::new(),
        records: std::collections::BTreeMap::new(),
    };
    journal.auth_tag = compute_journal_auth_tag(&journal, auth_key)?;
    Ok((journal, None))
}

struct BoundedJournalWriter {
    buf: Vec<u8>,
    max_bytes: usize,
}

impl std::io::Write for BoundedJournalWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.buf.len().saturating_add(data.len()) > self.max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "--state journal exceeds maximum size of {} bytes",
                    self.max_bytes
                ),
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialize_state_journal_bounded(
    journal: &BatchStateJournal,
    max_bytes: usize,
) -> CliResult<Vec<u8>> {
    let mut writer = BoundedJournalWriter {
        buf: Vec::with_capacity(max_bytes.min(4096)),
        max_bytes,
    };
    serde_json::to_writer_pretty(&mut writer, journal).map_err(|err| {
        if err.is_io() {
            CliError::Message(format!(
                "--state journal exceeds maximum size of {max_bytes} bytes"
            ))
        } else {
            CliError::from(err)
        }
    })?;
    if !writer.buf.ends_with(b"\n") {
        std::io::Write::write_all(&mut writer, b"\n").map_err(|_| {
            CliError::Message(format!(
                "--state journal exceeds maximum size of {max_bytes} bytes"
            ))
        })?;
    }
    Ok(writer.buf)
}

fn persist_state_journal(
    state_path: &Path,
    journal: &mut BatchStateJournal,
    auth_key: &[u8; 32],
    prior_snapshot: Option<&StateJournalSnapshot>,
) -> CliResult<StateJournalSnapshot> {
    reject_symlink_traversal_in_path(state_path, "--state", true)?;
    journal.auth_tag = compute_journal_auth_tag(journal, auth_key)?;
    let bytes = serialize_state_journal_bounded(journal, MAX_STATE_JOURNAL_BYTES as usize)?;
    #[cfg(unix)]
    {
        atomic_write_private_ciphertext(
            state_path,
            &bytes,
            prior_snapshot.map(|s| s.prior.clone()),
        )?;
    }
    #[cfg(windows)]
    {
        windows_dacl::atomic_write_private_journal(state_path, &bytes, prior_snapshot)?;
    }
    let refreshed = read_existing_state_journal_for_cas(state_path)?.ok_or_else(|| {
        CliError::Message(format!(
            "--state journal {} disappeared immediately after write",
            state_path.display()
        ))
    })?;
    if refreshed.prior.bytes.as_slice() != bytes.as_slice() {
        return Err(CliError::ConcurrentModification {
            path: state_path.display().to_string(),
        });
    }
    if let Some(prev) = prior_snapshot {
        if refreshed.file_id == prev.file_id {
            return Err(CliError::ConcurrentModification {
                path: state_path.display().to_string(),
            });
        }
    }
    Ok(refreshed)
}

fn create_private_backup_file(path: &Path, prior_bytes: &[u8]) -> CliResult<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    seclusor_crypto::acl::reject_writable_directory_acl(parent)?;
    #[cfg(windows)]
    windows_dacl::reject_writable_directory_dacl(parent).map_err(CliError::Io)?;

    let ts = utc_compact_timestamp_now();
    let base_name = path
        .file_name()
        .ok_or_else(|| CliError::Message(format!("invalid file path {}", path.display())))?
        .to_string_lossy();
    let backup_path = parent.join(format!("{base_name}.bak-{ts}"));

    if fs::symlink_metadata(&backup_path).is_ok() {
        return Err(CliError::Message(format!(
            "refusing to create backup {}: path already exists",
            backup_path.display()
        )));
    }

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut options = fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        let file = options.open(&backup_path).map_err(CliError::Io)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(CliError::Io)?;
        file
    };
    #[cfg(windows)]
    let mut file = windows_dacl::create_new_private_file(&backup_path).map_err(CliError::Io)?;
    if let Err(err) = seclusor_crypto::acl::prepare_private_file(&file, &backup_path) {
        #[cfg(unix)]
        let _ = file.set_len(0);
        #[cfg(windows)]
        windows_dacl::delete_open_handle_on_close(&file);
        drop(file);
        return Err(CliError::Io(err));
    }
    if let Err(err) =
        std::io::Write::write_all(&mut file, prior_bytes).and_then(|()| file.sync_all())
    {
        #[cfg(unix)]
        let _ = file.set_len(0);
        #[cfg(windows)]
        windows_dacl::delete_open_handle_on_close(&file);
        drop(file);
        return Err(CliError::Io(err));
    }
    drop(file);
    #[cfg(unix)]
    {
        let dir = fs::File::open(parent).map_err(CliError::Io)?;
        dir.sync_all().map_err(CliError::Io)?;
    }
    Ok(backup_path)
}

#[cfg(unix)]
fn format_unix_mode(mode: u32) -> Option<String> {
    Some(format!("{:04o}", mode & 0o777))
}

#[cfg(not(unix))]
fn format_unix_mode(_mode: u32) -> Option<String> {
    None
}

#[cfg(unix)]
fn tightened_unix_mode(mode: u32) -> u32 {
    let m = mode & 0o777;
    if m & 0o077 != 0 {
        m & !0o077
    } else {
        m
    }
}

#[cfg(not(unix))]
fn tightened_unix_mode(mode: u32) -> u32 {
    mode
}

/// Probe whether `bytes` is a JSON secrets document (plaintext or inline)
/// without retaining any credential values in unzeroized heap strings.
///
/// Bounded to `MAX_SECRETS_DOC_BYTES` (4 MiB) so an oversized non-age blob
/// under `--allow-large` (up to 24 MiB) is never parsed as a secrets document.
fn is_json_secrets_document(bytes: &[u8]) -> bool {
    if bytes.len() > seclusor_core::constants::MAX_SECRETS_DOC_BYTES {
        return false;
    }
    refuse_if_secrets_bundle_document(bytes).is_err()
}

const MAX_BATCH_RECIPIENT_FILE_BYTES: u64 = 1024 * 1024;

#[cfg(test)]
type PostStatHook = Box<dyn FnOnce()>;

#[cfg(test)]
type InnerFdHook = Box<dyn FnOnce(i32)>;

#[cfg(test)]
thread_local! {
    static BATCH_RECIPIENT_POST_STAT_HOOK: std::cell::RefCell<Option<PostStatHook>> =
        std::cell::RefCell::new(None);
    static BATCH_RECIPIENT_POST_EXCHANGE_HOOK: std::cell::RefCell<Option<PostStatHook>> =
        std::cell::RefCell::new(None);
    static BATCH_RECIPIENT_POST_INNER_FD_HOOK: std::cell::RefCell<Option<InnerFdHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_batch_recipient_post_stat_hook(hook: Option<PostStatHook>) {
    BATCH_RECIPIENT_POST_STAT_HOOK.with(|h| *h.borrow_mut() = hook);
}

#[cfg(test)]
fn set_batch_recipient_post_exchange_hook(hook: Option<PostStatHook>) {
    BATCH_RECIPIENT_POST_EXCHANGE_HOOK.with(|h| *h.borrow_mut() = hook);
}

#[cfg(all(test, unix))]
fn set_batch_recipient_post_inner_fd_hook(hook: Option<InnerFdHook>) {
    BATCH_RECIPIENT_POST_INNER_FD_HOOK.with(|h| *h.borrow_mut() = hook);
}

#[cfg(all(test, unix))]
fn run_batch_recipient_post_stat_hook() {
    let hook = BATCH_RECIPIENT_POST_STAT_HOOK.with(|h| h.borrow_mut().take());
    if let Some(f) = hook {
        f();
    }
}

#[cfg(all(test, unix))]
fn run_batch_recipient_post_exchange_hook() {
    let hook = BATCH_RECIPIENT_POST_EXCHANGE_HOOK.with(|h| h.borrow_mut().take());
    if let Some(f) = hook {
        f();
    }
}

#[cfg(all(test, unix))]
fn run_batch_recipient_post_inner_fd_hook(inner_fd: libc::c_int) {
    let hook = BATCH_RECIPIENT_POST_INNER_FD_HOOK.with(|h| h.borrow_mut().take());
    if let Some(f) = hook {
        f(inner_fd);
    }
}

/// Validate a Unix directory's ownership and mode bits from its open handle metadata.
///
/// - The directory owner (`dir_uid`) must be `current_uid` or `0` (`root`).
/// - For the target's immediate parent directory (`is_leaf_parent == true`),
///   group and other write bits (`0o022`) must be clear so no untrusted
///   namespace writer can create, unlink, or rename entries in the directory.
/// - For intermediate ancestor directories (`is_leaf_parent == false`), group
///   and other write bits must be clear unless the directory is owned by `root`
///   (`dir_uid == 0`) and has the sticky bit (`0o1000`, e.g. `/tmp`), where the
///   kernel forbids non-owners from renaming or unlinking child directories
///   owned by `current_uid`.
#[cfg(any(unix, test))]
fn validate_unix_directory_owner_and_mode(
    current_uid: u32,
    dir_uid: u32,
    dir_mode: u32,
    is_leaf_parent: bool,
    dir_display: &Path,
) -> CliResult<()> {
    if dir_uid != current_uid && dir_uid != 0 {
        return Err(CliError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "directory {} is owned by uid {dir_uid} (expected current uid {current_uid} or 0)",
                dir_display.display()
            ),
        )));
    }
    let writable_by_group_or_other = (dir_mode & 0o022) != 0;
    if writable_by_group_or_other {
        let sticky_root_ancestor = !is_leaf_parent && dir_uid == 0 && (dir_mode & 0o1000) != 0;
        if !sticky_root_ancestor {
            return Err(CliError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "directory {} has insecure group/other-writable mode {:04o}; \
                     remove group/other write permissions (chmod go-w)",
                    dir_display.display(),
                    dir_mode & 0o7777
                ),
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
unsafe fn atomic_swap_entries(
    first_dir_fd: libc::c_int,
    first_name: *const libc::c_char,
    second_dir_fd: libc::c_int,
    second_name: *const libc::c_char,
) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let rc = unsafe {
            libc::renameatx_np(
                first_dir_fd,
                first_name,
                second_dir_fd,
                second_name,
                libc::RENAME_SWAP,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        const RENAME_EXCHANGE: libc::c_uint = 2;
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                first_dir_fd,
                first_name,
                second_dir_fd,
                second_name,
                RENAME_EXCHANGE,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (first_dir_fd, first_name, second_dir_fd, second_name);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "atomic directory entry swap is not supported on this platform",
        ))
    }
}

struct BatchRecipientRefreshPlan {
    user_path: PathBuf,
    canon_parent: PathBuf,
    parent_dir: fs::File,
    parent_id: (u64, u64),
    #[cfg(windows)]
    leaf_name: std::ffi::OsString,
    #[cfg(unix)]
    leaf_cstr: std::ffi::CString,
    content: Vec<u8>,
    existing_file_id: Option<(u64, u64)>,
    #[cfg(unix)]
    existing_mode: Option<u32>,
    prior_bytes: Option<Vec<u8>>,
}

/// Open `dir_path` without following symlinks (using step-by-step `openat`
/// with `O_DIRECTORY | O_NOFOLLOW` on Unix, and `FILE_SHARE_READ | FILE_SHARE_WRITE`
/// without `FILE_SHARE_DELETE` on Windows so the kernel blocks directory or
/// ancestor renames while the handle is held) and return `(dir_file, canon_dir, dir_id)`.
fn open_dir_nofollow_anchored(
    dir_path: &Path,
    flag_label: &str,
) -> CliResult<(fs::File, PathBuf, (u64, u64))> {
    reject_symlink_traversal_in_user_path(dir_path, flag_label)?;
    seclusor_crypto::acl::reject_writable_directory_acl(dir_path)?;
    #[cfg(windows)]
    windows_dacl::reject_writable_directory_dacl(dir_path).map_err(CliError::Io)?;

    #[cfg(unix)]
    let dir_file = {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::path::Component;

        // SAFETY: `getuid` has no memory-safety preconditions and cannot fail.
        let current_uid = unsafe { libc::getuid() };

        let base_path = if dir_path.is_relative() {
            let cwd = std::env::current_dir().map_err(CliError::Io)?;
            reject_symlink_traversal_in_user_path(&cwd, flag_label)?;
            cwd.join(dir_path)
        } else {
            dir_path.to_path_buf()
        };

        let root_cstr = CString::new("/").expect("valid root CString");
        // SAFETY: `root_cstr` is a valid NUL-terminated string.
        let root_fd = unsafe {
            libc::open(
                root_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root_fd < 0 {
            return Err(CliError::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: `root_fd` is a valid newly opened file descriptor.
        let mut cur_dir = unsafe { fs::File::from_raw_fd(root_fd) };
        let mut cur_path = PathBuf::from("/");

        for comp in base_path.components() {
            match comp {
                Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
                Component::ParentDir => {
                    cur_path.pop();
                    let parent_cstr = CString::new("..").expect("valid .. CString");
                    // SAFETY: `cur_dir` is an open directory FD and `parent_cstr` is valid.
                    let next_fd = unsafe {
                        libc::openat(
                            cur_dir.as_raw_fd(),
                            parent_cstr.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if next_fd < 0 {
                        return Err(CliError::Io(std::io::Error::last_os_error()));
                    }
                    // SAFETY: `next_fd` is a valid newly opened directory FD.
                    cur_dir = unsafe { fs::File::from_raw_fd(next_fd) };
                    let step_meta = cur_dir.metadata().map_err(CliError::Io)?;
                    validate_unix_directory_owner_and_mode(
                        current_uid,
                        step_meta.uid(),
                        step_meta.permissions().mode(),
                        false,
                        &cur_path,
                    )?;
                }
                Component::Normal(part) => {
                    cur_path.push(part);
                    let meta = fs::symlink_metadata(&cur_path).map_err(CliError::Io)?;
                    let mut flags =
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
                    if is_symlink_or_reparse_point(&meta) {
                        #[cfg(target_os = "macos")]
                        if is_macos_system_root_symlink(&cur_path, &meta) {
                            flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
                        } else {
                            return Err(CliError::Message(format!(
                                "refusing symlink in {flag_label} path {}; symlinks are not followed",
                                dir_path.display()
                            )));
                        }
                        #[cfg(not(target_os = "macos"))]
                        {
                            return Err(CliError::Message(format!(
                                "refusing symlink in {flag_label} path {}; symlinks are not followed",
                                dir_path.display()
                            )));
                        }
                    }
                    let c_part = CString::new(part.as_bytes()).map_err(|_| {
                        CliError::Message(format!(
                            "invalid NUL byte in {flag_label} path {}",
                            dir_path.display()
                        ))
                    })?;
                    // SAFETY: `cur_dir` is an open directory FD and `c_part` is NUL-terminated.
                    let next_fd =
                        unsafe { libc::openat(cur_dir.as_raw_fd(), c_part.as_ptr(), flags) };
                    if next_fd < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() == Some(libc::ELOOP) {
                            return Err(CliError::Message(format!(
                                "refusing symlink in {flag_label} path {}; symlinks are not followed",
                                dir_path.display()
                            )));
                        }
                        return Err(CliError::Io(err));
                    }
                    // SAFETY: `next_fd` is a valid newly opened directory FD.
                    cur_dir = unsafe { fs::File::from_raw_fd(next_fd) };
                    let step_meta = cur_dir.metadata().map_err(CliError::Io)?;
                    validate_unix_directory_owner_and_mode(
                        current_uid,
                        step_meta.uid(),
                        step_meta.permissions().mode(),
                        false,
                        &cur_path,
                    )?;
                }
            }
        }
        let leaf_dir_meta = cur_dir.metadata().map_err(CliError::Io)?;
        validate_unix_directory_owner_and_mode(
            current_uid,
            leaf_dir_meta.uid(),
            leaf_dir_meta.permissions().mode(),
            true,
            dir_path,
        )?;
        cur_dir
    };

    #[cfg(windows)]
    let dir_file = windows_dacl::open_dir_nofollow_anchored_windows(dir_path, flag_label)?;

    let (open_dir_id, _) = file_identity_and_nlink(&dir_file).map_err(CliError::Io)?;
    let canon_dir = fs::canonicalize(dir_path).map_err(CliError::Io)?;
    reject_symlink_traversal_in_user_path(&canon_dir, flag_label)?;
    seclusor_crypto::acl::reject_writable_directory_acl(&canon_dir)?;
    #[cfg(windows)]
    windows_dacl::reject_writable_directory_dacl(&canon_dir).map_err(CliError::Io)?;
    let (canon_dir_id, _) = path_identity_and_nlink_nofollow(&canon_dir).map_err(CliError::Io)?;
    if open_dir_id != canon_dir_id {
        return Err(CliError::ConcurrentModification {
            path: dir_path.display().to_string(),
        });
    }
    Ok((dir_file, canon_dir, open_dir_id))
}

#[allow(clippy::too_many_arguments)]
fn prepare_batch_recipient_refresh(
    wr_path: &Path,
    selected_files: &[SelectedBatchFile],
    identity_paths: &[PathBuf],
    passphrase_file: Option<&Path>,
    recipient_files: &[PathBuf],
    prior_recipient_files: &[PathBuf],
    target_strings: &[String],
) -> CliResult<BatchRecipientRefreshPlan> {
    reject_symlink_traversal_in_path(wr_path, "--write-recipients", true)?;

    let leaf_os = wr_path
        .file_name()
        .filter(|n| !n.is_empty() && *n != "." && *n != "..")
        .ok_or_else(|| {
            CliError::Message(format!(
                "--write-recipients target {} must name a regular file",
                wr_path.display()
            ))
        })?
        .to_os_string();
    let parent_path = wr_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let (parent_dir, canon_parent, parent_id) =
        open_dir_nofollow_anchored(parent_path, "--write-recipients")?;
    let target_in_canon_parent = canon_parent.join(&leaf_os);

    for selected in selected_files {
        if paths_alias(wr_path, &selected.path)?
            || paths_alias(&target_in_canon_parent, &selected.path)?
        {
            return Err(CliError::Message(format!(
                "--write-recipients path {} aliases selected blob path {}",
                wr_path.display(),
                selected.path.display()
            )));
        }
    }
    for id_path in identity_paths {
        if paths_alias(wr_path, id_path)? || paths_alias(&target_in_canon_parent, id_path)? {
            return Err(CliError::Message(format!(
                "--write-recipients path {} aliases identity source path {}; \
                 choose a separate recipient-list path",
                wr_path.display(),
                id_path.display()
            )));
        }
    }
    if let Some(pp_path) = passphrase_file {
        if paths_alias(wr_path, pp_path)? || paths_alias(&target_in_canon_parent, pp_path)? {
            return Err(CliError::Message(format!(
                "--write-recipients path {} aliases --passphrase-file path {}; \
                 choose a separate recipient-list path",
                wr_path.display(),
                pp_path.display()
            )));
        }
    }
    for prior_path in prior_recipient_files {
        if paths_alias(wr_path, prior_path)? || paths_alias(&target_in_canon_parent, prior_path)? {
            return Err(CliError::Message(format!(
                "--write-recipients path {} aliases --prior-recipient-file path {}; \
                 choose a separate recipient-list path",
                wr_path.display(),
                prior_path.display()
            )));
        }
    }
    for rfile in recipient_files {
        let same_explicit = {
            let r_parent = rfile
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            match (fs::canonicalize(r_parent), rfile.file_name()) {
                (Ok(rc_parent), Some(r_leaf)) => rc_parent == canon_parent && r_leaf == leaf_os,
                _ => false,
            }
        };
        if !same_explicit
            && (paths_alias(wr_path, rfile)? || paths_alias(&target_in_canon_parent, rfile)?)
        {
            return Err(CliError::Message(format!(
                "--write-recipients path {} aliases --recipient-file path {}; \
                 use the same explicitly named path to refresh that source",
                wr_path.display(),
                rfile.display()
            )));
        }
    }

    #[cfg(unix)]
    let (leaf_cstr, existing_file_id, existing_mode, prior_bytes) = {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;

        let leaf_cstr = CString::new(leaf_os.as_bytes()).map_err(|_| {
            CliError::Message(format!(
                "invalid NUL byte in --write-recipients path {}",
                wr_path.display()
            ))
        })?;
        // SAFETY: `parent_dir` is an open directory FD and `leaf_cstr` is NUL-terminated.
        // `O_NOFOLLOW` guarantees we NEVER follow or canonicalize a leaf symlink.
        let fd = unsafe {
            libc::openat(
                parent_dir.as_raw_fd(),
                leaf_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                (leaf_cstr, None, None, None)
            } else if err.raw_os_error() == Some(libc::ELOOP) {
                return Err(CliError::Message(format!(
                    "refusing symlink in --write-recipients path {}; symlinks are not followed",
                    wr_path.display()
                )));
            } else {
                return Err(CliError::Io(err));
            }
        } else {
            // SAFETY: `fd` is a valid newly opened file descriptor.
            let mut file = unsafe { fs::File::from_raw_fd(fd) };
            let open_meta = file.metadata().map_err(CliError::Io)?;
            if is_symlink_or_reparse_point(&open_meta) {
                return Err(CliError::Message(format!(
                    "refusing symlink in --write-recipients path {}; symlinks are not followed",
                    wr_path.display()
                )));
            }
            if !open_meta.is_file() {
                return Err(CliError::Message(format!(
                    "--write-recipients target {} must be a regular file path",
                    wr_path.display()
                )));
            }
            let (open_id, open_nlink) = file_identity_and_nlink(&file).map_err(CliError::Io)?;
            if open_nlink != 1 {
                return Err(CliError::Message(format!(
                    "refusing hardlinked --write-recipients path {} (nlink = {open_nlink})",
                    wr_path.display()
                )));
            }
            let mut st: libc::stat = unsafe { core::mem::zeroed() };
            // SAFETY: `parent_dir` is an open directory FD and `leaf_cstr` is valid.
            let rc = unsafe {
                libc::fstatat(
                    parent_dir.as_raw_fd(),
                    leaf_cstr.as_ptr(),
                    &mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc != 0 {
                return Err(CliError::Io(std::io::Error::last_os_error()));
            }
            #[allow(clippy::unnecessary_cast)]
            let stat_id = (st.st_dev as u64, st.st_ino as u64);
            #[allow(clippy::unnecessary_cast)]
            let stat_nlink = st.st_nlink as u64;
            if stat_id != open_id || stat_nlink != 1 {
                return Err(CliError::ConcurrentModification {
                    path: wr_path.display().to_string(),
                });
            }
            let hint_len = open_meta.len();
            if hint_len > MAX_BATCH_RECIPIENT_FILE_BYTES {
                return Err(CliError::Message(format!(
                    "existing --write-recipients target {} exceeds the 1 MiB safety limit",
                    wr_path.display()
                )));
            }
            let cap = (hint_len as usize)
                .saturating_add(1)
                .min((MAX_BATCH_RECIPIENT_FILE_BYTES as usize).saturating_add(1));
            let mut buf = vec![0u8; cap];
            let mut total = 0usize;
            while total < buf.len() {
                match file.read(&mut buf[total..]) {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(err) => return Err(CliError::Io(err)),
                }
            }
            buf.truncate(total);
            if total == cap || (buf.len() as u64) > MAX_BATCH_RECIPIENT_FILE_BYTES {
                return Err(CliError::Message(format!(
                    "existing --write-recipients target {} exceeds the 1 MiB safety limit",
                    wr_path.display()
                )));
            }
            let mode = open_meta.permissions().mode() & 0o777;
            (leaf_cstr, Some(open_id), Some(mode), Some(buf))
        }
    };

    #[cfg(windows)]
    let (existing_file_id, prior_bytes) = {
        const GENERIC_READ: u32 = 0x8000_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_OPEN: u32 = 1;

        windows_dacl::recover_displaced_windows_entry_in_dir(&parent_dir, &leaf_os)
            .map_err(CliError::Io)?;

        match windows_dacl::open_relative_entry_nofollow(
            &parent_dir,
            &leaf_os,
            GENERIC_READ,
            FILE_SHARE_READ,
            FILE_OPEN,
            false,
        ) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (None, None),
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                return Err(CliError::Message(format!(
                    "refusing symlink in --write-recipients path {}; symlinks are not followed",
                    wr_path.display()
                )));
            }
            Err(err) => return Err(CliError::Io(err)),
            Ok(mut file) => {
                let open_meta = file.metadata().map_err(CliError::Io)?;
                if is_symlink_or_reparse_point(&open_meta) {
                    return Err(CliError::Message(format!(
                        "refusing symlink in --write-recipients path {}; symlinks are not followed",
                        wr_path.display()
                    )));
                }
                if !open_meta.is_file() {
                    return Err(CliError::Message(format!(
                        "--write-recipients target {} must be a regular file path",
                        wr_path.display()
                    )));
                }
                let (open_id, open_nlink) = file_identity_and_nlink(&file).map_err(CliError::Io)?;
                if open_nlink != 1 {
                    return Err(CliError::Message(format!(
                        "refusing hardlinked --write-recipients path {} (nlink = {open_nlink})",
                        wr_path.display()
                    )));
                }
                let (rel_id, rel_nlink) =
                    windows_dacl::stat_relative_nofollow(&parent_dir, &leaf_os)
                        .map_err(CliError::Io)?;
                if rel_id != open_id || rel_nlink != 1 {
                    return Err(CliError::ConcurrentModification {
                        path: wr_path.display().to_string(),
                    });
                }
                let hint_len = open_meta.len();
                if hint_len > MAX_BATCH_RECIPIENT_FILE_BYTES {
                    return Err(CliError::Message(format!(
                        "existing --write-recipients target {} exceeds the 1 MiB safety limit",
                        wr_path.display()
                    )));
                }
                let cap = (hint_len as usize)
                    .saturating_add(1)
                    .min((MAX_BATCH_RECIPIENT_FILE_BYTES as usize).saturating_add(1));
                let mut buf = vec![0u8; cap];
                let mut total = 0usize;
                while total < buf.len() {
                    match file.read(&mut buf[total..]) {
                        Ok(0) => break,
                        Ok(n) => total += n,
                        Err(err) => return Err(CliError::Io(err)),
                    }
                }
                buf.truncate(total);
                if total == cap || (buf.len() as u64) > MAX_BATCH_RECIPIENT_FILE_BYTES {
                    return Err(CliError::Message(format!(
                        "existing --write-recipients target {} exceeds the 1 MiB safety limit",
                        wr_path.display()
                    )));
                }
                (Some(open_id), Some(buf))
            }
        }
    };

    let mut content = target_strings.join("\n").into_bytes();
    content.push(b'\n');

    Ok(BatchRecipientRefreshPlan {
        user_path: wr_path.to_path_buf(),
        canon_parent,
        parent_dir,
        parent_id,
        #[cfg(windows)]
        leaf_name: leaf_os,
        #[cfg(unix)]
        leaf_cstr,
        content,
        existing_file_id,
        #[cfg(unix)]
        existing_mode,
        prior_bytes,
    })
}

fn commit_batch_recipient_refresh(plan: &BatchRecipientRefreshPlan) -> CliResult<()> {
    let inner = (|| -> CliResult<()> {
        reject_symlink_traversal_in_path(&plan.user_path, "--write-recipients", true)?;
        let user_parent = plan
            .user_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let (_, current_canon_parent, current_parent_id) =
            open_dir_nofollow_anchored(user_parent, "--write-recipients")?;
        let (handle_parent_id, _) =
            file_identity_and_nlink(&plan.parent_dir).map_err(CliError::Io)?;
        if current_parent_id != plan.parent_id
            || handle_parent_id != plan.parent_id
            || current_canon_parent != plan.canon_parent
        {
            return Err(CliError::ConcurrentModification {
                path: plan.user_path.display().to_string(),
            });
        }

        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::io::Write;
            use std::os::fd::{AsRawFd, FromRawFd};
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            struct UnixFlockGuard(libc::c_int);
            impl Drop for UnixFlockGuard {
                fn drop(&mut self) {
                    // SAFETY: `self.0` is an open file descriptor locked by this guard.
                    unsafe {
                        let _ = libc::flock(self.0, libc::LOCK_UN);
                    }
                }
            }

            let parent_fd = plan.parent_dir.as_raw_fd();
            // Serialize cooperative namespace writers on `parent_fd` across the entire
            // staging, atomic exchange, and isolated displacement cleanup sequence.
            // SAFETY: `parent_fd` is a valid open directory FD.
            if unsafe { libc::flock(parent_fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(CliError::ConcurrentModification {
                    path: plan.user_path.display().to_string(),
                });
            }
            let _parent_lock = UnixFlockGuard(parent_fd);

            // SAFETY: `getuid` has no memory-safety preconditions and cannot fail.
            let current_uid = unsafe { libc::getuid() };
            let parent_meta = plan.parent_dir.metadata().map_err(CliError::Io)?;
            validate_unix_directory_owner_and_mode(
                current_uid,
                parent_meta.uid(),
                parent_meta.permissions().mode(),
                true,
                &plan.canon_parent,
            )?;

            let pid = std::process::id();
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let create_mode: libc::c_uint = if plan.existing_mode.is_some() {
                0o600
            } else {
                0o644
            };

            // Create a three-level staging hierarchy inside `parent_fd`:
            // `outer_dir` (`.seclusor-rcpt-<pid>-<ts>-<attempt>.tmp`, created mode `0o300` so it
            // is NEVER readable by `opendir` / `getdents`) -> `mid_dir` (`.m-<64-csprng-hex>`,
            // created mode `0o300`) -> `inner_dir` (`"s"`).
            // Critically:
            // 1. `outer_dir` is created mode `0o300` (no `0o400` read bit) and `mid_dir` has a
            //    256-bit CSPRNG name, so no process can enumerate `outer_dir` or guess `mid_dir`.
            // 2. `outer_dir` is sealed to `0o000` (`fchmodat(parent_fd, outer_cstr, 0, 0)`)
            //    BEFORE `inner_dir` (`"s"`) is created inside `mid_fd`, and `mid_fd` is sealed
            //    to `0o000` (`fchmod(mid_fd, 0)`) BEFORE `"t"` is created inside `inner_fd`.
            //    Thus `inner_dir` does not even exist while `outer_dir` is traversable, and no
            //    other process can ever open or retain a descriptor to `inner_dir`.
            // 3. Immediately after `atomic_swap_entries`, `inner_fd` itself is sealed to `0o500`
            //    (`fchmod(inner_fd, 0o500)`) while verifying the displaced inode at `(inner_fd, "t")`,
            //    preventing even a hypothetical retained `inner_fd` descriptor from mutating
            //    `(inner_fd, "t")`; if any mismatch is observed, the staging entry is preserved
            //    without calling `unlinkat`.
            let mut csprng_bytes = [0u8; 32];
            fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut csprng_bytes))
                .map_err(CliError::Io)?;
            let mut mid_hex = String::with_capacity(66);
            mid_hex.push_str(".m-");
            for b in &csprng_bytes {
                use std::fmt::Write as _;
                let _ = write!(&mut mid_hex, "{b:02x}");
            }
            let mid_cstr = CString::new(mid_hex).expect("valid CString");
            let inner_cstr = CString::new("s").expect("valid CString");
            let staged_cstr = CString::new("t").expect("valid CString");

            #[cfg(target_os = "macos")]
            const DIR_SEARCH_OPEN_FLAGS: libc::c_int =
                libc::O_EXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            #[cfg(not(target_os = "macos"))]
            const DIR_SEARCH_OPEN_FLAGS: libc::c_int =
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            #[cfg(target_os = "macos")]
            const OUTER_INIT_MODE: libc::mode_t = 0o300;
            #[cfg(not(target_os = "macos"))]
            const OUTER_INIT_MODE: libc::mode_t = 0o700;

            let mut outer_cstr_opt = None;
            let mut outer_dir_opt = None;
            for attempt in 0..64u32 {
                let candidate =
                    CString::new(format!(".seclusor-rcpt-{pid}-{ts}-{attempt}.tmp")).unwrap();
                // SAFETY: `parent_fd` is an open directory FD and `candidate` is NUL-terminated.
                let mkdir_rc =
                    unsafe { libc::mkdirat(parent_fd, candidate.as_ptr(), OUTER_INIT_MODE) };
                if mkdir_rc == 0 {
                    // SAFETY: `parent_fd` and `candidate` are valid.
                    let ofd = unsafe {
                        libc::openat(parent_fd, candidate.as_ptr(), DIR_SEARCH_OPEN_FLAGS)
                    };
                    if ofd < 0 {
                        let err = std::io::Error::last_os_error();
                        unsafe {
                            let _ =
                                libc::unlinkat(parent_fd, candidate.as_ptr(), libc::AT_REMOVEDIR);
                        }
                        return Err(CliError::Io(err));
                    }
                    // SAFETY: `ofd` is a valid newly opened directory FD.
                    let ofile = unsafe { fs::File::from_raw_fd(ofd) };
                    outer_cstr_opt = Some(candidate);
                    outer_dir_opt = Some(ofile);
                    break;
                }
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    continue;
                }
                return Err(CliError::Io(err));
            }
            let outer_cstr = outer_cstr_opt.ok_or_else(|| {
                CliError::Message(
                    "failed to allocate unique temporary recipient staging directory".to_string(),
                )
            })?;
            let outer_dir = outer_dir_opt.expect("outer_dir set with outer_cstr");
            let outer_fd = outer_dir.as_raw_fd();

            // Create `mid_dir` (`.m-<64-csprng-hex>`) inside `0o300` `outer_dir` and open `mid_fd`.
            // SAFETY: `outer_fd` and `mid_cstr` are valid.
            if unsafe { libc::mkdirat(outer_fd, mid_cstr.as_ptr(), OUTER_INIT_MODE) } != 0 {
                let err = std::io::Error::last_os_error();
                drop(outer_dir);
                unsafe {
                    let _ = libc::unlinkat(parent_fd, outer_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(CliError::Io(err));
            }
            // SAFETY: `outer_fd` and `mid_cstr` are valid.
            let mid_raw_fd =
                unsafe { libc::openat(outer_fd, mid_cstr.as_ptr(), DIR_SEARCH_OPEN_FLAGS) };
            if mid_raw_fd < 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    let _ = libc::unlinkat(outer_fd, mid_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                drop(outer_dir);
                unsafe {
                    let _ = libc::unlinkat(parent_fd, outer_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(CliError::Io(err));
            }
            // SAFETY: `mid_raw_fd` is a valid newly opened directory FD.
            let mid_dir = unsafe { fs::File::from_raw_fd(mid_raw_fd) };
            let mid_fd = mid_dir.as_raw_fd();

            // Seal `outer_fd` to mode `0o000` BEFORE `inner_dir` (`"s"`) is created inside `mid_fd`,
            // so `outer_dir` is already non-traversable before `inner_dir` ever exists.
            // SAFETY: `outer_fd` is an open directory FD.
            if unsafe { libc::fchmod(outer_fd, 0) } != 0 {
                let err = std::io::Error::last_os_error();
                drop(mid_dir);
                unsafe {
                    let _ = libc::fchmod(outer_fd, 0o700);
                    let _ = libc::unlinkat(outer_fd, mid_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                drop(outer_dir);
                unsafe {
                    let _ = libc::unlinkat(parent_fd, outer_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(CliError::Io(err));
            }

            // Now create `inner_dir` (`"s"`) inside `mid_fd` via the open descriptor while
            // `outer_dir` is already sealed to `0o000`.
            // SAFETY: `mid_fd` and `inner_cstr` are valid.
            if unsafe { libc::mkdirat(mid_fd, inner_cstr.as_ptr(), 0o700) } != 0 {
                let err = std::io::Error::last_os_error();
                drop(mid_dir);
                unsafe {
                    let _ = libc::fchmod(outer_fd, 0o700);
                    let _ = libc::unlinkat(outer_fd, mid_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                drop(outer_dir);
                unsafe {
                    let _ = libc::unlinkat(parent_fd, outer_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(CliError::Io(err));
            }
            // SAFETY: `mid_fd` and `inner_cstr` are valid.
            let inner_raw_fd = unsafe {
                libc::openat(
                    mid_fd,
                    inner_cstr.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if inner_raw_fd < 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    let _ = libc::unlinkat(mid_fd, inner_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                drop(mid_dir);
                unsafe {
                    let _ = libc::fchmod(outer_fd, 0o700);
                    let _ = libc::unlinkat(outer_fd, mid_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                drop(outer_dir);
                unsafe {
                    let _ = libc::unlinkat(parent_fd, outer_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(CliError::Io(err));
            }
            // SAFETY: `inner_raw_fd` is a valid newly opened directory FD.
            let inner_dir = unsafe { fs::File::from_raw_fd(inner_raw_fd) };
            let inner_fd = inner_dir.as_raw_fd();

            // Seal `mid_fd` to mode `0o000` BEFORE `"t"` is ever created inside `inner_fd`.
            // Notice that `"t"` does not exist yet, so if `fchmod(mid_fd, 0)` fails, only
            // `AT_REMOVEDIR` directory cleanup runs (no file `unlinkat` on unsealed staging).
            // SAFETY: `mid_fd` is an open directory FD.
            if unsafe { libc::fchmod(mid_fd, 0) } != 0 {
                let err = std::io::Error::last_os_error();
                drop(inner_dir);
                unsafe {
                    let _ = libc::fchmod(mid_fd, 0o700);
                    let _ = libc::unlinkat(mid_fd, inner_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                drop(mid_dir);
                unsafe {
                    let _ = libc::fchmod(outer_fd, 0o700);
                    let _ = libc::unlinkat(outer_fd, mid_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                drop(outer_dir);
                unsafe {
                    let _ = libc::unlinkat(parent_fd, outer_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(CliError::Io(err));
            }

            #[cfg(test)]
            run_batch_recipient_post_inner_fd_hook(inner_fd);

            let (outer_id, _) = file_identity_and_nlink(&outer_dir).map_err(CliError::Io)?;
            let (mid_id, _) = file_identity_and_nlink(&mid_dir).map_err(CliError::Io)?;
            let (inner_id, _) = file_identity_and_nlink(&inner_dir).map_err(CliError::Io)?;
            let preserved_staged_path = plan
                .canon_parent
                .join(outer_cstr.to_string_lossy().as_ref())
                .join(mid_cstr.to_string_lossy().as_ref())
                .join("s")
                .join("t");

            // Unlock `outer_fd`, `mid_fd`, and `inner_fd` to `0o700` when preserving uncertain
            // artifacts on disk so the operator or test harness can inspect or recover them.
            let expose_preserved_staging = || {
                // SAFETY: `outer_fd`, `mid_fd`, and `inner_fd` are open directory FDs.
                unsafe {
                    let _ = libc::fchmod(inner_fd, 0o700);
                    let _ = libc::fchmod(mid_fd, 0o700);
                    let _ = libc::fchmod(outer_fd, 0o700);
                }
            };

            // SAFETY: `inner_fd` and `staged_cstr` are valid; both `outer_fd` and `mid_fd`
            // are already sealed to mode `0o000`.
            let temp_raw_fd = unsafe {
                libc::openat(
                    inner_fd,
                    staged_cstr.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    create_mode,
                )
            };
            if temp_raw_fd < 0 {
                let err = std::io::Error::last_os_error();
                expose_preserved_staging();
                drop(inner_dir);
                unsafe {
                    let _ = libc::unlinkat(mid_fd, inner_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                drop(mid_dir);
                unsafe {
                    let _ = libc::unlinkat(outer_fd, mid_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                drop(outer_dir);
                unsafe {
                    let _ = libc::unlinkat(parent_fd, outer_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(CliError::Io(err));
            }
            // SAFETY: `temp_raw_fd` is a valid newly opened file FD.
            let mut temp_file = unsafe { fs::File::from_raw_fd(temp_raw_fd) };

            // Only unlink `"t"` inside `inner_fd` when `outer_fd` and `mid_fd` are proven by
            // handle (`fstat`) to still have mode `0o000`, `inner_fd` is sealed to `0o500`
            // during the `fstatat` verification of `(inner_fd, "t")` (so even a hypothetical
            // retained `inner_fd` descriptor cannot mutate `inner_fd` while `(inner_fd, "t")`
            // is verified), and `(inner_fd, "t")` matches `expected_unlink_id` with `nlink == 1`.
            let cleanup_isolated_staging = |expected_unlink_id: (u64, u64)| -> bool {
                // Seal `inner_fd` to read/search-only (`0o500`) BEFORE inspecting `(inner_fd, "t")`
                // so no descriptor to `inner_fd` can rename, link, or swap entries inside `inner_fd`
                // between `fstatat` and `unlinkat`.
                // SAFETY: `inner_fd` is an open directory FD.
                if unsafe { libc::fchmod(inner_fd, 0o500) } != 0 {
                    expose_preserved_staging();
                    return false;
                }
                let mut outer_st: libc::stat = unsafe { core::mem::zeroed() };
                let mut mid_st: libc::stat = unsafe { core::mem::zeroed() };
                let mut inner_st: libc::stat = unsafe { core::mem::zeroed() };
                let mut staged_st: libc::stat = unsafe { core::mem::zeroed() };
                // SAFETY: `outer_fd`, `mid_fd`, `inner_fd`, and `staged_cstr` are valid.
                let outer_rc = unsafe { libc::fstat(outer_fd, &mut outer_st) };
                let mid_rc = unsafe { libc::fstat(mid_fd, &mut mid_st) };
                let inner_rc = unsafe { libc::fstat(inner_fd, &mut inner_st) };
                let staged_rc = unsafe {
                    libc::fstatat(
                        inner_fd,
                        staged_cstr.as_ptr(),
                        &mut staged_st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if outer_rc != 0 || mid_rc != 0 || inner_rc != 0 || staged_rc != 0 {
                    expose_preserved_staging();
                    return false;
                }
                #[allow(clippy::unnecessary_cast)]
                let cur_outer_id = (outer_st.st_dev as u64, outer_st.st_ino as u64);
                #[allow(clippy::unnecessary_cast)]
                let cur_outer_mode = (outer_st.st_mode as u32) & 0o777;
                #[allow(clippy::unnecessary_cast)]
                let cur_mid_id = (mid_st.st_dev as u64, mid_st.st_ino as u64);
                #[allow(clippy::unnecessary_cast)]
                let cur_mid_mode = (mid_st.st_mode as u32) & 0o777;
                #[allow(clippy::unnecessary_cast)]
                let cur_inner_id = (inner_st.st_dev as u64, inner_st.st_ino as u64);
                #[allow(clippy::unnecessary_cast)]
                let cur_inner_mode = (inner_st.st_mode as u32) & 0o777;
                #[allow(clippy::unnecessary_cast)]
                let cur_staged_id = (staged_st.st_dev as u64, staged_st.st_ino as u64);
                #[allow(clippy::unnecessary_cast)]
                let cur_staged_nlink = staged_st.st_nlink as u64;
                if cur_outer_id != outer_id
                    || cur_outer_mode != 0
                    || cur_mid_id != mid_id
                    || cur_mid_mode != 0
                    || cur_inner_id != inner_id
                    || cur_inner_mode != 0o500
                    || cur_staged_id != expected_unlink_id
                    || cur_staged_nlink != 1
                {
                    expose_preserved_staging();
                    return false;
                }
                // SAFETY: `outer_fd` and `mid_fd` are mode `0o000`, `inner_fd` was verified while
                // sealed at `0o500`, and `(inner_fd, "t")` is proven to be `expected_unlink_id`
                // with `nlink == 1`. Restore `0o700` on `inner_fd` to unlink `"t"`, then remove
                // the empty staging directories with `AT_REMOVEDIR`.
                let unlinked = unsafe {
                    libc::fchmod(inner_fd, 0o700) == 0
                        && libc::unlinkat(inner_fd, staged_cstr.as_ptr(), 0) == 0
                };
                if !unlinked {
                    expose_preserved_staging();
                    return false;
                }
                unsafe {
                    let _ = libc::fchmod(mid_fd, 0o700);
                    let _ = libc::unlinkat(mid_fd, inner_cstr.as_ptr(), libc::AT_REMOVEDIR);
                    let _ = libc::fchmod(outer_fd, 0o700);
                    let _ = libc::unlinkat(outer_fd, mid_cstr.as_ptr(), libc::AT_REMOVEDIR);
                    let _ = libc::unlinkat(parent_fd, outer_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
                true
            };

            let (temp_id, temp_nlink) = match file_identity_and_nlink(&temp_file) {
                Ok(v) => v,
                Err(err) => {
                    drop(temp_file);
                    expose_preserved_staging();
                    return Err(CliError::Io(err));
                }
            };
            if temp_nlink != 1 {
                drop(temp_file);
                expose_preserved_staging();
                return Err(CliError::ConcurrentModification {
                    path: plan.user_path.display().to_string(),
                });
            }

            if let Some(mode) = plan.existing_mode {
                // SAFETY: `temp_file` is an open regular file FD.
                let rc = unsafe { libc::fchmod(temp_file.as_raw_fd(), mode as libc::mode_t) };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    drop(temp_file);
                    let _ = cleanup_isolated_staging(temp_id);
                    return Err(CliError::Io(err));
                }
            }

            // Lock and keep `temp_file` open across publication so the staged inode
            // cannot be modified or replaced before or during atomic exchange.
            // SAFETY: `temp_file` is a valid open file descriptor.
            if unsafe { libc::flock(temp_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                drop(temp_file);
                expose_preserved_staging();
                return Err(CliError::ConcurrentModification {
                    path: plan.user_path.display().to_string(),
                });
            }
            let _temp_lock = UnixFlockGuard(temp_file.as_raw_fd());

            if let Err(err) = temp_file
                .write_all(&plan.content)
                .and_then(|()| temp_file.sync_all())
            {
                drop(_temp_lock);
                drop(temp_file);
                let _ = cleanup_isolated_staging(temp_id);
                return Err(CliError::Io(err));
            }

            if let Some(expected_id) = plan.existing_file_id {
                let expected_bytes = plan.prior_bytes.as_deref().unwrap_or(&[]);
                // SAFETY: `parent_fd` is an open directory FD and `leaf_cstr` is valid.
                let target_fd = unsafe {
                    libc::openat(
                        parent_fd,
                        plan.leaf_cstr.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                    )
                };
                if target_fd < 0 {
                    let err = std::io::Error::last_os_error();
                    drop(_temp_lock);
                    drop(temp_file);
                    let _ = cleanup_isolated_staging(temp_id);
                    if err.kind() == std::io::ErrorKind::NotFound
                        || err.raw_os_error() == Some(libc::ELOOP)
                    {
                        return Err(CliError::ConcurrentModification {
                            path: plan.user_path.display().to_string(),
                        });
                    }
                    return Err(CliError::Io(err));
                }
                // SAFETY: `target_fd` is a valid open file descriptor.
                let mut target_file = unsafe { fs::File::from_raw_fd(target_fd) };
                // SAFETY: `target_file` is a valid open file descriptor.
                if unsafe { libc::flock(target_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }
                    != 0
                {
                    drop(target_file);
                    drop(_temp_lock);
                    drop(temp_file);
                    let _ = cleanup_isolated_staging(temp_id);
                    return Err(CliError::ConcurrentModification {
                        path: plan.user_path.display().to_string(),
                    });
                }
                let _target_lock = UnixFlockGuard(target_file.as_raw_fd());

                let open_meta = target_file.metadata().map_err(CliError::Io)?;
                if !open_meta.is_file() || is_symlink_or_reparse_point(&open_meta) {
                    drop(_target_lock);
                    drop(target_file);
                    drop(_temp_lock);
                    drop(temp_file);
                    let _ = cleanup_isolated_staging(temp_id);
                    return Err(CliError::ConcurrentModification {
                        path: plan.user_path.display().to_string(),
                    });
                }
                let (open_id, open_nlink) =
                    file_identity_and_nlink(&target_file).map_err(CliError::Io)?;
                let mut st: libc::stat = unsafe { core::mem::zeroed() };
                // SAFETY: `parent_fd` is an open directory FD and `leaf_cstr` is valid.
                let stat_rc = unsafe {
                    libc::fstatat(
                        parent_fd,
                        plan.leaf_cstr.as_ptr(),
                        &mut st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if stat_rc != 0 {
                    drop(_target_lock);
                    drop(target_file);
                    drop(_temp_lock);
                    drop(temp_file);
                    let _ = cleanup_isolated_staging(temp_id);
                    return Err(CliError::ConcurrentModification {
                        path: plan.user_path.display().to_string(),
                    });
                }
                #[allow(clippy::unnecessary_cast)]
                let stat_id = (st.st_dev as u64, st.st_ino as u64);
                #[allow(clippy::unnecessary_cast)]
                let stat_nlink = st.st_nlink as u64;
                #[allow(clippy::unnecessary_cast)]
                let stat_mode = (st.st_mode as u32) & 0o777;
                if open_id != expected_id
                    || stat_id != expected_id
                    || open_nlink != 1
                    || stat_nlink != 1
                    || Some(stat_mode) != plan.existing_mode
                    || open_meta.len() != expected_bytes.len() as u64
                {
                    drop(_target_lock);
                    drop(target_file);
                    drop(_temp_lock);
                    drop(temp_file);
                    let _ = cleanup_isolated_staging(temp_id);
                    return Err(CliError::ConcurrentModification {
                        path: plan.user_path.display().to_string(),
                    });
                }
                let cap = expected_bytes.len().saturating_add(1);
                let mut buf = vec![0u8; cap];
                let mut total = 0usize;
                while total < buf.len() {
                    match target_file.read(&mut buf[total..]) {
                        Ok(0) => break,
                        Ok(n) => total += n,
                        Err(err) => {
                            drop(_target_lock);
                            drop(target_file);
                            drop(_temp_lock);
                            drop(temp_file);
                            let _ = cleanup_isolated_staging(temp_id);
                            return Err(CliError::Io(err));
                        }
                    }
                }
                if total == cap || &buf[..total] != expected_bytes {
                    drop(_target_lock);
                    drop(target_file);
                    drop(_temp_lock);
                    drop(temp_file);
                    let _ = cleanup_isolated_staging(temp_id);
                    return Err(CliError::ConcurrentModification {
                        path: plan.user_path.display().to_string(),
                    });
                }

                let mut pre_temp_st: libc::stat = unsafe { core::mem::zeroed() };
                // SAFETY: `inner_fd` and `staged_cstr` are valid.
                if unsafe {
                    libc::fstatat(
                        inner_fd,
                        staged_cstr.as_ptr(),
                        &mut pre_temp_st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    drop(_target_lock);
                    drop(target_file);
                    drop(_temp_lock);
                    drop(temp_file);
                    expose_preserved_staging();
                    return Err(CliError::ConcurrentModification {
                        path: plan.user_path.display().to_string(),
                    });
                }
                #[allow(clippy::unnecessary_cast)]
                let pre_temp_stat_id = (pre_temp_st.st_dev as u64, pre_temp_st.st_ino as u64);
                #[allow(clippy::unnecessary_cast)]
                let pre_temp_stat_nlink = pre_temp_st.st_nlink as u64;
                let (cur_temp_id, cur_temp_nlink) =
                    file_identity_and_nlink(&temp_file).map_err(CliError::Io)?;
                if pre_temp_stat_id != temp_id
                    || cur_temp_id != temp_id
                    || pre_temp_stat_nlink != 1
                    || cur_temp_nlink != 1
                {
                    drop(_target_lock);
                    drop(target_file);
                    drop(_temp_lock);
                    drop(temp_file);
                    expose_preserved_staging();
                    return Err(CliError::ConcurrentModification {
                        path: plan.user_path.display().to_string(),
                    });
                }

                #[cfg(test)]
                run_batch_recipient_post_stat_hook();

                // Atomically exchange `(inner_fd, "t")` and `(parent_fd, leaf_cstr)`.
                // Because `outer_fd` is mode `0o000`, the displaced destination inode moves
                // directly into the `0o000`-gated `inner_fd` where no path-based writer
                // can traverse `outer_dir` to swap or unlink it.
                // SAFETY: `inner_fd`, `staged_cstr`, `parent_fd`, and `leaf_cstr` are valid.
                if let Err(err) = unsafe {
                    atomic_swap_entries(
                        inner_fd,
                        staged_cstr.as_ptr(),
                        parent_fd,
                        plan.leaf_cstr.as_ptr(),
                    )
                } {
                    drop(_target_lock);
                    drop(target_file);
                    drop(_temp_lock);
                    drop(temp_file);
                    let _ = cleanup_isolated_staging(temp_id);
                    return Err(CliError::Io(err));
                }

                #[cfg(test)]
                run_batch_recipient_post_exchange_hook();

                let mut displaced_st: libc::stat = unsafe { core::mem::zeroed() };
                let mut published_st: libc::stat = unsafe { core::mem::zeroed() };
                // SAFETY: `inner_fd`, `staged_cstr`, `parent_fd`, and `leaf_cstr` are valid.
                let disp_rc = unsafe {
                    libc::fstatat(
                        inner_fd,
                        staged_cstr.as_ptr(),
                        &mut displaced_st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                let pub_rc = unsafe {
                    libc::fstatat(
                        parent_fd,
                        plan.leaf_cstr.as_ptr(),
                        &mut published_st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                #[allow(clippy::unnecessary_cast)]
                let displaced_id = (displaced_st.st_dev as u64, displaced_st.st_ino as u64);
                #[allow(clippy::unnecessary_cast)]
                let displaced_nlink = displaced_st.st_nlink as u64;
                #[allow(clippy::unnecessary_cast)]
                let published_id = (published_st.st_dev as u64, published_st.st_ino as u64);
                #[allow(clippy::unnecessary_cast)]
                let published_nlink = published_st.st_nlink as u64;

                if disp_rc != 0
                    || pub_rc != 0
                    || displaced_id != expected_id
                    || displaced_nlink != 1
                    || published_id != temp_id
                    || published_nlink != 1
                {
                    // Roll back the swap when `leaf_cstr` still holds our published `temp_id`
                    // so the substituted entry at `(inner_fd, "t")` is swapped back to `leaf_cstr`.
                    let rb_swap_ok = if pub_rc == 0 && published_id == temp_id {
                        // SAFETY: `inner_fd`, `staged_cstr`, `parent_fd`, and `leaf_cstr` are valid.
                        unsafe {
                            atomic_swap_entries(
                                inner_fd,
                                staged_cstr.as_ptr(),
                                parent_fd,
                                plan.leaf_cstr.as_ptr(),
                            )
                            .is_ok()
                        }
                    } else {
                        false
                    };
                    let mut rb_staged_st: libc::stat = unsafe { core::mem::zeroed() };
                    let mut rb_leaf_st: libc::stat = unsafe { core::mem::zeroed() };
                    // SAFETY: `inner_fd`, `staged_cstr`, `parent_fd`, and `leaf_cstr` are valid.
                    let rb_staged_rc = unsafe {
                        libc::fstatat(
                            inner_fd,
                            staged_cstr.as_ptr(),
                            &mut rb_staged_st,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    };
                    let rb_leaf_rc = unsafe {
                        libc::fstatat(
                            parent_fd,
                            plan.leaf_cstr.as_ptr(),
                            &mut rb_leaf_st,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    };
                    #[allow(clippy::unnecessary_cast)]
                    let rb_staged_id = (rb_staged_st.st_dev as u64, rb_staged_st.st_ino as u64);
                    #[allow(clippy::unnecessary_cast)]
                    let rb_leaf_id = (rb_leaf_st.st_dev as u64, rb_leaf_st.st_ino as u64);

                    let restored = rb_swap_ok
                        && disp_rc == 0
                        && rb_staged_rc == 0
                        && rb_leaf_rc == 0
                        && rb_staged_id == temp_id
                        && rb_leaf_id == displaced_id;

                    drop(_target_lock);
                    drop(target_file);
                    drop(_temp_lock);
                    drop(temp_file);

                    // Preserve uncertain artifacts on any post-exchange rollback: never call
                    // `unlinkat` after an exchange mismatch has been observed, even when
                    // reverse swap restored `leaf_cstr`.
                    expose_preserved_staging();
                    if !restored {
                        return Err(CliError::Message(format!(
                            "concurrent modification detected during --write-recipients publication for {}; \
                             automatic rollback could not restore destination entry; displaced file preserved at {}",
                            plan.user_path.display(),
                            preserved_staged_path.display()
                        )));
                    }

                    return Err(CliError::ConcurrentModification {
                        path: plan.user_path.display().to_string(),
                    });
                }

                // The displaced entry at `(inner_fd, "t")` is proven to be `expected_id`
                // inside the `0o000`-gated staging directory; unlink it inside `inner_fd`
                // and confirm `target_file`'s link count dropped to 0.
                if !cleanup_isolated_staging(expected_id) {
                    drop(_target_lock);
                    drop(target_file);
                    drop(_temp_lock);
                    drop(temp_file);
                    return Err(CliError::ConcurrentModification {
                        path: plan.user_path.display().to_string(),
                    });
                }
                let (after_target_id, after_target_nlink) =
                    file_identity_and_nlink(&target_file).map_err(CliError::Io)?;
                drop(_target_lock);
                drop(target_file);
                if after_target_id != expected_id || after_target_nlink != 0 {
                    drop(_temp_lock);
                    drop(temp_file);
                    return Err(CliError::ConcurrentModification {
                        path: plan.user_path.display().to_string(),
                    });
                }
            } else {
                // Target did not exist at preparation time: publish with atomic no-clobber
                // (`linkat`) from `(inner_fd, "t")` to `(parent_fd, leaf_cstr)`, then
                // remove `(inner_fd, "t")` inside the `0o000`-gated staging directory.
                // SAFETY: `inner_fd`, `staged_cstr`, `parent_fd`, and `leaf_cstr` are valid.
                let link_rc = unsafe {
                    libc::linkat(
                        inner_fd,
                        staged_cstr.as_ptr(),
                        parent_fd,
                        plan.leaf_cstr.as_ptr(),
                        0,
                    )
                };
                if link_rc != 0 {
                    let err = std::io::Error::last_os_error();
                    drop(_temp_lock);
                    drop(temp_file);
                    let _ = cleanup_isolated_staging(temp_id);
                    if err.kind() == std::io::ErrorKind::AlreadyExists {
                        return Err(CliError::ConcurrentModification {
                            path: plan.user_path.display().to_string(),
                        });
                    }
                    return Err(CliError::Io(err));
                }
                let (linked_id, linked_nlink) =
                    file_identity_and_nlink(&temp_file).map_err(CliError::Io)?;
                if linked_id != temp_id || linked_nlink != 2 {
                    drop(_temp_lock);
                    drop(temp_file);
                    expose_preserved_staging();
                    return Err(CliError::ConcurrentModification {
                        path: plan.user_path.display().to_string(),
                    });
                }
                // Seal `inner_fd` to `0o500` BEFORE inspecting `(inner_fd, "t")` and verify
                // that `(inner_fd, "t")` is still `temp_id` with `nlink == 2` before unlinking.
                // SAFETY: `inner_fd`, `mid_fd`, `outer_fd`, and `staged_cstr` are valid.
                if unsafe { libc::fchmod(inner_fd, 0o500) } != 0 {
                    drop(_temp_lock);
                    drop(temp_file);
                    expose_preserved_staging();
                    return Err(CliError::Io(std::io::Error::last_os_error()));
                }
                let mut cur_staged_st: libc::stat = unsafe { core::mem::zeroed() };
                let cur_staged_rc = unsafe {
                    libc::fstatat(
                        inner_fd,
                        staged_cstr.as_ptr(),
                        &mut cur_staged_st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                #[allow(clippy::unnecessary_cast)]
                let cur_staged_id = (cur_staged_st.st_dev as u64, cur_staged_st.st_ino as u64);
                #[allow(clippy::unnecessary_cast)]
                let cur_staged_nlink = cur_staged_st.st_nlink as u64;
                if cur_staged_rc != 0 || cur_staged_id != temp_id || cur_staged_nlink != 2 {
                    drop(_temp_lock);
                    drop(temp_file);
                    expose_preserved_staging();
                    return Err(CliError::ConcurrentModification {
                        path: plan.user_path.display().to_string(),
                    });
                }
                unsafe {
                    let _ = libc::fchmod(inner_fd, 0o700);
                    let _ = libc::unlinkat(inner_fd, staged_cstr.as_ptr(), 0);
                    let _ = libc::fchmod(mid_fd, 0o700);
                    let _ = libc::unlinkat(mid_fd, inner_cstr.as_ptr(), libc::AT_REMOVEDIR);
                    let _ = libc::fchmod(outer_fd, 0o700);
                    let _ = libc::unlinkat(outer_fd, mid_cstr.as_ptr(), libc::AT_REMOVEDIR);
                    let _ = libc::unlinkat(parent_fd, outer_cstr.as_ptr(), libc::AT_REMOVEDIR);
                }
            }

            let (final_temp_id, final_temp_nlink) =
                file_identity_and_nlink(&temp_file).map_err(CliError::Io)?;
            drop(_temp_lock);
            drop(temp_file);
            if final_temp_id != temp_id || final_temp_nlink != 1 {
                return Err(CliError::ConcurrentModification {
                    path: plan.user_path.display().to_string(),
                });
            }

            let mut pub_st: libc::stat = unsafe { core::mem::zeroed() };
            // SAFETY: `parent_fd` and `leaf_cstr` are valid.
            let pub_rc = unsafe {
                libc::fstatat(
                    parent_fd,
                    plan.leaf_cstr.as_ptr(),
                    &mut pub_st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if pub_rc != 0 {
                return Err(CliError::Io(std::io::Error::last_os_error()));
            }
            #[allow(clippy::unnecessary_cast)]
            let pub_id = (pub_st.st_dev as u64, pub_st.st_ino as u64);
            #[allow(clippy::unnecessary_cast)]
            let pub_nlink = pub_st.st_nlink as u64;
            if pub_id != temp_id || pub_nlink != 1 {
                return Err(CliError::ConcurrentModification {
                    path: plan.user_path.display().to_string(),
                });
            }
            plan.parent_dir.sync_all().map_err(CliError::Io)?;
        }

        #[cfg(windows)]
        {
            windows_dacl::commit_batch_recipient_refresh_windows(
                &plan.parent_dir,
                &plan.canon_parent,
                plan.parent_id,
                &plan.leaf_name,
                &plan.content,
                plan.existing_file_id,
                plan.prior_bytes.as_deref(),
            )?;
        }

        Ok(())
    })();

    inner.map_err(|source| CliError::RecipientRefreshFailed {
        output_path: "<blob-rekey-batch>".to_string(),
        recipient_path: plan.user_path.display().to_string(),
        source: Box::new(source),
    })
}

#[cfg(test)]
pub(crate) fn handle_blob_rekey_batch(args: BlobRekeyBatchArgs) -> CliResult<()> {
    handle_blob_rekey_batch_with_policy(args, false)
}

pub(crate) fn handle_blob_rekey_batch_with_policy(
    args: BlobRekeyBatchArgs,
    allow_recipient_mismatch: bool,
) -> CliResult<()> {
    // 1. Explicit recipient channel required (never fall back to SECLUSOR_RECIPIENTS).
    if !recipient_channels_present(&args.recipients) {
        return Err(CliError::Message(
            "blob rekey-batch requires at least one of --recipient, --recipient-file, or \
             --recipient-env-var (implicit SECLUSOR_RECIPIENTS fallback is not used for rekey)"
                .to_string(),
        ));
    }
    if args.backup && !args.apply {
        return Err(CliError::Message(
            "--backup is only valid with --apply (plan mode writes nothing)".to_string(),
        ));
    }
    if !args.apply && args.write_recipients.is_some() {
        return Err(CliError::Message(
            "--write-recipients is only valid with --apply (plan mode writes nothing)".to_string(),
        ));
    }

    let selected_files = collect_batch_files(&args)?;
    let target_recipients = resolve_recipients(&args.recipients)?;
    let target_strings = recipient_strings(&target_recipients);
    let prior_strings = resolve_prior_recipients(&args.prior_recipients)?;

    // Single identity resolution for the entire batch (one passphrase read).
    let (identities, mut identity_paths) =
        resolve_identities_with_sources(&args.identities, &args.passphrase, true)?;
    let (verify_identities, verify_paths) = resolve_verify_identities(&args.verify_identities)?;
    identity_paths.extend(verify_paths);

    // Self-lockout candidate selection: any loaded or verify identity in target_strings.
    let mut target_verify_candidates: Vec<Identity> = Vec::new();
    let mut retired_source_identities: Vec<Identity> = Vec::new();
    for id in &identities {
        let pubkey = id.to_public().to_string();
        if target_strings.iter().any(|r| r == &pubkey) {
            target_verify_candidates.push(id.clone());
        } else {
            retired_source_identities.push(id.clone());
        }
    }
    for id in &verify_identities {
        let pubkey = id.to_public().to_string();
        if target_strings.iter().any(|r| r == &pubkey) {
            target_verify_candidates.push(id.clone());
        }
    }
    if target_verify_candidates.is_empty() && !args.allow_self_lockout {
        return Err(CliError::Message(
            "none of the loaded or --verify-identity-* private keys belongs to the target \
             recipient set; refusing blob rekey-batch to prevent self-lockout. Supply \
             --verify-identity-file / --verify-identity-public-key for a target recipient \
             or pass --allow-self-lockout"
                .to_string(),
        ));
    }
    if args.state.is_some() && target_verify_candidates.is_empty() {
        return Err(CliError::Message(
            "--state with --allow-self-lockout requires at least one target-set verification \
             identity (--verify-identity-file / --verify-identity-public-key or -i matching \
             a target recipient) so resumed journal state can authenticate and verify target \
             decryption independently of the source key"
                .to_string(),
        ));
    }

    // Alias checks for batch files, --state, and --write-recipients before any writes.
    for selected in &selected_files {
        let blob_path = &selected.path;
        for rfile in &args.recipients.recipient_files {
            if paths_alias(blob_path, rfile)? {
                return Err(CliError::Message(format!(
                    "selected blob path {} aliases --recipient-file path {}",
                    blob_path.display(),
                    rfile.display()
                )));
            }
        }
        for pfile in &args.prior_recipients.prior_recipient_files {
            if paths_alias(blob_path, pfile)? {
                return Err(CliError::Message(format!(
                    "selected blob path {} aliases --prior-recipient-file path {}",
                    blob_path.display(),
                    pfile.display()
                )));
            }
        }
        for id_path in &identity_paths {
            if paths_alias(blob_path, id_path)? {
                return Err(CliError::Message(format!(
                    "selected blob path {} aliases identity source path {}",
                    blob_path.display(),
                    id_path.display()
                )));
            }
        }
        if let Some(pp_file) = &args.passphrase.passphrase_file {
            if paths_alias(blob_path, pp_file)? {
                return Err(CliError::Message(format!(
                    "selected blob path {} aliases --passphrase-file path {}",
                    blob_path.display(),
                    pp_file.display()
                )));
            }
        }
    }

    if let Some(state_path) = &args.state {
        for selected in &selected_files {
            let blob_path = &selected.path;
            if paths_alias(state_path, blob_path)? {
                return Err(CliError::Message(format!(
                    "--state path {} aliases selected blob path {}",
                    state_path.display(),
                    blob_path.display()
                )));
            }
        }
        for rfile in &args.recipients.recipient_files {
            if paths_alias(state_path, rfile)? {
                return Err(CliError::Message(format!(
                    "--state path {} aliases --recipient-file path {}",
                    state_path.display(),
                    rfile.display()
                )));
            }
        }
        for pfile in &args.prior_recipients.prior_recipient_files {
            if paths_alias(state_path, pfile)? {
                return Err(CliError::Message(format!(
                    "--state path {} aliases --prior-recipient-file path {}",
                    state_path.display(),
                    pfile.display()
                )));
            }
        }
        for id_path in &identity_paths {
            if paths_alias(state_path, id_path)? {
                return Err(CliError::Message(format!(
                    "--state path {} aliases identity source path {}",
                    state_path.display(),
                    id_path.display()
                )));
            }
        }
        if let Some(pp_file) = &args.passphrase.passphrase_file {
            if paths_alias(state_path, pp_file)? {
                return Err(CliError::Message(format!(
                    "--state path {} aliases --passphrase-file path {}",
                    state_path.display(),
                    pp_file.display()
                )));
            }
        }
        if let Some(wr_path) = &args.write_recipients {
            if paths_alias(state_path, wr_path)? {
                return Err(CliError::Message(format!(
                    "--state path {} aliases --write-recipients path {}",
                    state_path.display(),
                    wr_path.display()
                )));
            }
        }
    }

    let recipient_refresh = if let Some(wr_path) = &args.write_recipients {
        Some(prepare_batch_recipient_refresh(
            wr_path,
            &selected_files,
            &identity_paths,
            args.passphrase.passphrase_file.as_deref(),
            &args.recipients.recipient_files,
            &args.prior_recipients.prior_recipient_files,
            &target_strings,
        )?)
    } else {
        None
    };

    let journal_auth_key = derive_journal_auth_key(&target_verify_candidates);
    let mut journal_state = if let Some(state_path) = &args.state {
        Some(load_or_init_state_journal(
            state_path,
            &target_strings,
            prior_strings.as_deref(),
            allow_recipient_mismatch,
            args.allow_self_lockout,
            args.allow_large,
            &journal_auth_key,
        )?)
    } else {
        None
    };

    if args.apply && args.backup {
        eprintln!(
            "warning: --backup copies retain the prior ciphertext and remain decryptable by \
             prior identities (including any compromised identity); delete .bak-* files once \
             the batch is verified"
        );
    }
    if target_verify_candidates.is_empty() && args.allow_self_lockout {
        eprintln!(
            "warning: proceeding with --allow-self-lockout; no target-set private identity \
             was available to decrypt and verify rekeyed blobs before commit"
        );
    }

    let soft_limit = if args.allow_large {
        None
    } else {
        Some(BLOB_MAX_FILE_BYTES)
    };

    let mut report_files: Vec<BatchReportFileEntry> = Vec::with_capacity(selected_files.len());
    let mut summary = BatchReportSummary {
        selected: selected_files.len(),
        ..BatchReportSummary::default()
    };
    #[cfg(test)]
    let mut commits_completed = 0usize;

    for selected in &selected_files {
        let blob_path = &selected.path;
        let path_str = blob_path.display().to_string();

        // Step 1: Re-verify no ancestor component was swapped to a symlink after selection,
        // then perform a bounded read of the candidate file and verify selection identity.
        let read_res =
            (|| -> std::result::Result<PrivateCiphertextPriorSnapshot, BlobReadForRekeyError> {
                reject_symlink_traversal_in_user_path(&selected.user_path, "input")
                    .map_err(BlobReadForRekeyError::Other)?;
                reject_symlink_traversal_in_user_path(blob_path, "input")
                    .map_err(BlobReadForRekeyError::Other)?;
                let (snap, read_id) = read_blob_input_for_rekey_with_id(
                    blob_path,
                    soft_limit,
                    BLOB_MAX_CIPHERTEXT_HARD_BYTES,
                    true,
                )?;
                if read_id != selected.identity {
                    return Err(BlobReadForRekeyError::Other(
                        CliError::ConcurrentModification {
                            path: path_str.clone(),
                        },
                    ));
                }
                Ok(snap)
            })();
        let prior_snapshot = match read_res {
            Ok(snap) => snap,
            Err(BlobReadForRekeyError::TooLarge(msg)) => {
                summary.skipped += 1;
                eprintln!("skip {path_str}: too-large ({msg})");
                report_files.push(BatchReportFileEntry {
                    path: path_str,
                    status: "too-large".to_string(),
                    opened_with: None,
                    stanzas_before: None,
                    stanzas_after: None,
                    delta: None,
                    mode_before: None,
                    mode_after: None,
                    backup: None,
                    sha256_before: None,
                    sha256_after: None,
                    error: Some(msg),
                });
                continue;
            }
            Err(BlobReadForRekeyError::Other(err)) => {
                let status = if args.apply { "failed" } else { "error" };
                summary.failed += 1;
                let msg = err.to_string();
                eprintln!("{status} {path_str}: {msg}");
                report_files.push(BatchReportFileEntry {
                    path: path_str,
                    status: status.to_string(),
                    opened_with: None,
                    stanzas_before: None,
                    stanzas_after: None,
                    delta: None,
                    mode_before: None,
                    mode_after: None,
                    backup: None,
                    sha256_before: None,
                    sha256_after: None,
                    error: Some(msg),
                });
                if args.fail_fast {
                    break;
                }
                continue;
            }
        };

        let current_sha256 = sha256_hex(&prior_snapshot.bytes);
        #[cfg(unix)]
        let raw_mode = prior_snapshot.identity.2;
        #[cfg(not(unix))]
        let raw_mode = 0u32;
        let mode_before = format_unix_mode(raw_mode);
        let mode_after_planned = format_unix_mode(tightened_unix_mode(raw_mode));

        // Step 2: Check journal for idempotent resume (`sha256_after` match -> `already-done`).
        if let Some((ref mut journal, ref mut journal_snap)) = journal_state {
            if let Some(rec) = journal.records.get(&path_str).cloned() {
                if current_sha256 == rec.sha256_after {
                    let resume_verify_res: CliResult<()> = (|| {
                        if rec.status != "rekeyed" && !rec.displaced_verified {
                            return Err(CliError::Message(format!(
                                "on-disk blob matched journal sha256_after for {path_str}, but its in_progress replacement did not complete displaced-inode link-count verification (old ciphertext may retain a surviving hardlink); inspect and resolve before resuming"
                            )));
                        }
                        let stanzas_now = classify_blob_ciphertext_header(&prior_snapshot.bytes)?;
                        if stanzas_now != target_recipients.len()
                            || rec.stanzas_after != target_recipients.len()
                        {
                            return Err(CliError::Message(format!(
                                "on-disk blob matched journal sha256_after but its X25519 stanza count ({stanzas_now}) does not match target recipient count ({})",
                                target_recipients.len()
                            )));
                        }
                        if target_verify_candidates.is_empty() {
                            return Err(CliError::Message(
                                "refusing journal-based already-done completion without a target-set verification identity"
                                    .to_string(),
                            ));
                        }
                        let verified_pt = seclusor_crypto::decrypt_zeroizing(
                            &prior_snapshot.bytes,
                            &target_verify_candidates,
                        )
                        .map_err(|_| {
                            CliError::Message(
                                "on-disk blob matched journal sha256_after but could not be decrypted by any target-set verification identity"
                                    .to_string(),
                            )
                        })?;
                        refuse_if_secrets_bundle_document(&verified_pt)?;
                        for retired_id in &retired_source_identities {
                            if seclusor_crypto::decrypt_zeroizing(
                                &prior_snapshot.bytes,
                                std::slice::from_ref(retired_id),
                            )
                            .is_ok()
                            {
                                return Err(CliError::Message(
                                    "on-disk blob matched journal sha256_after but is still decryptable by a retired source identity"
                                        .to_string(),
                                ));
                            }
                        }
                        Ok(())
                    })();
                    if let Err(err) = resume_verify_res {
                        let status = if args.apply { "failed" } else { "error" };
                        summary.failed += 1;
                        let msg = err.to_string();
                        eprintln!("{status} {path_str}: {msg}");
                        report_files.push(BatchReportFileEntry {
                            path: path_str,
                            status: status.to_string(),
                            opened_with: None,
                            stanzas_before: None,
                            stanzas_after: None,
                            delta: None,
                            mode_before,
                            mode_after: None,
                            backup: None,
                            sha256_before: Some(current_sha256),
                            sha256_after: None,
                            error: Some(msg),
                        });
                        if args.fail_fast {
                            break;
                        }
                        continue;
                    }

                    // If the journal recorded `in_progress` and a crash happened right after
                    // atomic rename before the post-commit journal update, upgrade it to `rekeyed`
                    // when running under `--apply`.
                    if args.apply && rec.status != "rekeyed" {
                        let prev_rec = journal.records.get(&path_str).cloned();
                        if let Some(entry) = journal.records.get_mut(&path_str) {
                            entry.status = "rekeyed".to_string();
                        }
                        if let Some(state_path) = &args.state {
                            match persist_state_journal(
                                state_path,
                                journal,
                                &journal_auth_key,
                                journal_snap.as_ref(),
                            ) {
                                Ok(new_snap) => *journal_snap = Some(new_snap),
                                Err(err) => {
                                    if let Some(prev) = prev_rec {
                                        journal.records.insert(path_str.clone(), prev);
                                    }
                                    summary.failed += 1;
                                    let msg = format!(
                                        "resumed output matched {path_str}, but state journal promotion at {} failed: {err}",
                                        state_path.display()
                                    );
                                    eprintln!("failed {path_str}: {msg}");
                                    report_files.push(BatchReportFileEntry {
                                        path: path_str,
                                        status: "failed".to_string(),
                                        opened_with: Some(rec.opened_with),
                                        stanzas_before: Some(rec.stanzas_before),
                                        stanzas_after: Some(rec.stanzas_after),
                                        delta: rec.delta,
                                        mode_before: rec.mode_before.or(mode_before),
                                        mode_after: rec.mode_after.or(mode_after_planned),
                                        backup: rec.backup,
                                        sha256_before: Some(rec.sha256_before),
                                        sha256_after: Some(rec.sha256_after),
                                        error: Some(msg),
                                    });
                                    if args.fail_fast {
                                        break;
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                    summary.already_done += 1;
                    eprintln!("already-done {path_str} (matched journal sha256_after)");
                    report_files.push(BatchReportFileEntry {
                        path: path_str,
                        status: "already-done".to_string(),
                        opened_with: Some(rec.opened_with),
                        stanzas_before: Some(rec.stanzas_before),
                        stanzas_after: Some(rec.stanzas_after),
                        delta: rec.delta,
                        mode_before: rec.mode_before.or(mode_before),
                        mode_after: rec.mode_after.or(mode_after_planned),
                        backup: rec.backup,
                        sha256_before: Some(rec.sha256_before),
                        sha256_after: Some(rec.sha256_after),
                        error: None,
                    });
                    continue;
                }
                if current_sha256 != rec.sha256_before {
                    let status = if args.apply { "failed" } else { "error" };
                    summary.failed += 1;
                    let msg = format!(
                        "on-disk sha256 ({current_sha256}) matches neither journal sha256_before ({}) nor sha256_after ({})",
                        rec.sha256_before, rec.sha256_after
                    );
                    eprintln!("{status} {path_str}: {msg}");
                    report_files.push(BatchReportFileEntry {
                        path: path_str,
                        status: status.to_string(),
                        opened_with: None,
                        stanzas_before: None,
                        stanzas_after: None,
                        delta: None,
                        mode_before,
                        mode_after: None,
                        backup: None,
                        sha256_before: Some(current_sha256),
                        sha256_after: None,
                        error: Some(msg),
                    });
                    if args.fail_fast {
                        break;
                    }
                    continue;
                }
                // current_sha256 == rec.sha256_before: safe to retry from the beginning.
            }
        }

        // Step 3: Classify header (scrypt vs non-age vs X25519 blob).
        match seclusor_crypto::is_scrypt_ciphertext(&prior_snapshot.bytes) {
            Ok(true) => {
                summary.skipped += 1;
                let msg =
                    "passphrase-encrypted (scrypt) blob; convert to X25519 recipient mode first"
                        .to_string();
                eprintln!("skip {path_str}: scrypt");
                report_files.push(BatchReportFileEntry {
                    path: path_str,
                    status: "scrypt".to_string(),
                    opened_with: None,
                    stanzas_before: None,
                    stanzas_after: None,
                    delta: None,
                    mode_before,
                    mode_after: None,
                    backup: None,
                    sha256_before: Some(current_sha256),
                    sha256_after: None,
                    error: Some(msg),
                });
                continue;
            }
            Ok(false) => {}
            Err(_) => {
                if is_json_secrets_document(&prior_snapshot.bytes) {
                    summary.skipped += 1;
                    let msg =
                        "file is a seclusor JSON secrets document; use `seclusor secrets rekey`"
                            .to_string();
                    eprintln!("skip {path_str}: secrets-document (use `seclusor secrets rekey`)");
                    report_files.push(BatchReportFileEntry {
                        path: path_str,
                        status: "secrets-document".to_string(),
                        opened_with: None,
                        stanzas_before: None,
                        stanzas_after: None,
                        delta: None,
                        mode_before,
                        mode_after: None,
                        backup: None,
                        sha256_before: Some(current_sha256),
                        sha256_after: None,
                        error: Some(msg),
                    });
                } else {
                    summary.skipped += 1;
                    let msg = "file is not an age ciphertext blob".to_string();
                    eprintln!("skip {path_str}: not-age");
                    report_files.push(BatchReportFileEntry {
                        path: path_str,
                        status: "not-age".to_string(),
                        opened_with: None,
                        stanzas_before: None,
                        stanzas_after: None,
                        delta: None,
                        mode_before,
                        mode_after: None,
                        backup: None,
                        sha256_before: Some(current_sha256),
                        sha256_after: None,
                        error: Some(msg),
                    });
                }
                continue;
            }
        }

        let stanzas_before = match classify_blob_ciphertext_header(&prior_snapshot.bytes) {
            Ok(n) => n,
            Err(err) => {
                summary.skipped += 1;
                let msg = err.to_string();
                eprintln!("skip {path_str}: not-age ({msg})");
                report_files.push(BatchReportFileEntry {
                    path: path_str,
                    status: "not-age".to_string(),
                    opened_with: None,
                    stanzas_before: None,
                    stanzas_after: None,
                    delta: None,
                    mode_before,
                    mode_after: None,
                    backup: None,
                    sha256_before: Some(current_sha256),
                    sha256_after: None,
                    error: Some(msg),
                });
                continue;
            }
        };

        // Step 4: Try to decrypt with loaded identities.
        let (plaintext, opened_with) =
            match decrypt_blob_recording_opening_identity(&prior_snapshot.bytes, &identities) {
                Ok(pair) => pair,
                Err(_) => {
                    // Never relabel `not-openable` as `already-done` without a journal `sha256_after` match.
                    summary.not_openable += 1;
                    summary.skipped += 1;
                    eprintln!("skip {path_str}: not-openable by supplied identities");
                    report_files.push(BatchReportFileEntry {
                        path: path_str,
                        status: "not-openable".to_string(),
                        opened_with: None,
                        stanzas_before: Some(stanzas_before),
                        stanzas_after: None,
                        delta: None,
                        mode_before,
                        mode_after: None,
                        backup: None,
                        sha256_before: Some(current_sha256),
                        sha256_after: None,
                        error: None,
                    });
                    continue;
                }
            };

        // Step 5: Refuse seclusor bundle documents (route to `secrets rekey`).
        if let Err(err) = refuse_if_secrets_bundle_document(&plaintext) {
            drop(plaintext);
            summary.skipped += 1;
            let msg = err.to_string();
            eprintln!("skip {path_str}: secrets-document (use `seclusor secrets rekey`)");
            report_files.push(BatchReportFileEntry {
                path: path_str,
                status: "secrets-document".to_string(),
                opened_with: Some(opened_with),
                stanzas_before: Some(stanzas_before),
                stanzas_after: None,
                delta: None,
                mode_before,
                mode_after: None,
                backup: None,
                sha256_before: Some(current_sha256),
                sha256_after: None,
                error: Some(msg),
            });
            continue;
        }

        // Step 6: Evaluate `--prior-*` tripwires and delta policy.
        if let Some(prior) = prior_strings.as_deref() {
            if stanzas_before != prior.len() || !prior.iter().any(|r| r == &opened_with) {
                drop(plaintext);
                let msg = if stanzas_before != prior.len() {
                    format!(
                        "asserted prior recipient count ({}) does not match input blob age header stanza count ({stanzas_before})",
                        prior.len()
                    )
                } else {
                    format!(
                        "opening identity {opened_with} is not in the asserted prior recipient set"
                    )
                };
                if args.apply {
                    summary.failed += 1;
                } else {
                    summary.skipped += 1;
                }
                eprintln!("prior-mismatch {path_str}: {msg}");
                report_files.push(BatchReportFileEntry {
                    path: path_str,
                    status: "prior-mismatch".to_string(),
                    opened_with: Some(opened_with),
                    stanzas_before: Some(stanzas_before),
                    stanzas_after: None,
                    delta: None,
                    mode_before,
                    mode_after: None,
                    backup: None,
                    sha256_before: Some(current_sha256),
                    sha256_after: None,
                    error: Some(msg),
                });
                if args.fail_fast && args.apply {
                    break;
                }
                continue;
            }
        }

        let delta_notice = match evaluate_blob_rekey_delta_policy(
            prior_strings.as_deref(),
            &target_strings,
            stanzas_before,
            &opened_with,
            allow_recipient_mismatch,
        ) {
            Ok(notice) => notice,
            Err(err) => {
                drop(plaintext);
                let status = if args.apply { "failed" } else { "error" };
                summary.failed += 1;
                let msg = err.to_string();
                eprintln!("{status} {path_str}: {msg}");
                report_files.push(BatchReportFileEntry {
                    path: path_str,
                    status: status.to_string(),
                    opened_with: Some(opened_with),
                    stanzas_before: Some(stanzas_before),
                    stanzas_after: None,
                    delta: None,
                    mode_before,
                    mode_after: None,
                    backup: None,
                    sha256_before: Some(current_sha256),
                    sha256_after: None,
                    error: Some(msg),
                });
                if args.fail_fast {
                    break;
                }
                continue;
            }
        };

        let report_delta = match &delta_notice {
            BlobDeltaNotice::Match => Some(BatchReportDelta {
                added: vec![],
                removed: vec![],
            }),
            BlobDeltaNotice::Delta { added, removed } => Some(BatchReportDelta {
                added: added.clone(),
                removed: removed.clone(),
            }),
            BlobDeltaNotice::Indeterminate { .. } => None,
        };

        // Step 7: Encrypt with fresh file key and run pre-commit verification in memory.
        // Plan and apply share one code path through step 7.
        let new_ciphertext = match seclusor_crypto::encrypt(&plaintext, &target_recipients) {
            Ok(ct) => ct,
            Err(err) => {
                drop(plaintext);
                let status = if args.apply { "failed" } else { "error" };
                summary.failed += 1;
                let msg = err.to_string();
                eprintln!("{status} {path_str}: {msg}");
                report_files.push(BatchReportFileEntry {
                    path: path_str,
                    status: status.to_string(),
                    opened_with: Some(opened_with),
                    stanzas_before: Some(stanzas_before),
                    stanzas_after: None,
                    delta: report_delta,
                    mode_before,
                    mode_after: None,
                    backup: None,
                    sha256_before: Some(current_sha256),
                    sha256_after: None,
                    error: Some(msg),
                });
                if args.fail_fast {
                    break;
                }
                continue;
            }
        };

        let verify_res: CliResult<usize> = (|| {
            if seclusor_crypto::is_scrypt_ciphertext(&new_ciphertext)? {
                return Err(CliError::Message(
                    "internal error: rekeyed blob unexpectedly produced scrypt header".to_string(),
                ));
            }
            let stanzas_after = seclusor_crypto::count_x25519_recipient_stanzas(&new_ciphertext)?;
            if stanzas_after != target_recipients.len() {
                return Err(CliError::Message(format!(
                    "internal error: rekeyed blob stanza count ({stanzas_after}) does not match target recipient count ({})",
                    target_recipients.len()
                )));
            }
            if !target_verify_candidates.is_empty() {
                use sha2::Digest as _;
                let mut expected_hasher = sha2::Sha256::new();
                expected_hasher.update(plaintext.as_slice());
                let expected_digest: Zeroizing<[u8; 32]> =
                    Zeroizing::new(expected_hasher.finalize().into());

                let verified_pt = seclusor_crypto::decrypt_zeroizing(
                    &new_ciphertext,
                    &target_verify_candidates,
                )
                .map_err(|_| {
                    CliError::Message(
                        "pre-commit verification failed: target identity could not decrypt the newly encrypted blob"
                            .to_string(),
                    )
                })?;

                let mut actual_hasher = sha2::Sha256::new();
                actual_hasher.update(verified_pt.as_slice());
                let actual_digest: Zeroizing<[u8; 32]> =
                    Zeroizing::new(actual_hasher.finalize().into());

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
            }
            Ok(stanzas_after)
        })();
        drop(plaintext);

        let stanzas_after = match verify_res {
            Ok(n) => n,
            Err(err) => {
                let status = if args.apply { "failed" } else { "error" };
                summary.failed += 1;
                let msg = err.to_string();
                eprintln!("{status} {path_str}: {msg}");
                report_files.push(BatchReportFileEntry {
                    path: path_str,
                    status: status.to_string(),
                    opened_with: Some(opened_with),
                    stanzas_before: Some(stanzas_before),
                    stanzas_after: None,
                    delta: report_delta,
                    mode_before,
                    mode_after: None,
                    backup: None,
                    sha256_before: Some(current_sha256),
                    sha256_after: None,
                    error: Some(msg),
                });
                if args.fail_fast {
                    break;
                }
                continue;
            }
        };

        summary.affected += 1;
        let new_sha256 = sha256_hex(&new_ciphertext);
        emit_blob_delta_notice(&delta_notice);

        if !args.apply {
            eprintln!(
                "affected {path_str} (opened_with: {opened_with}, stanzas: {stanzas_before} -> {stanzas_after})"
            );
            report_files.push(BatchReportFileEntry {
                path: path_str,
                status: "affected".to_string(),
                opened_with: Some(opened_with),
                stanzas_before: Some(stanzas_before),
                stanzas_after: Some(stanzas_after),
                delta: report_delta,
                mode_before,
                mode_after: mode_after_planned,
                backup: None,
                sha256_before: Some(current_sha256),
                sha256_after: Some(new_sha256),
                error: None,
            });
            continue;
        }

        #[cfg(test)]
        if let Some(limit) = BATCH_FAIL_AFTER_COMMITS.with(|c| c.get()) {
            if commits_completed >= limit {
                summary.failed += 1;
                let msg = "injected batch failure after commit limit".to_string();
                eprintln!("failed {path_str}: {msg}");
                report_files.push(BatchReportFileEntry {
                    path: path_str,
                    status: "failed".to_string(),
                    opened_with: Some(opened_with),
                    stanzas_before: Some(stanzas_before),
                    stanzas_after: Some(stanzas_after),
                    delta: report_delta,
                    mode_before,
                    mode_after: None,
                    backup: None,
                    sha256_before: Some(current_sha256),
                    sha256_after: None,
                    error: Some(msg),
                });
                if args.fail_fast {
                    break;
                }
                continue;
            }
        }

        // Step 8 (apply): Optional `.bak-<UTC>Z` 0600 backup before replacement.
        let backup_path_str = if args.backup {
            match create_private_backup_file(blob_path, &prior_snapshot.bytes) {
                Ok(bpath) => Some(bpath.display().to_string()),
                Err(err) => {
                    summary.failed += 1;
                    let msg = format!("backup creation failed: {err}");
                    eprintln!("failed {path_str}: {msg}");
                    report_files.push(BatchReportFileEntry {
                        path: path_str,
                        status: "failed".to_string(),
                        opened_with: Some(opened_with),
                        stanzas_before: Some(stanzas_before),
                        stanzas_after: Some(stanzas_after),
                        delta: report_delta,
                        mode_before,
                        mode_after: None,
                        backup: None,
                        sha256_before: Some(current_sha256),
                        sha256_after: None,
                        error: Some(msg),
                    });
                    if args.fail_fast {
                        break;
                    }
                    continue;
                }
            }
        } else {
            None
        };

        // Step 9 (apply): Two-phase journal phase 1 (`in_progress`) persisted durably BEFORE replacement.
        if let (Some(state_path), Some((ref mut journal, ref mut journal_snap))) =
            (&args.state, &mut journal_state)
        {
            let prev_record = journal.records.insert(
                path_str.clone(),
                BatchJournalRecord {
                    path: path_str.clone(),
                    sha256_before: current_sha256.clone(),
                    sha256_after: new_sha256.clone(),
                    status: "in_progress".to_string(),
                    displaced_verified: false,
                    ts: utc_compact_timestamp_now(),
                    opened_with: opened_with.clone(),
                    stanzas_before,
                    stanzas_after,
                    delta: report_delta.clone(),
                    mode_before: mode_before.clone(),
                    mode_after: mode_after_planned.clone(),
                    backup: backup_path_str.clone(),
                },
            );
            match persist_state_journal(
                state_path,
                journal,
                &journal_auth_key,
                journal_snap.as_ref(),
            ) {
                Ok(new_snap) => *journal_snap = Some(new_snap),
                Err(err) => {
                    if let Some(prev) = prev_record {
                        journal.records.insert(path_str.clone(), prev);
                    } else {
                        journal.records.remove(&path_str);
                    }
                    summary.failed += 1;
                    let msg = format!("pre-commit state journal write failed: {err}");
                    eprintln!("failed {path_str}: {msg}");
                    report_files.push(BatchReportFileEntry {
                        path: path_str,
                        status: "failed".to_string(),
                        opened_with: Some(opened_with),
                        stanzas_before: Some(stanzas_before),
                        stanzas_after: Some(stanzas_after),
                        delta: report_delta,
                        mode_before,
                        mode_after: None,
                        backup: backup_path_str,
                        sha256_before: Some(current_sha256),
                        sha256_after: None,
                        error: Some(msg),
                    });
                    if args.fail_fast {
                        break;
                    }
                    continue;
                }
            }
        }

        // Step 10 (apply): Atomic replacement + post-commit re-read check.
        let commit_res: CliResult<()> = (|| {
            reject_symlink_traversal_in_user_path(&selected.user_path, "input")?;
            reject_symlink_traversal_in_user_path(blob_path, "input")?;
            let (pre_commit_id, pre_commit_nlink) =
                path_identity_and_nlink_nofollow(blob_path).map_err(CliError::Io)?;
            if pre_commit_id != selected.identity || pre_commit_nlink != 1 {
                return Err(CliError::ConcurrentModification {
                    path: path_str.clone(),
                });
            }
            atomic_write_private_ciphertext(blob_path, &new_ciphertext, Some(prior_snapshot))?;
            let post_commit_bytes =
                read_file_bounded_zeroizing(blob_path, None, BLOB_MAX_CIPHERTEXT_HARD_BYTES)
                    .map_err(|err| CliError::PostCommitFailure {
                        path: path_str.clone(),
                        step: "re-read verification",
                        source: Box::new(err),
                    })?;
            if post_commit_bytes.as_slice() != new_ciphertext.as_slice() {
                return Err(CliError::PostCommitFailure {
                    path: path_str.clone(),
                    step: "re-read byte comparison",
                    source: Box::new(CliError::Message(
                        "on-disk bytes after commit did not match written ciphertext".to_string(),
                    )),
                });
            }
            Ok(())
        })();

        if let Err(err) = commit_res {
            summary.failed += 1;
            let msg = err.to_string();
            eprintln!("failed {path_str}: {msg}");
            report_files.push(BatchReportFileEntry {
                path: path_str,
                status: "failed".to_string(),
                opened_with: Some(opened_with),
                stanzas_before: Some(stanzas_before),
                stanzas_after: Some(stanzas_after),
                delta: report_delta,
                mode_before,
                mode_after: None,
                backup: backup_path_str,
                sha256_before: Some(current_sha256),
                sha256_after: None,
                error: Some(msg),
            });
            if args.fail_fast {
                break;
            }
            continue;
        }

        // Persist durable evidence that displaced-inode link verification succeeded
        // BEFORE any simulated post-replacement crash so only verified replacements
        // can be auto-promoted from `in_progress` on resume.
        if let (Some(state_path), Some((ref mut journal, ref mut journal_snap))) =
            (&args.state, &mut journal_state)
        {
            let prev_record = journal.records.get(&path_str).cloned();
            if let Some(entry) = journal.records.get_mut(&path_str) {
                entry.displaced_verified = true;
                entry.ts = utc_compact_timestamp_now();
            }
            if let Err(err) = persist_state_journal(
                state_path,
                journal,
                &journal_auth_key,
                journal_snap.as_ref(),
            )
            .map(|snap| *journal_snap = Some(snap))
            {
                if let Some(prev) = prev_record {
                    journal.records.insert(path_str.clone(), prev);
                }
                summary.failed += 1;
                let msg = format!(
                    "output was committed to {path_str}, but post-commit displaced-verification state journal update at {} failed: {err}",
                    state_path.display()
                );
                eprintln!("failed {path_str}: {msg}");
                report_files.push(BatchReportFileEntry {
                    path: path_str,
                    status: "failed".to_string(),
                    opened_with: Some(opened_with),
                    stanzas_before: Some(stanzas_before),
                    stanzas_after: Some(stanzas_after),
                    delta: report_delta,
                    mode_before,
                    mode_after: mode_after_planned,
                    backup: backup_path_str,
                    sha256_before: Some(current_sha256),
                    sha256_after: Some(new_sha256),
                    error: Some(msg),
                });
                if args.fail_fast {
                    break;
                }
                continue;
            }
        }

        #[cfg(test)]
        if BATCH_ABORT_AFTER_PLANNED_JOURNAL.with(|c| c.get()) {
            return Err(CliError::Message(
                "simulated crash after blob replacement before post-commit journal mark"
                    .to_string(),
            ));
        }

        // Step 11 (apply): Two-phase journal phase 2 (`rekeyed`).
        if let (Some(state_path), Some((ref mut journal, ref mut journal_snap))) =
            (&args.state, &mut journal_state)
        {
            let prev_record = journal.records.get(&path_str).cloned();
            if let Some(entry) = journal.records.get_mut(&path_str) {
                entry.status = "rekeyed".to_string();
                entry.displaced_verified = true;
                entry.ts = utc_compact_timestamp_now();
            }
            if let Err(err) = persist_state_journal(
                state_path,
                journal,
                &journal_auth_key,
                journal_snap.as_ref(),
            )
            .map(|snap| *journal_snap = Some(snap))
            {
                if let Some(prev) = prev_record {
                    journal.records.insert(path_str.clone(), prev);
                }
                summary.failed += 1;
                let msg = format!(
                    "output was committed to {path_str}, but post-commit state journal update at {} failed: {err}",
                    state_path.display()
                );
                eprintln!("failed {path_str}: {msg}");
                report_files.push(BatchReportFileEntry {
                    path: path_str,
                    status: "failed".to_string(),
                    opened_with: Some(opened_with),
                    stanzas_before: Some(stanzas_before),
                    stanzas_after: Some(stanzas_after),
                    delta: report_delta,
                    mode_before,
                    mode_after: mode_after_planned,
                    backup: backup_path_str,
                    sha256_before: Some(current_sha256),
                    sha256_after: Some(new_sha256),
                    error: Some(msg),
                });
                if args.fail_fast {
                    break;
                }
                continue;
            }
        }

        #[cfg(test)]
        {
            commits_completed += 1;
        }
        summary.rekeyed += 1;
        eprintln!("rekeyed {path_str} (opened_with: {opened_with})");
        report_files.push(BatchReportFileEntry {
            path: path_str,
            status: "rekeyed".to_string(),
            opened_with: Some(opened_with),
            stanzas_before: Some(stanzas_before),
            stanzas_after: Some(stanzas_after),
            delta: report_delta,
            mode_before,
            mode_after: mode_after_planned,
            backup: backup_path_str,
            sha256_before: Some(current_sha256),
            sha256_after: Some(new_sha256),
            error: None,
        });
    }

    // `--write-recipients` is written once, ONLY if every selected file ended
    // `rekeyed` or `already-done` (and at least one file was selected).
    let all_selected_rekeyed_or_done = !selected_files.is_empty()
        && report_files.len() == selected_files.len()
        && report_files
            .iter()
            .all(|f| f.status == "rekeyed" || f.status == "already-done");

    let mut recipient_refresh_err: Option<CliError> = None;
    if args.apply {
        if all_selected_rekeyed_or_done {
            if let Some(plan) = recipient_refresh.as_ref() {
                match commit_batch_recipient_refresh(plan) {
                    Ok(()) => {
                        eprintln!("wrote recipient set to {}", plan.user_path.display());
                    }
                    Err(err) => {
                        recipient_refresh_err = Some(err);
                    }
                }
            }
        } else if recipient_refresh.is_some() {
            eprintln!(
                "warning: skipping --write-recipients because not all selected files ended rekeyed or already-done"
            );
        }
    }

    let mode_str = if args.apply { "apply" } else { "plan" };
    eprintln!(
        "blob rekey-batch ({mode_str}): selected={} affected={} rekeyed={} already_done={} not_openable={} skipped={} failed={}",
        summary.selected,
        summary.affected,
        summary.rekeyed,
        summary.already_done,
        summary.not_openable,
        summary.skipped,
        summary.failed
    );

    let report = BatchReport {
        version: 1,
        mode: mode_str.to_string(),
        target_recipients: target_strings,
        files: report_files,
        summary,
    };

    let any_prior_mismatch = report.files.iter().any(|f| f.status == "prior-mismatch");
    let has_failures = if args.apply {
        report.summary.failed > 0 || any_prior_mismatch
    } else {
        report.summary.failed > 0
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for f in &report.files {
            if (args.apply && (f.status == "rekeyed" || f.status == "already-done"))
                || (!args.apply && f.status == "affected")
            {
                println!("{}", f.path);
            }
        }
    }

    if let Some(err) = recipient_refresh_err {
        return Err(err);
    }
    if has_failures {
        return Err(CliError::CommandFailed(1));
    }
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

    fn validate_batch_report_against_schema(report: &BatchReport) {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../schemas/seclusor/v1.1.0/blob-rekey-batch.schema.json"
        ))
        .expect("schema json must parse");
        assert_eq!(schema["$id"], "seclusor/v1.1.0/blob-rekey-batch");

        let val = serde_json::to_value(report).expect("serialize report");
        let obj = val.as_object().expect("report must be object");
        let req = schema["required"]
            .as_array()
            .expect("required array")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<Vec<_>>();
        for k in &req {
            assert!(obj.contains_key(*k), "missing required top-level key {k}");
        }
        assert_eq!(obj.len(), req.len(), "no extra top-level keys allowed");
        assert_eq!(val["version"], 1);
        assert!(val["mode"] == "plan" || val["mode"] == "apply");
        let tr = val["target_recipients"]
            .as_array()
            .expect("target_recipients array");
        assert!(!tr.is_empty());
        for r in tr {
            assert!(r.as_str().unwrap().starts_with("age1"));
        }

        let allowed_statuses: Vec<&str> = schema["$defs"]["file_entry"]["properties"]["status"]
            ["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let entry_req: Vec<&str> = schema["$defs"]["file_entry"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();

        for item in val["files"].as_array().expect("files array") {
            let item_obj = item.as_object().expect("file_entry object");
            for k in &entry_req {
                assert!(item_obj.contains_key(*k), "missing file_entry key {k}");
            }
            assert_eq!(item_obj.len(), entry_req.len());
            let st = item["status"].as_str().expect("status string");
            assert!(
                allowed_statuses.contains(&st),
                "unexpected status {st:?} not in schema enum"
            );
            if let Some(s) = item["sha256_before"].as_str() {
                assert_eq!(s.len(), 64);
                assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
            }
            if let Some(s) = item["sha256_after"].as_str() {
                assert_eq!(s.len(), 64);
                assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
            }
        }

        let sum_req: Vec<&str> = schema["$defs"]["summary"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let sum_obj = val["summary"].as_object().expect("summary object");
        for k in &sum_req {
            assert!(sum_obj.contains_key(*k), "missing summary key {k}");
            assert!(sum_obj[*k].is_u64(), "summary.{k} must be non-negative int");
        }
        assert_eq!(sum_obj.len(), sum_req.len());
    }

    #[test]
    fn blob_rekey_batch_plan_classifies_mixed_directory_and_skips_hidden_temps_and_symlinks() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (old_id_path, old_r) = blob_fixture_identity_and_recipient(dir.path());
        let other_id_path = dir.path().join("other-identity.txt");
        let other_gen = seclusor_keyring::generate_identity_file(&other_id_path).expect("gen");
        let other_r: seclusor_crypto::Recipient = other_gen.recipient.parse().expect("parse");
        let new_id_path = dir.path().join("new-identity.txt");
        let new_gen = seclusor_keyring::generate_identity_file(&new_id_path).expect("gen new");

        let packs_dir = dir.path().join("packs");
        fs::create_dir_all(&packs_dir).expect("mkdir packs");

        // 1. Affected blob (openable by old_id).
        let affected_path = packs_dir.join("01-affected.age");
        let affected_ct =
            seclusor_crypto::encrypt(BLOB_REKEY_SENTINEL.as_bytes(), std::slice::from_ref(&old_r))
                .expect("enc affected");
        fs::write(&affected_path, &affected_ct).expect("write affected");

        // 2. Not-openable blob (encrypted only to other_r).
        let not_openable_path = packs_dir.join("02-not-openable.age");
        let not_openable_ct =
            seclusor_crypto::encrypt(b"other-payload", std::slice::from_ref(&other_r))
                .expect("enc other");
        fs::write(&not_openable_path, &not_openable_ct).expect("write not-openable");

        // 3. Scrypt blob.
        let scrypt_path = packs_dir.join("03-scrypt.age");
        let scrypt_ct = seclusor_crypto::encrypt_with_passphrase(b"scrypt-payload", "test-pass")
            .expect("scrypt");
        fs::write(&scrypt_path, &scrypt_ct).expect("write scrypt");

        // 4. Bundle secrets document (.age).
        let bundle_doc_path = packs_dir.join("04-bundle-doc.age");
        seclusor_codec::encrypt_bundle_to_file(
            &fixture_secrets(),
            std::slice::from_ref(&old_r),
            &bundle_doc_path,
        )
        .expect("write bundle doc");

        // 5. Not-age file with .age suffix.
        let not_age_path = packs_dir.join("05-not-age.age");
        fs::write(&not_age_path, b"plain text not age").expect("write not-age");

        // 6. Hidden file, .seclusor-* temp file, and .bak-* file (all must be skipped).
        fs::write(packs_dir.join(".hidden.age"), &affected_ct).expect("write hidden");
        fs::write(packs_dir.join(".seclusor-tmp123.age"), &affected_ct).expect("write temp");
        fs::write(
            packs_dir.join("01-affected.age.bak-20261008T143000Z"),
            &affected_ct,
        )
        .expect("write bak");

        // 7. Nested directory (must be ignored without --recursive).
        let nested_dir = packs_dir.join("nested");
        fs::create_dir_all(&nested_dir).expect("mkdir nested");
        fs::write(nested_dir.join("nested-pack.age"), &affected_ct).expect("write nested");

        // 8. Symlink inside packs_dir (must be skipped).
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(&affected_path, packs_dir.join("99-symlink.age")).expect("symlink");
        }

        // Run plan mode via handle_blob_rekey_batch_with_policy (default apply=false).
        handle_blob_rekey_batch_with_policy(
            BlobRekeyBatchArgs {
                files: vec![],
                dir: Some(packs_dir.clone()),
                glob: "*.age".to_string(),
                recursive: false,
                apply: false,
                state: None,
                backup: false,
                fail_fast: false,
                json: true,
                write_recipients: None,
                allow_self_lockout: false,
                allow_large: false,
                recipients: RecipientArgs {
                    recipients: vec![new_gen.recipient.clone()],
                    recipient_files: vec![],
                    recipient_env_var: None,
                },
                prior_recipients: PriorRecipientArgs::default(),
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
        .expect("plan mode must exit 0");

        // Plan mode writes nothing: affected_path must still have its original bytes.
        assert_eq!(fs::read(&affected_path).unwrap(), affected_ct);
        assert_no_blob_sentinel_in_dir(&packs_dir);
    }

    #[test]
    fn blob_rekey_batch_apply_partial_failure_journal_resume_and_backup() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (old_id_path, old_r) = blob_fixture_identity_and_recipient(dir.path());
        let other_id_path = dir.path().join("other-identity.txt");
        let other_gen = seclusor_keyring::generate_identity_file(&other_id_path).expect("gen");
        let other_r: seclusor_crypto::Recipient = other_gen.recipient.parse().expect("parse");
        let new_id_path = dir.path().join("new-identity.txt");
        let new_gen = seclusor_keyring::generate_identity_file(&new_id_path).expect("gen new");

        let packs_dir = dir.path().join("packs");
        fs::create_dir_all(&packs_dir).expect("mkdir packs");

        let blob1 = packs_dir.join("a.age");
        let blob2 = packs_dir.join("b.age");
        let blob_other = packs_dir.join("c-other.age");
        let ct1 = seclusor_crypto::encrypt(b"payload-a", std::slice::from_ref(&old_r)).unwrap();
        let ct2 = seclusor_crypto::encrypt(b"payload-b", std::slice::from_ref(&old_r)).unwrap();
        let ct_other =
            seclusor_crypto::encrypt(b"payload-other", std::slice::from_ref(&other_r)).unwrap();
        fs::write(&blob1, &ct1).unwrap();
        fs::write(&blob2, &ct2).unwrap();
        fs::write(&blob_other, &ct_other).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&blob1, fs::Permissions::from_mode(0o644)).unwrap();
        }

        let state_path = dir.path().join("rekey-state.json");
        let recipients_out = dir.path().join("recipients-out.txt");

        // T15: Inject failure after 1 commit: blob1 commits, blob2 fails, exit 1,
        // --write-recipients is NOT written, and state journal is 0600.
        set_batch_fail_after_commits(Some(1));
        let err_partial = handle_blob_rekey_batch_with_policy(
            BlobRekeyBatchArgs {
                files: vec![blob1.clone(), blob2.clone()],
                dir: None,
                glob: "*.age".to_string(),
                recursive: false,
                apply: true,
                state: Some(state_path.clone()),
                backup: true,
                fail_fast: false,
                json: true,
                write_recipients: Some(recipients_out.clone()),
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
                verify_identities: VerifyIdentityArgs {
                    verify_identity_files: vec![new_id_path.clone()],
                    verify_identity_public_key: None,
                },
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect_err("partial failure in apply mode must return CommandFailed(1)");
        set_batch_fail_after_commits(None);
        assert!(matches!(err_partial, CliError::CommandFailed(1)));
        assert!(
            !recipients_out.exists(),
            "--write-recipients must not be written when any file failed"
        );
        assert!(state_path.exists(), "state journal must be created");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&state_path).unwrap().permissions().mode() & 0o777,
                0o600,
                "state journal must be 0600"
            );
            assert_eq!(
                fs::metadata(&blob1).unwrap().permissions().mode() & 0o777,
                0o600,
                "blob1 must be tightened from 0644 to 0600"
            );
        }

        // T17: Check that a .bak-<UTC>Z file was created for blob1 with 0600 permissions and original bytes.
        let bak_files: Vec<PathBuf> = fs::read_dir(&packs_dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("a.age.bak-")
            })
            .collect();
        assert_eq!(bak_files.len(), 1, "expected one backup file for a.age");
        let bak_name = bak_files[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(bak_name.ends_with('Z') && !bak_name.contains(':'));
        assert_eq!(fs::read(&bak_files[0]).unwrap(), ct1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&bak_files[0]).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        // T16: Re-run with simulated crash between blob2's replacement and post-commit journal update!
        // On this run, blob1 is already-done via sha256_after, and blob2 is replaced on disk while its
        // journal record is still `in_progress`.
        set_batch_abort_after_planned_journal(true);
        let _ = handle_blob_rekey_batch_with_policy(
            BlobRekeyBatchArgs {
                files: vec![blob1.clone(), blob2.clone()],
                dir: None,
                glob: "*.age".to_string(),
                recursive: false,
                apply: true,
                state: Some(state_path.clone()),
                backup: false,
                fail_fast: false,
                json: false,
                write_recipients: Some(recipients_out.clone()),
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
                verify_identities: VerifyIdentityArgs {
                    verify_identity_files: vec![new_id_path.clone()],
                    verify_identity_public_key: None,
                },
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect_err("simulated crash after replacement must abort");
        set_batch_abort_after_planned_journal(false);

        // Now resume on [blob1, blob2]: both match `sha256_after` in the journal (blob2 was `in_progress`),
        // so both are recognized as `already-done` and `--write-recipients` is now written!
        handle_blob_rekey_batch_with_policy(
            BlobRekeyBatchArgs {
                files: vec![blob1.clone(), blob2.clone()],
                dir: None,
                glob: "*.age".to_string(),
                recursive: false,
                apply: true,
                state: Some(state_path.clone()),
                backup: false,
                fail_fast: false,
                json: true,
                write_recipients: Some(recipients_out.clone()),
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
                verify_identities: VerifyIdentityArgs {
                    verify_identity_files: vec![new_id_path.clone()],
                    verify_identity_public_key: None,
                },
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect("resume when all files match sha256_after must succeed");
        assert!(
            recipients_out.exists(),
            "--write-recipients must be written once all selected files are rekeyed or already-done"
        );

        // Also verify that `blob_other` (which is `not-openable` and not in journal) is NEVER
        // mislabeled `already-done` and causes `--write-recipients` to be skipped.
        let recipients_out_2 = dir.path().join("recipients-out-2.txt");
        handle_blob_rekey_batch_with_policy(
            BlobRekeyBatchArgs {
                files: vec![blob1.clone(), blob2.clone(), blob_other.clone()],
                dir: None,
                glob: "*.age".to_string(),
                recursive: false,
                apply: true,
                state: Some(state_path.clone()),
                backup: false,
                fail_fast: false,
                json: true,
                write_recipients: Some(recipients_out_2.clone()),
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
                    identity_files: vec![old_id_path],
                    identity_public_key: None,
                },
                verify_identities: VerifyIdentityArgs {
                    verify_identity_files: vec![new_id_path],
                    verify_identity_public_key: None,
                },
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect("not-openable is skipped (exit 0), not failed");
        assert!(
            !recipients_out_2.exists(),
            "--write-recipients must not be written when a selected file was not-openable"
        );
    }

    #[test]
    fn blob_rekey_batch_schema_validates_plan_and_apply_reports() {
        let report_plan = BatchReport {
            version: 1,
            mode: "plan".to_string(),
            target_recipients: vec![
                "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_string(),
            ],
            files: vec![
                BatchReportFileEntry {
                    path: "/tmp/a.age".to_string(),
                    status: "affected".to_string(),
                    opened_with: Some(
                        "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
                            .to_string(),
                    ),
                    stanzas_before: Some(2),
                    stanzas_after: Some(1),
                    delta: Some(BatchReportDelta {
                        added: vec![],
                        removed: vec![
                            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
                                .to_string(),
                        ],
                    }),
                    mode_before: Some("0644".to_string()),
                    mode_after: Some("0600".to_string()),
                    backup: None,
                    sha256_before: Some("a".repeat(64)),
                    sha256_after: Some("b".repeat(64)),
                    error: None,
                },
                BatchReportFileEntry {
                    path: "/tmp/b.age".to_string(),
                    status: "not-openable".to_string(),
                    opened_with: None,
                    stanzas_before: Some(1),
                    stanzas_after: None,
                    delta: None,
                    mode_before: Some("0600".to_string()),
                    mode_after: None,
                    backup: None,
                    sha256_before: Some("c".repeat(64)),
                    sha256_after: None,
                    error: None,
                },
            ],
            summary: BatchReportSummary {
                selected: 2,
                affected: 1,
                rekeyed: 0,
                already_done: 0,
                not_openable: 1,
                skipped: 1,
                failed: 0,
            },
        };
        validate_batch_report_against_schema(&report_plan);

        // Also exercise handle_blob_rekey_batch directly (default allow_recipient_mismatch=false).
        let dir = tempfile::tempdir().expect("temp dir");
        let (id_path, r) = blob_fixture_identity_and_recipient(dir.path());
        let blob_path = dir.path().join("single.age");
        fs::write(
            &blob_path,
            seclusor_crypto::encrypt(b"data", std::slice::from_ref(&r)).unwrap(),
        )
        .unwrap();
        handle_blob_rekey_batch(BlobRekeyBatchArgs {
            files: vec![blob_path.clone()],
            dir: None,
            glob: "*.age".to_string(),
            recursive: false,
            apply: false,
            state: None,
            backup: false,
            fail_fast: false,
            json: true,
            write_recipients: None,
            allow_self_lockout: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![r.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
            prior_recipients: PriorRecipientArgs {
                prior_recipients: vec![r.to_string()],
                prior_recipient_files: vec![],
            },
            identities: IdentityArgs {
                identity_files: vec![id_path.clone()],
                identity_public_key: None,
            },
            verify_identities: VerifyIdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("handle_blob_rekey_batch with matching prior set must succeed");

        // Reject hardlinked inputs in batch selection on all platforms (Unix and Windows),
        // both when both links are selected and when only one link is selected while an
        // unselected hardlink exists.
        let hardlink_path = dir.path().join("single-hardlink.age");
        fs::hard_link(&blob_path, &hardlink_path).expect("create hardlink");
        let err_hardlink_single = handle_blob_rekey_batch(BlobRekeyBatchArgs {
            files: vec![blob_path.clone()],
            dir: None,
            glob: "*.age".to_string(),
            recursive: false,
            apply: false,
            state: None,
            backup: false,
            fail_fast: false,
            json: false,
            write_recipients: None,
            allow_self_lockout: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![r.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
            prior_recipients: PriorRecipientArgs {
                prior_recipients: vec![r.to_string()],
                prior_recipient_files: vec![],
            },
            identities: IdentityArgs {
                identity_files: vec![id_path.clone()],
                identity_public_key: None,
            },
            verify_identities: VerifyIdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("blob with unselected hardlink (nlink > 1) must be rejected on all platforms");
        assert!(err_hardlink_single.to_string().contains("hardlink"));
        fs::remove_file(&hardlink_path).expect("remove hardlink");

        // Regular-file substitution after selection changes cross-platform
        // (dev, ino) / (volume_serial, file_index) and must be rejected.
        let subst_blob_path = dir.path().join("subst-target.age");
        fs::copy(&blob_path, &subst_blob_path).expect("copy subst target");
        let selected = collect_batch_files(&BlobRekeyBatchArgs {
            files: vec![subst_blob_path.clone()],
            dir: None,
            glob: "*.age".to_string(),
            recursive: false,
            apply: false,
            state: None,
            backup: false,
            fail_fast: false,
            json: false,
            write_recipients: None,
            allow_self_lockout: false,
            allow_large: false,
            recipients: RecipientArgs::default(),
            prior_recipients: PriorRecipientArgs::default(),
            identities: IdentityArgs::default(),
            verify_identities: VerifyIdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("select subst target");
        assert_eq!(selected.len(), 1);
        let replacement_blob_path = dir.path().join("subst-replacement.age");
        fs::write(
            &replacement_blob_path,
            seclusor_crypto::encrypt(b"replacement-data", std::slice::from_ref(&r)).unwrap(),
        )
        .unwrap();
        fs::remove_file(&subst_blob_path).unwrap();
        fs::rename(&replacement_blob_path, &subst_blob_path).unwrap();
        let (_, new_file_id) = read_blob_input_for_rekey_with_id(
            &selected[0].path,
            Some(BLOB_MAX_FILE_BYTES),
            BLOB_MAX_CIPHERTEXT_HARD_BYTES,
            true,
        )
        .expect("read replaced regular file");
        assert_ne!(
            new_file_id, selected[0].identity,
            "replaced regular file must have a distinct file identity from selection"
        );

        // A path-guard failure on a filename containing "MB limit" or "maximum size"
        // must be classified as an error/failure, never as `too-large` (`skipped`).
        let tricky_name_path = dir.path().join("tricky MB limit maximum size.age");
        fs::copy(&blob_path, &tricky_name_path).unwrap();
        let tricky_hardlink = dir.path().join("tricky-link.age");
        fs::hard_link(&tricky_name_path, &tricky_hardlink).unwrap();
        let tricky_res = read_blob_input_for_rekey_with_id(
            &tricky_name_path,
            Some(BLOB_MAX_FILE_BYTES),
            BLOB_MAX_CIPHERTEXT_HARD_BYTES,
            true,
        );
        assert!(
            matches!(tricky_res, Err(BlobReadForRekeyError::Other(_))),
            "path-guard error on filename containing 'MB limit' must not be classified as TooLarge"
        );
        fs::remove_file(&tricky_hardlink).unwrap();
        fs::remove_file(&tricky_name_path).unwrap();

        // Reject intermediate symlink traversal in absolute FILE, --dir, and --write-recipients paths,
        // and reject non-UTF-8 input paths.
        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;

            let real_sub = dir.path().join("real-sub");
            fs::create_dir(&real_sub).unwrap();
            let sub_blob = real_sub.join("pack.age");
            fs::copy(&blob_path, &sub_blob).unwrap();
            let link_sub = dir.path().join("link-sub");
            std::os::unix::fs::symlink(&real_sub, &link_sub).unwrap();

            let err_abs_dir = reject_symlink_traversal_in_user_path(&link_sub, "--dir")
                .expect_err("symlinked --dir must be rejected");
            assert!(err_abs_dir.to_string().contains("symlink"));

            let via_link_blob = link_sub.join("pack.age");
            let err_abs_file = reject_symlink_traversal_in_user_path(&via_link_blob, "input")
                .expect_err("absolute FILE traversing a symlinked parent must be rejected");
            assert!(err_abs_file.to_string().contains("symlink"));

            let via_link_recipients = link_sub.join("recipients.txt");
            let err_symlink_wr = handle_blob_rekey_batch(BlobRekeyBatchArgs {
                files: vec![blob_path.clone()],
                dir: None,
                glob: "*.age".to_string(),
                recursive: false,
                apply: true,
                state: None,
                backup: false,
                fail_fast: false,
                json: false,
                write_recipients: Some(via_link_recipients),
                allow_self_lockout: false,
                allow_large: false,
                recipients: RecipientArgs {
                    recipients: vec![r.to_string()],
                    recipient_files: vec![],
                    recipient_env_var: None,
                },
                prior_recipients: PriorRecipientArgs {
                    prior_recipients: vec![r.to_string()],
                    prior_recipient_files: vec![],
                },
                identities: IdentityArgs {
                    identity_files: vec![id_path.clone()],
                    identity_public_key: None,
                },
                verify_identities: VerifyIdentityArgs::default(),
                passphrase: PassphraseArgs::default(),
            })
            .expect_err("--write-recipients traversing a symlinked parent must be rejected");
            assert!(err_symlink_wr.to_string().contains("symlink"));

            // Leaf symlink at --write-recipients must be rejected without canonicalizing/following.
            let outside_victim = dir.path().join("outside-victim.txt");
            fs::write(&outside_victim, "do-not-overwrite\n").unwrap();
            let leaf_symlink_wr = real_sub.join("leaf-link-recipients.txt");
            std::os::unix::fs::symlink(&outside_victim, &leaf_symlink_wr).unwrap();
            let err_leaf_symlink = prepare_batch_recipient_refresh(
                &leaf_symlink_wr,
                &[],
                &[],
                None,
                &[],
                &[],
                &[r.to_string()],
            )
            .err()
            .expect("leaf symlink --write-recipients must be rejected");
            assert!(err_leaf_symlink.to_string().contains("symlink"));
            fs::remove_file(&leaf_symlink_wr).unwrap();

            // Transient symlink / file-swap between prepare and commit: even if a regular file
            // with identical prior bytes is placed back at the path after a transient symlink swap,
            // its file identity (dev, ino) changed and commit_batch_recipient_refresh must refuse.
            let transient_wr = real_sub.join("transient-recipients.txt");
            fs::write(&transient_wr, format!("{r}\n")).unwrap();
            let prep_plan = prepare_batch_recipient_refresh(
                &transient_wr,
                &[],
                &[],
                None,
                &[],
                &[],
                &[r.to_string()],
            )
            .expect("prepare existing recipient file");
            fs::remove_file(&transient_wr).unwrap();
            std::os::unix::fs::symlink(&outside_victim, &transient_wr).unwrap();
            fs::remove_file(&transient_wr).unwrap();
            fs::write(&transient_wr, format!("{r}\n")).unwrap();
            assert!(
                commit_batch_recipient_refresh(&prep_plan).is_err(),
                "transient swap changing recipient file identity must fail closed"
            );
            assert_eq!(
                fs::read_to_string(&outside_victim).unwrap(),
                "do-not-overwrite\n"
            );

            // Ancestor directory swap between prepare and commit: if the parent directory path
            // is swapped to a symlink pointing to an attacker directory after preparation,
            // commit_batch_recipient_refresh must refuse and never write to the redirected directory.
            let swap_dir = dir.path().join("swap-parent");
            let redirected_dir = dir.path().join("redirected-parent");
            fs::create_dir(&swap_dir).unwrap();
            fs::create_dir(&redirected_dir).unwrap();
            let swap_wr = swap_dir.join("recipients.txt");
            let swap_plan = prepare_batch_recipient_refresh(
                &swap_wr,
                &[],
                &[],
                None,
                &[],
                &[],
                &[r.to_string()],
            )
            .expect("prepare in swap_dir");
            let backup_swap_dir = dir.path().join("swap-parent-moved");
            fs::rename(&swap_dir, &backup_swap_dir).unwrap();
            std::os::unix::fs::symlink(&redirected_dir, &swap_dir).unwrap();
            assert!(
                commit_batch_recipient_refresh(&swap_plan).is_err(),
                "ancestor/parent swap to symlink after preparation must fail closed"
            );
            assert!(
                !redirected_dir.join("recipients.txt").exists(),
                "must never write recipient file into redirected symlink target directory"
            );
            fs::remove_file(&swap_dir).unwrap();
            fs::remove_dir_all(&backup_swap_dir).unwrap();
            fs::remove_dir_all(&redirected_dir).unwrap();

            // Group/other-writable parent directory on Unix must be rejected by handle-verified
            // ownership/mode check.
            validate_unix_directory_owner_and_mode(1000, 1000, 0o700, true, Path::new("/tmp/d"))
                .expect("owner-only directory mode 0700 must pass");
            validate_unix_directory_owner_and_mode(1000, 0, 0o1777, false, Path::new("/tmp"))
                .expect("root-owned sticky ancestor /tmp (1777) must pass");
            assert!(
                validate_unix_directory_owner_and_mode(
                    1000,
                    9999,
                    0o700,
                    true,
                    Path::new("/tmp/foreign")
                )
                .is_err(),
                "foreign-owned directory must be rejected"
            );
            assert!(
                validate_unix_directory_owner_and_mode(
                    1000,
                    1000,
                    0o777,
                    true,
                    Path::new("/tmp/world-writable")
                )
                .is_err(),
                "world-writable leaf parent directory must be rejected"
            );
            let writable_parent = dir.path().join("writable-parent");
            fs::create_dir(&writable_parent).unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&writable_parent, fs::Permissions::from_mode(0o777)).unwrap();
            }
            let err_writable_parent = prepare_batch_recipient_refresh(
                &writable_parent.join("recipients.txt"),
                &[],
                &[],
                None,
                &[],
                &[],
                &[r.to_string()],
            )
            .err()
            .expect("group/other-writable parent directory must be rejected");
            assert!(err_writable_parent
                .to_string()
                .contains("group/other-writable"));
            fs::remove_dir_all(&writable_parent).unwrap();

            // Deterministic post-stat substitution test: inject a destination replacement
            // immediately after the final pre-publication fstatat + byte read. Atomic swap
            // (`RENAME_SWAP` / `RENAME_EXCHANGE`) must detect that the displaced inode is
            // not `expected_id`, roll back the swap so the substituted entry remains intact,
            // and fail closed.
            let post_stat_wr = real_sub.join("post-stat-recipients.txt");
            fs::write(&post_stat_wr, "age1old\n").unwrap();
            let post_stat_plan = prepare_batch_recipient_refresh(
                &post_stat_wr,
                &[],
                &[],
                None,
                &[],
                &[],
                &[r.to_string()],
            )
            .expect("prepare post-stat recipient file");
            let post_stat_wr_clone = post_stat_wr.clone();
            set_batch_recipient_post_stat_hook(Some(Box::new(move || {
                let replacement = post_stat_wr_clone.with_extension("subst");
                fs::write(&replacement, "substituted-after-final-stat\n").unwrap();
                fs::rename(&replacement, &post_stat_wr_clone).unwrap();
            })));
            let post_stat_err = commit_batch_recipient_refresh(&post_stat_plan)
                .expect_err("post-stat destination substitution must be caught and rolled back");
            set_batch_recipient_post_stat_hook(None);
            assert!(matches!(
                post_stat_err,
                CliError::RecipientRefreshFailed { .. }
            ));
            assert_eq!(
                fs::read_to_string(&post_stat_wr).unwrap(),
                "substituted-after-final-stat\n",
                "rollback must preserve the substituted destination entry untouched"
            );
            fs::remove_file(&post_stat_wr).unwrap();
            for entry in fs::read_dir(&real_sub).unwrap().flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".seclusor-rcpt-")
                {
                    let _ = fs::remove_dir_all(entry.path());
                }
            }

            // Deterministic failed-rollback test: if the destination is substituted after
            // the final pre-publication fstatat AND a concurrent writer replaces the leaf
            // with a directory right after the first exchange so reverse swap and linkat
            // both fail, cleanup_temp must NOT unlink the displaced file at temp_cstr; it
            // must preserve the displaced file on disk and report its recovery path.
            let failed_rb_wr = real_sub.join("failed-rb-recipients.txt");
            fs::write(&failed_rb_wr, "age1old\n").unwrap();
            let failed_rb_plan = prepare_batch_recipient_refresh(
                &failed_rb_wr,
                &[],
                &[],
                None,
                &[],
                &[],
                &[r.to_string()],
            )
            .expect("prepare failed-rb recipient file");
            let failed_rb_wr_stat = failed_rb_wr.clone();
            set_batch_recipient_post_stat_hook(Some(Box::new(move || {
                let replacement = failed_rb_wr_stat.with_extension("subst2");
                fs::write(&replacement, "displaced-must-not-be-deleted\n").unwrap();
                fs::rename(&replacement, &failed_rb_wr_stat).unwrap();
            })));
            let failed_rb_wr_exch = failed_rb_wr.clone();
            set_batch_recipient_post_exchange_hook(Some(Box::new(move || {
                // Remove the published leaf and place a non-empty directory at `failed_rb_wr`
                // so neither reverse exchange nor `linkat` can restore `failed_rb_wr`.
                fs::remove_file(&failed_rb_wr_exch).unwrap();
                fs::create_dir(&failed_rb_wr_exch).unwrap();
                fs::write(failed_rb_wr_exch.join("blocker"), "block").unwrap();
            })));
            let failed_rb_err = commit_batch_recipient_refresh(&failed_rb_plan)
                .expect_err("failed rollback must fail closed and report recovery path");
            set_batch_recipient_post_stat_hook(None);
            set_batch_recipient_post_exchange_hook(None);
            let err_text = failed_rb_err.to_string();
            let preserved_path_str = err_text
                .split("displaced file preserved at ")
                .nth(1)
                .unwrap_or_else(|| panic!("unexpected error message: {err_text}"));
            let preserved_file_path = PathBuf::from(preserved_path_str);
            let preserved_entries: Vec<PathBuf> = fs::read_dir(&real_sub)
                .unwrap()
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".seclusor-rcpt-")
                })
                .collect();
            assert_eq!(
                preserved_entries.len(),
                1,
                "displaced file staging directory must be preserved when rollback fails"
            );
            assert!(
                preserved_file_path.starts_with(fs::canonicalize(&preserved_entries[0]).unwrap())
                    && preserved_file_path.ends_with("s/t"),
                "unexpected preserved path: {}",
                preserved_file_path.display()
            );
            assert_eq!(
                fs::read_to_string(&preserved_file_path).unwrap(),
                "displaced-must-not-be-deleted\n"
            );
            fs::remove_dir_all(&preserved_entries[0]).unwrap();
            fs::remove_dir_all(&failed_rb_wr).unwrap();

            // Deterministic retained-inner-descriptor substitution test: even if a hypothetical
            // same-UID actor retained a descriptor to `inner_fd` and exchanged an unrelated file
            // into `(inner_fd, "t")` after `atomic_swap_entries`, `commit_batch_recipient_refresh`
            // must detect the mismatch, never call `unlinkat` on the substituted file, and leave
            // the unrelated file intact on disk.
            let retained_fd_wr = real_sub.join("retained-fd-recipients.txt");
            fs::write(&retained_fd_wr, "age1old\n").unwrap();
            let retained_fd_plan = prepare_batch_recipient_refresh(
                &retained_fd_wr,
                &[],
                &[],
                None,
                &[],
                &[],
                &[r.to_string()],
            )
            .expect("prepare retained-fd recipient file");
            let bystander_path = real_sub.join("bystander-unrelated.txt");
            fs::write(&bystander_path, "unrelated-bystander-must-survive\n").unwrap();
            let captured_inner_fd = std::rc::Rc::new(std::cell::Cell::new(-1i32));
            let captured_clone = captured_inner_fd.clone();
            set_batch_recipient_post_inner_fd_hook(Some(Box::new(move |fd| {
                captured_clone.set(unsafe { libc::dup(fd) });
            })));
            let bystander_clone = bystander_path.clone();
            let real_sub_clone = real_sub.clone();
            set_batch_recipient_post_exchange_hook(Some(Box::new(move || {
                use std::ffi::CString;
                use std::os::fd::AsRawFd;
                let dup_fd = captured_inner_fd.get();
                assert!(dup_fd >= 0);
                let sub_dir = fs::File::open(&real_sub_clone).unwrap();
                let staged_c = CString::new("t").unwrap();
                let bystander_c =
                    CString::new(bystander_clone.file_name().unwrap().to_str().unwrap()).unwrap();
                unsafe {
                    atomic_swap_entries(
                        dup_fd,
                        staged_c.as_ptr(),
                        sub_dir.as_raw_fd(),
                        bystander_c.as_ptr(),
                    )
                    .expect("swap bystander into retained inner_fd/t");
                    libc::close(dup_fd);
                }
            })));
            let retained_err = commit_batch_recipient_refresh(&retained_fd_plan).expect_err(
                "retained-inner-descriptor substitution must fail closed without unlinking bystander",
            );
            set_batch_recipient_post_inner_fd_hook(None);
            set_batch_recipient_post_exchange_hook(None);
            assert!(matches!(
                retained_err,
                CliError::RecipientRefreshFailed { .. }
            ));
            // Reverse swap restored the bystander back to `retained_fd_wr` and preserved the
            // staging directory without calling `unlinkat` on the bystander inode!
            assert_eq!(
                fs::read_to_string(&retained_fd_wr).unwrap(),
                "unrelated-bystander-must-survive\n",
                "bystander file swapped via retained inner_fd must never be unlinked"
            );
            for entry in fs::read_dir(&real_sub).unwrap().flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".seclusor-rcpt-")
                {
                    let _ = fs::remove_dir_all(entry.path());
                }
            }
            let _ = fs::remove_file(&retained_fd_wr);
            let _ = fs::remove_file(&bystander_path);

            let non_utf8_path = dir.path().join(OsStr::from_bytes(b"non-utf8-\xff.age"));
            let err_non_utf8 = collect_batch_files(&BlobRekeyBatchArgs {
                files: vec![non_utf8_path],
                dir: None,
                glob: "*.age".to_string(),
                recursive: false,
                apply: false,
                state: None,
                backup: false,
                fail_fast: false,
                json: false,
                write_recipients: None,
                allow_self_lockout: false,
                allow_large: false,
                recipients: RecipientArgs::default(),
                prior_recipients: PriorRecipientArgs::default(),
                identities: IdentityArgs::default(),
                verify_identities: VerifyIdentityArgs::default(),
                passphrase: PassphraseArgs::default(),
            })
            .expect_err("non-UTF-8 input path must be rejected before lossy key conversion");
            assert!(err_non_utf8.to_string().contains("non-UTF-8"));
        }

        // Load identity to derive the authentic HMAC key for journal tests.
        let loaded_ids = seclusor_keyring::load_identity_file_auto(&id_path, None).unwrap();
        let test_auth_key = derive_journal_auth_key(&loaded_ids);

        // Disallow --state with --allow-self-lockout when no target-set verification identity
        // is provided, and reject a journal authenticated only by a retired source key.
        let rotated_id_path = dir.path().join("rotated-target-id.txt");
        let rotated_gen = seclusor_keyring::generate_identity_file(&rotated_id_path).unwrap();
        let err_lockout_state = handle_blob_rekey_batch(BlobRekeyBatchArgs {
            files: vec![blob_path.clone()],
            dir: None,
            glob: "*.age".to_string(),
            recursive: false,
            apply: false,
            state: Some(dir.path().join("lockout-state.json")),
            backup: false,
            fail_fast: false,
            json: false,
            write_recipients: None,
            allow_self_lockout: true,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![rotated_gen.recipient.clone()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
            prior_recipients: PriorRecipientArgs {
                prior_recipients: vec![r.to_string()],
                prior_recipient_files: vec![],
            },
            identities: IdentityArgs {
                identity_files: vec![id_path.clone()],
                identity_public_key: None,
            },
            verify_identities: VerifyIdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err(
            "--state with --allow-self-lockout and no target verification identity must be refused",
        );
        assert!(err_lockout_state
            .to_string()
            .contains("--state with --allow-self-lockout requires"));

        // Reject forged --state journal lacking a valid cryptographic auth_tag.
        let forged_state_path = dir.path().join("forged-state.json");
        let canon_blob_str = fs::canonicalize(&blob_path).unwrap().display().to_string();
        let mut forged_journal = BatchStateJournal {
            schema: STATE_JOURNAL_SCHEMA.to_string(),
            operation: "blob-rekey-batch".to_string(),
            target_recipients: vec![r.to_string()],
            prior_recipients: Some(vec![r.to_string()]),
            allow_recipient_mismatch: false,
            allow_self_lockout: false,
            allow_large: false,
            auth_tag: "0".repeat(64),
            records: std::collections::BTreeMap::new(),
        };
        forged_journal.records.insert(
            canon_blob_str.clone(),
            BatchJournalRecord {
                path: canon_blob_str.clone(),
                sha256_before: "a".repeat(64),
                sha256_after: sha256_hex(&fs::read(&blob_path).unwrap()),
                status: "rekeyed".to_string(),
                displaced_verified: true,
                ts: "20261116T000000Z".to_string(),
                opened_with: r.to_string(),
                stanzas_before: 1,
                stanzas_after: 1,
                delta: None,
                mode_before: Some("0600".to_string()),
                mode_after: Some("0600".to_string()),
                backup: None,
            },
        );
        atomic_write_private_ciphertext(
            &forged_state_path,
            serde_json::to_vec_pretty(&forged_journal)
                .unwrap()
                .as_slice(),
            None,
        )
        .unwrap();
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const WRITE_DAC: u32 = 0x0004_0000;
            const WRITE_OWNER: u32 = 0x0008_0000;
            let file = fs::OpenOptions::new()
                .access_mode(WRITE_DAC | WRITE_OWNER)
                .open(&forged_state_path)
                .unwrap();
            windows_dacl::restrict_private_file_dacl(&file).unwrap();
        }
        let err_forged = handle_blob_rekey_batch(BlobRekeyBatchArgs {
            files: vec![blob_path.clone()],
            dir: None,
            glob: "*.age".to_string(),
            recursive: false,
            apply: false,
            state: Some(forged_state_path),
            backup: false,
            fail_fast: false,
            json: false,
            write_recipients: None,
            allow_self_lockout: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![r.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
            prior_recipients: PriorRecipientArgs {
                prior_recipients: vec![r.to_string()],
                prior_recipient_files: vec![],
            },
            identities: IdentityArgs {
                identity_files: vec![id_path.clone()],
                identity_public_key: None,
            },
            verify_identities: VerifyIdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("forged --state journal without valid HMAC auth_tag must be rejected");
        assert!(err_forged.to_string().contains("authenticity verification"));

        // Reject malformed --state journal where sha256_before == sha256_after (even with a valid auth_tag).
        let bad_state_path = dir.path().join("bad-state.json");
        let mut bad_journal = BatchStateJournal {
            schema: STATE_JOURNAL_SCHEMA.to_string(),
            operation: "blob-rekey-batch".to_string(),
            target_recipients: vec![r.to_string()],
            prior_recipients: Some(vec![r.to_string()]),
            allow_recipient_mismatch: false,
            allow_self_lockout: false,
            allow_large: false,
            auth_tag: String::new(),
            records: std::collections::BTreeMap::new(),
        };
        bad_journal.records.insert(
            canon_blob_str.clone(),
            BatchJournalRecord {
                path: canon_blob_str,
                sha256_before: "a".repeat(64),
                sha256_after: "a".repeat(64),
                status: "in_progress".to_string(),
                displaced_verified: false,
                ts: "20261116T000000Z".to_string(),
                opened_with: r.to_string(),
                stanzas_before: 1,
                stanzas_after: 1,
                delta: Some(BatchReportDelta {
                    added: vec![],
                    removed: vec![],
                }),
                mode_before: Some("0600".to_string()),
                mode_after: Some("0600".to_string()),
                backup: None,
            },
        );
        persist_state_journal(&bad_state_path, &mut bad_journal, &test_auth_key, None).unwrap();
        let err_bad_state = handle_blob_rekey_batch(BlobRekeyBatchArgs {
            files: vec![blob_path.clone()],
            dir: None,
            glob: "*.age".to_string(),
            recursive: false,
            apply: false,
            state: Some(bad_state_path.clone()),
            backup: false,
            fail_fast: false,
            json: false,
            write_recipients: None,
            allow_self_lockout: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![r.to_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
            prior_recipients: PriorRecipientArgs {
                prior_recipients: vec![r.to_string()],
                prior_recipient_files: vec![],
            },
            identities: IdentityArgs {
                identity_files: vec![id_path.clone()],
                identity_public_key: None,
            },
            verify_identities: VerifyIdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("journal record with sha256_before == sha256_after must be rejected");
        assert!(err_bad_state.to_string().contains("malformed record"));

        // Foreign-owned journal with victim-only protected DACL must be rejected;
        // unprotected DACLs, non-owner ACEs, unexpected ACE types, and truncated ACE
        // headers must all be rejected before SID cast.
        validate_windows_ace_header(WINDOWS_ACCESS_ALLOWED_ACE_TYPE, 20, Some(12))
            .expect("valid ACCESS_ALLOWED_ACE header must pass");
        assert!(
            validate_windows_ace_header(1, 20, Some(12)).is_err(),
            "non-ACCESS_ALLOWED_ACE_TYPE must be rejected before casting"
        );
        assert!(
            validate_windows_ace_header(WINDOWS_ACCESS_ALLOWED_ACE_TYPE, 8, None).is_err(),
            "truncated ACE header (< 12 bytes) must be rejected before casting"
        );
        assert!(
            validate_windows_ace_header(WINDOWS_ACCESS_ALLOWED_ACE_TYPE, 16, Some(12)).is_err(),
            "SID length exceeding AceSize must be rejected"
        );

        let victim_sid: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 21, 10, 20, 30];
        let attacker_sid: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 21, 99, 99, 99];
        let protected_ctrl = WINDOWS_SE_DACL_PRESENT | WINDOWS_SE_DACL_PROTECTED;
        validate_windows_owner_and_dacl_sids(
            victim_sid,
            Some(victim_sid),
            protected_ctrl,
            &[(WINDOWS_ACCESS_ALLOWED_ACE_TYPE, victim_sid)],
        )
        .expect("owner-owned protected victim-only DACL must pass");
        let foreign_owner_err = validate_windows_owner_and_dacl_sids(
            victim_sid,
            Some(attacker_sid),
            protected_ctrl,
            &[(WINDOWS_ACCESS_ALLOWED_ACE_TYPE, victim_sid)],
        )
        .expect_err("foreign-owned journal with victim-only DACL must be rejected");
        assert!(foreign_owner_err
            .to_string()
            .contains("not owned by the current user SID"));
        let unprotected_err = validate_windows_owner_and_dacl_sids(
            victim_sid,
            Some(victim_sid),
            WINDOWS_SE_DACL_PRESENT,
            &[(WINDOWS_ACCESS_ALLOWED_ACE_TYPE, victim_sid)],
        )
        .expect_err("unprotected DACL must be rejected");
        assert!(unprotected_err.to_string().contains("protected owner-only"));
        let non_owner_ace_err = validate_windows_owner_and_dacl_sids(
            victim_sid,
            Some(victim_sid),
            protected_ctrl,
            &[
                (WINDOWS_ACCESS_ALLOWED_ACE_TYPE, victim_sid),
                (WINDOWS_ACCESS_ALLOWED_ACE_TYPE, attacker_sid),
            ],
        )
        .expect_err("non-owner ACE in DACL must be rejected");
        assert!(non_owner_ace_err.to_string().contains("non-owner SID"));

        // Windows parent-directory ownership and DACL validation:
        // - trusted owner + trusted ACEs pass;
        // - foreign directory owner is rejected even if DACL has no dangerous grants;
        // - non-basic ACE types (e.g. callback or object ACEs) are rejected fail-closed;
        // - untrusted SID with dangerous write/file-add/child-delete mask is rejected.
        validate_windows_directory_owner_and_dacl(
            true,
            WINDOWS_SE_DACL_PRESENT,
            &[(
                WINDOWS_ACCESS_ALLOWED_ACE_TYPE,
                WINDOWS_DANGEROUS_DIR_WRITE_MASK,
                true,
            )],
        )
        .expect("trusted directory owner and trusted ACE must pass");
        let foreign_dir_owner_err = validate_windows_directory_owner_and_dacl(
            false,
            WINDOWS_SE_DACL_PRESENT,
            &[(WINDOWS_ACCESS_ALLOWED_ACE_TYPE, 0, true)],
        )
        .expect_err("foreign directory owner must be rejected");
        assert!(foreign_dir_owner_err
            .to_string()
            .contains("not owned by a trusted principal"));
        let callback_ace_dir_err = validate_windows_directory_owner_and_dacl(
            true,
            WINDOWS_SE_DACL_PRESENT,
            &[(9, 0, true)],
        )
        .expect_err("callback/object ACE type in directory DACL must be rejected");
        assert!(callback_ace_dir_err
            .to_string()
            .contains("unsupported ACE type"));
        let untrusted_dir_write_err = validate_windows_directory_owner_and_dacl(
            true,
            WINDOWS_SE_DACL_PRESENT,
            &[(WINDOWS_ACCESS_ALLOWED_ACE_TYPE, 0x0002, false)],
        )
        .expect_err("untrusted FILE_ADD_FILE grant in directory DACL must be rejected");
        assert!(untrusted_dir_write_err
            .to_string()
            .contains("grants non-owner write"));

        // Verify Windows FILE_RENAME_INFO.FileName offset matches native ABI layout
        // (20 bytes on 64-bit platforms, 12 bytes on 32-bit platforms) and
        // build_windows_file_rename_info_buffer enforces non-null RootDirectory and
        // relative leaf names without path separators.
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            windows_file_rename_info_filename_offset(),
            20,
            "FILE_RENAME_INFO.FileName must start at byte offset 20 on 64-bit targets"
        );
        #[cfg(target_pointer_width = "32")]
        assert_eq!(
            windows_file_rename_info_filename_offset(),
            12,
            "FILE_RENAME_INFO.FileName must start at byte offset 12 on 32-bit targets"
        );
        let dummy_root = 0x1234usize as *mut core::ffi::c_void;
        let leaf_utf16: Vec<u16> = "recipients.txt".encode_utf16().collect();
        assert!(
            build_windows_file_rename_info_buffer(core::ptr::null_mut(), &leaf_utf16, true)
                .is_err(),
            "null RootDirectory must be rejected"
        );
        for bad_leaf in [
            "C:\\recipients.txt",
            "sub\\recipients.txt",
            "sub/recipients.txt",
            "..",
        ] {
            let wide: Vec<u16> = bad_leaf.encode_utf16().collect();
            assert!(
                build_windows_file_rename_info_buffer(dummy_root, &wide, true).is_err(),
                "non-leaf or separator-containing FileName {bad_leaf:?} must be rejected"
            );
        }
        let (rename_buf, rename_len) =
            build_windows_file_rename_info_buffer(dummy_root, &leaf_utf16, true)
                .expect("valid relative leaf with non-null RootDirectory must succeed");
        let rename_bytes =
            unsafe { core::slice::from_raw_parts(rename_buf.as_ptr().cast::<u8>(), rename_len) };
        assert_eq!(rename_bytes[0], 1, "ReplaceIfExists must be 1");
        let name_offset = windows_file_rename_info_filename_offset();
        let encoded_name = unsafe {
            core::slice::from_raw_parts(
                rename_bytes.as_ptr().add(name_offset).cast::<u16>(),
                leaf_utf16.len(),
            )
        };
        assert_eq!(encoded_name, leaf_utf16.as_slice());

        // Bounded journal serialization rejects overflow before allocation growth or
        // publication and preserves the previous readable journal.
        let preserved_state_path = dir.path().join("preserved-state.json");
        let mut bounded_journal = BatchStateJournal {
            schema: STATE_JOURNAL_SCHEMA.to_string(),
            operation: "blob-rekey-batch".to_string(),
            target_recipients: vec![r.to_string()],
            prior_recipients: Some(vec![r.to_string()]),
            allow_recipient_mismatch: false,
            allow_self_lockout: false,
            allow_large: false,
            auth_tag: String::new(),
            records: std::collections::BTreeMap::new(),
        };
        let initial_snap = persist_state_journal(
            &preserved_state_path,
            &mut bounded_journal,
            &test_auth_key,
            None,
        )
        .unwrap();
        let initial_on_disk = fs::read(&preserved_state_path).unwrap();
        let small_cap = initial_on_disk.len();
        serialize_state_journal_bounded(&bounded_journal, small_cap)
            .expect("exact-fit journal serialization must succeed");
        bounded_journal.records.insert(
            "/tmp/extra.age".to_string(),
            BatchJournalRecord {
                path: "/tmp/extra.age".to_string(),
                sha256_before: "a".repeat(64),
                sha256_after: "b".repeat(64),
                status: "in_progress".to_string(),
                displaced_verified: false,
                ts: "20261117T000000Z".to_string(),
                opened_with: r.to_string(),
                stanzas_before: 1,
                stanzas_after: 1,
                delta: None,
                mode_before: Some("0600".to_string()),
                mode_after: Some("0600".to_string()),
                backup: None,
            },
        );
        let overflow_err = serialize_state_journal_bounded(&bounded_journal, small_cap)
            .expect_err("journal crossing size limit must be rejected before write");
        assert!(overflow_err.to_string().contains("exceeds maximum size"));
        assert_eq!(
            fs::read(&preserved_state_path).unwrap(),
            initial_on_disk,
            "previous readable journal on disk must remain intact when serialization overflows"
        );
        assert_eq!(
            initial_snap.prior.bytes.as_slice(),
            initial_on_disk.as_slice()
        );

        // An `in_progress` journal record with `displaced_verified: false` (e.g. when a
        // concurrent process created a hardlink on the old ciphertext between CAS and
        // replacement so `atomic_write_private_ciphertext` returned `PostCommitFailure`
        // before `displaced_verified` could be set) MUST NOT be promoted to `rekeyed` /
        // `already-done` on resume even when on-disk ciphertext matches `sha256_after`.
        let unverified_blob_path = dir.path().join("unverified-displaced.age");
        let target_recip: seclusor_crypto::Recipient = rotated_gen.recipient.parse().unwrap();
        let new_ct = seclusor_crypto::encrypt(b"rotated-secret", &[target_recip]).unwrap();
        fs::write(&unverified_blob_path, &new_ct).unwrap();
        let canon_unverified_str = fs::canonicalize(&unverified_blob_path)
            .unwrap()
            .display()
            .to_string();
        let rotated_ids =
            seclusor_keyring::load_identity_file_auto(&rotated_id_path, None).unwrap();
        let rotated_auth_key = derive_journal_auth_key(&rotated_ids);
        let unverified_state_path = dir.path().join("unverified-displaced-state.json");
        let mut unverified_journal = BatchStateJournal {
            schema: STATE_JOURNAL_SCHEMA.to_string(),
            operation: "blob-rekey-batch".to_string(),
            target_recipients: vec![rotated_gen.recipient.clone()],
            prior_recipients: Some(vec![r.to_string()]),
            allow_recipient_mismatch: false,
            allow_self_lockout: false,
            allow_large: false,
            auth_tag: String::new(),
            records: std::collections::BTreeMap::new(),
        };
        unverified_journal.records.insert(
            canon_unverified_str.clone(),
            BatchJournalRecord {
                path: canon_unverified_str,
                sha256_before: "a".repeat(64),
                sha256_after: sha256_hex(&new_ct),
                status: "in_progress".to_string(),
                displaced_verified: false,
                ts: "20261117T000000Z".to_string(),
                opened_with: r.to_string(),
                stanzas_before: 1,
                stanzas_after: 1,
                delta: None,
                mode_before: Some("0600".to_string()),
                mode_after: Some("0600".to_string()),
                backup: None,
            },
        );
        persist_state_journal(
            &unverified_state_path,
            &mut unverified_journal,
            &rotated_auth_key,
            None,
        )
        .unwrap();
        let unverified_resume_err = handle_blob_rekey_batch(BlobRekeyBatchArgs {
            files: vec![unverified_blob_path.clone()],
            dir: None,
            glob: "*.age".to_string(),
            recursive: false,
            apply: true,
            state: Some(unverified_state_path.clone()),
            backup: false,
            fail_fast: false,
            json: false,
            write_recipients: None,
            allow_self_lockout: false,
            allow_large: false,
            recipients: RecipientArgs {
                recipients: vec![rotated_gen.recipient.clone()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
            prior_recipients: PriorRecipientArgs {
                prior_recipients: vec![r.to_string()],
                prior_recipient_files: vec![],
            },
            identities: IdentityArgs {
                identity_files: vec![id_path.clone()],
                identity_public_key: None,
            },
            verify_identities: VerifyIdentityArgs {
                verify_identity_files: vec![rotated_id_path.clone()],
                verify_identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("unverified in_progress replacement must not be auto-promoted on resume");
        assert!(matches!(unverified_resume_err, CliError::CommandFailed(1)));
        let (reloaded_unverified, _) = load_or_init_state_journal(
            &unverified_state_path,
            std::slice::from_ref(&rotated_gen.recipient),
            Some(&[r.to_string()]),
            false,
            false,
            false,
            &rotated_auth_key,
        )
        .unwrap();
        assert_eq!(
            reloaded_unverified.records.values().next().unwrap().status,
            "in_progress",
            "unverified in_progress record must remain in_progress and never promote to rekeyed"
        );
        fs::remove_file(&unverified_blob_path).unwrap();
        fs::remove_file(&unverified_state_path).unwrap();

        // Windows journal handle-retention and replacement checks:
        // 1. Retained data handle is rejected by share_mode(0) / FILE_SHARE_DELETE.
        // 2. Retained WRITE_DAC-only handle on the old file object is orphaned onto the
        //    unlinked file object when `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` publishes
        //    a new temp file object (`new_snap.file_id != initial_snap.file_id`), and any
        //    unauthenticated journal modification is rejected by `auth_tag`.
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const WRITE_DAC: u32 = 0x0004_0000;
            const FILE_SHARE_ALL: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;

            let retained_data_handle =
                fs::File::open(&preserved_state_path).expect("open retained data handle");
            assert!(
                read_existing_state_journal_for_cas(&preserved_state_path).is_err(),
                "retained data handle on --state must be rejected by share_mode(0)"
            );
            assert!(
                persist_state_journal(
                    &preserved_state_path,
                    &mut bounded_journal,
                    &test_auth_key,
                    Some(&initial_snap),
                )
                .is_err(),
                "retained data handle on --state must be rejected before rewrite"
            );
            drop(retained_data_handle);

            // Any retained handle on `--state` (even a `WRITE_DAC`-only handle) is rejected by
            // `ShareAccess = 0` during `atomic_write_private_journal` and `read_existing_state_journal_for_cas`.
            let retained_write_dac = fs::OpenOptions::new()
                .access_mode(WRITE_DAC)
                .share_mode(FILE_SHARE_ALL)
                .open(&preserved_state_path)
                .expect("open retained WRITE_DAC handle");
            assert!(
                persist_state_journal(
                    &preserved_state_path,
                    &mut bounded_journal,
                    &test_auth_key,
                    Some(&initial_snap),
                )
                .is_err(),
                "retained WRITE_DAC handle on --state must be rejected by ShareAccess = 0"
            );
            drop(retained_write_dac);

            let (old_handle_id, _) =
                path_identity_and_nlink_nofollow(&preserved_state_path).unwrap();
            assert_eq!(old_handle_id, initial_snap.file_id);

            let replaced_snap = persist_state_journal(
                &preserved_state_path,
                &mut bounded_journal,
                &test_auth_key,
                Some(&initial_snap),
            )
            .expect("rewrite journal via handle-bound displacement");
            assert_ne!(
                replaced_snap.file_id, old_handle_id,
                "handle-bound replacement must bind state_path to a new file object"
            );

            // Windows runtime test for batch --write-recipients creation, replacement, and
            // automatic crash-recovery of `.seclusor-displaced-<leaf>` via SetFileInformationByHandle.
            let win_rcpt_path = dir.path().join("win-recipients.txt");
            let create_plan = prepare_batch_recipient_refresh(
                &win_rcpt_path,
                &[],
                &[],
                None,
                &[],
                &[],
                &[r.to_string()],
            )
            .expect("prepare new Windows recipient file");
            commit_batch_recipient_refresh(&create_plan)
                .expect("create Windows recipient file via SetFileInformationByHandle");
            assert_eq!(
                fs::read_to_string(&win_rcpt_path).unwrap(),
                format!("{r}\n")
            );

            let replace_plan = prepare_batch_recipient_refresh(
                &win_rcpt_path,
                &[],
                &[],
                None,
                &[],
                &[],
                &[rotated_gen.recipient.clone()],
            )
            .expect("prepare existing Windows recipient file");
            commit_batch_recipient_refresh(&replace_plan)
                .expect("replace Windows recipient file via SetFileInformationByHandle");
            assert_eq!(
                fs::read_to_string(&win_rcpt_path).unwrap(),
                format!("{}\n", rotated_gen.recipient)
            );

            // Simulate an interrupted replacement where `win-recipients.txt` was displaced to
            // `.seclusor-displaced-win-recipients.txt` before the new file was published:
            // the next `prepare_batch_recipient_refresh` must automatically recover it by handle.
            let displaced_rcpt_path = dir.path().join(".seclusor-displaced-win-recipients.txt");
            fs::rename(&win_rcpt_path, &displaced_rcpt_path).unwrap();
            assert!(!win_rcpt_path.exists());
            let recovered_plan = prepare_batch_recipient_refresh(
                &win_rcpt_path,
                &[],
                &[],
                None,
                &[],
                &[],
                &[r.to_string()],
            )
            .expect("recover displaced Windows recipient file on prepare");
            assert!(
                win_rcpt_path.exists() && !displaced_rcpt_path.exists(),
                "displaced Windows recipient file must be restored to leaf_name"
            );
            commit_batch_recipient_refresh(&recovered_plan)
                .expect("commit after recovering displaced Windows recipient file");
            assert_eq!(
                fs::read_to_string(&win_rcpt_path).unwrap(),
                format!("{r}\n")
            );
        }

        // On macOS, a --state journal with a non-owner extended ACL must be rejected (not merely warned).
        #[cfg(target_os = "macos")]
        {
            let acl_state_path = dir.path().join("acl-state.json");
            let mut valid_journal = BatchStateJournal {
                schema: STATE_JOURNAL_SCHEMA.to_string(),
                operation: "blob-rekey-batch".to_string(),
                target_recipients: vec![r.to_string()],
                prior_recipients: Some(vec![r.to_string()]),
                allow_recipient_mismatch: false,
                allow_self_lockout: false,
                allow_large: false,
                auth_tag: String::new(),
                records: std::collections::BTreeMap::new(),
            };
            persist_state_journal(&acl_state_path, &mut valid_journal, &test_auth_key, None)
                .unwrap();
            let status = std::process::Command::new("/bin/chmod")
                .args(["+a", "user:root allow read,write"])
                .arg(&acl_state_path)
                .status()
                .expect("run /bin/chmod +a");
            assert!(status.success(), "set non-owner ACL on state journal");
            let acl_err = read_existing_state_journal_for_cas(&acl_state_path)
                .expect_err("non-owner ACL on --state journal must be refused");
            assert!(
                acl_err.to_string().contains("non-owner extended ACL"),
                "unexpected error: {acl_err}"
            );
        }
    }
}
