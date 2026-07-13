//! seclusor-keyring
//!
//! Identity/recipient management. Library consumers (e.g. lanyte-attest) will
//! link this crate directly.

mod error;

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use seclusor_core::constants::INLINE_CIPHERTEXT_PREFIX;
use seclusor_core::validate::validate_strict;
use seclusor_core::SecretsFile;
use secrecy::{ExposeSecret, SecretString};

pub use error::{KeyringError, Result};
pub use seclusor_crypto::{Identity, Recipient};

/// Default environment variable used for recipient discovery.
pub const DEFAULT_RECIPIENTS_ENV_VAR: &str = "SECLUSOR_RECIPIENTS";

/// Maximum bytes read from recipient file/env sources.
pub const MAX_RECIPIENT_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_REPO_ROOT_SEARCH_DEPTH: usize = 32;

/// Maximum size of a passphrase-protected identity file (before decryption).
pub const MAX_PROTECTED_IDENTITY_FILE_BYTES: usize = 8192;

/// Maximum header bytes inspected for public-key metadata (no secret decrypt).
pub const MAX_IDENTITY_PUBLIC_METADATA_BYTES: usize = 8192;

/// Marker for age-encrypted (passphrase-protected) identity files.
const AGE_ARMOR_BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

/// Generated age identity material.
#[derive(Clone, PartialEq, Eq)]
pub struct GeneratedIdentity {
    /// Secret identity string (`AGE-SECRET-KEY-...`).
    pub identity: String,
    /// Public recipient string (`age1...`).
    pub recipient: String,
}

/// Recipient discovery options.
#[derive(Debug, Clone, Default)]
pub struct RecipientDiscoveryOptions {
    /// Optional file containing recipient entries (one per line).
    pub recipient_file: Option<PathBuf>,
    /// Optional environment variable containing recipient entries.
    pub recipient_env_var: Option<String>,
}

/// Generate a new X25519 age identity and recipient pair.
pub fn generate_identity() -> GeneratedIdentity {
    let identity = Identity::generate();
    let recipient = identity.to_public();
    GeneratedIdentity {
        identity: seclusor_crypto::identity_to_string(&identity),
        recipient: recipient.to_string(),
    }
}

/// Generate a new identity and atomically create an identity file.
///
/// File creation fails if the target already exists.
/// On Unix, file mode is restricted to `0600`.
pub fn generate_identity_file(path: impl AsRef<Path>) -> Result<GeneratedIdentity> {
    let path = path.as_ref();
    enforce_identity_file_pathguard(path)?;
    let generated = generate_identity();
    let mut file = create_new_identity_file(path)?;
    writeln!(file, "# public key: {}", generated.recipient)?;
    writeln!(file, "{}", generated.identity)?;
    file.flush()?;
    Ok(generated)
}

/// Generate a new identity and create a passphrase-protected identity file.
///
/// The file contains a public key comment header followed by an age-encrypted
/// block containing the secret key. Same pathguard and permission enforcement
/// as `generate_identity_file`.
pub fn generate_identity_file_with_passphrase(
    path: impl AsRef<Path>,
    passphrase: &SecretString,
) -> Result<GeneratedIdentity> {
    let path = path.as_ref();
    enforce_identity_file_pathguard(path)?;
    let generated = generate_identity();

    let inner = format!(
        "# public key: {}\n{}\n",
        generated.recipient, generated.identity
    );
    // Encrypt the inner identity content with passphrase, writing directly
    // to an armored output so the file is ASCII-safe and contains the
    // BEGIN AGE ENCRYPTED FILE marker for detection.
    let encryptor = age::Encryptor::with_user_passphrase(secrecy::SecretString::from(
        passphrase.expose_secret().to_owned(),
    ));
    let mut armored_buf = Vec::new();
    {
        let armor_writer = age::armor::ArmoredWriter::wrap_output(
            &mut armored_buf,
            age::armor::Format::AsciiArmor,
        )
        .map_err(|_| KeyringError::Crypto(seclusor_crypto::CryptoError::EncryptionFailed))?;
        let mut encrypt_writer = encryptor
            .wrap_output(armor_writer)
            .map_err(|_| KeyringError::Crypto(seclusor_crypto::CryptoError::EncryptionFailed))?;
        encrypt_writer
            .write_all(inner.as_bytes())
            .map_err(|_| KeyringError::Crypto(seclusor_crypto::CryptoError::EncryptionFailed))?;
        encrypt_writer
            .finish()
            .and_then(|armor| armor.finish())
            .map_err(|_| KeyringError::Crypto(seclusor_crypto::CryptoError::EncryptionFailed))?;
    }

    let mut file = create_new_identity_file(path)?;
    writeln!(
        file,
        "# This is a passphrase-protected seclusor identity file."
    )?;
    writeln!(file, "# Public key: {}", generated.recipient)?;
    writeln!(
        file,
        "# To use this identity, you will be prompted for a passphrase."
    )?;
    file.write_all(&armored_buf)?;
    file.flush()?;
    Ok(generated)
}

/// Check whether an identity file is passphrase-protected (age-encrypted).
///
/// Reads up to 4 KiB to detect the `BEGIN AGE ENCRYPTED FILE` marker.
pub fn is_passphrase_protected_identity(path: impl AsRef<Path>) -> Result<bool> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; 4096];
    let n = file.read(&mut buf)?;
    let header = String::from_utf8_lossy(&buf[..n]);
    Ok(header.contains(AGE_ARMOR_BEGIN))
}

/// Load identities from a passphrase-protected identity file.
///
/// On Unix, file permissions must be exactly `0600` (same contract as
/// plaintext identity files). Reads through a bounded reader capped at
/// `MAX_PROTECTED_IDENTITY_FILE_BYTES` to prevent resource exhaustion.
pub fn load_identity_file_with_passphrase(
    path: impl AsRef<Path>,
    passphrase: &SecretString,
) -> Result<Vec<Identity>> {
    let path = path.as_ref();

    // Enforce 0600 + owner UID — same contract as plaintext identities
    seclusor_crypto::assert_identity_file_access(path)?;

    // Bounded read to enforce size cap at read time (no TOCTOU gap)
    let max = MAX_PROTECTED_IDENTITY_FILE_BYTES as u64;
    let mut file = File::open(path)?;
    let mut limited = std::io::Read::by_ref(&mut file).take(max + 1);
    let mut raw_bytes = Vec::new();
    limited
        .read_to_end(&mut raw_bytes)
        .map_err(|_| KeyringError::ProtectedIdentityDecryptFailed)?;
    if raw_bytes.len() as u64 > max {
        return Err(KeyringError::ProtectedIdentityFileTooLarge {
            actual: raw_bytes.len() as u64,
            max: MAX_PROTECTED_IDENTITY_FILE_BYTES,
        });
    }

    let raw =
        String::from_utf8(raw_bytes).map_err(|_| KeyringError::ProtectedIdentityDecryptFailed)?;

    // Extract the age-armored block (skip comment header lines)
    let armor_start = raw
        .find(AGE_ARMOR_BEGIN)
        .ok_or(KeyringError::ProtectedIdentityDecryptFailed)?;
    let armored = &raw[armor_start..];

    let decrypted = {
        let armored_reader = age::armor::ArmoredReader::new(armored.as_bytes());
        let decryptor = age::Decryptor::new_buffered(armored_reader)
            .map_err(|_| KeyringError::ProtectedIdentityDecryptFailed)?;
        let pp_identity =
            age::scrypt::Identity::new(SecretString::from(passphrase.expose_secret().to_owned()));
        let mut reader = decryptor
            .decrypt(std::iter::once(&pp_identity as &dyn age::Identity))
            .map_err(|_| KeyringError::ProtectedIdentityDecryptFailed)?;
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|_| KeyringError::ProtectedIdentityDecryptFailed)?;
        buf
    };

    let inner = String::from_utf8(decrypted).map_err(|_| KeyringError::ProtectedIdentityNotUtf8)?;

    Ok(seclusor_crypto::parse_identity_file_contents(&inner)?)
}

/// Load identities from an identity file, autodetecting plaintext vs protected.
///
/// If the file is passphrase-protected and no passphrase is provided, returns
/// `ProtectedIdentityNoPassphrase`. If plaintext, the passphrase is ignored.
///
/// Access preflight (Unix `0600` + owner) runs **before** any format detection
/// or secret-body read so insecure files fail closed without probing contents.
pub fn load_identity_file_auto(
    path: impl AsRef<Path>,
    passphrase: Option<&SecretString>,
) -> Result<Vec<Identity>> {
    let path = path.as_ref();
    seclusor_crypto::assert_identity_file_access(path)?;
    if is_passphrase_protected_identity(path)? {
        match passphrase {
            Some(pp) => load_identity_file_with_passphrase(path, pp),
            None => Err(KeyringError::ProtectedIdentityNoPassphrase),
        }
    } else {
        Ok(seclusor_crypto::load_identity_file(path)?)
    }
}

/// Resolve the primary platform seclusor config directory.
///
/// Order:
/// 1. Absolute `$XDG_CONFIG_HOME/seclusor` when set (relative values ignored)
/// 2. macOS: `$HOME/Library/Application Support/seclusor`
/// 3. Other Unix: `$HOME/.config/seclusor`
/// 4. Windows: `%APPDATA%\seclusor` (then `%USERPROFILE%\.config\seclusor`)
///
/// When absolute `XDG_CONFIG_HOME` is set on macOS, it **replaces** Application
/// Support as the primary root (not additive). For discovery, also see
/// [`legacy_seclusor_config_dirs`] which adds the documented `~/.config/seclusor`
/// compatibility root on macOS when XDG is unset.
pub fn seclusor_config_dir() -> Option<PathBuf> {
    if let Some(xdg) = absolute_xdg_config_home() {
        return Some(xdg.join("seclusor"));
    }

    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")?;
        if home.is_empty() {
            return None;
        }
        Some(
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("seclusor"),
        )
    }

    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let appdata = appdata.trim();
            if !appdata.is_empty() {
                return Some(PathBuf::from(appdata).join("seclusor"));
            }
        }
        if let Ok(home) = std::env::var("USERPROFILE") {
            let home = home.trim();
            if !home.is_empty() {
                return Some(PathBuf::from(home).join(".config").join("seclusor"));
            }
        }
        return None;
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let home = std::env::var_os("HOME")?;
        if home.is_empty() {
            return None;
        }
        Some(PathBuf::from(home).join(".config").join("seclusor"))
    }

    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// Additional bounded config roots kept for operator-doc compatibility.
///
/// On macOS, docs historically used `~/.config/seclusor/` while the platform
/// primary is Application Support. That path is an explicit secondary root
/// only (still non-recursive, still no home walk). Empty on non-macOS.
pub fn legacy_seclusor_config_dirs() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let mut dirs = Vec::new();
        if absolute_xdg_config_home().is_none() {
            if let Some(home) = std::env::var_os("HOME") {
                if !home.is_empty() {
                    dirs.push(PathBuf::from(home).join(".config").join("seclusor"));
                }
            }
        }
        dirs
    }
    #[cfg(not(target_os = "macos"))]
    {
        Vec::new()
    }
}

/// Bounded identity-file search roots for public-key lookup.
///
/// For each config root (primary + legacy compatibility):
/// - `<config>/identities/` (dedicated directory; non-recursive; any non-hidden
///   regular file — **symlinks are skipped** via `DirEntry::file_type`)
/// - `<config>/` itself (direct files only; non-recursive; filtered by
///   [`is_config_root_identity_candidate`])
///
/// Does not walk `$HOME`, `$PATH`, or arbitrary environment overrides.
///
/// On macOS, an absolute `XDG_CONFIG_HOME` **replaces** the Application Support
/// primary (it is not additive). Relative `XDG_CONFIG_HOME` is ignored.
pub fn default_identity_search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    for cfg in seclusor_config_dir()
        .into_iter()
        .chain(legacy_seclusor_config_dirs())
    {
        for root in [cfg.join("identities"), cfg] {
            if seen.insert(root.clone()) {
                roots.push(root);
            }
        }
    }
    roots
}

/// Parse a public key from identity-file header comments (public metadata only).
///
/// Recognizes comment lines of the form `# public key: age1...` with
/// case-insensitive label matching (`# Public key:` included). Stops at the
/// first non-comment body/armor line when used via incremental readers.
/// Does not decrypt passphrase-protected bodies.
pub fn parse_public_key_from_identity_header(header: &str) -> Option<String> {
    for line in header.lines() {
        match classify_identity_header_line(line) {
            HeaderLine::PublicKey(pk) => return Some(pk),
            HeaderLine::Comment => continue,
            HeaderLine::Body => break,
        }
    }
    None
}

/// Read public-key metadata from an identity file with a bounded header read.
///
/// Reads **comment lines only** (through newline). At the first non-comment
/// body/armor line, stops after the first non-whitespace body byte without
/// buffering the remainder of that line (so secret material is not pulled into
/// memory during discovery). Total header bytes are capped by
/// [`MAX_IDENTITY_PUBLIC_METADATA_BYTES`].
///
/// Returns `Ok(None)` when the header has no recognizable public-key comment.
/// Does not enforce 0600/ownership — those gates run only when loading secrets.
pub fn read_identity_file_public_key(path: impl AsRef<Path>) -> Result<Option<String>> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let mut limited =
        std::io::Read::by_ref(&mut file).take(MAX_IDENTITY_PUBLIC_METADATA_BYTES as u64);
    read_identity_public_key_from_reader(&mut limited)
}

/// Public-key metadata scan over an arbitrary reader.
///
/// `pub(crate)` test seam for the no-read-ahead regression (poison readers).
/// Not a consumer API — callers should use [`read_identity_file_public_key`].
///
/// Stops without read-ahead into body lines: once a non-whitespace byte that
/// is not `#` is observed, returns `Ok(None)` (or the key if found earlier)
/// without consuming further bytes from that line.
pub(crate) fn read_identity_public_key_from_reader<R: Read>(
    reader: &mut R,
) -> Result<Option<String>> {
    let mut total = 0usize;
    loop {
        match read_next_header_line(reader, &mut total)? {
            HeaderScan::PublicKey(pk) => return Ok(Some(pk)),
            HeaderScan::Continue => continue,
            HeaderScan::Stop => return Ok(None),
            HeaderScan::Eof => return Ok(None),
        }
    }
}

/// Locate the unique identity file whose header advertises `public_key`.
///
/// `public_key` must parse as an age recipient (`age1...`). Discovery is limited
/// to [`default_identity_search_roots`]. Matching uses public metadata only.
///
/// Errors:
/// - [`KeyringError::InvalidIdentityPublicKey`] — bad encoding
/// - [`KeyringError::IdentityPublicKeyNotFound`] — no match
/// - [`KeyringError::AmbiguousIdentityPublicKey`] — two or more matches
pub fn find_identity_path_by_public_key(public_key: &str) -> Result<PathBuf> {
    let want = normalize_public_key(public_key)?;
    let mut matches = Vec::new();

    for root in default_identity_search_roots() {
        if !root.is_dir() {
            continue;
        }
        let is_identities_dir = root
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == "identities");

        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if !ft.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.starts_with('.') {
                continue;
            }
            // Dedicated identities/ dir: any non-hidden regular file.
            // Config root: only compatibility identity filename patterns.
            if !is_identities_dir && !is_config_root_identity_candidate(name) {
                continue;
            }

            match read_identity_file_public_key(&path) {
                Ok(Some(found)) => {
                    if found == want {
                        matches.push(path);
                    }
                }
                Ok(None) => {}
                // Skip unreadable candidates during discovery.
                Err(_) => continue,
            }
        }
    }

    matches.sort();
    match matches.len() {
        0 => Err(KeyringError::IdentityPublicKeyNotFound),
        1 => Ok(matches.remove(0)),
        _ => Err(KeyringError::AmbiguousIdentityPublicKey { paths: matches }),
    }
}

/// Resolve and load the identity file matching `public_key` (narrow load).
///
/// Performs discovery via public metadata, then loads only the matched path
/// through [`load_identity_file_auto`] (access preflight + optional passphrase).
///
/// After load, verifies that at least one loaded identity's derived public key
/// equals the requested key (header comments are untrusted). Mismatch yields
/// [`KeyringError::IdentityPublicKeyMismatch`].
pub fn load_identity_by_public_key(
    public_key: &str,
    passphrase: Option<&SecretString>,
) -> Result<Vec<Identity>> {
    let want = normalize_public_key(public_key)?;
    let path = find_identity_path_by_public_key(&want)?;
    let identities = load_identity_file_auto(&path, passphrase)?;
    let matches = identities
        .iter()
        .any(|identity| identity.to_public().to_string() == want);
    if !matches {
        return Err(KeyringError::IdentityPublicKeyMismatch { path });
    }
    Ok(identities)
}

fn normalize_public_key(public_key: &str) -> Result<String> {
    let trimmed = public_key.trim();
    if trimmed.is_empty() {
        return Err(KeyringError::InvalidIdentityPublicKey);
    }
    let recipient = trimmed
        .parse::<Recipient>()
        .map_err(|_| KeyringError::InvalidIdentityPublicKey)?;
    Ok(recipient.to_string())
}

fn absolute_xdg_config_home() -> Option<PathBuf> {
    let xdg = std::env::var("XDG_CONFIG_HOME").ok()?;
    let xdg = xdg.trim();
    if xdg.is_empty() {
        return None;
    }
    let path = PathBuf::from(xdg);
    // XDG Base Directory Spec: XDG_CONFIG_HOME must be absolute.
    if path.is_absolute() {
        Some(path)
    } else {
        None
    }
}

/// Compatibility filename filter for files living directly under a config root.
///
/// The dedicated `identities/` directory accepts any non-hidden regular file.
/// Config-root scans are narrower to avoid treating every operator file as an
/// identity candidate (ambiguity / exposure / DoS).
///
/// Accepted names (case-insensitive):
/// - `identity`
/// - `identity.txt`
/// - `identity*.txt`
/// - `*.identity`
pub fn is_config_root_identity_candidate(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower == "identity" || lower == "identity.txt" {
        return true;
    }
    if lower.starts_with("identity") && lower.ends_with(".txt") {
        return true;
    }
    lower.ends_with(".identity")
}

enum HeaderLine {
    PublicKey(String),
    Comment,
    Body,
}

fn classify_identity_header_line(line: &str) -> HeaderLine {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return HeaderLine::Comment;
    }
    if let Some(pk) = public_key_from_comment_line(line) {
        return HeaderLine::PublicKey(pk);
    }
    if trimmed.starts_with('#') {
        return HeaderLine::Comment;
    }
    HeaderLine::Body
}

fn public_key_from_comment_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.starts_with('#') {
        return None;
    }
    let rest = trimmed[1..].trim_start();
    let lower = rest.to_ascii_lowercase();
    const LABEL: &str = "public key:";
    if !lower.starts_with(LABEL) {
        return None;
    }
    // Slice using the original `rest` length of the label (ASCII-only).
    let value = rest[LABEL.len()..].trim();
    if value.is_empty() || !value.starts_with("age1") {
        return None;
    }
    // Reject if extra tokens / trailing junk after the key (first whitespace).
    let token = value.split_whitespace().next().unwrap_or(value);
    token.parse::<Recipient>().ok().map(|r| r.to_string())
}

enum HeaderScan {
    PublicKey(String),
    Continue,
    /// Hit a body/armor line (or byte budget); do not read further body bytes.
    Stop,
    Eof,
}

/// Read the next header unit from `reader`.
///
/// Blank and comment lines are fully consumed through `\n` (within the remaining
/// byte budget). Body lines are detected from the first non-whitespace byte; if
/// that byte is not `#`, scanning stops **without** reading the rest of the line.
fn read_next_header_line<R: Read>(reader: &mut R, total: &mut usize) -> Result<HeaderScan> {
    if *total >= MAX_IDENTITY_PUBLIC_METADATA_BYTES {
        return Ok(HeaderScan::Stop);
    }

    let mut byte = [0u8; 1];
    // Skip leading ASCII whitespace except newlines (those end a blank line).
    let first = loop {
        if *total >= MAX_IDENTITY_PUBLIC_METADATA_BYTES {
            return Ok(HeaderScan::Stop);
        }
        match reader.read(&mut byte)? {
            0 => return Ok(HeaderScan::Eof),
            _ => {
                *total += 1;
                match byte[0] {
                    b'\n' => return Ok(HeaderScan::Continue), // blank line
                    b'\r' | b' ' | b'\t' => continue,
                    other => break other,
                }
            }
        }
    };

    // Body / armor / secret line: stop without reading any further bytes.
    if first != b'#' {
        return Ok(HeaderScan::Stop);
    }

    // Comment line: accumulate through newline (or budget), then classify.
    let mut line = vec![b'#'];
    loop {
        if *total >= MAX_IDENTITY_PUBLIC_METADATA_BYTES {
            break;
        }
        match reader.read(&mut byte)? {
            0 => break,
            _ => {
                *total += 1;
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
        }
    }

    let text = String::from_utf8_lossy(&line);
    match classify_identity_header_line(text.trim_end_matches(['\n', '\r'])) {
        HeaderLine::PublicKey(pk) => Ok(HeaderScan::PublicKey(pk)),
        HeaderLine::Comment => Ok(HeaderScan::Continue),
        // A '#' line that classify treats as body shouldn't happen; treat as stop.
        HeaderLine::Body => Ok(HeaderScan::Stop),
    }
}

/// Parse recipient entries from file contents.
///
/// Empty lines and comments (`#`) are ignored.
pub fn parse_recipient_file_contents(contents: &str) -> Result<Vec<Recipient>> {
    let mut recipients = Vec::new();

    for (line_number, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let recipient =
            line.parse::<Recipient>()
                .map_err(|_| KeyringError::InvalidRecipientLine {
                    line: line_number + 1,
                })?;
        recipients.push(recipient);
    }

    if recipients.is_empty() {
        return Err(KeyringError::EmptyRecipientSet);
    }

    Ok(recipients)
}

/// Discover recipients from a file path.
pub fn discover_recipients_from_file(path: impl AsRef<Path>) -> Result<Vec<Recipient>> {
    let contents = read_utf8_file_with_limit(
        path.as_ref(),
        MAX_RECIPIENT_SOURCE_BYTES,
        "recipient file",
        KeyringError::InvalidRecipientFileEncoding,
    )?;
    parse_recipient_file_contents(&contents)
}

/// Discover recipients from an environment variable.
pub fn discover_recipients_from_env_var(env_var: &str) -> Result<Vec<Recipient>> {
    let value = std::env::var(env_var).map_err(|_| KeyringError::RecipientEnvVarMissing {
        env_var: env_var.to_string(),
    })?;

    if value.len() > MAX_RECIPIENT_SOURCE_BYTES {
        return Err(KeyringError::RecipientSourceTooLarge {
            input: "recipient env var",
            actual: value.len(),
            max: MAX_RECIPIENT_SOURCE_BYTES,
        });
    }

    parse_recipients_env_value(&value)
}

/// Discover recipients from configured sources and return a de-duplicated set.
pub fn discover_recipients(opts: &RecipientDiscoveryOptions) -> Result<Vec<Recipient>> {
    if opts.recipient_file.is_none() && opts.recipient_env_var.is_none() {
        return Err(KeyringError::MissingRecipientSources);
    }

    let mut recipients = Vec::new();

    if let Some(path) = &opts.recipient_file {
        recipients.extend(discover_recipients_from_file(path)?);
    }

    if let Some(env_var) = &opts.recipient_env_var {
        recipients.extend(discover_recipients_from_env_var(env_var)?);
    }

    dedupe_recipients(&mut recipients);

    if recipients.is_empty() {
        return Err(KeyringError::EmptyRecipientSet);
    }

    Ok(recipients)
}

/// Rekey bundle ciphertext by decrypting with old identities and encrypting with new recipients.
pub fn rekey_bundle_ciphertext(
    ciphertext: &[u8],
    old_identities: &[Identity],
    new_recipients: &[Recipient],
) -> Result<Vec<u8>> {
    let plaintext = seclusor_crypto::decrypt(ciphertext, old_identities)?;
    Ok(seclusor_crypto::encrypt(&plaintext, new_recipients)?)
}

/// Rekey a single inline ciphertext value (`sec:age:v1:<base64>`).
pub fn rekey_inline_value(
    inline_ciphertext: &str,
    old_identities: &[Identity],
    new_recipients: &[Recipient],
) -> Result<String> {
    let plaintext = seclusor_crypto::decrypt_inline_value(inline_ciphertext, old_identities)?;
    Ok(seclusor_crypto::encrypt_inline_value(
        &plaintext,
        new_recipients,
    )?)
}

/// Rekey all inline ciphertext values in a secrets document.
///
/// Plaintext values and `ref` credentials are preserved as-is.
pub fn rekey_inline_document(
    secrets: &SecretsFile,
    old_identities: &[Identity],
    new_recipients: &[Recipient],
) -> Result<SecretsFile> {
    validate_strict(secrets)?;

    let mut out = secrets.clone();
    for project in &mut out.projects {
        for (key, credential) in &mut project.credentials {
            match (&credential.value, &credential.reference) {
                (Some(value), None) => {
                    if !value.starts_with(INLINE_CIPHERTEXT_PREFIX) {
                        continue;
                    }

                    let plaintext = seclusor_crypto::decrypt_inline_value(value, old_identities)?;
                    let plaintext = String::from_utf8(plaintext).map_err(|_| {
                        KeyringError::NonUtf8InlineValue {
                            project: project.project_slug.clone(),
                            key: key.clone(),
                        }
                    })?;
                    let rekeyed = seclusor_crypto::encrypt_inline_value(
                        plaintext.as_bytes(),
                        new_recipients,
                    )?;
                    credential.value = Some(rekeyed);
                }
                (None, Some(_)) => {}
                (Some(_), Some(_)) | (None, None) => {
                    return Err(KeyringError::InvalidCredentialShape {
                        project: project.project_slug.clone(),
                        key: key.clone(),
                    });
                }
            }
        }
    }

    validate_strict(&out)?;
    Ok(out)
}

fn parse_recipients_env_value(value: &str) -> Result<Vec<Recipient>> {
    let mut recipients = Vec::new();

    for (index, token) in value
        .split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
        .filter(|token| !token.is_empty())
        .enumerate()
    {
        let recipient = token
            .parse::<Recipient>()
            .map_err(|_| KeyringError::InvalidRecipientToken { index })?;
        recipients.push(recipient);
    }

    if recipients.is_empty() {
        return Err(KeyringError::EmptyRecipientSet);
    }

    Ok(recipients)
}

fn dedupe_recipients(recipients: &mut Vec<Recipient>) {
    let mut seen = HashSet::new();
    recipients.retain(|recipient| seen.insert(recipient.to_string()));
}

fn enforce_identity_file_pathguard(path: &Path) -> Result<()> {
    let target = canonicalize_target_path(path)?;

    // Anchor detection to target ancestry so callers running outside the repo
    // cannot bypass pathguard with absolute in-repo paths.
    let target_anchor = target.parent().unwrap_or(target.as_path());
    if let Some(repo_root) = detect_repo_root(target_anchor)? {
        if target.starts_with(&repo_root) {
            return Err(KeyringError::IdentityFilePathBlocked {
                path: target,
                repo_root,
            });
        }
    }

    // Fallback to cwd ancestry for relative paths and boundary-hint workflows.
    let cwd = fs::canonicalize(std::env::current_dir()?)?;
    if let Some(repo_root) = detect_repo_root(&cwd)? {
        if target.starts_with(&repo_root) {
            return Err(KeyringError::IdentityFilePathBlocked {
                path: target,
                repo_root,
            });
        }
    }

    Ok(())
}

fn canonicalize_target_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    let mut probe = absolute.clone();
    let mut suffix = Vec::<OsString>::new();
    while !probe.exists() {
        let Some(name) = probe.file_name() else {
            break;
        };
        suffix.push(name.to_os_string());

        let Some(parent) = probe.parent() else {
            break;
        };
        probe = parent.to_path_buf();
    }

    let mut canonical = fs::canonicalize(&probe)?;
    for segment in suffix.iter().rev() {
        canonical.push(segment);
    }
    Ok(canonical)
}

fn detect_repo_root(start: &Path) -> Result<Option<PathBuf>> {
    let mut current = start.to_path_buf();
    for _ in 0..=MAX_REPO_ROOT_SEARCH_DEPTH {
        if is_repo_root_marker(&current)? {
            return Ok(Some(current));
        }

        let Some(parent) = current.parent() else {
            break;
        };
        current = parent.to_path_buf();
    }

    Ok(None)
}

fn is_repo_root_marker(dir: &Path) -> Result<bool> {
    if dir.join(".git").exists() {
        return Ok(true);
    }

    if dir.join("schemas").is_dir() && dir.join("config").is_dir() {
        return Ok(true);
    }

    let cargo_toml = dir.join("Cargo.toml");
    if cargo_toml.is_file() {
        let metadata = fs::metadata(&cargo_toml)?;
        if metadata.len() <= 128 * 1024 {
            let contents = fs::read_to_string(cargo_toml)?;
            if contents.contains("[workspace]") {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn create_new_identity_file(path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    KeyringError::IdentityFileAlreadyExists {
                        path: path.to_path_buf(),
                    }
                } else {
                    err.into()
                }
            })
    }

    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    KeyringError::IdentityFileAlreadyExists {
                        path: path.to_path_buf(),
                    }
                } else {
                    err.into()
                }
            })
    }
}

fn read_utf8_file_with_limit(
    path: &Path,
    max: usize,
    input: &'static str,
    encoding_error: KeyringError,
) -> Result<String> {
    let actual = fs::metadata(path)?.len();
    if actual > max as u64 {
        return Err(KeyringError::RecipientSourceTooLarge {
            input,
            actual: actual as usize,
            max,
        });
    }

    let mut file = File::open(path)?;
    let mut limited = std::io::Read::by_ref(&mut file).take((max as u64) + 1);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;

    if bytes.len() > max {
        return Err(KeyringError::RecipientSourceTooLarge {
            input,
            actual: bytes.len(),
            max,
        });
    }

    String::from_utf8(bytes).map_err(|_| encoding_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seclusor_core::Credential;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn cwd_lock() -> &'static Mutex<()> {
        static CWD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        CWD_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn unique_repo_relative_path(prefix: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        PathBuf::from(format!("{prefix}-{}-{now}.txt", std::process::id()))
    }

    fn fixture_rekey_document(old_recipient: &Recipient) -> SecretsFile {
        let mut sf = SecretsFile::new("demo");
        sf.projects[0].credentials.insert(
            "PLAIN".to_string(),
            Credential::with_value("secret", "plain-value"),
        );
        sf.projects[0].credentials.insert(
            "REF_ONLY".to_string(),
            Credential::with_ref("ref", "vault://path"),
        );
        let inline = seclusor_crypto::encrypt_inline_value(
            b"encrypted-value",
            std::slice::from_ref(old_recipient),
        )
        .expect("inline encryption");
        sf.projects[0]
            .credentials
            .insert("ENC".to_string(), Credential::with_value("secret", &inline));
        sf
    }

    #[test]
    fn generate_identity_produces_parseable_material() {
        let generated = generate_identity();
        assert!(generated.identity.starts_with("AGE-SECRET-KEY-"));
        assert!(generated.recipient.starts_with("age1"));
        let identities =
            seclusor_crypto::parse_identities([generated.identity]).expect("identity should parse");
        let recipients = seclusor_crypto::parse_recipients([generated.recipient])
            .expect("recipient should parse");
        assert_eq!(identities.len(), 1);
        assert_eq!(recipients.len(), 1);
    }

    #[test]
    fn generate_identity_file_writes_expected_content() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("identity.txt");

        let generated =
            generate_identity_file(&path).expect("identity file generation should work");
        let contents = fs::read_to_string(&path).expect("read generated file");

        assert!(contents.contains("# public key: "));
        assert!(contents.contains(&generated.recipient));
        assert!(contents.contains(&generated.identity));
    }

    #[test]
    fn generate_identity_file_rejects_path_under_repo_root() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        let path = unique_repo_relative_path("identity-pathguard-test");

        let err = match generate_identity_file(&path) {
            Ok(_) => panic!("pathguard must reject repo-root path"),
            Err(err) => err,
        };
        assert!(matches!(err, KeyringError::IdentityFilePathBlocked { .. }));

        // Ensure the test does not leave local artifacts in repo paths.
        assert!(!path.exists());
    }

    #[test]
    fn generate_identity_file_allows_path_outside_repo_root() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("identity.txt");
        let result = generate_identity_file(&path);
        assert!(result.is_ok());
        assert!(path.exists());
    }

    #[test]
    fn generate_identity_file_rejects_repo_target_when_cwd_outside_repo() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        let original_cwd = std::env::current_dir().expect("current dir");
        let outside = tempfile::tempdir().expect("temp dir");
        std::env::set_current_dir(outside.path()).expect("set cwd");

        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("repo root")
            .to_path_buf();
        let target = repo_root.join(unique_repo_relative_path("identity-pathguard-abs-test"));

        let err = match generate_identity_file(&target) {
            Ok(_) => panic!("must reject in-repo target regardless of cwd"),
            Err(err) => err,
        };
        assert!(matches!(err, KeyringError::IdentityFilePathBlocked { .. }));
        assert!(!target.exists());

        std::env::set_current_dir(original_cwd).expect("restore cwd");
    }

    #[test]
    fn generate_identity_file_fails_if_exists() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("identity.txt");
        fs::write(&path, "already-present\n").expect("create file");

        let err = match generate_identity_file(&path) {
            Ok(_) => panic!("must fail for existing file"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            KeyringError::IdentityFileAlreadyExists { .. }
        ));
    }

    #[test]
    #[cfg(unix)]
    fn generate_identity_file_sets_unix_0600_permissions() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("identity.txt");
        generate_identity_file(&path).expect("generation should work");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn parse_recipient_file_contents_handles_comments_and_blank_lines() {
        let recipient = Identity::generate().to_public().to_string();
        let contents = format!("# comment\n\n{recipient}\n");
        let recipients = parse_recipient_file_contents(&contents).expect("parse should work");
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0].to_string(), recipient);
    }

    #[test]
    fn parse_recipient_file_contents_reports_line_number() {
        let valid = Identity::generate().to_public().to_string();
        let err = parse_recipient_file_contents(&format!("{valid}\nnot-a-recipient"))
            .expect_err("parse should fail");
        assert!(matches!(
            err,
            KeyringError::InvalidRecipientLine { line: 2 }
        ));
    }

    #[test]
    fn discover_recipients_from_file_rejects_oversized_input() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("recipients.txt");
        let file = File::create(&path).expect("create file");
        file.set_len((MAX_RECIPIENT_SOURCE_BYTES as u64) + 1)
            .expect("set len");
        drop(file);

        let err = discover_recipients_from_file(&path).expect_err("must fail");
        assert!(matches!(err, KeyringError::RecipientSourceTooLarge { .. }));
    }

    #[test]
    fn discover_recipients_from_env_var_parses_delimiters() {
        let _guard = env_lock().lock().expect("lock env");
        let env_var = "SECLUSOR_RECIPIENTS_TEST_D4A_PARSE";
        let r1 = Identity::generate().to_public().to_string();
        let r2 = Identity::generate().to_public().to_string();
        std::env::set_var(env_var, format!("{r1},{r2}\n{r1}"));

        let recipients = discover_recipients_from_env_var(env_var).expect("env parse should work");
        std::env::remove_var(env_var);

        assert_eq!(recipients.len(), 3);
    }

    #[test]
    fn discover_recipients_combines_sources_and_dedupes() {
        let _guard = env_lock().lock().expect("lock env");
        let env_var = "SECLUSOR_RECIPIENTS_TEST_D4A_DEDUPE";
        let r1 = Identity::generate().to_public().to_string();
        let r2 = Identity::generate().to_public().to_string();
        let dir = tempfile::tempdir().expect("temp dir");
        let file_path = dir.path().join("recipients.txt");
        fs::write(&file_path, format!("# file list\n{r1}\n")).expect("write file");
        std::env::set_var(env_var, format!("{r1},{r2}"));

        let opts = RecipientDiscoveryOptions {
            recipient_file: Some(file_path),
            recipient_env_var: Some(env_var.to_string()),
        };
        let recipients = discover_recipients(&opts).expect("discover should work");
        std::env::remove_var(env_var);

        assert_eq!(recipients.len(), 2);
    }

    #[test]
    fn discover_recipients_requires_source() {
        let err =
            discover_recipients(&RecipientDiscoveryOptions::default()).expect_err("must fail");
        assert!(matches!(err, KeyringError::MissingRecipientSources));
    }

    #[test]
    fn generate_protected_identity_file_roundtrip() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("identity-protected.txt");
        let passphrase = SecretString::from("test-passphrase-42");

        let generated = generate_identity_file_with_passphrase(&path, &passphrase)
            .expect("protected generation should work");

        // File contains armor marker
        let contents = fs::read_to_string(&path).expect("read file");
        assert!(contents.contains(AGE_ARMOR_BEGIN));
        // Public key visible in header comment
        assert!(contents.contains(&format!("# Public key: {}", generated.recipient)));
        // Secret key NOT visible in file
        assert!(!contents.contains("AGE-SECRET-KEY-"));

        // Verify size is well under 8 KiB limit
        let size = fs::metadata(&path).expect("metadata").len();
        assert!(
            size < MAX_PROTECTED_IDENTITY_FILE_BYTES as u64,
            "protected identity should be well under {} bytes, was {}",
            MAX_PROTECTED_IDENTITY_FILE_BYTES,
            size
        );

        // Roundtrip: load with correct passphrase
        let identities =
            load_identity_file_with_passphrase(&path, &passphrase).expect("load should work");
        assert_eq!(identities.len(), 1);

        // The loaded identity can decrypt something encrypted to the recipient
        let recipient: Recipient = generated.recipient.parse().expect("parse recipient");
        let ciphertext =
            seclusor_crypto::encrypt(b"test-payload", std::slice::from_ref(&recipient))
                .expect("encrypt");
        let decrypted =
            seclusor_crypto::decrypt(&ciphertext, &identities).expect("decrypt should work");
        assert_eq!(decrypted, b"test-payload");
    }

    #[test]
    fn load_protected_identity_wrong_passphrase() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("identity-wrong-pp.txt");
        let passphrase = SecretString::from("alpha-green-42");
        let bad = SecretString::from("beta-red-99");

        generate_identity_file_with_passphrase(&path, &passphrase).expect("generate");

        let err = match load_identity_file_with_passphrase(&path, &bad) {
            Ok(_) => panic!("must fail with incorrect passphrase"),
            Err(e) => e,
        };
        assert!(matches!(err, KeyringError::ProtectedIdentityDecryptFailed));
        // Error message must not contain either passphrase value
        let msg = err.to_string();
        assert!(!msg.contains("alpha-green"));
        assert!(!msg.contains("beta-red"));
    }

    #[test]
    fn is_passphrase_protected_detects_formats() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        let dir = tempfile::tempdir().expect("temp dir");

        // Plaintext identity
        let plain_path = dir.path().join("plain.txt");
        generate_identity_file(&plain_path).expect("generate plaintext");
        assert!(!is_passphrase_protected_identity(&plain_path).expect("detect plain"));

        // Protected identity
        let prot_path = dir.path().join("protected.txt");
        let passphrase = SecretString::from("detect-test");
        generate_identity_file_with_passphrase(&prot_path, &passphrase)
            .expect("generate protected");
        assert!(is_passphrase_protected_identity(&prot_path).expect("detect protected"));
    }

    #[test]
    fn load_identity_file_auto_plaintext() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("auto-plain.txt");
        generate_identity_file(&path).expect("generate");

        // Plaintext: passphrase ignored
        let ids = load_identity_file_auto(&path, None).expect("load plain without passphrase");
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn load_identity_file_auto_protected_no_passphrase() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("auto-prot-no-pp.txt");
        let passphrase = SecretString::from("auto-test");
        generate_identity_file_with_passphrase(&path, &passphrase).expect("generate");

        let err = match load_identity_file_auto(&path, None) {
            Ok(_) => panic!("must fail without passphrase"),
            Err(e) => e,
        };
        assert!(
            matches!(err, KeyringError::ProtectedIdentityNoPassphrase),
            "expected ProtectedIdentityNoPassphrase, got: {err}"
        );
    }

    #[test]
    fn load_identity_file_auto_protected_with_passphrase() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("auto-prot-with-pp.txt");
        let passphrase = SecretString::from("auto-test-2");
        generate_identity_file_with_passphrase(&path, &passphrase).expect("generate");

        let ids = load_identity_file_auto(&path, Some(&passphrase)).expect("load");
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn protected_identity_file_size_limit_enforced() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("oversized.txt");

        // Write a file that exceeds the limit with valid-looking header
        let mut content = String::from("# comment\n");
        content.push_str(AGE_ARMOR_BEGIN);
        content.push('\n');
        while content.len() <= MAX_PROTECTED_IDENTITY_FILE_BYTES {
            content.push_str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
        }
        fs::write(&path, &content).expect("write oversized");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set perms");
        }

        let passphrase = SecretString::from("irrelevant");
        let err = match load_identity_file_with_passphrase(&path, &passphrase) {
            Ok(_) => panic!("must reject oversized file"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            KeyringError::ProtectedIdentityFileTooLarge { .. }
        ));
    }

    #[test]
    fn protected_identity_malformed_armor_fails_closed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("malformed.txt");

        // Has the marker but garbage content — must not fall back to plaintext
        let content = format!(
            "# Public key: age1fake\n{}\nnot-valid-age-data\n-----END AGE ENCRYPTED FILE-----\n",
            AGE_ARMOR_BEGIN
        );
        fs::write(&path, &content).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set perms");
        }

        let passphrase = SecretString::from("any");
        let err = match load_identity_file_with_passphrase(&path, &passphrase) {
            Ok(_) => panic!("must fail on malformed armor"),
            Err(e) => e,
        };
        assert!(matches!(err, KeyringError::ProtectedIdentityDecryptFailed));
    }

    #[test]
    fn rekey_bundle_ciphertext_rotates_recipient_set() {
        let old_identity = Identity::generate();
        let old_recipient = old_identity.to_public();
        let new_identity = Identity::generate();
        let new_recipient = new_identity.to_public();
        let plaintext = b"bundle secret payload";

        let ciphertext = seclusor_crypto::encrypt(plaintext, std::slice::from_ref(&old_recipient))
            .expect("encrypt");
        let rekeyed = rekey_bundle_ciphertext(
            &ciphertext,
            std::slice::from_ref(&old_identity),
            std::slice::from_ref(&new_recipient),
        )
        .expect("rekey bundle");

        let decrypted_new = seclusor_crypto::decrypt(&rekeyed, std::slice::from_ref(&new_identity))
            .expect("decrypt new");
        assert_eq!(decrypted_new, plaintext);

        let err = seclusor_crypto::decrypt(&rekeyed, std::slice::from_ref(&old_identity))
            .expect_err("old identity should fail after rekey");
        assert!(matches!(
            err,
            seclusor_crypto::CryptoError::DecryptionFailed
        ));
    }

    #[test]
    fn rekey_inline_document_rotates_inline_values_only() {
        let old_identity = Identity::generate();
        let old_recipient = old_identity.to_public();
        let new_identity = Identity::generate();
        let new_recipient = new_identity.to_public();
        let secrets = fixture_rekey_document(&old_recipient);

        let rekeyed = rekey_inline_document(
            &secrets,
            std::slice::from_ref(&old_identity),
            std::slice::from_ref(&new_recipient),
        )
        .expect("rekey inline document");

        let enc_value = rekeyed.projects[0].credentials["ENC"]
            .value
            .as_ref()
            .expect("rekeyed value");
        assert!(enc_value.starts_with(INLINE_CIPHERTEXT_PREFIX));

        let decrypted_new =
            seclusor_crypto::decrypt_inline_value(enc_value, std::slice::from_ref(&new_identity))
                .expect("new identity decrypts");
        assert_eq!(decrypted_new, b"encrypted-value");

        let err =
            seclusor_crypto::decrypt_inline_value(enc_value, std::slice::from_ref(&old_identity))
                .expect_err("old identity should fail");
        assert!(matches!(
            err,
            seclusor_crypto::CryptoError::DecryptionFailed
        ));

        assert_eq!(
            rekeyed.projects[0].credentials["PLAIN"].value.as_deref(),
            Some("plain-value")
        );
        assert_eq!(
            rekeyed.projects[0].credentials["REF_ONLY"]
                .reference
                .as_deref(),
            Some("vault://path")
        );
    }

    #[test]
    fn parse_public_key_comment_is_case_insensitive() {
        let pk = Identity::generate().to_public().to_string();
        assert_eq!(
            parse_public_key_from_identity_header(&format!("# public key: {pk}\n")),
            Some(pk.clone())
        );
        assert_eq!(
            parse_public_key_from_identity_header(&format!("# Public key: {pk}\n")),
            Some(pk.clone())
        );
        assert_eq!(
            parse_public_key_from_identity_header(&format!("# PUBLIC KEY: {pk}\n")),
            Some(pk)
        );
        assert_eq!(
            parse_public_key_from_identity_header("# comment only\nAGE-SECRET-KEY-x\n"),
            None
        );
    }

    #[test]
    fn read_identity_file_public_key_plain_and_protected() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        let dir = tempfile::tempdir().expect("temp dir");

        let plain = dir.path().join("plain.txt");
        let gen = generate_identity_file(&plain).expect("generate plain");
        assert_eq!(
            read_identity_file_public_key(&plain).expect("read plain"),
            Some(gen.recipient.clone())
        );

        let protected = dir.path().join("protected.txt");
        let pp = SecretString::from("test-passphrase-for-lookup".to_owned());
        let gen2 = generate_identity_file_with_passphrase(&protected, &pp).expect("generate pp");
        assert_eq!(
            read_identity_file_public_key(&protected).expect("read protected"),
            Some(gen2.recipient)
        );
        // Metadata path must not require passphrase and must not open secret body.
        assert!(is_passphrase_protected_identity(&protected).expect("detect protected"));
    }

    #[test]
    fn find_identity_path_by_public_key_discovers_config_and_identities_subdir() {
        let _guard = env_lock().lock().expect("lock env");
        let dir = tempfile::tempdir().expect("temp dir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());

        let cfg = dir.path().join("seclusor");
        let identities = cfg.join("identities");
        fs::create_dir_all(&identities).expect("mkdir identities");

        let direct = cfg.join("identity.txt");
        let gen_direct = generate_identity_file(&direct).expect("direct identity");

        let nested = identities.join("ops.txt");
        let gen_nested = generate_identity_file(&nested).expect("nested identity");

        assert_eq!(
            find_identity_path_by_public_key(&gen_direct.recipient).expect("find direct"),
            direct
        );
        assert_eq!(
            find_identity_path_by_public_key(&gen_nested.recipient).expect("find nested"),
            nested
        );

        let loaded =
            load_identity_by_public_key(&gen_direct.recipient, None).expect("load by public key");
        assert_eq!(loaded.len(), 1);

        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn find_identity_path_by_public_key_ambiguous_and_missing() {
        let _guard = env_lock().lock().expect("lock env");
        let dir = tempfile::tempdir().expect("temp dir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());

        let cfg = dir.path().join("seclusor");
        let identities = cfg.join("identities");
        fs::create_dir_all(&identities).expect("mkdir");

        let a = cfg.join("identity.txt");
        let gen = generate_identity_file(&a).expect("a");
        // Second file with the same public key comment (duplicate metadata).
        let b = identities.join("copy.txt");
        fs::write(
            &b,
            format!(
                "# public key: {}\n# duplicate metadata only\n",
                gen.recipient
            ),
        )
        .expect("write b");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&b, fs::Permissions::from_mode(0o600)).expect("chmod b");
        }

        let err = find_identity_path_by_public_key(&gen.recipient).expect_err("ambiguous");
        match &err {
            KeyringError::AmbiguousIdentityPublicKey { paths } => {
                assert_eq!(paths.len(), 2);
                let rendered = err.to_string();
                assert!(rendered.contains("ambiguous"));
                assert!(
                    rendered.contains(a.file_name().unwrap().to_str().unwrap())
                        || rendered.contains("identity.txt")
                );
            }
            other => panic!("unexpected error: {other}"),
        }

        let other = Identity::generate().to_public().to_string();
        let missing = find_identity_path_by_public_key(&other).expect_err("missing");
        assert!(matches!(missing, KeyringError::IdentityPublicKeyNotFound));

        let bad = find_identity_path_by_public_key("not-an-age-key").expect_err("bad key");
        assert!(matches!(bad, KeyringError::InvalidIdentityPublicKey));

        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn discovery_does_not_recurse_home_or_nested_dirs() {
        let _guard = env_lock().lock().expect("lock env");
        let dir = tempfile::tempdir().expect("temp dir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());

        let cfg = dir.path().join("seclusor");
        let deep = cfg.join("identities").join("nested");
        fs::create_dir_all(&deep).expect("mkdir deep");
        let buried = deep.join("hidden.txt");
        let gen = generate_identity_file(&buried).expect("buried");

        // File is under identities/nested/ — non-recursive scan must not find it.
        let err = find_identity_path_by_public_key(&gen.recipient).expect_err("must not recurse");
        assert!(matches!(err, KeyringError::IdentityPublicKeyNotFound));

        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    #[cfg(unix)]
    fn load_identity_file_auto_rejects_insecure_permissions() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("identity.txt");
        generate_identity_file(&path).expect("generate");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");

        let err = match load_identity_file_auto(&path, None) {
            Ok(_) => panic!("must fail perms"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            KeyringError::Crypto(
                seclusor_crypto::CryptoError::InsecureIdentityFilePermissions { .. }
            )
        ));
    }

    #[test]
    #[cfg(unix)]
    fn load_identity_file_auto_insecure_protected_fails_before_passphrase_probe() {
        let _guard = cwd_lock().lock().expect("lock cwd");
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("protected.txt");
        let pp = SecretString::from("test-passphrase-for-preflight".to_owned());
        generate_identity_file_with_passphrase(&path, &pp).expect("generate protected");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");

        // No passphrase supplied: without preflight-first this would return
        // ProtectedIdentityNoPassphrase after reading the file header.
        let err = match load_identity_file_auto(&path, None) {
            Ok(_) => panic!("must fail perms before passphrase path"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err,
                KeyringError::Crypto(
                    seclusor_crypto::CryptoError::InsecureIdentityFilePermissions { .. }
                )
            ),
            "expected permissions error, got {err}"
        );
        assert!(!matches!(err, KeyringError::ProtectedIdentityNoPassphrase));
    }

    #[test]
    fn public_key_metadata_stops_before_secret_body() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("identity.txt");
        let real = Identity::generate().to_public().to_string();
        let decoy = Identity::generate().to_public().to_string();
        // Body appears before a decoy public-key comment; metadata reader must
        // stop at the body and must not treat the trailing decoy as metadata.
        let contents = format!(
            "# comment\nAGE-SECRET-KEY-1NOTAREALKEY000000000000000000000000000000000000000000000000\n# public key: {decoy}\n# public key: {real}\n"
        );
        fs::write(&path, contents).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        }

        assert_eq!(
            read_identity_file_public_key(&path).expect("read metadata"),
            None
        );
        // Header-only parse of a full blob is for unit convenience; production
        // path stops at body, so decoy must not win.
        assert_eq!(
            parse_public_key_from_identity_header(
                "# public key: AGE-WRONG\nAGE-SECRET-KEY-1x\n# public key: decoy\n"
            ),
            None
        );
        let _ = real;
    }

    /// Reader that panics if any byte past `max_allowed` is requested.
    struct BoundedProbeRead {
        data: &'static [u8],
        pos: usize,
        /// Exclusive upper bound on readable positions (first body byte + 1).
        max_allowed: usize,
    }

    impl Read for BoundedProbeRead {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            if self.pos >= self.max_allowed {
                panic!(
                    "metadata reader requested body bytes after first body byte (pos={}, max_allowed={})",
                    self.pos, self.max_allowed
                );
            }
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    #[test]
    fn load_identity_by_public_key_rejects_mislabeled_header() {
        let _guard = env_lock().lock().expect("lock env");
        let dir = tempfile::tempdir().expect("temp dir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());

        let cfg = dir.path().join("seclusor");
        fs::create_dir_all(cfg.join("identities")).expect("mkdir");
        let path = cfg.join("identity.txt");

        // Real identity A, but header advertises unrelated public key B.
        let real = generate_identity();
        let decoy = Identity::generate().to_public().to_string();
        fs::write(&path, format!("# public key: {decoy}\n{}\n", real.identity))
            .expect("write mislabeled");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        }

        // Discovery matches on the untrusted header...
        assert_eq!(
            find_identity_path_by_public_key(&decoy).expect("find by decoy comment"),
            path
        );
        // ...but load must fail closed when the body is a different key.
        let err = match load_identity_by_public_key(&decoy, None) {
            Ok(_) => panic!("mislabeled identity must not load"),
            Err(e) => e,
        };
        assert!(
            matches!(err, KeyringError::IdentityPublicKeyMismatch { .. }),
            "unexpected: {err}"
        );
        // Correct key for the body is not advertised, so no-match on discovery.
        let missing = find_identity_path_by_public_key(&real.recipient).expect_err("no comment");
        assert!(matches!(missing, KeyringError::IdentityPublicKeyNotFound));

        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn metadata_reader_does_not_read_ahead_into_body_line() {
        // Comment then body: only the first body byte ('A') may be read.
        let input: &'static [u8] =
            b"# comment\nAGE-SECRET-KEY-1SHOULD_NOT_BE_FULLY_READ\n# public key: age1decoy\n";
        let body_start = input.iter().position(|&b| b == b'A').expect("body start");
        let mut reader = BoundedProbeRead {
            data: input,
            pos: 0,
            max_allowed: body_start + 1,
        };
        let found = read_identity_public_key_from_reader(&mut reader).expect("scan");
        assert_eq!(found, None);
        assert_eq!(
            reader.pos,
            body_start + 1,
            "must stop immediately after first body byte"
        );
    }

    #[test]
    fn public_key_metadata_finds_key_in_leading_comments_only() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("identity.txt");
        let pk = Identity::generate().to_public().to_string();
        fs::write(
            &path,
            format!("# Public key: {pk}\nAGE-SECRET-KEY-1NOTAREALKEY000000000000000000000000000000000000000000000000\n"),
        )
        .expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        assert_eq!(
            read_identity_file_public_key(&path).expect("read"),
            Some(pk)
        );
    }

    #[test]
    fn config_root_filename_filter_and_relative_xdg_ignored() {
        let _guard = env_lock().lock().expect("lock env");
        let dir = tempfile::tempdir().expect("temp dir");
        // Relative XDG must be ignored (XDG requires absolute paths).
        std::env::set_var("XDG_CONFIG_HOME", "relative-config-home");
        assert!(
            absolute_xdg_config_home().is_none(),
            "relative XDG_CONFIG_HOME must be ignored"
        );
        // Force absolute XDG for the positive filter test next.
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        assert_eq!(
            absolute_xdg_config_home().as_deref(),
            Some(dir.path()),
            "absolute XDG_CONFIG_HOME must be accepted"
        );

        let cfg = dir.path().join("seclusor");
        fs::create_dir_all(&cfg).expect("mkdir");
        let identities = cfg.join("identities");
        fs::create_dir_all(&identities).expect("mkdir identities");

        let pk = Identity::generate().to_public().to_string();
        // Non-candidate name at config root must be ignored.
        let notes = cfg.join("notes.txt");
        fs::write(&notes, format!("# public key: {pk}\n")).expect("write notes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&notes, fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        let missing = find_identity_path_by_public_key(&pk).expect_err("notes ignored");
        assert!(matches!(missing, KeyringError::IdentityPublicKeyNotFound));

        // Candidate name at config root is accepted.
        let identity = cfg.join("identity.txt");
        fs::write(&identity, format!("# public key: {pk}\n")).expect("write identity");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        assert_eq!(
            find_identity_path_by_public_key(&pk).expect("find identity.txt"),
            identity
        );

        // identities/ still accepts arbitrary non-hidden names.
        let other_pk = Identity::generate().to_public().to_string();
        let nested = identities.join("ops-key");
        fs::write(&nested, format!("# public key: {other_pk}\n")).expect("write nested");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&nested, fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        assert_eq!(
            find_identity_path_by_public_key(&other_pk).expect("find nested"),
            nested
        );

        assert!(is_config_root_identity_candidate("identity.txt"));
        assert!(is_config_root_identity_candidate("identity-ops.txt"));
        assert!(is_config_root_identity_candidate("team.identity"));
        assert!(!is_config_root_identity_candidate("notes.txt"));
        assert!(!is_config_root_identity_candidate("recipients.txt"));

        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn ambiguous_paths_are_sorted() {
        let _guard = env_lock().lock().expect("lock env");
        let dir = tempfile::tempdir().expect("temp dir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());

        let cfg = dir.path().join("seclusor");
        let identities = cfg.join("identities");
        fs::create_dir_all(&identities).expect("mkdir");
        let pk = Identity::generate().to_public().to_string();

        let z = identities.join("z.txt");
        let a = identities.join("a.txt");
        for path in [&z, &a] {
            fs::write(path, format!("# public key: {pk}\n")).expect("write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
            }
        }

        let err = find_identity_path_by_public_key(&pk).expect_err("ambiguous");
        match err {
            KeyringError::AmbiguousIdentityPublicKey { paths } => {
                assert_eq!(paths, vec![a, z]);
            }
            other => panic!("unexpected: {other}"),
        }

        std::env::remove_var("XDG_CONFIG_HOME");
    }
}
