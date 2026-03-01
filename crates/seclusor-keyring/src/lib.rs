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

pub use error::{KeyringError, Result};
pub use seclusor_crypto::{Identity, Recipient};

/// Default environment variable used for recipient discovery.
pub const DEFAULT_RECIPIENTS_ENV_VAR: &str = "SECLUSOR_RECIPIENTS";

/// Maximum bytes read from recipient file/env sources.
pub const MAX_RECIPIENT_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_REPO_ROOT_SEARCH_DEPTH: usize = 32;

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
    let boundary = std::env::var_os("FULMEN_WORKSPACE_ROOT")
        .map(PathBuf::from)
        .and_then(|path| fs::canonicalize(path).ok());

    let mut current = start.to_path_buf();
    for _ in 0..=MAX_REPO_ROOT_SEARCH_DEPTH {
        if is_repo_root_marker(&current)? {
            return Ok(Some(current));
        }

        let Some(parent) = current.parent() else {
            break;
        };
        let parent = parent.to_path_buf();

        if let Some(boundary) = &boundary {
            if !parent.starts_with(boundary) {
                break;
            }
        }

        current = parent;
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
}
