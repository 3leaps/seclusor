use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::Path;

use seclusor_codec::{
    resolve_runtime_document_from_file, resolve_runtime_source_from_file, DocumentSource,
    ResolvedDocument,
};
use seclusor_core::constants::{INLINE_CIPHERTEXT_PREFIX, MAX_SECRETS_DOC_BYTES};
use seclusor_core::validate::validate_strict;
use seclusor_core::{SeclusorError, SecretsFile};
use seclusor_crypto::Identity;

use crate::error::{CliError, CliResult};

/// Result of a single bounded read that routes write commands (encrypted-target guard).
///
/// Classification and the original bytes share one read so the guard does not
/// reopen the path before deciding refuse vs plaintext handling.
#[derive(Debug)]
pub(crate) enum WriteTargetProbe {
    /// Strict-valid plaintext secrets document — safe for existing write paths.
    Plaintext(SecretsFile),
    /// Positively identified encrypted document — refuse before mutation.
    Encrypted { source: DocumentSource },
    /// Not positively encrypted. Carry the same bounded bytes into existing
    /// plaintext parse / lenient recovery so those semantics stay intact.
    NotEncrypted(Vec<u8>),
}

pub(crate) fn read_secrets_file(path: &Path) -> CliResult<SecretsFile> {
    let bytes = read_file_with_limit(path, MAX_SECRETS_DOC_BYTES)?;
    secrets_from_bytes(&bytes)
}

/// One bounded read + fail-closed encrypted-write probe.
pub(crate) fn probe_write_target(path: &Path) -> CliResult<WriteTargetProbe> {
    let bytes = read_file_with_limit(path, MAX_SECRETS_DOC_BYTES)?;
    Ok(probe_write_target_bytes(&bytes))
}

/// Probe already-read document bytes (no second open).
pub(crate) fn probe_write_target_bytes(bytes: &[u8]) -> WriteTargetProbe {
    // 1. Bundle marker wins even if the payload is malformed.
    if is_bundle_marker(bytes) {
        return WriteTargetProbe::Encrypted {
            source: DocumentSource::Bundle,
        };
    }

    // 2. Strict classification: valid SecretsFile → inline refuse / plaintext continue.
    match seclusor_codec::classify_document_bytes(bytes) {
        Ok(DocumentSource::Bundle) => WriteTargetProbe::Encrypted {
            source: DocumentSource::Bundle,
        },
        Ok(DocumentSource::Inline) => WriteTargetProbe::Encrypted {
            source: DocumentSource::Inline,
        },
        Ok(DocumentSource::Plaintext) => match secrets_from_bytes(bytes) {
            Ok(secrets) => WriteTargetProbe::Plaintext(secrets),
            // Classification said plaintext but re-parse failed — treat as
            // unclassified so existing error paths remain available.
            Err(_) => WriteTargetProbe::NotEncrypted(bytes.to_vec()),
        },
        Err(_) => {
            // 3. Strict-model failure: inspect credential value nodes only for
            // the inline prefix (not description/ref/raw substring of the file).
            // Includes bare-string legacy credentials and object `.value` fields.
            if credential_values_have_inline_ciphertext(bytes) {
                WriteTargetProbe::Encrypted {
                    source: DocumentSource::Inline,
                }
            } else {
                // 4. Not positively encrypted — hand same bytes to plaintext/lenient.
                WriteTargetProbe::NotEncrypted(bytes.to_vec())
            }
        }
    }
}

/// Error for refused encrypted write targets. No document body content.
pub(crate) fn refuse_encrypted_write(path: &Path, source: DocumentSource) -> CliError {
    let token = match source {
        DocumentSource::Bundle => "bundle",
        DocumentSource::Inline => "inline",
        DocumentSource::Plaintext => "plaintext",
    };
    CliError::EncryptedWriteUnsupported {
        path: path.display().to_string(),
        source_kind: token,
    }
}

pub(crate) fn secrets_from_bytes(bytes: &[u8]) -> CliResult<SecretsFile> {
    let secrets: SecretsFile = serde_json::from_slice(bytes)?;
    validate_strict(&secrets)?;
    Ok(secrets)
}

fn is_bundle_marker(input: &[u8]) -> bool {
    input.starts_with(b"age-encryption.org/")
        || input.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----")
}

/// Walk only `projects[].credentials.*` for the inline marker on credential
/// *values* (bare-string credential or object `.value` field). Never scans
/// descriptions, refs, or arbitrary file substrings.
fn credential_values_have_inline_ciphertext(bytes: &[u8]) -> bool {
    let Ok(root) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    let Some(projects) = root.get("projects").and_then(|p| p.as_array()) else {
        return false;
    };
    for project in projects {
        let Some(credentials) = project.get("credentials").and_then(|c| c.as_object()) else {
            continue;
        };
        for credential in credentials.values() {
            if credential_node_is_inline_ciphertext(credential) {
                return true;
            }
        }
    }
    false
}

fn credential_node_is_inline_ciphertext(credential: &serde_json::Value) -> bool {
    match credential {
        serde_json::Value::String(value) => value.starts_with(INLINE_CIPHERTEXT_PREFIX),
        serde_json::Value::Object(fields) => fields
            .get("value")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value.starts_with(INLINE_CIPHERTEXT_PREFIX)),
        _ => false,
    }
}

pub(crate) fn read_runtime_secrets_file(
    path: &Path,
    identities: &[Identity],
) -> CliResult<SecretsFile> {
    Ok(resolve_runtime_source_from_file(path, identities)?)
}

/// Classified runtime load for list/validate (mode + source tokens).
pub(crate) fn read_runtime_document_file(
    path: &Path,
    identities: &[Identity],
) -> CliResult<ResolvedDocument> {
    Ok(resolve_runtime_document_from_file(path, identities)?)
}

pub(crate) fn write_secrets_file(
    path: &Path,
    secrets: &SecretsFile,
    create_new: bool,
) -> CliResult<()> {
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

pub(crate) fn write_json_value_file(path: &Path, value: &serde_json::Value) -> CliResult<()> {
    let data = serde_json::to_vec_pretty(value)?;
    if data.len() > MAX_SECRETS_DOC_BYTES {
        return Err(CliError::Core(SeclusorError::DocumentTooLarge {
            actual: data.len(),
            max: MAX_SECRETS_DOC_BYTES,
        }));
    }

    fs::write(path, data)?;
    Ok(())
}

pub(crate) fn read_file_with_limit(path: &Path, max: usize) -> CliResult<Vec<u8>> {
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
    use std::fs;

    use seclusor_core::constants::MAX_SECRETS_DOC_BYTES;
    use seclusor_core::SeclusorError;

    use crate::error::CliError;
    use crate::test_support::*;

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
}
