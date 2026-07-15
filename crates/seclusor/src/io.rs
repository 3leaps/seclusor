use std::fs;
use std::io::Read;
use std::path::Path;

use seclusor_codec::{
    resolve_runtime_document_from_file, resolve_runtime_source_from_file, DocumentSource,
    ResolvedDocument,
};
use seclusor_core::constants::{
    INLINE_CIPHERTEXT_PREFIX, MAX_BUNDLE_CIPHERTEXT_BYTES, MAX_SECRETS_DOC_BYTES,
};
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
    ///
    /// `bytes` are the exact load-time contents for CAS (e.g. plaintext rekey).
    Plaintext {
        secrets: SecretsFile,
        bytes: Vec<u8>,
    },
    /// Positively identified encrypted document.
    ///
    /// `bytes` are the same bounded contents used for classification and commit
    /// CAS: full JSON for inline, full ciphertext (bounded) for bundle. One
    /// read must cover classify → mutate → CAS.
    Encrypted {
        source: DocumentSource,
        bytes: Vec<u8>,
    },
    /// Not positively encrypted. Carry the same bounded bytes into existing
    /// plaintext parse / lenient recovery so those semantics stay intact.
    NotEncrypted(Vec<u8>),
}

pub(crate) fn read_secrets_file(path: &Path) -> CliResult<SecretsFile> {
    let bytes = read_file_with_limit(path, MAX_SECRETS_DOC_BYTES)?;
    secrets_from_bytes(&bytes)
}

/// One bounded read + fail-closed encrypted-write probe.
///
/// Opens the path **once**: probes the first 64 bytes for a bundle marker from
/// that descriptor, then continues the bounded read from the same handle so
/// classification and any later plaintext handling share identical bytes.
pub(crate) fn probe_write_target(path: &Path) -> CliResult<WriteTargetProbe> {
    let bytes = read_write_target_bytes(path)?;
    Ok(probe_write_target_bytes(&bytes))
}

/// Single-open bounded read for write-target probing.
///
/// Bundle markers are detected from a 64-byte prefix on the same file
/// descriptor used for the remainder of the read, so oversized bundles refuse
/// as encrypted targets without a second open and without misreporting as
/// document-too-large when only the prefix is needed for the marker win.
fn read_write_target_bytes(path: &Path) -> CliResult<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = fs::File::open(path)?;
    let mut prefix = [0u8; 64];
    let prefix_len = file.read(&mut prefix)?;
    let prefix = &prefix[..prefix_len];

    // One open: rewind and bound-read with the codec-appropriate limit so the
    // same bytes serve classification, decrypt/mutate, and commit-time CAS.
    let max = if seclusor_codec::is_bundle_ciphertext(prefix) {
        MAX_BUNDLE_CIPHERTEXT_BYTES
    } else {
        MAX_SECRETS_DOC_BYTES
    };

    file.seek(SeekFrom::Start(0))?;
    let mut limited = file.take((max as u64) + 1);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf)?;
    if buf.len() > max {
        if seclusor_codec::is_bundle_ciphertext(prefix) {
            return Err(CliError::Codec(
                seclusor_codec::CodecError::BundleCiphertextTooLarge {
                    actual: buf.len() as u64,
                    max: max as u64,
                },
            ));
        }
        return Err(CliError::Core(SeclusorError::DocumentTooLarge {
            actual: buf.len(),
            max: MAX_SECRETS_DOC_BYTES,
        }));
    }
    Ok(buf)
}

/// Probe already-read document bytes (no second open).
pub(crate) fn probe_write_target_bytes(bytes: &[u8]) -> WriteTargetProbe {
    // 1. Bundle marker wins even if the payload is malformed.
    if seclusor_codec::is_bundle_ciphertext(bytes) {
        return WriteTargetProbe::Encrypted {
            source: DocumentSource::Bundle,
            bytes: bytes.to_vec(),
        };
    }

    // 2. Strict classification: valid SecretsFile → inline refuse / plaintext continue.
    match seclusor_codec::classify_document_bytes(bytes) {
        Ok(DocumentSource::Bundle) => WriteTargetProbe::Encrypted {
            source: DocumentSource::Bundle,
            bytes: bytes.to_vec(),
        },
        Ok(DocumentSource::Inline) => WriteTargetProbe::Encrypted {
            source: DocumentSource::Inline,
            bytes: bytes.to_vec(),
        },
        Ok(DocumentSource::Plaintext) => match secrets_from_bytes(bytes) {
            Ok(secrets) => WriteTargetProbe::Plaintext {
                secrets,
                bytes: bytes.to_vec(),
            },
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
                    bytes: bytes.to_vec(),
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
    debug_assert!(
        !matches!(source, DocumentSource::Plaintext),
        "refuse_encrypted_write is only for positively identified encrypted sources"
    );
    CliError::EncryptedWriteUnsupported {
        path: path.display().to_string(),
        source_kind: source.token(),
    }
}

pub(crate) fn secrets_from_bytes(bytes: &[u8]) -> CliResult<SecretsFile> {
    let secrets: SecretsFile = serde_json::from_slice(bytes)?;
    validate_strict(&secrets)?;
    Ok(secrets)
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

/// Write a **plaintext** secrets JSON document.
///
/// Plaintext paths intentionally do **not** use the ciphertext-only atomic
/// writer (orphan temps must never hold plaintext). Encrypted commits must call
/// [`crate::atomic_write::atomic_write_ciphertext`] with a CAS token.
pub(crate) fn write_secrets_file(
    path: &Path,
    secrets: &SecretsFile,
    create_new: bool,
) -> CliResult<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let data = serde_json::to_vec_pretty(secrets)?;
    if data.len() > MAX_SECRETS_DOC_BYTES {
        return Err(CliError::Core(SeclusorError::DocumentTooLarge {
            actual: data.len(),
            max: MAX_SECRETS_DOC_BYTES,
        }));
    }

    if create_new {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(&data)?;
        file.write_all(b"\n")?;
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
