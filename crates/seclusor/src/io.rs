use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::Path;

use seclusor_codec::resolve_runtime_source_from_file;
use seclusor_core::constants::MAX_SECRETS_DOC_BYTES;
use seclusor_core::validate::validate_strict;
use seclusor_core::{SeclusorError, SecretsFile};
use seclusor_crypto::Identity;

use crate::error::{CliError, CliResult};

pub(crate) fn read_secrets_file(path: &Path) -> CliResult<SecretsFile> {
    let bytes = read_file_with_limit(path, MAX_SECRETS_DOC_BYTES)?;
    let secrets: SecretsFile = serde_json::from_slice(&bytes)?;
    validate_strict(&secrets)?;
    Ok(secrets)
}

pub(crate) fn read_runtime_secrets_file(
    path: &Path,
    identities: &[Identity],
) -> CliResult<SecretsFile> {
    Ok(resolve_runtime_source_from_file(path, identities)?)
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
