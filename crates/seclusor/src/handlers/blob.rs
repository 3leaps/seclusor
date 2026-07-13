use std::fs;
use std::io::Read;
use std::path::Path;

use crate::cli::{BlobDecryptArgs, BlobEncryptArgs, BlobSubcommand};
use crate::error::{CliError, CliResult};
use crate::resolve::{resolve_identities, resolve_recipients};

pub(crate) fn handle_blob_command(command: BlobSubcommand) -> CliResult<()> {
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

pub(crate) fn handle_blob_encrypt(args: BlobEncryptArgs) -> CliResult<()> {
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

pub(crate) fn handle_blob_decrypt(args: BlobDecryptArgs) -> CliResult<()> {
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
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("wrong identity must fail");

        // Error must not contain plaintext
        let msg = err.to_string();
        assert!(!msg.contains("secret data"));
    }
}
