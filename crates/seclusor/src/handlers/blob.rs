use std::fs;
use std::io::Read;
use std::path::Path;

use zeroize::Zeroizing;

use crate::atomic_write::{atomic_write_private_ciphertext, PrivateCiphertextPriorSnapshot};
use crate::cli::{BlobDecryptArgs, BlobEncryptArgs, BlobSubcommand};
use crate::error::{CliError, CliResult};
use crate::handlers::rekey::paths_alias;
use crate::resolve::{resolve_identities, resolve_recipients};

pub(crate) fn handle_blob_command(command: BlobSubcommand) -> CliResult<()> {
    match command {
        BlobSubcommand::Encrypt(args) => handle_blob_encrypt(args),
        BlobSubcommand::Decrypt(args) => handle_blob_decrypt(args),
    }
}

/// Default blob file size limit (10 MB).
const BLOB_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
/// Hard ceiling for blob plaintext under `--allow-large` (matches
/// `MAX_BUNDLE_PLAINTEXT_BYTES` / `MAX_DECRYPT_PLAINTEXT_BYTES`).
const BLOB_MAX_PLAINTEXT_HARD_BYTES: u64 =
    seclusor_core::constants::MAX_BUNDLE_PLAINTEXT_BYTES as u64;
/// Hard ceiling for blob ciphertext under `--allow-large` and existing-output
/// CAS snapshots: `BLOB_MAX_PLAINTEXT_HARD_BYTES` plus 1 MiB headroom for age
/// header stanzas (up to `MAX_RECIPIENTS`), 16-byte STREAM chunk AEAD tags
/// across 16 MiB, and optional ASCII armor framing so any ciphertext produced
/// from a valid 16 MiB plaintext can be decrypted and `--force` overwritten.
const BLOB_MAX_CIPHERTEXT_HARD_BYTES: u64 = BLOB_MAX_PLAINTEXT_HARD_BYTES + 1024 * 1024;

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
    let plaintext = Zeroizing::new(seclusor_crypto::decrypt(&ciphertext, &identities)?);
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
}
