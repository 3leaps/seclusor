//! Packaging test matrix for encrypted write / rekey (devrev hold on PR #39).
//!
//! Evidence-only suite: product code already multi-seat green. These cases
//! pin recipient-channel equality, scrypt refuse, stanza divergence, rekey
//! hygiene, and import-env coverage called out for packaging.

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use seclusor_core::{Credential, SecretsFile};

    use crate::cli::*;
    use crate::handlers::bundle::handle_bundle_encrypt;
    use crate::handlers::rekey::handle_rekey;
    use crate::handlers::secrets::{handle_import_env, handle_set, handle_set_with_policy};
    use crate::io::{read_secrets_file, write_secrets_file};
    use crate::test_support::*;

    fn list_sibling_names(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn write_recipient_file(path: &std::path::Path, recipients: &[&str]) {
        let mut body = String::new();
        for r in recipients {
            body.push_str(r);
            body.push('\n');
        }
        fs::write(path, body).expect("recipient file");
    }

    fn established_inline_one_field(dir: &std::path::Path) -> (PathBuf, PathBuf, String) {
        let identity_file = dir.join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        let recipient = fixture_recipient_string();
        let mut secrets = SecretsFile::new("demo");
        secrets
            .establish_recipients(vec![recipient.clone()])
            .expect("establish");
        let ct = seclusor_crypto::encrypt_inline_value(
            b"seed",
            std::slice::from_ref(&fixture_identity().to_public()),
        )
        .expect("enc");
        secrets.projects[0]
            .credentials
            .insert("API_KEY".into(), Credential::with_value("secret", &ct));
        let path = dir.join("inline.json");
        write_secrets_file(&path, &secrets, true).expect("write");
        (path, identity_file, recipient)
    }

    // --- Recipient-file / recipient-env equality + mismatch ---

    #[test]
    fn set_inline_recipient_file_equality_and_mismatch() {
        let dir = tempfile::tempdir().expect("temp");
        let (inline, identity_file, recipient) = established_inline_one_field(dir.path());
        let rfile = dir.path().join("recipients.txt");
        write_recipient_file(&rfile, &[recipient.as_str()]);

        handle_set(SetArgs {
            file: inline.clone(),
            project: Some("demo".into()),
            key: "API_KEY".into(),
            credential_type: "secret".into(),
            value: Some("via-file".into()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![],
                recipient_file: Some(rfile.clone()),
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file.clone()],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("recipient-file equality");

        let other = seclusor_keyring::generate_identity_file(dir.path().join("other.txt"))
            .expect("other")
            .recipient;
        write_recipient_file(&rfile, &[other.as_str()]);
        let before = fs::read(&inline).expect("before");
        let names = list_sibling_names(dir.path());
        let err = handle_set(SetArgs {
            file: inline.clone(),
            project: Some("demo".into()),
            key: "API_KEY".into(),
            credential_type: "secret".into(),
            value: Some("mismatch-body".into()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![],
                recipient_file: Some(rfile),
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("mismatch");
        assert!(err.to_string().contains("do not match") || err.to_string().contains("rekey"));
        assert!(!err.to_string().contains("mismatch-body"));
        assert_eq!(fs::read(&inline).expect("after"), before);
        assert_eq!(list_sibling_names(dir.path()), names);
    }

    #[test]
    fn set_inline_recipient_env_equality_and_mismatch() {
        let dir = tempfile::tempdir().expect("temp");
        let (inline, identity_file, recipient) = established_inline_one_field(dir.path());
        let var = "SECLUSOR_TEST_PKG_RECIPIENTS";
        std::env::set_var(var, &recipient);

        handle_set(SetArgs {
            file: inline.clone(),
            project: Some("demo".into()),
            key: "API_KEY".into(),
            credential_type: "secret".into(),
            value: Some("via-env".into()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![],
                recipient_file: None,
                recipient_env_var: Some(var.to_string()),
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file.clone()],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("recipient-env equality");

        let other = seclusor_keyring::generate_identity_file(dir.path().join("other.txt"))
            .expect("other")
            .recipient;
        std::env::set_var(var, &other);
        let before = fs::read(&inline).expect("before");
        let err = handle_set(SetArgs {
            file: inline.clone(),
            project: Some("demo".into()),
            key: "API_KEY".into(),
            credential_type: "secret".into(),
            value: Some("env-mismatch".into()),
            reference: None,
            description: None,
            create_project: false,
            value_stdin: false,
            value_file: None,
            value_env: None,
            recipients: RecipientArgs {
                recipients: vec![],
                recipient_file: None,
                recipient_env_var: Some(var.to_string()),
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("env mismatch");
        std::env::remove_var(var);
        assert!(err.to_string().contains("do not match") || err.to_string().contains("rekey"));
        assert!(!err.to_string().contains("env-mismatch"));
        assert_eq!(fs::read(&inline).expect("after"), before);
    }

    fn with_import_prefix(inline: &std::path::Path) {
        let mut secrets = read_secrets_file(inline).expect("load");
        secrets.env_prefix = Some("APP_".into());
        write_secrets_file(inline, &secrets, false).expect("write");
    }

    #[test]
    fn import_env_inline_recipient_file_equality_and_mismatch() {
        let dir = tempfile::tempdir().expect("temp");
        let (inline, identity_file, recipient) = established_inline_one_field(dir.path());
        with_import_prefix(&inline);
        let rfile = dir.path().join("recipients.txt");
        write_recipient_file(&rfile, &[recipient.as_str()]);
        let dotenv = dir.path().join("import.env");
        fs::write(&dotenv, "APP_API_KEY=via-file\n").expect("dotenv");

        handle_import_env(ImportEnvArgs {
            file: inline.clone(),
            project: Some("demo".into()),
            credential_type: "secret".into(),
            prefix: Some("APP_".into()),
            strip_prefix: true,
            dotenv_file: Some(dotenv.clone()),
            create_project: false,
            recipients: RecipientArgs {
                recipients: vec![],
                recipient_file: Some(rfile.clone()),
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file.clone()],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("import recipient-file equality");

        let other = seclusor_keyring::generate_identity_file(dir.path().join("other.txt"))
            .expect("other")
            .recipient;
        write_recipient_file(&rfile, &[other.as_str()]);
        fs::write(&dotenv, "APP_API_KEY=should-not-land\n").expect("dotenv");
        let before = fs::read(&inline).expect("before");
        let names = list_sibling_names(dir.path());

        let err = handle_import_env(ImportEnvArgs {
            file: inline.clone(),
            project: Some("demo".into()),
            credential_type: "secret".into(),
            prefix: Some("APP_".into()),
            strip_prefix: true,
            dotenv_file: Some(dotenv),
            create_project: false,
            recipients: RecipientArgs {
                recipients: vec![],
                recipient_file: Some(rfile),
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("import file mismatch");
        assert!(err.to_string().contains("do not match") || err.to_string().contains("rekey"));
        assert!(!err.to_string().contains("should-not-land"));
        assert_eq!(fs::read(&inline).expect("after"), before);
        assert_eq!(list_sibling_names(dir.path()), names);
    }

    #[test]
    fn import_env_inline_recipient_env_equality_and_mismatch() {
        let dir = tempfile::tempdir().expect("temp");
        let (inline, identity_file, recipient) = established_inline_one_field(dir.path());
        with_import_prefix(&inline);
        let var = "SECLUSOR_TEST_PKG_IMPORT_RECIPIENTS";
        std::env::set_var(var, &recipient);
        let dotenv = dir.path().join("import.env");
        fs::write(&dotenv, "APP_API_KEY=via-env\n").expect("dotenv");

        handle_import_env(ImportEnvArgs {
            file: inline.clone(),
            project: Some("demo".into()),
            credential_type: "secret".into(),
            prefix: Some("APP_".into()),
            strip_prefix: true,
            dotenv_file: Some(dotenv.clone()),
            create_project: false,
            recipients: RecipientArgs {
                recipients: vec![],
                recipient_file: None,
                recipient_env_var: Some(var.to_string()),
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file.clone()],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("import recipient-env equality");

        let other = seclusor_keyring::generate_identity_file(dir.path().join("other.txt"))
            .expect("other")
            .recipient;
        std::env::set_var(var, &other);
        fs::write(&dotenv, "APP_API_KEY=env-mismatch-body\n").expect("dotenv");
        let before = fs::read(&inline).expect("before");
        let names = list_sibling_names(dir.path());

        let err = handle_import_env(ImportEnvArgs {
            file: inline.clone(),
            project: Some("demo".into()),
            credential_type: "secret".into(),
            prefix: Some("APP_".into()),
            strip_prefix: true,
            dotenv_file: Some(dotenv),
            create_project: false,
            recipients: RecipientArgs {
                recipients: vec![],
                recipient_file: None,
                recipient_env_var: Some(var.to_string()),
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("import env mismatch");
        std::env::remove_var(var);
        assert!(err.to_string().contains("do not match") || err.to_string().contains("rekey"));
        assert!(!err.to_string().contains("env-mismatch-body"));
        assert_eq!(fs::read(&inline).expect("after"), before);
        assert_eq!(list_sibling_names(dir.path()), names);
    }

    // --- Scrypt SC-011 refuse ---

    #[test]
    fn set_scrypt_bundle_refuses_naming_sc011() {
        let dir = tempfile::tempdir().expect("temp");
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        let secrets = fixture_secrets();
        let scrypt =
            seclusor_codec::encrypt_bundle_with_passphrase(&secrets, "test-passphrase-not-secret")
                .expect("scrypt encrypt");
        let path = dir.path().join("scrypt.age");
        fs::write(&path, &scrypt).expect("write");
        let before = scrypt.clone();
        let names = list_sibling_names(dir.path());

        let err = handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".into()),
            key: "API_KEY".into(),
            credential_type: "secret".into(),
            value: Some("nope".into()),
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
        .expect_err("scrypt refuse");

        let msg = err.to_string();
        assert!(msg.contains("SC-011"), "must name SC-011, got {msg}");
        assert!(!msg.contains("nope"));
        assert_eq!(fs::read(&path).expect("after"), before);
        assert_eq!(list_sibling_names(dir.path()), names);
    }

    #[test]
    fn rekey_scrypt_bundle_refuses_naming_sc011_before_identity() {
        // No identity files: classification must still name SC-011 (probe before resolve).
        let dir = tempfile::tempdir().expect("temp");
        let secrets = fixture_secrets();
        let scrypt =
            seclusor_codec::encrypt_bundle_with_passphrase(&secrets, "test-passphrase-not-secret")
                .expect("scrypt");
        let path = dir.path().join("scrypt.age");
        fs::write(&path, &scrypt).expect("write");
        let before = scrypt;
        let names = list_sibling_names(dir.path());

        let err = handle_rekey(RekeyArgs {
            file: path.clone(),
            output: None,
            write_recipients: None,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("scrypt rekey without identity");
        let msg = err.to_string();
        assert!(
            msg.contains("SC-011"),
            "must name SC-011 before identity fail, got {msg}"
        );
        assert_eq!(fs::read(&path).expect("after"), before);
        assert_eq!(list_sibling_names(dir.path()), names);
    }

    // --- Stanza divergence (metadata present, heterogeneous field) ---

    #[test]
    fn set_inline_stanza_divergence_refuses() {
        let dir = tempfile::tempdir().expect("temp");
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        let r1 = fixture_identity().to_public();
        let gen2 =
            seclusor_keyring::generate_identity_file(dir.path().join("id2.txt")).expect("id2");
        let r2: seclusor_crypto::Recipient = gen2.recipient.parse().expect("r2");

        let mut secrets = SecretsFile::new("demo");
        secrets
            .establish_recipients(vec![fixture_recipient_string()])
            .expect("meta claims 1");
        // Field encrypted to TWO recipients while metadata claims one.
        let ct = seclusor_crypto::encrypt_inline_value(b"het", &[r1, r2]).expect("enc");
        secrets.projects[0]
            .credentials
            .insert("API_KEY".into(), Credential::with_value("secret", &ct));
        let path = dir.path().join("het.json");
        write_secrets_file(&path, &secrets, true).expect("write");
        let before = fs::read(&path).expect("before");
        let names = list_sibling_names(dir.path());

        let err = handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".into()),
            key: "API_KEY".into(),
            credential_type: "secret".into(),
            value: Some("rewrite".into()),
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
        .expect_err("stanza divergence");

        assert!(err.to_string().contains("stanza") || err.to_string().contains("rekey"));
        assert!(!err.to_string().contains("rewrite"));
        assert_eq!(fs::read(&path).expect("after"), before);
        assert_eq!(list_sibling_names(dir.path()), names);
    }

    // --- Rekey hygiene ---

    #[test]
    fn rekey_inline_to_output_leaves_source_unchanged() {
        let dir = tempfile::tempdir().expect("temp");
        let (inline, identity_file) = write_inline_encrypted_file(dir.path());
        let before = fs::read(&inline).expect("before");
        let out = dir.path().join("rekeyed.json");

        handle_rekey(RekeyArgs {
            file: inline.clone(),
            output: Some(out.clone()),
            write_recipients: None,
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
        .expect("rekey output");

        assert_eq!(fs::read(&inline).expect("source"), before);
        let rekeyed: SecretsFile =
            serde_json::from_slice(&fs::read(&out).expect("out")).expect("parse");
        assert!(rekeyed.recipients.is_some());
    }

    #[test]
    fn rekey_missing_identity_refuses_hygiene() {
        let dir = tempfile::tempdir().expect("temp");
        let (inline, _) = write_inline_encrypted_file(dir.path());
        let before = fs::read(&inline).expect("before");
        let names = list_sibling_names(dir.path());
        let err = handle_rekey(RekeyArgs {
            file: inline.clone(),
            output: None,
            write_recipients: None,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("missing identity");
        assert!(err.to_string().contains("identity"));
        assert_eq!(fs::read(&inline).expect("after"), before);
        assert_eq!(list_sibling_names(dir.path()), names);
    }

    #[test]
    fn rekey_wrong_identity_refuses_hygiene() {
        let dir = tempfile::tempdir().expect("temp");
        let (inline, _) = write_inline_encrypted_file(dir.path());
        let wrong = dir.path().join("wrong.txt");
        seclusor_keyring::generate_identity_file(&wrong).expect("wrong");
        let before = fs::read(&inline).expect("before");
        let names = list_sibling_names(dir.path());
        let err = handle_rekey(RekeyArgs {
            file: inline.clone(),
            output: None,
            write_recipients: None,
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
        assert!(!err.to_string().contains("sk-123"));
        assert_eq!(fs::read(&inline).expect("after"), before);
        assert_eq!(list_sibling_names(dir.path()), names);
    }

    #[test]
    fn rekey_passphrase_protected_identity_roundtrip() {
        use seclusor_keyring::generate_identity_file_with_passphrase;
        use secrecy::SecretString;

        let dir = tempfile::tempdir().expect("temp");
        let protected = dir.path().join("protected.txt");
        let pp = SecretString::from("test-rekey-passphrase-not-a-secret".to_owned());
        let gen = generate_identity_file_with_passphrase(&protected, &pp).expect("protected id");
        let recipient = gen.recipient;

        let input = dir.path().join("plain.json");
        let bundle = dir.path().join("secrets.age");
        write_secrets_file(&input, &fixture_secrets(), true).expect("write");
        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![recipient.clone()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt for protected recipient");

        // Rekey in place to same set (establishes metadata) with passphrase-env.
        let var = "SECLUSOR_TEST_REKEY_PP";
        std::env::set_var(var, "test-rekey-passphrase-not-a-secret");
        handle_rekey(RekeyArgs {
            file: bundle.clone(),
            output: None,
            write_recipients: None,
            recipients: RecipientArgs {
                recipients: vec![recipient.clone()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![protected.clone()],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs {
                passphrase: false,
                passphrase_env: Some(var.to_string()),
                passphrase_file: None,
                passphrase_stdin: false,
            },
        })
        .expect("rekey with protected identity");
        std::env::remove_var(var);

        let identities =
            seclusor_keyring::load_identity_file_auto(&protected, Some(&pp)).expect("load");
        let secrets =
            seclusor_codec::decrypt_bundle(&fs::read(&bundle).expect("read"), &identities)
                .expect("decrypt after rekey");
        assert!(secrets.recipients.is_some());
        assert_eq!(
            secrets.projects[0].credentials["API_KEY"].value.as_deref(),
            Some("sk-123")
        );
    }

    #[test]
    fn rekey_protected_identity_missing_passphrase_refuses() {
        use seclusor_keyring::generate_identity_file_with_passphrase;
        use secrecy::SecretString;

        let dir = tempfile::tempdir().expect("temp");
        let protected = dir.path().join("protected.txt");
        let pp = SecretString::from("unused-passphrase-for-protected-file".to_owned());
        let gen = generate_identity_file_with_passphrase(&protected, &pp).expect("protected");
        let (inline, _) = write_inline_encrypted_file(dir.path());
        // Re-encrypt inline for protected recipient so rekey would need it.
        let secrets = fixture_secrets();
        let r: seclusor_crypto::Recipient = gen.recipient.parse().expect("r");
        let encrypted =
            seclusor_codec::encrypt_inline(&secrets, std::slice::from_ref(&r)).expect("encrypt");
        write_secrets_file(&inline, &encrypted, false).expect("write");
        let before = fs::read(&inline).expect("before");
        let names = list_sibling_names(dir.path());

        // Unset passphrase-env: non-interactive refuse without rpassword.
        // (Auto-prompt / --passphrase still require a controlling console; this
        // test pins the explicit missing-channel path used by CI/scripts.)
        let unset_var = "SECLUSOR_TEST_REKEY_PP_UNSET";
        std::env::remove_var(unset_var);
        let err = handle_rekey(RekeyArgs {
            file: inline.clone(),
            output: None,
            write_recipients: None,
            recipients: RecipientArgs {
                recipients: vec![gen.recipient],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![protected],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs {
                passphrase: false,
                passphrase_env: Some(unset_var.to_string()),
                passphrase_file: None,
                passphrase_stdin: false,
            },
        })
        .expect_err("missing passphrase");
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("passphrase") || msg.contains("protected"),
            "{msg}"
        );
        assert_eq!(fs::read(&inline).expect("after"), before);
        assert_eq!(list_sibling_names(dir.path()), names);
    }

    // --- S1 packaging strengtheners ---

    #[test]
    fn set_bundle_n_to_one_snapshots_no_residual_temp() {
        let dir = tempfile::tempdir().expect("temp");
        let input = dir.path().join("plain.json");
        let bundle = dir.path().join("secrets.age");
        let id_a = dir.path().join("id-a.txt");
        let id_b = dir.path().join("id-b.txt");
        write_identity_file(&id_a, TEST_IDENTITY);
        let gen_b = seclusor_keyring::generate_identity_file(&id_b).expect("b");
        write_secrets_file(&input, &fixture_secrets(), true).expect("write");
        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string(), gen_b.recipient],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt");
        let before = fs::read(&bundle).expect("before");
        let names_before = list_sibling_names(dir.path());

        let err = handle_set(SetArgs {
            file: bundle.clone(),
            project: Some("demo".into()),
            key: "API_KEY".into(),
            credential_type: "secret".into(),
            value: Some("solo".into()),
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
        .expect_err("N→1");
        assert!(!err.to_string().contains("solo"));
        assert_eq!(fs::read(&bundle).expect("after"), before);
        assert_eq!(list_sibling_names(dir.path()), names_before);
    }

    #[test]
    fn set_bundle_override_permits_detected_same_count_member_change() {
        // Metadata detects the same-count member change; the explicit override
        // deliberately accepts it while the stanza-count tripwire stays green.
        let dir = tempfile::tempdir().expect("temp");
        let input = dir.path().join("plain.json");
        let bundle = dir.path().join("secrets.age");
        let id_a = dir.path().join("id-a.txt");
        let id_c = dir.path().join("id-c.txt");
        write_identity_file(&id_a, TEST_IDENTITY);
        let gen_c = seclusor_keyring::generate_identity_file(&id_c).expect("c");
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
        .expect("encrypt to A");

        // Replace A with C (same count 1) using explicit delta consent.
        handle_set_with_policy(
            SetArgs {
                file: bundle.clone(),
                project: Some("demo".into()),
                key: "API_KEY".into(),
                credential_type: "secret".into(),
                value: Some("swapped".into()),
                reference: None,
                description: None,
                create_project: false,
                value_stdin: false,
                value_file: None,
                value_env: None,
                recipients: RecipientArgs {
                    recipients: vec![gen_c.recipient.clone()],
                    recipient_file: None,
                    recipient_env_var: None,
                },
                identities: IdentityArgs {
                    identity_files: vec![id_a],
                    identity_public_key: None,
                },
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect("same-count member change is accepted with override");

        let ct = fs::read(&bundle).expect("read");
        assert_eq!(
            seclusor_crypto::count_x25519_recipient_stanzas(&ct).expect("c"),
            1
        );
        // A can no longer decrypt after the deliberately accepted change to C.
        let fail = seclusor_codec::decrypt_bundle(&ct, &[fixture_identity()]);
        assert!(
            fail.is_err(),
            "old recipient should fail after accepted member change"
        );
        let id_c_ident = seclusor_keyring::load_identity_file_auto(&id_c, None).expect("id c");
        let secrets = seclusor_codec::decrypt_bundle(&ct, &id_c_ident).expect("C decrypts");
        assert_eq!(
            secrets.projects[0].credentials["API_KEY"].value.as_deref(),
            Some("swapped")
        );
        assert_eq!(
            secrets.recipients.as_deref(),
            Some(std::slice::from_ref(&gen_c.recipient))
        );
    }

    // --- Metadata-less import-env establishment same-count ---

    #[test]
    fn import_env_bundle_same_count_establishment() {
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
        .expect("encrypt metadata-less");

        let dotenv = dir.path().join("import.env");
        fs::write(&dotenv, "APP_API_KEY=imported\n").expect("dotenv");
        handle_import_env(ImportEnvArgs {
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
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("import establish same-count");

        let dec = seclusor_codec::decrypt_bundle(
            &fs::read(&bundle).expect("read"),
            &[fixture_identity()],
        )
        .expect("dec");
        assert!(dec.recipients.is_some());
        assert_eq!(
            dec.projects[0].credentials["API_KEY"].value.as_deref(),
            Some("imported")
        );
    }

    #[test]
    fn import_env_bundle_resize_refuses() {
        let dir = tempfile::tempdir().expect("temp");
        let input = dir.path().join("plain.json");
        let bundle = dir.path().join("secrets.age");
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        let gen2 = seclusor_keyring::generate_identity_file(dir.path().join("id2.txt")).expect("2");
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
        .expect("encrypt 1");
        let dotenv = dir.path().join("import.env");
        fs::write(&dotenv, "APP_API_KEY=grow\n").expect("dotenv");
        let before = fs::read(&bundle).expect("before");
        let names = list_sibling_names(dir.path());

        let err = handle_import_env(ImportEnvArgs {
            file: bundle.clone(),
            project: Some("demo".into()),
            credential_type: "secret".into(),
            prefix: Some("APP_".into()),
            strip_prefix: true,
            dotenv_file: Some(dotenv),
            create_project: false,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string(), gen2.recipient],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("1→2 import refuse");
        assert!(err.to_string().contains("rekey") || err.to_string().contains("stanza"));
        assert!(!err.to_string().contains("grow"));
        assert_eq!(fs::read(&bundle).expect("after"), before);
        assert_eq!(list_sibling_names(dir.path()), names);
    }
}
