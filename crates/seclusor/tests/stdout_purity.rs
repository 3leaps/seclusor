use std::fs;
use std::path::Path;
use std::process::Command;

fn write_fixture(path: &Path) {
    let fixture = r#"{
  "schema_version": "v1.0.0",
  "projects": [
    {
      "project_slug": "demo",
      "credentials": {
        "API_KEY": {
          "type": "secret",
          "value": "sk-123",
          "description": "primary API token"
        },
        "EMPTY_DESC": { "type": "secret", "value": "sk-empty" }
      }
    }
  ]
}"#;
    fs::write(path, fixture).expect("write fixture");
}

fn run_seclusor(args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_seclusor");
    Command::new(bin).args(args).output().expect("run seclusor")
}

#[test]
fn list_stdout_only_on_success() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = dir.path().join("secrets.json");
    write_fixture(&secrets);

    let output = run_seclusor(&[
        "secrets",
        "list",
        "--file",
        secrets.to_str().expect("utf8 path"),
        "--project",
        "demo",
    ]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stderr).expect("utf8 stderr"), "");
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "API_KEY\nEMPTY_DESC\n"
    );
}

#[test]
fn get_redacted_stdout_only_on_success() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = dir.path().join("secrets.json");
    write_fixture(&secrets);

    let output = run_seclusor(&[
        "secrets",
        "get",
        "--file",
        secrets.to_str().expect("utf8 path"),
        "--project",
        "demo",
        "--key",
        "API_KEY",
    ]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stderr).expect("utf8 stderr"), "");
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "<redacted>\n"
    );
}

#[test]
fn get_show_description_writes_description_only_to_stdout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = dir.path().join("secrets.json");
    write_fixture(&secrets);

    let output = run_seclusor(&[
        "secrets",
        "get",
        "--file",
        secrets.to_str().expect("utf8 path"),
        "--project",
        "demo",
        "--key",
        "API_KEY",
        "--show-description",
    ]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stderr).expect("utf8 stderr"), "");
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "primary API token\n"
    );
}

#[test]
fn get_show_description_is_empty_when_unset() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = dir.path().join("secrets.json");
    write_fixture(&secrets);

    let output = run_seclusor(&[
        "secrets",
        "get",
        "--file",
        secrets.to_str().expect("utf8 path"),
        "--project",
        "demo",
        "--key",
        "EMPTY_DESC",
        "--show-description",
    ]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stderr).expect("utf8 stderr"), "");
    assert_eq!(String::from_utf8(output.stdout).expect("utf8 stdout"), "");
}

#[test]
fn get_rejects_show_description_with_reveal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = dir.path().join("secrets.json");
    write_fixture(&secrets);

    let output = run_seclusor(&[
        "secrets",
        "get",
        "--file",
        secrets.to_str().expect("utf8 path"),
        "--project",
        "demo",
        "--key",
        "API_KEY",
        "--show-description",
        "--reveal",
    ]);
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).expect("utf8 stdout"), "");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("--show-description"));
    assert!(stderr.contains("--reveal"));
}

#[test]
fn list_verbose_writes_tab_separated_descriptions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = dir.path().join("secrets.json");
    write_fixture(&secrets);

    let output = run_seclusor(&[
        "secrets",
        "list",
        "--file",
        secrets.to_str().expect("utf8 path"),
        "--project",
        "demo",
        "--verbose",
    ]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stderr).expect("utf8 stderr"), "");
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "API_KEY\tprimary API token\nEMPTY_DESC\n"
    );
}

#[test]
fn export_json_stdout_is_valid_json_and_stderr_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = dir.path().join("secrets.json");
    write_fixture(&secrets);

    let output = run_seclusor(&[
        "secrets",
        "export-env",
        "--file",
        secrets.to_str().expect("utf8 path"),
        "--project",
        "demo",
        "--format",
        "json",
        "--prefix",
        "APP_",
    ]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stderr).expect("utf8 stderr"), "");

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(parsed["APP_API_KEY"], "sk-123");
}

#[test]
fn export_shell_format_requires_allow() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = dir.path().join("secrets.json");
    write_fixture(&secrets);

    let output = run_seclusor(&[
        "secrets",
        "export-env",
        "--file",
        secrets.to_str().expect("utf8 path"),
        "--project",
        "demo",
        "--format",
        "export",
        "--prefix",
        "APP_",
    ]);
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).expect("utf8 stdout"), "");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("--allow"),
        "stderr should require allow pattern: {stderr}"
    );
}

#[test]
fn export_shell_format_with_allow_writes_export_lines_empty_stderr() {
    // Process capture means stdout is not a TTY, so --force is not required.
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = dir.path().join("secrets.json");
    write_fixture(&secrets);

    let output = run_seclusor(&[
        "secrets",
        "export-env",
        "--file",
        secrets.to_str().expect("utf8 path"),
        "--project",
        "demo",
        "--format",
        "export",
        "--prefix",
        "APP_",
        "--allow",
        "APP_API_KEY",
    ]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8(output.stderr).expect("utf8 stderr"), "");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(
        stdout.contains("export APP_API_KEY="),
        "expected shell export line, got {stdout:?}"
    );
    assert!(!stdout.contains("EMPTY_DESC"), "allow filter should apply");
}

#[test]
fn export_shell_format_verbose_summary_on_stderr_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = dir.path().join("secrets.json");
    write_fixture(&secrets);

    let output = run_seclusor(&[
        "secrets",
        "export-env",
        "--file",
        secrets.to_str().expect("utf8 path"),
        "--project",
        "demo",
        "--format",
        "export",
        "--prefix",
        "APP_",
        "--allow",
        "APP_API_KEY",
        "--verbose",
    ]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("export APP_API_KEY="));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("Exported 1 variables from demo"),
        "expected completion summary, got {stderr:?}"
    );
    // Allow patterns may appear under --verbose only; stdout must stay pure.
    assert!(!stdout.contains("Exported"));
}

#[test]
fn missing_file_failure_writes_diagnostics_to_stderr_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing.json");

    let output = run_seclusor(&[
        "secrets",
        "list",
        "--file",
        missing.to_str().expect("utf8 path"),
        "--project",
        "demo",
    ]);
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).expect("utf8 stdout"), "");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        !stderr.trim().is_empty(),
        "stderr should include diagnostics"
    );
}

#[test]
fn invalid_document_failure_writes_diagnostics_to_stderr_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let invalid = dir.path().join("invalid.json");
    fs::write(
        &invalid,
        r#"{"schema_version":"v9.9.9","projects":[{"project_slug":"demo","credentials":{}}]}"#,
    )
    .expect("write invalid fixture");

    let output = run_seclusor(&[
        "secrets",
        "validate",
        "--file",
        invalid.to_str().expect("utf8 path"),
    ]);
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).expect("utf8 stdout"), "");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        !stderr.trim().is_empty(),
        "stderr should include diagnostics"
    );
}

#[test]
fn validate_plaintext_full_is_valid_token_only_on_stdout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = dir.path().join("secrets.json");
    write_fixture(&secrets);

    let output = run_seclusor(&[
        "secrets",
        "validate",
        "--file",
        secrets.to_str().expect("utf8 path"),
    ]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "valid\n"
    );
    assert_eq!(String::from_utf8(output.stderr).expect("utf8 stderr"), "");
}

/// Process-boundary guardrail: structural-only success is machine-distinguishable.
#[test]
fn validate_inline_without_identity_is_structural_only_on_stdout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (inline, _identity) = prepare_inline_encrypted(dir.path());

    let output = run_seclusor(&[
        "secrets",
        "validate",
        "--file",
        inline.to_str().expect("utf8 path"),
    ]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "structural-only valid\n"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("structural-only"),
        "stderr must reinforce structural-only mode, got: {stderr}"
    );
    assert!(
        !stderr.to_ascii_lowercase().contains("authentic"),
        "must not claim authenticity"
    );
    assert!(
        !stderr.to_ascii_lowercase().contains("decryptab"),
        "must not claim decryptability of values"
    );
}

/// Full mode with identity: `valid` token only, empty stderr (stdout purity).
#[test]
fn validate_inline_with_identity_is_full_valid_empty_stderr() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (inline, identity) = prepare_inline_encrypted(dir.path());

    let output = run_seclusor(&[
        "secrets",
        "validate",
        "--file",
        inline.to_str().expect("utf8 path"),
        "--identity-file",
        identity.to_str().expect("utf8 identity"),
    ]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "valid\n"
    );
    assert_eq!(String::from_utf8(output.stderr).expect("utf8 stderr"), "");
}

/// Build an inline-encrypted secrets file via the CLI for process-boundary tests.
fn prepare_inline_encrypted(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let input = dir.join("input.json");
    let inline = dir.join("inline.json");
    let identity = dir.join("identity.txt");
    write_fixture(&input);

    let generated = Command::new(env!("CARGO_BIN_EXE_seclusor"))
        .args([
            "keys",
            "age",
            "identity",
            "generate",
            "--output",
            identity.to_str().expect("utf8 identity"),
        ])
        .output()
        .expect("generate identity");
    assert!(
        generated.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let recipient = String::from_utf8(generated.stdout).expect("utf8 recipient");

    let encrypted = Command::new(env!("CARGO_BIN_EXE_seclusor"))
        .args([
            "secrets",
            "inline",
            "encrypt",
            "--input",
            input.to_str().expect("utf8 input"),
            "--output",
            inline.to_str().expect("utf8 inline"),
            "--recipient",
            recipient.trim(),
        ])
        .output()
        .expect("inline encrypt");
    assert!(
        encrypted.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&encrypted.stderr)
    );

    (inline, identity)
}

#[test]
fn unset_lenient_recovery_keeps_plaintext_off_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let invalid = dir.path().join("invalid.json");
    fs::write(
        &invalid,
        r#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"CLOUDFLARE_API_TOKEN":"cfat_secret_token","API_KEY":{"type":"secret","value":"sk-123"}}}]}"#,
    )
    .expect("write invalid fixture");

    let output = run_seclusor(&[
        "secrets",
        "unset",
        "--file",
        invalid.to_str().expect("utf8 path"),
        "--project",
        "demo",
        "--key",
        "CLOUDFLARE_API_TOKEN",
    ]);
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert_eq!(stdout, "ok\n");

    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("warning: file contains malformed credentials; using lenient parse"));
    assert!(!stderr.contains("cfat_secret_token"));

    let repaired = fs::read_to_string(&invalid).expect("read repaired file");
    assert!(!repaired.contains("CLOUDFLARE_API_TOKEN"));
    assert!(!repaired.contains("cfat_secret_token"));
}

#[test]
fn unset_lenient_recovery_fails_when_other_malformed_credentials_remain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let invalid = dir.path().join("invalid.json");
    fs::write(
        &invalid,
        r#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"BAD_ONE":"cfat_one","BAD_TWO":"cfat_two"}}]}"#,
    )
    .expect("write invalid fixture");

    let output = run_seclusor(&[
        "secrets",
        "unset",
        "--file",
        invalid.to_str().expect("utf8 path"),
        "--project",
        "demo",
        "--key",
        "BAD_ONE",
    ]);
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).expect("utf8 stdout"), "");

    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("warning: file contains malformed credentials; using lenient parse"));
    assert!(stderr.contains("file was updated, but malformed credentials remain after removing"));
    assert!(!stderr.contains("cfat_one"));
    assert!(!stderr.contains("cfat_two"));

    let repaired = fs::read_to_string(&invalid).expect("read repaired file");
    assert!(!repaired.contains("BAD_ONE"));
    assert!(!repaired.contains("cfat_one"));
    assert!(repaired.contains("BAD_TWO"));
}

#[test]
fn blob_rekey_and_verify_stdout_purity_and_process_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let old_id = dir.path().join("old-identity.txt");
    let new_id = dir.path().join("new-identity.txt");
    let plain = dir.path().join("blob.txt");
    let blob = dir.path().join("blob.age");
    let recipients_out = dir.path().join("recipients.txt");

    fs::write(&plain, b"SECRET_BLOB_CONTENT_42").expect("write plain");

    let gen_old = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        old_id.to_str().expect("utf8"),
    ]);
    assert!(gen_old.status.success());
    let old_recipient = String::from_utf8(gen_old.stdout)
        .expect("utf8")
        .trim()
        .to_string();

    let gen_new = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        new_id.to_str().expect("utf8"),
    ]);
    assert!(gen_new.status.success());
    let new_recipient = String::from_utf8(gen_new.stdout)
        .expect("utf8")
        .trim()
        .to_string();

    let enc = run_seclusor(&[
        "secrets",
        "blob",
        "encrypt",
        "--input",
        plain.to_str().expect("utf8"),
        "--output",
        blob.to_str().expect("utf8"),
        "--recipient",
        &old_recipient,
    ]);
    assert!(enc.status.success());
    assert_eq!(String::from_utf8(enc.stdout).expect("utf8"), "");

    // Verify with old identity: stdout is opening recipient + newline, stderr is empty.
    let verify_old = run_seclusor(&[
        "secrets",
        "blob",
        "verify",
        "--input",
        blob.to_str().expect("utf8"),
        "--identity-file",
        old_id.to_str().expect("utf8"),
    ]);
    assert!(verify_old.status.success());
    assert_eq!(
        String::from_utf8(verify_old.stdout).expect("utf8"),
        format!("{old_recipient}\n")
    );
    assert_eq!(String::from_utf8(verify_old.stderr).expect("utf8"), "");

    // Rekey in place to new_recipient with pre-commit verification via --verify-identity-file.
    let rekey = run_seclusor(&[
        "secrets",
        "blob",
        "rekey",
        "--input",
        blob.to_str().expect("utf8"),
        "--identity-file",
        old_id.to_str().expect("utf8"),
        "--prior-recipient",
        &old_recipient,
        "--recipient",
        &new_recipient,
        "--verify-identity-file",
        new_id.to_str().expect("utf8"),
        "--write-recipients",
        recipients_out.to_str().expect("utf8"),
        "--allow-recipient-mismatch",
    ]);
    assert!(
        rekey.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&rekey.stderr)
    );
    assert_eq!(
        String::from_utf8(rekey.stdout).expect("utf8"),
        format!("{}\n", blob.display())
    );
    let rekey_stderr = String::from_utf8(rekey.stderr).expect("utf8");
    assert!(rekey_stderr.contains("recipient set change accepted:"));
    assert!(rekey_stderr.contains(&format!("+{new_recipient}")));
    assert!(rekey_stderr.contains(&format!("-{old_recipient}")));
    assert!(!rekey_stderr.contains("SECRET_BLOB_CONTENT_42"));
    assert_eq!(
        fs::read_to_string(&recipients_out).expect("read recipients"),
        format!("{new_recipient}\n")
    );

    // Verify with old identity now fails with empty stdout; new identity succeeds.
    let verify_old_after = run_seclusor(&[
        "secrets",
        "blob",
        "verify",
        "--input",
        blob.to_str().expect("utf8"),
        "--identity-file",
        old_id.to_str().expect("utf8"),
    ]);
    assert!(!verify_old_after.status.success());
    assert_eq!(
        String::from_utf8(verify_old_after.stdout).expect("utf8"),
        ""
    );

    let verify_new = run_seclusor(&[
        "secrets",
        "blob",
        "verify",
        "--input",
        blob.to_str().expect("utf8"),
        "--identity-file",
        new_id.to_str().expect("utf8"),
    ]);
    assert!(verify_new.status.success());
    assert_eq!(
        String::from_utf8(verify_new.stdout).expect("utf8"),
        format!("{new_recipient}\n")
    );
    assert_eq!(String::from_utf8(verify_new.stderr).expect("utf8"), "");
}

#[test]
fn blob_rekey_batch_json_stdout_purity_schema_and_single_passphrase_unlock() {
    use std::io::Write as _;
    use std::process::Stdio;

    let dir = tempfile::tempdir().expect("tempdir");
    let old_id = dir.path().join("old-protected-identity.txt");
    let new_id = dir.path().join("new-identity.txt");
    let plain1 = dir.path().join("plain1.txt");
    let plain2 = dir.path().join("plain2.txt");
    let blob1 = dir.path().join("one.age");
    let blob2 = dir.path().join("two.age");
    let state_file = dir.path().join("rekey-state.json");
    let recipients_out = dir.path().join("recipients.txt");

    let pp_str = "batch-single-unlock-passphrase-42";
    fs::write(&plain1, b"SECRET_BATCH_ONE_99").expect("write plain1");
    fs::write(&plain2, b"SECRET_BATCH_TWO_99").expect("write plain2");

    let bin = env!("CARGO_BIN_EXE_seclusor");
    let mut gen_old = Command::new(bin)
        .args([
            "keys",
            "age",
            "identity",
            "generate",
            "--output",
            old_id.to_str().unwrap(),
            "--passphrase-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn identity generate");
    writeln!(gen_old.stdin.as_mut().unwrap(), "{pp_str}").expect("write passphrase");
    let gen_old_out = gen_old.wait_with_output().expect("wait gen_old");
    assert!(
        gen_old_out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&gen_old_out.stderr)
    );
    let old_recipient = String::from_utf8(gen_old_out.stdout)
        .unwrap()
        .trim()
        .to_string();

    let gen_new = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        new_id.to_str().unwrap(),
    ]);
    assert!(gen_new.status.success());
    let new_recipient = String::from_utf8(gen_new.stdout)
        .unwrap()
        .trim()
        .to_string();

    for (inp, outp) in [(&plain1, &blob1), (&plain2, &blob2)] {
        let enc = run_seclusor(&[
            "secrets",
            "blob",
            "encrypt",
            "--input",
            inp.to_str().unwrap(),
            "--output",
            outp.to_str().unwrap(),
            "--recipient",
            &old_recipient,
        ]);
        assert!(enc.status.success());
    }
    fs::remove_file(&plain1).unwrap();
    fs::remove_file(&plain2).unwrap();

    // T18 + T19: Run `secrets blob rekey-batch --apply --json` with a single passphrase line on stdin.
    let mut child = Command::new(bin)
        .args([
            "secrets",
            "--allow-recipient-mismatch",
            "blob",
            "rekey-batch",
            blob1.to_str().unwrap(),
            blob2.to_str().unwrap(),
            "--apply",
            "--json",
            "--state",
            state_file.to_str().unwrap(),
            "--write-recipients",
            recipients_out.to_str().unwrap(),
            "--identity-file",
            old_id.to_str().unwrap(),
            "--passphrase-stdin",
            "--recipient",
            &new_recipient,
            "--prior-recipient",
            &old_recipient,
            "--verify-identity-file",
            new_id.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rekey-batch");
    writeln!(child.stdin.as_mut().unwrap(), "{pp_str}").expect("write passphrase once");
    let output = child.wait_with_output().expect("wait rekey-batch");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_str = String::from_utf8(output.stdout).expect("utf8 stdout");
    let stderr_str = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(!stdout_str.contains("SECRET_BATCH_ONE_99"));
    assert!(!stdout_str.contains("SECRET_BATCH_TWO_99"));
    assert!(!stderr_str.contains("SECRET_BATCH_ONE_99"));
    assert!(!stderr_str.contains("SECRET_BATCH_TWO_99"));
    assert!(!stdout_str.contains(pp_str));
    assert!(!stderr_str.contains(pp_str));

    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/seclusor/v1.1.0/blob-rekey-batch.schema.json"
    ))
    .expect("schema json");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout_str).expect("stdout must be pure JSON");
    assert_eq!(parsed["version"], 1);
    assert_eq!(parsed["mode"], "apply");
    assert_eq!(parsed["summary"]["selected"], 2);
    assert_eq!(parsed["summary"]["rekeyed"], 2);
    assert_eq!(parsed["summary"]["failed"], 0);
    for req_key in schema["required"].as_array().unwrap() {
        assert!(parsed
            .as_object()
            .unwrap()
            .contains_key(req_key.as_str().unwrap()));
    }
    assert!(state_file.exists());
    assert_eq!(
        fs::read_to_string(&recipients_out).unwrap(),
        format!("{new_recipient}\n")
    );
}
