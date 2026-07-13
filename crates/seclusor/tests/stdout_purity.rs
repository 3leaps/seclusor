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
