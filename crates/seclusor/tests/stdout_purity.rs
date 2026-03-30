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
        "API_KEY": { "type": "secret", "value": "sk-123" }
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
        "API_KEY\n"
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
    assert!(stderr.contains("file still contains malformed credentials after removing"));
    assert!(!stderr.contains("cfat_one"));
    assert!(!stderr.contains("cfat_two"));

    let repaired = fs::read_to_string(&invalid).expect("read repaired file");
    assert!(!repaired.contains("BAD_ONE"));
    assert!(!repaired.contains("cfat_one"));
    assert!(repaired.contains("BAD_TWO"));
}
