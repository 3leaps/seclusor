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
