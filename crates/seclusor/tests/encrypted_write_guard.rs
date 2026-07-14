//! Process-boundary tests for the encrypted write-target guard.
//!
//! Verifies exit status, empty stdout, remedy-only stderr, byte-identical targets,
//! and no temp artifacts when write commands refuse encrypted inputs.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn seclusor_bin() -> &'static str {
    env!("CARGO_BIN_EXE_seclusor")
}

fn run_seclusor(args: &[&str]) -> std::process::Output {
    Command::new(seclusor_bin())
        .args(args)
        .output()
        .expect("run seclusor")
}

fn write_plaintext_fixture(path: &Path) {
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
        "OTHER": { "type": "secret", "value": "sk-other" }
      }
    }
  ]
}"#;
    fs::write(path, fixture).expect("write fixture");
}

fn prepare_inline_encrypted(dir: &Path) -> PathBuf {
    let input = dir.join("input.json");
    let inline = dir.join("inline.json");
    write_plaintext_fixture(&input);

    let identity = dir.join("identity.txt");
    let generated = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        identity.to_str().expect("utf8 identity"),
    ]);
    assert!(
        generated.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let recipient = String::from_utf8(generated.stdout).expect("utf8 recipient");

    let encrypted = run_seclusor(&[
        "secrets",
        "inline",
        "encrypt",
        "--input",
        input.to_str().expect("utf8 input"),
        "--output",
        inline.to_str().expect("utf8 inline"),
        "--recipient",
        recipient.trim(),
    ]);
    assert!(
        encrypted.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&encrypted.stderr)
    );
    inline
}

fn prepare_binary_bundle(dir: &Path) -> PathBuf {
    let input = dir.join("input.json");
    let bundle = dir.join("secrets.age");
    write_plaintext_fixture(&input);

    let identity = dir.join("identity.txt");
    let generated = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        identity.to_str().expect("utf8 identity"),
    ]);
    assert!(
        generated.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let recipient = String::from_utf8(generated.stdout).expect("utf8 recipient");

    let encrypted = run_seclusor(&[
        "secrets",
        "bundle",
        "encrypt",
        "--input",
        input.to_str().expect("utf8 input"),
        "--output",
        bundle.to_str().expect("utf8 bundle"),
        "--recipient",
        recipient.trim(),
    ]);
    assert!(
        encrypted.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&encrypted.stderr)
    );
    bundle
}

fn list_dir_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn assert_refusal(
    output: &std::process::Output,
    path: &Path,
    before: &[u8],
    dir: &Path,
    names_before: &[String],
    expected_source: &str,
) {
    assert!(
        !output.status.success(),
        "expected nonzero exit; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "",
        "stdout must be empty on refusal"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing to write into encrypted secrets file"),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains(&format!("source: {expected_source}")),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("not available in this version"),
        "stderr={stderr}"
    );
    // Error output must not include plaintext or ciphertext content.
    assert!(!stderr.contains("sk-123"));
    assert!(!stderr.contains("sec:age:v1:"));
    assert!(!stderr.contains("age-encryption.org"));

    let after = fs::read(path).expect("re-read target");
    assert_eq!(after, before, "target must remain byte-identical");
    assert_eq!(
        list_dir_names(dir),
        names_before,
        "refusal must not create sibling/temp artifacts"
    );
}

fn refuse_matrix_for_target(path: &Path, dir: &Path, expected_source: &str) {
    let before = fs::read(path).expect("read before");
    let names_before = list_dir_names(dir);
    let path_s = path.to_str().expect("utf8 path");

    let cases: &[(&str, Vec<&str>)] = &[
        (
            "set",
            vec![
                "secrets",
                "set",
                "--file",
                path_s,
                "--project",
                "demo",
                "--key",
                "API_KEY",
                "--value",
                "injected",
            ],
        ),
        (
            "unset",
            vec![
                "secrets",
                "unset",
                "--file",
                path_s,
                "--project",
                "demo",
                "--key",
                "API_KEY",
            ],
        ),
        (
            "import-env",
            vec![
                "secrets",
                "import-env",
                "--file",
                path_s,
                "--project",
                "demo",
                "--prefix",
                "APP_",
            ],
        ),
        (
            "init --force",
            vec![
                "secrets",
                "init",
                "--file",
                path_s,
                "--project",
                "other",
                "--force",
            ],
        ),
    ];

    for (label, args) in cases {
        let output = run_seclusor(args);
        assert_refusal(&output, path, &before, dir, &names_before, expected_source);
        let _ = label;
    }
}

#[test]
fn process_refuses_valid_inline_for_all_write_entry_points() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inline = prepare_inline_encrypted(dir.path());
    refuse_matrix_for_target(&inline, dir.path(), "inline");
}

#[test]
fn process_refuses_binary_bundle_for_all_write_entry_points() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bundle = prepare_binary_bundle(dir.path());
    refuse_matrix_for_target(&bundle, dir.path(), "bundle");
}

#[test]
fn process_refuses_armored_bundle_marker_for_all_write_entry_points() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("armored.age");
    fs::write(
        &path,
        b"-----BEGIN AGE ENCRYPTED FILE-----\nnot-a-real-payload\n",
    )
    .expect("write armored");
    refuse_matrix_for_target(&path, dir.path(), "bundle");
}

#[test]
fn process_plaintext_set_stdout_ok() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secrets.json");
    write_plaintext_fixture(&path);

    let output = run_seclusor(&[
        "secrets",
        "set",
        "--file",
        path.to_str().expect("utf8"),
        "--project",
        "demo",
        "--key",
        "API_KEY",
        "--value",
        "new-value",
    ]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ok\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn process_plaintext_unset_stdout_ok() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secrets.json");
    write_plaintext_fixture(&path);

    let output = run_seclusor(&[
        "secrets",
        "unset",
        "--file",
        path.to_str().expect("utf8"),
        "--project",
        "demo",
        "--key",
        "OTHER",
    ]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ok\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn process_plaintext_init_prints_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("fresh.json");
    let path_s = path.to_str().expect("utf8");

    let output = run_seclusor(&["secrets", "init", "--file", path_s, "--project", "demo"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{path_s}\n")
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

/// Existing plaintext targets remain overwritable with `init --force` after encrypted-target preflight.
#[test]
fn process_plaintext_init_force_overwrites_existing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secrets.json");
    write_plaintext_fixture(&path);
    let path_s = path.to_str().expect("utf8");

    let output = run_seclusor(&[
        "secrets",
        "init",
        "--file",
        path_s,
        "--project",
        "replacement",
        "--force",
    ]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{path_s}\n")
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");

    let reloaded: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read after init"))
            .expect("parse reloaded json");
    let projects = reloaded["projects"].as_array().expect("projects array");
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0]["project_slug"], "replacement");
    let credentials = projects[0]["credentials"]
        .as_object()
        .expect("credentials object");
    assert!(
        credentials.is_empty(),
        "force init must replace document; credentials={credentials:?}"
    );
    assert!(!credentials.contains_key("API_KEY"));
    assert!(!credentials.contains_key("OTHER"));
}

#[test]
fn process_plaintext_import_env_prints_count() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secrets.json");
    write_plaintext_fixture(&path);
    let dotenv = dir.path().join(".env");
    fs::write(&dotenv, "APP_NEW=from-env\n").expect("write dotenv");

    let output = run_seclusor(&[
        "secrets",
        "import-env",
        "--file",
        path.to_str().expect("utf8"),
        "--project",
        "demo",
        "--prefix",
        "APP_",
        "--dotenv-file",
        dotenv.to_str().expect("utf8 dotenv"),
    ]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "1\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}
