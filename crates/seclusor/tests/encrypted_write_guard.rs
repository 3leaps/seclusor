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

const SELF_LOCKOUT_WARNING: &str =
    "warning: none of the loaded identities corresponds to the target recipient set; \
     this write may produce a document that is not decryptable with the supplied identities";

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

/// Refuse without mutating the target: empty stdout, no value/ciphertext leak,
/// byte-identical file, no sibling temps.
fn assert_policy_refusal(
    output: &std::process::Output,
    path: &Path,
    before: &[u8],
    dir: &Path,
    names_before: &[String],
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
    // Error output must not include plaintext or ciphertext content.
    assert!(!stderr.contains("sk-123"));
    assert!(!stderr.contains("sec:age:v1:"));
    assert!(!stderr.contains("age-encryption.org"));
    assert!(!stderr.contains("injected"));

    let after = fs::read(path).expect("re-read target");
    assert_eq!(after, before, "target must remain byte-identical");
    assert_eq!(
        list_dir_names(dir),
        names_before,
        "refusal must not create sibling/temp artifacts"
    );
}

fn assert_legacy_encrypted_unsupported(
    output: &std::process::Output,
    path: &Path,
    before: &[u8],
    dir: &Path,
    names_before: &[String],
    expected_source: &str,
) {
    assert_policy_refusal(output, path, before, dir, names_before);
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
}

/// Encrypting writes without identity/recipients (or unsupported init) must refuse
/// without mutating the target.
fn refuse_incomplete_encrypting_matrix(path: &Path, dir: &Path, expected_source: &str) {
    let before = fs::read(path).expect("read before");
    let names_before = list_dir_names(dir);
    let path_s = path.to_str().expect("utf8 path");

    // set --value without recipients (and without identity for bundle).
    let set_out = run_seclusor(&[
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
    ]);
    assert_policy_refusal(&set_out, path, &before, dir, &names_before);
    let set_err = String::from_utf8_lossy(&set_out.stderr);
    assert!(
        set_err.contains("recipient")
            || set_err.contains("identity")
            || set_err.contains("rekey")
            || set_err.contains("ciphertext")
            || set_err.contains("decrypt"),
        "stderr={set_err}"
    );

    // init --force remains the legacy EncryptedWriteUnsupported surface.
    let init_out = run_seclusor(&[
        "secrets",
        "init",
        "--file",
        path_s,
        "--project",
        "other",
        "--force",
    ]);
    assert_legacy_encrypted_unsupported(
        &init_out,
        path,
        &before,
        dir,
        &names_before,
        expected_source,
    );
}

#[test]
fn process_refuses_encrypting_writes_on_valid_inline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inline = prepare_inline_encrypted(dir.path());
    refuse_incomplete_encrypting_matrix(&inline, dir.path(), "inline");
}

#[test]
fn process_refuses_binary_bundle_for_all_write_entry_points() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bundle = prepare_binary_bundle(dir.path());
    refuse_incomplete_encrypting_matrix(&bundle, dir.path(), "bundle");
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
    refuse_incomplete_encrypting_matrix(&path, dir.path(), "bundle");
}

#[test]
fn process_set_inline_with_recipient_covers_single_field_doc() {
    let dir = tempfile::tempdir().expect("tempdir");
    let input = dir.path().join("one.json");
    fs::write(
        &input,
        r#"{
  "schema_version": "v1.0.0",
  "projects": [{
    "project_slug": "demo",
    "credentials": {
      "API_KEY": { "type": "secret", "value": "sk-old" }
    }
  }]
}"#,
    )
    .expect("write");
    let identity = dir.path().join("identity.txt");
    let gen = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        identity.to_str().unwrap(),
    ]);
    assert!(gen.status.success());
    let recipient = String::from_utf8(gen.stdout).unwrap();
    let recipient = recipient.trim();
    let inline = dir.path().join("inline.json");
    let enc = run_seclusor(&[
        "secrets",
        "inline",
        "encrypt",
        "--input",
        input.to_str().unwrap(),
        "--output",
        inline.to_str().unwrap(),
        "--recipient",
        recipient,
    ]);
    assert!(
        enc.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let set = Command::new(seclusor_bin())
        .args([
            "secrets",
            "set",
            "--file",
            inline.to_str().unwrap(),
            "--project",
            "demo",
            "--key",
            "API_KEY",
            "--value-env",
            "SECLUSOR_TEST_SET_VALUE",
            "--identity-file",
            identity.to_str().unwrap(),
        ])
        .env("SECLUSOR_TEST_SET_VALUE", "fresh-secret")
        .output()
        .expect("run set");
    assert!(
        set.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&set.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&set.stdout), "ok\n");
    assert!(
        !String::from_utf8_lossy(&set.stderr).contains(SELF_LOCKOUT_WARNING),
        "matching loaded identity must not warn"
    );
    let after: serde_json::Value =
        serde_json::from_slice(&fs::read(&inline).unwrap()).expect("parse");
    assert_eq!(after["schema_version"], "v1.1.0");
    assert!(after["recipients"].is_array());
    let ct = after["projects"][0]["credentials"]["API_KEY"]["value"]
        .as_str()
        .unwrap();
    assert!(ct.starts_with("sec:age:v1:"));

    let other_identity = dir.path().join("other-identity.txt");
    let other_generated = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        other_identity.to_str().unwrap(),
    ]);
    assert!(other_generated.status.success());
    let other_recipient = String::from_utf8(other_generated.stdout).unwrap();
    let rotated = Command::new(seclusor_bin())
        .args([
            "secrets",
            "set",
            "--file",
            inline.to_str().unwrap(),
            "--project",
            "demo",
            "--key",
            "API_KEY",
            "--value-env",
            "SECLUSOR_TEST_SET_VALUE",
            "--recipient",
            other_recipient.trim(),
            "--identity-file",
            identity.to_str().unwrap(),
            "--allow-recipient-mismatch",
        ])
        .env("SECLUSOR_TEST_SET_VALUE", "rotated-secret")
        .output()
        .expect("run rotated set");
    assert!(
        rotated.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&rotated.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&rotated.stdout), "ok\n");
    let rotated_stderr = String::from_utf8_lossy(&rotated.stderr);
    assert!(rotated_stderr.contains("recipient set change accepted"));
    assert!(rotated_stderr.contains(SELF_LOCKOUT_WARNING));
    assert!(!rotated_stderr.contains("fresh-secret"));
    assert!(!rotated_stderr.contains("rotated-secret"));
}

#[test]
fn process_import_env_inline_encrypted_happy_and_mismatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let input = dir.path().join("one.json");
    fs::write(
        &input,
        r#"{
  "schema_version": "v1.0.0",
  "env_prefix": "APP_",
  "projects": [{
    "project_slug": "demo",
    "credentials": {
      "TOKEN": { "type": "secret", "value": "old" }
    }
  }]
}"#,
    )
    .expect("write");
    let identity = dir.path().join("identity.txt");
    let gen = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        identity.to_str().unwrap(),
    ]);
    assert!(gen.status.success());
    let recipient = String::from_utf8(gen.stdout).unwrap();
    let recipient = recipient.trim();
    let inline = dir.path().join("inline.json");
    let enc = run_seclusor(&[
        "secrets",
        "inline",
        "encrypt",
        "--input",
        input.to_str().unwrap(),
        "--output",
        inline.to_str().unwrap(),
        "--recipient",
        recipient,
    ]);
    assert!(
        enc.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let dotenv = dir.path().join("import.env");
    fs::write(&dotenv, "APP_TOKEN=from-process\n").expect("dotenv");
    let import = run_seclusor(&[
        "secrets",
        "import-env",
        "--file",
        inline.to_str().unwrap(),
        "--project",
        "demo",
        "--prefix",
        "APP_",
        "--dotenv-file",
        dotenv.to_str().unwrap(),
        "--identity-file",
        identity.to_str().unwrap(),
    ]);
    assert!(
        import.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&import.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&import.stdout).trim(), "1");
    assert!(
        !String::from_utf8_lossy(&import.stderr).contains(SELF_LOCKOUT_WARNING),
        "matching loaded identity must not warn"
    );

    // Mismatch recipients refuse without mutating.
    let before = fs::read(&inline).expect("before");
    let other_id = dir.path().join("other.txt");
    let gen2 = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        other_id.to_str().unwrap(),
    ]);
    assert!(gen2.status.success());
    let other_r = String::from_utf8(gen2.stdout).unwrap();
    let other_r = other_r.trim();
    let bad = run_seclusor(&[
        "secrets",
        "import-env",
        "--file",
        inline.to_str().unwrap(),
        "--project",
        "demo",
        "--prefix",
        "APP_",
        "--dotenv-file",
        dotenv.to_str().unwrap(),
        "--recipient",
        other_r,
        "--identity-file",
        identity.to_str().unwrap(),
    ]);
    assert!(!bad.status.success());
    assert_eq!(fs::read(&inline).expect("after"), before);
    assert!(String::from_utf8_lossy(&bad.stdout).is_empty());

    let allowed = run_seclusor(&[
        "secrets",
        "import-env",
        "--file",
        inline.to_str().unwrap(),
        "--project",
        "demo",
        "--prefix",
        "APP_",
        "--dotenv-file",
        dotenv.to_str().unwrap(),
        "--recipient",
        other_r,
        "--identity-file",
        identity.to_str().unwrap(),
        "--allow-recipient-mismatch",
    ]);
    assert!(
        allowed.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&allowed.stdout), "1\n");
    let allowed_stderr = String::from_utf8_lossy(&allowed.stderr);
    assert!(allowed_stderr.contains("recipient set change accepted"));
    assert!(allowed_stderr.contains(&format!("  +{other_r}")));
    assert!(allowed_stderr.contains(&format!("  -{recipient}")));
    assert!(allowed_stderr.contains(SELF_LOCKOUT_WARNING));
    assert!(!allowed_stderr.contains("AGE-SECRET"));
    assert!(!allowed_stderr.contains("from-process"));
    let rotated: seclusor_core::SecretsFile =
        serde_json::from_slice(&fs::read(&inline).expect("read rotated inline"))
            .expect("parse rotated inline");
    assert_eq!(
        rotated.recipients.as_deref(),
        Some(std::slice::from_ref(&other_r.to_string()))
    );

    let bundle = dir.path().join("bundle.age");
    let bundle_encrypt = run_seclusor(&[
        "secrets",
        "bundle",
        "encrypt",
        "--input",
        input.to_str().unwrap(),
        "--output",
        bundle.to_str().unwrap(),
        "--recipient",
        recipient,
    ]);
    assert!(bundle_encrypt.status.success());
    let bundle_before = fs::read(&bundle).expect("bundle before");
    let bundle_names_before = list_dir_names(dir.path());
    let bundle_refused = run_seclusor(&[
        "secrets",
        "import-env",
        "--file",
        bundle.to_str().unwrap(),
        "--project",
        "demo",
        "--prefix",
        "APP_",
        "--dotenv-file",
        dotenv.to_str().unwrap(),
        "--recipient",
        other_r,
        "--identity-file",
        identity.to_str().unwrap(),
    ]);
    assert_policy_refusal(
        &bundle_refused,
        &bundle,
        &bundle_before,
        dir.path(),
        &bundle_names_before,
    );

    let bundle_allowed = run_seclusor(&[
        "secrets",
        "import-env",
        "--file",
        bundle.to_str().unwrap(),
        "--project",
        "demo",
        "--prefix",
        "APP_",
        "--dotenv-file",
        dotenv.to_str().unwrap(),
        "--recipient",
        other_r,
        "--identity-file",
        identity.to_str().unwrap(),
        "--allow-recipient-mismatch",
    ]);
    assert!(
        bundle_allowed.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&bundle_allowed.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&bundle_allowed.stdout), "1\n");
    let bundle_stderr = String::from_utf8_lossy(&bundle_allowed.stderr);
    assert!(bundle_stderr.contains("recipient set change accepted"));
    assert!(bundle_stderr.contains(&format!("  +{other_r}")));
    assert!(bundle_stderr.contains(&format!("  -{recipient}")));
    assert!(bundle_stderr.contains(SELF_LOCKOUT_WARNING));
    assert!(!bundle_stderr.contains("AGE-SECRET"));
    assert!(!bundle_stderr.contains("from-process"));

    let decrypted = dir.path().join("bundle-decrypted.json");
    let bundle_decrypt = run_seclusor(&[
        "secrets",
        "bundle",
        "decrypt",
        "--input",
        bundle.to_str().unwrap(),
        "--output",
        decrypted.to_str().unwrap(),
        "--identity-file",
        other_id.to_str().unwrap(),
    ]);
    assert!(
        bundle_decrypt.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&bundle_decrypt.stderr)
    );
}

#[test]
fn process_import_env_override_refuses_partial_inline_coverage() {
    let dir = tempfile::tempdir().expect("tempdir");
    let plaintext = dir.path().join("multi.json");
    let inline = dir.path().join("multi-inline.json");
    let identity = dir.path().join("identity.txt");
    let other_identity = dir.path().join("other-identity.txt");
    let dotenv = dir.path().join("import.env");
    write_plaintext_fixture(&plaintext);
    fs::write(&dotenv, "APP_API_KEY=rotated\n").expect("write dotenv");

    let generated = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        identity.to_str().expect("utf8 identity"),
    ]);
    assert!(generated.status.success());
    let recipient = String::from_utf8(generated.stdout).expect("utf8 recipient");

    let other_generated = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        other_identity.to_str().expect("utf8 other identity"),
    ]);
    assert!(other_generated.status.success());
    let other_recipient = String::from_utf8(other_generated.stdout).expect("utf8 other recipient");

    let encrypted = run_seclusor(&[
        "secrets",
        "inline",
        "encrypt",
        "--input",
        plaintext.to_str().expect("utf8 plaintext"),
        "--output",
        inline.to_str().expect("utf8 inline"),
        "--recipient",
        recipient.trim(),
    ]);
    assert!(encrypted.status.success());

    let before = fs::read(&inline).expect("before");
    let names_before = list_dir_names(dir.path());
    let refused = run_seclusor(&[
        "secrets",
        "import-env",
        "--file",
        inline.to_str().expect("utf8 inline"),
        "--project",
        "demo",
        "--prefix",
        "APP_",
        "--dotenv-file",
        dotenv.to_str().expect("utf8 dotenv"),
        "--recipient",
        other_recipient.trim(),
        "--identity-file",
        identity.to_str().expect("utf8 identity"),
        "--allow-recipient-mismatch",
    ]);
    assert_policy_refusal(&refused, &inline, &before, dir.path(), &names_before);
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("untouched inline ciphertext"));
    assert!(stderr.contains(&format!("  +{}", other_recipient.trim())));
    assert!(stderr.contains(&format!("  -{}", recipient.trim())));
}

#[test]
fn process_recipient_mismatch_override_rejects_read_before_file_io() {
    let output = run_seclusor(&[
        "secrets",
        "get",
        "--file",
        "definitely-missing-009-a.json",
        "--key",
        "ONLY",
        "--allow-recipient-mismatch",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("only valid for"));
    assert!(!stderr.contains("No such file"));
}

#[test]
fn process_inline_unset_structural_only_stdout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inline = prepare_inline_encrypted(dir.path());
    let path_s = inline.to_str().expect("utf8");
    let before = fs::read(&inline).expect("before");
    let before_json: serde_json::Value = serde_json::from_slice(&before).expect("parse before");
    let other_ct = before_json["projects"][0]["credentials"]["OTHER"]["value"]
        .as_str()
        .expect("OTHER ciphertext")
        .to_string();

    let output = run_seclusor(&[
        "secrets",
        "unset",
        "--file",
        path_s,
        "--project",
        "demo",
        "--key",
        "API_KEY",
    ]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "structural-only ok\n"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("structural-only"));
    assert!(stderr.contains("source: inline"));
    assert!(!stderr.contains("sk-123"));
    assert!(!stderr.contains("sec:age:v1:"));

    let after = fs::read(&inline).expect("after");
    assert_ne!(after, before);
    let after_json: serde_json::Value = serde_json::from_slice(&after).expect("parse after");
    assert!(after_json["projects"][0]["credentials"]
        .get("API_KEY")
        .is_none());
    assert_eq!(
        after_json["projects"][0]["credentials"]["OTHER"]["value"]
            .as_str()
            .expect("OTHER after"),
        other_ct,
        "untouched ciphertext must be byte-identical"
    );
}

#[test]
fn process_inline_description_only_structural_only_stdout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inline = prepare_inline_encrypted(dir.path());
    let path_s = inline.to_str().expect("utf8");
    let before = fs::read(&inline).expect("before");
    let before_json: serde_json::Value = serde_json::from_slice(&before).expect("parse before");
    let api_ct = before_json["projects"][0]["credentials"]["API_KEY"]["value"]
        .as_str()
        .expect("API_KEY ciphertext")
        .to_string();

    let output = run_seclusor(&[
        "secrets",
        "set",
        "--file",
        path_s,
        "--project",
        "demo",
        "--key",
        "API_KEY",
        "--description",
        "rotated note",
    ]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "structural-only ok\n"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("set: structural-only"));
    assert!(stderr.contains("source: inline"));

    let after_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&inline).expect("after")).expect("parse after");
    assert_eq!(
        after_json["projects"][0]["credentials"]["API_KEY"]["description"]
            .as_str()
            .expect("description"),
        "rotated note"
    );
    assert_eq!(
        after_json["projects"][0]["credentials"]["API_KEY"]["value"]
            .as_str()
            .expect("value"),
        api_ct
    );
    let _ = before;
}

#[test]
fn process_plaintext_description_only_stdout_ok() {
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
        "--description",
        "plain note",
    ]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ok\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

const MIXED_SENTINEL: &str = "SECLUSOR_PLAINTEXT_SENTINEL_7f3a";

fn prepare_mixed_inline(dir: &Path) -> PathBuf {
    let input = dir.join("mixed-input.json");
    let inline = dir.join("mixed.json");
    let fixture = format!(
        r#"{{
  "schema_version": "v1.0.0",
  "projects": [
    {{
      "project_slug": "demo",
      "credentials": {{
        "ENC_KEY": {{ "type": "secret", "value": "will-encrypt" }},
        "PLAIN_KEY": {{ "type": "secret", "value": "{MIXED_SENTINEL}" }},
        "REF_KEY": {{ "type": "ref", "ref": "vault://keep" }}
      }}
    }}
  ]
}}"#
    );
    fs::write(&input, fixture).expect("write mixed input");

    let identity = dir.join("identity.txt");
    let generated = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        identity.to_str().expect("utf8"),
    ]);
    assert!(generated.status.success());
    let recipient = String::from_utf8(generated.stdout).expect("utf8 recipient");

    // Encrypt only ENC_KEY by writing a fully-encrypted file then re-injecting plaintext.
    let fully = dir.join("fully.json");
    let encrypted = run_seclusor(&[
        "secrets",
        "inline",
        "encrypt",
        "--input",
        input.to_str().expect("utf8"),
        "--output",
        fully.to_str().expect("utf8"),
        "--recipient",
        recipient.trim(),
    ]);
    assert!(
        encrypted.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&encrypted.stderr)
    );

    let mut doc: serde_json::Value =
        serde_json::from_slice(&fs::read(&fully).expect("read fully")).expect("parse");
    doc["projects"][0]["credentials"]["PLAIN_KEY"]["value"] =
        serde_json::Value::String(MIXED_SENTINEL.to_string());
    doc["projects"][0]["credentials"]["REF_KEY"] =
        serde_json::json!({"type": "ref", "ref": "vault://keep"});
    fs::write(&inline, serde_json::to_vec_pretty(&doc).expect("serialize")).expect("write mixed");
    inline
}

#[test]
fn process_mixed_inline_unset_refuses_plaintext_residual() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = prepare_mixed_inline(dir.path());
    let before = fs::read(&path).expect("before");
    let names_before = list_dir_names(dir.path());

    let output = run_seclusor(&[
        "secrets",
        "unset",
        "--file",
        path.to_str().expect("utf8"),
        "--project",
        "demo",
        "--key",
        "ENC_KEY",
    ]);
    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("plaintext") || stderr.contains("PLAIN_KEY"),
        "stderr={stderr}"
    );
    assert!(!stderr.contains(MIXED_SENTINEL));
    assert!(!stderr.contains("sec:age:v1:"));
    assert_eq!(fs::read(&path).expect("after"), before);
    assert_eq!(list_dir_names(dir.path()), names_before);
}

#[test]
fn process_mixed_inline_description_only_refuses_plaintext_residual() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = prepare_mixed_inline(dir.path());
    let before = fs::read(&path).expect("before");
    let names_before = list_dir_names(dir.path());

    let output = run_seclusor(&[
        "secrets",
        "set",
        "--file",
        path.to_str().expect("utf8"),
        "--project",
        "demo",
        "--key",
        "ENC_KEY",
        "--description",
        "note",
    ]);
    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("plaintext") || stderr.contains("PLAIN_KEY"),
        "stderr={stderr}"
    );
    assert!(!stderr.contains(MIXED_SENTINEL));
    assert_eq!(fs::read(&path).expect("after"), before);
    assert_eq!(list_dir_names(dir.path()), names_before);
}

#[test]
fn process_description_only_create_project_refuses_empty_stdout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secrets.json");
    write_plaintext_fixture(&path);
    let before = fs::read(&path).expect("before");

    let output = run_seclusor(&[
        "secrets",
        "set",
        "--file",
        path.to_str().expect("utf8"),
        "--project",
        "demo",
        "--key",
        "API_KEY",
        "--description",
        "x",
        "--create-project",
    ]);
    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("description-only"));
    assert!(!stderr.contains("sk-123"));
    assert_eq!(fs::read(&path).expect("after"), before);
}

#[test]
fn process_description_only_missing_key_empty_stdout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secrets.json");
    write_plaintext_fixture(&path);
    let before = fs::read(&path).expect("before");

    let output = run_seclusor(&[
        "secrets",
        "set",
        "--file",
        path.to_str().expect("utf8"),
        "--project",
        "demo",
        "--key",
        "NO_SUCH_KEY",
        "--description",
        "x",
    ]);
    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("sk-123"));
    assert_eq!(fs::read(&path).expect("after"), before);
}

/// Encrypt an arbitrary plaintext JSON fixture to an inline file in `dir`.
fn prepare_inline_from_json(dir: &Path, fixture_json: &str, out_name: &str) -> PathBuf {
    let input = dir.join(format!("{out_name}.input.json"));
    let inline = dir.join(out_name);
    fs::write(&input, fixture_json).expect("write input");

    let identity = dir.join(format!("{out_name}.identity.txt"));
    let generated = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        identity.to_str().expect("utf8"),
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
        input.to_str().expect("utf8"),
        "--output",
        inline.to_str().expect("utf8"),
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

fn inline_ciphertext_samples(path: &Path) -> Vec<String> {
    let doc: serde_json::Value =
        serde_json::from_slice(&fs::read(path).expect("read")).expect("parse");
    let mut samples = Vec::new();
    if let Some(projects) = doc.get("projects").and_then(|p| p.as_array()) {
        for project in projects {
            if let Some(creds) = project.get("credentials").and_then(|c| c.as_object()) {
                for cred in creds.values() {
                    if let Some(value) = cred.get("value").and_then(|v| v.as_str()) {
                        if value.starts_with("sec:age:v1:") {
                            samples.push(value.to_string());
                        }
                    }
                }
            }
        }
    }
    samples
}

fn assert_inline_structural_failure(
    label: &str,
    output: &std::process::Output,
    path: &Path,
    before: &[u8],
    dir: &Path,
    names_before: &[String],
    ciphertext_samples: &[String],
) {
    assert!(
        !output.status.success(),
        "{label}: expected nonzero exit; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "",
        "{label}: stdout must be empty"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("sk-123") && !stderr.contains("sk-other"),
        "{label}: stderr leaked plaintext: {stderr}"
    );
    assert!(
        !stderr.contains("sec:age:v1:"),
        "{label}: stderr leaked ciphertext prefix: {stderr}"
    );
    for sample in ciphertext_samples {
        assert!(
            !stderr.contains(sample.as_str()),
            "{label}: stderr leaked ciphertext body"
        );
    }

    assert_eq!(
        fs::read(path).expect("re-read"),
        before,
        "{label}: target must remain byte-identical"
    );
    assert_eq!(
        list_dir_names(dir),
        names_before,
        "{label}: must not create sibling/temp artifacts"
    );
}

/// Valid-inline process matrix for structural failure paths (empty stdout,
/// sanitized stderr, byte-identical target, no sibling temps).
#[test]
fn process_inline_structural_failure_matrix() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Single-project inline for missing-key / missing-project / create-project.
    let single = prepare_inline_encrypted(dir.path());
    let single_s = single.to_str().expect("utf8");
    let single_before = fs::read(&single).expect("before single");
    let single_names = list_dir_names(dir.path());
    let single_cts = inline_ciphertext_samples(&single);

    let single_cases: &[(&str, Vec<&str>)] = &[
        (
            "description-only missing key",
            vec![
                "secrets",
                "set",
                "--file",
                single_s,
                "--project",
                "demo",
                "--key",
                "NO_SUCH_KEY",
                "--description",
                "x",
            ],
        ),
        (
            "description-only missing project",
            vec![
                "secrets",
                "set",
                "--file",
                single_s,
                "--project",
                "nope",
                "--key",
                "API_KEY",
                "--description",
                "x",
            ],
        ),
        (
            "description-only --create-project",
            vec![
                "secrets",
                "set",
                "--file",
                single_s,
                "--project",
                "demo",
                "--key",
                "API_KEY",
                "--description",
                "x",
                "--create-project",
            ],
        ),
        (
            "unset missing key",
            vec![
                "secrets",
                "unset",
                "--file",
                single_s,
                "--project",
                "demo",
                "--key",
                "NO_SUCH_KEY",
            ],
        ),
        (
            "unset missing project",
            vec![
                "secrets",
                "unset",
                "--file",
                single_s,
                "--project",
                "nope",
                "--key",
                "API_KEY",
            ],
        ),
    ];

    for (label, args) in single_cases {
        let output = run_seclusor(args);
        assert_inline_structural_failure(
            label,
            &output,
            &single,
            &single_before,
            dir.path(),
            &single_names,
            &single_cts,
        );
    }

    // Two-project inline for omitted-project ambiguity (description-only + unset).
    let multi_fixture = r#"{
  "schema_version": "v1.0.0",
  "projects": [
    {
      "project_slug": "demo",
      "credentials": {
        "API_KEY": { "type": "secret", "value": "alpha-secret" }
      }
    },
    {
      "project_slug": "other",
      "credentials": {
        "API_KEY": { "type": "secret", "value": "beta-secret" }
      }
    }
  ]
}"#;
    let multi = prepare_inline_from_json(dir.path(), multi_fixture, "multi-inline.json");
    let multi_s = multi.to_str().expect("utf8 multi");
    let multi_before = fs::read(&multi).expect("before multi");
    let multi_names = list_dir_names(dir.path());
    let multi_cts = inline_ciphertext_samples(&multi);

    let multi_cases: &[(&str, Vec<&str>)] = &[
        (
            "description-only omitted project ambiguous",
            vec![
                "secrets",
                "set",
                "--file",
                multi_s,
                "--key",
                "API_KEY",
                "--description",
                "x",
            ],
        ),
        (
            "unset omitted project ambiguous",
            vec!["secrets", "unset", "--file", multi_s, "--key", "API_KEY"],
        ),
    ];

    for (label, args) in multi_cases {
        let output = run_seclusor(args);
        assert_inline_structural_failure(
            label,
            &output,
            &multi,
            &multi_before,
            dir.path(),
            &multi_names,
            &multi_cts,
        );
    }
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Legacy --value emits a stderr warning; stdout stays pure.
    assert!(
        stderr.is_empty() || stderr.contains("prefer --value-stdin"),
        "stderr={stderr}"
    );
}

#[test]
fn process_piped_value_stdin_preserves_contract_and_rejects_echo_flag() {
    use std::io::Write;
    use std::process::Stdio;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secrets.json");
    write_plaintext_fixture(&path);

    let entered_value = b"piped-value-fixture";
    let mut child = Command::new(seclusor_bin())
        .args([
            "secrets",
            "set",
            "--file",
            path.to_str().expect("utf8"),
            "--project",
            "demo",
            "--key",
            "API_KEY",
            "--value-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn piped set");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(&[entered_value.as_slice(), b"\r\n"].concat())
        .expect("write piped value");
    let output = child.wait_with_output().expect("wait piped set");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"ok\n");
    assert!(output.stderr.is_empty());

    let revealed = run_seclusor(&[
        "secrets",
        "get",
        "--file",
        path.to_str().expect("utf8"),
        "--project",
        "demo",
        "--key",
        "API_KEY",
        "--reveal",
    ]);
    assert!(revealed.status.success());
    assert_eq!(revealed.stdout, [entered_value.as_slice(), b"\n"].concat());

    let before = fs::read(&path).expect("before rejected echo");
    let rejected = Command::new(seclusor_bin())
        .args([
            "secrets",
            "set",
            "--file",
            path.to_str().expect("utf8"),
            "--project",
            "demo",
            "--key",
            "API_KEY",
            "--value-stdin",
            "--echo-value",
        ])
        .stdin(Stdio::piped())
        .output()
        .expect("run rejected echo");
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        stderr.contains("--echo-value requires --value-stdin with terminal stdin"),
        "stderr={stderr}"
    );
    assert!(
        !stderr.contains(std::str::from_utf8(entered_value).expect("fixture utf8")),
        "stderr must not contain prior value"
    );
    assert_eq!(fs::read(&path).expect("after rejected echo"), before);
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

#[test]
fn process_rekey_delta_guard_override_and_stale_recipient_refusal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let plaintext = dir.path().join("plain.json");
    let bundle = dir.path().join("secrets.age");
    let old_identity = dir.path().join("old-identity.txt");
    let new_identity = dir.path().join("new-identity.txt");
    write_plaintext_fixture(&plaintext);

    let old_generated = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        old_identity.to_str().expect("utf8 old identity"),
    ]);
    assert!(old_generated.status.success());
    let old_recipient = String::from_utf8(old_generated.stdout).expect("utf8 old recipient");
    let old_recipient = old_recipient.trim();

    let new_generated = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        new_identity.to_str().expect("utf8 new identity"),
    ]);
    assert!(new_generated.status.success());
    let new_recipient = String::from_utf8(new_generated.stdout).expect("utf8 new recipient");
    let new_recipient = new_recipient.trim();

    // Construct a legacy v1.0 bundle directly. Current `bundle encrypt`
    // establishes metadata, so it cannot produce this migration fixture.
    let legacy: seclusor_core::SecretsFile =
        serde_json::from_slice(&fs::read(&plaintext).expect("read plaintext"))
            .expect("parse plaintext");
    let recipient = old_recipient
        .parse::<seclusor_crypto::Recipient>()
        .expect("parse old recipient");
    let ciphertext =
        seclusor_codec::encrypt_bundle(&legacy, &[recipient]).expect("encrypt legacy bundle");
    fs::write(&bundle, ciphertext).expect("write legacy bundle");

    // Establish v1.1.0 metadata on the legacy bundle. This is the explicit
    // degradation case: no header-derived recipient inference is attempted.
    let established = run_seclusor(&[
        "secrets",
        "rekey",
        "--file",
        bundle.to_str().expect("utf8 bundle"),
        "--identity-file",
        old_identity.to_str().expect("utf8 old identity"),
        "--recipient",
        old_recipient,
    ]);
    assert!(
        established.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&established.stderr)
    );
    assert!(String::from_utf8_lossy(&established.stderr).contains("comparison was indeterminate"));

    let before_refusal = fs::read(&bundle).expect("bundle before refusal");
    let names_before = list_dir_names(dir.path());
    let refused = run_seclusor(&[
        "secrets",
        "rekey",
        "--file",
        bundle.to_str().expect("utf8 bundle"),
        "--identity-file",
        old_identity.to_str().expect("utf8 old identity"),
        "--recipient",
        new_recipient,
    ]);
    assert_policy_refusal(
        &refused,
        &bundle,
        &before_refusal,
        dir.path(),
        &names_before,
    );
    let refused_stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(refused_stderr.contains("--allow-recipient-mismatch"));
    assert!(refused_stderr.contains(&format!("  +{new_recipient}")));
    assert!(refused_stderr.contains(&format!("  -{old_recipient}")));

    let allowed = run_seclusor(&[
        "secrets",
        "rekey",
        "--file",
        bundle.to_str().expect("utf8 bundle"),
        "--identity-file",
        old_identity.to_str().expect("utf8 old identity"),
        "--recipient",
        new_recipient,
        "--allow-recipient-mismatch",
    ]);
    assert!(
        allowed.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&allowed.stdout),
        format!("{}\n", bundle.display())
    );
    let allowed_stderr = String::from_utf8_lossy(&allowed.stderr);
    assert!(allowed_stderr.contains("recipient set change accepted"));
    assert!(allowed_stderr.contains(&format!("  +{new_recipient}")));
    assert!(allowed_stderr.contains(&format!("  -{old_recipient}")));
    assert!(allowed_stderr.contains("none of the loaded identities"));

    let same_set = run_seclusor(&[
        "secrets",
        "rekey",
        "--file",
        bundle.to_str().expect("utf8 bundle"),
        "--identity-file",
        new_identity.to_str().expect("utf8 new identity"),
        "--recipient",
        new_recipient,
    ]);
    assert!(
        same_set.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&same_set.stderr)
    );
    let same_set_stderr = String::from_utf8_lossy(&same_set.stderr);
    assert!(!same_set_stderr.contains("recipient set change accepted"));
    assert!(!same_set_stderr.contains("comparison was indeterminate"));
    assert!(!same_set_stderr.contains("none of the loaded identities"));

    // Incident regression: a stale durable recipient file must not silently
    // restore the retired recipient on the next write.
    let stale_recipients = dir.path().join("recipients.txt");
    fs::write(&stale_recipients, format!("{old_recipient}\n")).expect("write stale recipients");
    let before_stale_set = fs::read(&bundle).expect("bundle before stale set");
    let names_before_stale_set = list_dir_names(dir.path());
    let stale_set = Command::new(seclusor_bin())
        .args([
            "secrets",
            "set",
            "--file",
            bundle.to_str().expect("utf8 bundle"),
            "--project",
            "demo",
            "--key",
            "API_KEY",
            "--value-env",
            "SECLUSOR_TEST_ROTATED_VALUE",
            "--identity-file",
            new_identity.to_str().expect("utf8 new identity"),
            "--recipient-file",
            stale_recipients.to_str().expect("utf8 recipients"),
        ])
        .env("SECLUSOR_TEST_ROTATED_VALUE", "must-not-be-written")
        .output()
        .expect("run stale set");
    assert_policy_refusal(
        &stale_set,
        &bundle,
        &before_stale_set,
        dir.path(),
        &names_before_stale_set,
    );
    let stale_stderr = String::from_utf8_lossy(&stale_set.stderr);
    assert!(stale_stderr.contains(&format!("  +{old_recipient}")));
    assert!(stale_stderr.contains(&format!("  -{new_recipient}")));

    let decrypted = dir.path().join("decrypted.json");
    let new_decrypt = run_seclusor(&[
        "secrets",
        "bundle",
        "decrypt",
        "--input",
        bundle.to_str().expect("utf8 bundle"),
        "--output",
        decrypted.to_str().expect("utf8 decrypted"),
        "--identity-file",
        new_identity.to_str().expect("utf8 new identity"),
    ]);
    assert!(new_decrypt.status.success());

    let old_decrypt = run_seclusor(&[
        "secrets",
        "bundle",
        "decrypt",
        "--input",
        bundle.to_str().expect("utf8 bundle"),
        "--output",
        dir.path()
            .join("old-decrypt.json")
            .to_str()
            .expect("utf8 output"),
        "--identity-file",
        old_identity.to_str().expect("utf8 old identity"),
    ]);
    assert!(!old_decrypt.status.success());
}

#[test]
fn process_set_inline_override_allows_full_coverage_one_to_two_rotation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let plaintext = dir.path().join("single.json");
    let inline = dir.path().join("single-inline.json");
    let old_identity = dir.path().join("old-identity.txt");
    let new_identity = dir.path().join("new-identity.txt");
    fs::write(
        &plaintext,
        r#"{
  "schema_version": "v1.0.0",
  "projects": [{
    "project_slug": "demo",
    "credentials": {
      "ONLY": { "type": "secret", "value": "before" }
    }
  }]
}"#,
    )
    .expect("write single fixture");

    let old_generated = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        old_identity.to_str().expect("utf8 old identity"),
    ]);
    assert!(old_generated.status.success());
    let old_recipient = String::from_utf8(old_generated.stdout).expect("utf8 old recipient");
    let old_recipient = old_recipient.trim();

    let new_generated = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        new_identity.to_str().expect("utf8 new identity"),
    ]);
    assert!(new_generated.status.success());
    let new_recipient = String::from_utf8(new_generated.stdout).expect("utf8 new recipient");
    let new_recipient = new_recipient.trim();

    let encrypted = run_seclusor(&[
        "secrets",
        "inline",
        "encrypt",
        "--input",
        plaintext.to_str().expect("utf8 plaintext"),
        "--output",
        inline.to_str().expect("utf8 inline"),
        "--recipient",
        old_recipient,
    ]);
    assert!(encrypted.status.success());

    let rotated = Command::new(seclusor_bin())
        .args([
            "secrets",
            "set",
            "--file",
            inline.to_str().expect("utf8 inline"),
            "--project",
            "demo",
            "--key",
            "ONLY",
            "--value-env",
            "SECLUSOR_TEST_ROTATED_VALUE",
            "--identity-file",
            old_identity.to_str().expect("utf8 old identity"),
            "--recipient",
            old_recipient,
            "--recipient",
            new_recipient,
            "--allow-recipient-mismatch",
        ])
        .env("SECLUSOR_TEST_ROTATED_VALUE", "after")
        .output()
        .expect("run full-coverage inline rotation");
    assert!(
        rotated.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&rotated.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&rotated.stdout), "ok\n");
    let stderr = String::from_utf8_lossy(&rotated.stderr);
    assert!(stderr.contains("recipient set change accepted"));
    assert!(stderr.contains(&format!("  +{new_recipient}")));
    assert!(!stderr.contains("AGE-SECRET"));

    let document: seclusor_core::SecretsFile =
        serde_json::from_slice(&fs::read(&inline).expect("read inline")).expect("parse inline");
    assert_eq!(document.recipients.as_ref().map(Vec::len), Some(2));
    let value = document.projects[0].credentials["ONLY"]
        .value
        .as_deref()
        .expect("ciphertext");
    assert_eq!(
        seclusor_crypto::count_inline_x25519_recipient_stanzas(value).expect("stanzas"),
        2
    );

    for (identity, output_name) in [
        (&old_identity, "old-decrypted.json"),
        (&new_identity, "new-decrypted.json"),
    ] {
        let output = dir.path().join(output_name);
        let decrypted = run_seclusor(&[
            "secrets",
            "inline",
            "decrypt",
            "--input",
            inline.to_str().expect("utf8 inline"),
            "--output",
            output.to_str().expect("utf8 output"),
            "--identity-file",
            identity.to_str().expect("utf8 identity"),
        ]);
        assert!(
            decrypted.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&decrypted.stderr)
        );
    }
}
