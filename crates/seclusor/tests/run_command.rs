use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn seclusor_bin() -> &'static str {
    env!("CARGO_BIN_EXE_seclusor")
}

fn compile_fixture(dir: &Path, name: &str) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/run-fixture.rs");
    let output = dir.join(fixture_name(name));

    let status = Command::new("rustc")
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .status()
        .expect("compile test fixture");
    assert!(status.success(), "fixture compilation failed");
    output
}

#[cfg(windows)]
fn fixture_name(name: &str) -> String {
    format!("{name}.exe")
}

#[cfg(not(windows))]
fn fixture_name(name: &str) -> String {
    name.to_string()
}

fn path_with(dir: &Path) -> String {
    let paths = std::iter::once(dir.to_path_buf()).chain(
        std::env::var_os("PATH")
            .into_iter()
            .flat_map(|raw| std::env::split_paths(&raw).collect::<Vec<_>>()),
    );
    std::env::join_paths(paths)
        .expect("join PATH")
        .into_string()
        .expect("utf8 PATH")
}

fn run_seclusor(args: &[String]) -> Output {
    Command::new(seclusor_bin())
        .args(args)
        .output()
        .expect("run seclusor")
}

fn run_seclusor_in(dir: &Path, args: &[String]) -> Output {
    Command::new(seclusor_bin())
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run seclusor")
}

fn write_secrets_fixture(path: &Path) {
    let long_value = "x".repeat(65_536);
    let fixture = serde_json::json!({
        "schema_version": "v1.0.0",
        "projects": [{
            "project_slug": "demo",
            "credentials": {
                "APP_SIMPLE": { "type": "secret", "value": "sk-123abc" },
                "APP_SPACES": { "type": "secret", "value": "hello world" },
                "APP_SINGLE_QUOTE": { "type": "secret", "value": "it's a secret" },
                "APP_DOUBLE_QUOTE": { "type": "secret", "value": "say \"hello\"" },
                "APP_EQUALS": { "type": "secret", "value": "key=value=extra" },
                "APP_NEWLINES": { "type": "secret", "value": "line1\nline2" },
                "APP_METACHARS": { "type": "secret", "value": "$(whoami); rm -rf /" },
                "APP_BACKTICKS": { "type": "secret", "value": "`date`" },
                "APP_DOLLARS": { "type": "secret", "value": "$HOME" },
                "APP_UNICODE": { "type": "secret", "value": "secret_unicode" },
                "APP_LONG": { "type": "secret", "value": long_value },
                "DB_HOST": { "type": "secret", "value": "db.internal" },
                "APP_DEBUG": { "type": "secret", "value": "true" }
            }
        }]
    });
    fs::write(
        path,
        serde_json::to_vec_pretty(&fixture).expect("serialize fixture"),
    )
    .expect("write fixture");
}

fn write_unicode_secrets_fixture(path: &Path) {
    let fixture = serde_json::json!({
        "schema_version": "v1.0.0",
        "projects": [{
            "project_slug": "demo",
            "credentials": {
                "APP_UNICODE": { "type": "secret", "value": "sécret_密钥_🔑" }
            }
        }]
    });
    fs::write(
        path,
        serde_json::to_vec_pretty(&fixture).expect("serialize fixture"),
    )
    .expect("write unicode fixture");
}

fn make_base_args(secrets: &Path) -> Vec<String> {
    vec![
        "secrets".to_string(),
        "run".to_string(),
        "--file".to_string(),
        secrets.display().to_string(),
        "--project".to_string(),
        "demo".to_string(),
    ]
}

fn run_dump_with_capture(
    secrets: &Path,
    extra_cli_args: &[&str],
    command: &[String],
    capture_keys: &[&str],
) -> Output {
    let mut args = make_base_args(secrets);
    args.extend(extra_cli_args.iter().map(|s| s.to_string()));
    args.extend(command.iter().cloned());

    Command::new(seclusor_bin())
        .env("SECLUSOR_TEST_CAPTURE_KEYS", capture_keys.join(","))
        .args(&args)
        .output()
        .expect("run seclusor")
}

fn parsed_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout json")
}

fn temp_secrets_file() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secrets.json");
    write_secrets_fixture(&path);
    (dir, path)
}

#[test]
fn run_accepts_separator_and_preserves_child_args() {
    let (_dir, secrets) = temp_secrets_file();
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-fixture");
    let mut args = make_base_args(&secrets);
    args.push("--".to_string());
    args.extend({
        let mut cmd = vec![fixture.display().to_string(), "dump".to_string()];
        cmd.extend(
            ["hello", "-la", "--color=auto"]
                .iter()
                .map(|s| s.to_string()),
        );
        cmd
    });

    let output = Command::new(seclusor_bin())
        .env("SECLUSOR_TEST_CAPTURE_KEYS", "APP_SIMPLE")
        .args(&args)
        .output()
        .expect("run seclusor");

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parsed_stdout(&output);
    assert_eq!(
        payload["args"],
        serde_json::json!(["hello", "-la", "--color=auto"])
    );
    assert_eq!(payload["env"]["APP_SIMPLE"], "sk-123abc");
}

#[test]
fn run_works_without_separator() {
    let (_dir, secrets) = temp_secrets_file();
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-fixture");
    let output = run_dump_with_capture(
        &secrets,
        &[],
        &[
            fixture.display().to_string(),
            "dump".to_string(),
            "hello".to_string(),
        ],
        &["APP_SIMPLE"],
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parsed_stdout(&output);
    assert_eq!(payload["args"], serde_json::json!(["hello"]));
}

#[test]
fn run_preserves_double_dash_for_child() {
    let (_dir, secrets) = temp_secrets_file();
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-fixture");
    let mut args = make_base_args(&secrets);
    args.push("--".to_string());
    args.push(fixture.display().to_string());
    args.push("dump".to_string());
    args.push("--".to_string());
    args.push("echo".to_string());
    args.push("test".to_string());

    let output = Command::new(seclusor_bin())
        .env("SECLUSOR_TEST_CAPTURE_KEYS", "APP_SIMPLE")
        .args(&args)
        .output()
        .expect("run seclusor");

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parsed_stdout(&output);
    assert_eq!(payload["args"], serde_json::json!(["--", "echo", "test"]));
}

#[test]
fn run_requires_command_after_separator() {
    let (_dir, secrets) = temp_secrets_file();
    let args = vec![
        "secrets".to_string(),
        "run".to_string(),
        "--file".to_string(),
        secrets.display().to_string(),
        "--project".to_string(),
        "demo".to_string(),
        "--".to_string(),
    ];

    let output = run_seclusor(&args);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("required arguments were not provided"),
        "stderr={stderr}"
    );
}

#[test]
fn run_resolves_absolute_relative_and_path_commands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = dir.path().join("secrets.json");
    write_secrets_fixture(&secrets);

    let helper_copy = compile_fixture(dir.path(), "run-fixture-local");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&helper_copy).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&helper_copy, perms).expect("chmod helper");
    }

    let absolute = run_dump_with_capture(
        &secrets,
        &[],
        &[
            helper_copy.display().to_string(),
            "dump".to_string(),
            "abs".to_string(),
        ],
        &["APP_SIMPLE"],
    );
    assert!(
        absolute.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&absolute.stderr)
    );

    let mut relative_args = make_base_args(&secrets);
    relative_args.push(
        format!(".{}", std::path::MAIN_SEPARATOR).to_string() + &fixture_name("run-fixture-local"),
    );
    relative_args.push("dump".to_string());
    relative_args.push("rel".to_string());
    let relative = Command::new(seclusor_bin())
        .current_dir(dir.path())
        .env("SECLUSOR_TEST_CAPTURE_KEYS", "APP_SIMPLE")
        .args(&relative_args)
        .output()
        .expect("run relative");
    assert!(
        relative.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&relative.stderr)
    );

    let path_helper = compile_fixture(dir.path(), "run-fixture-path");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path_helper).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path_helper, perms).expect("chmod path helper");
    }
    let mut path_args = make_base_args(&secrets);
    path_args.push(fixture_name("run-fixture-path"));
    path_args.push("dump".to_string());
    path_args.push("path".to_string());
    let path_output = Command::new(seclusor_bin())
        .current_dir(dir.path())
        .env("SECLUSOR_TEST_CAPTURE_KEYS", "APP_SIMPLE")
        .env("PATH", path_with(dir.path()))
        .args(&path_args)
        .output()
        .expect("run path");
    assert!(
        path_output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&path_output.stderr)
    );
}

#[test]
fn run_reports_command_not_found() {
    let (_dir, secrets) = temp_secrets_file();
    let mut args = make_base_args(&secrets);
    args.push("definitely-not-a-real-command-seclusor".to_string());

    let output = run_seclusor(&args);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(!stderr.trim().is_empty());
}

#[cfg(unix)]
#[test]
fn run_reports_permission_denied_for_non_executable_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = dir.path().join("secrets.json");
    write_secrets_fixture(&secrets);
    let target = dir.path().join("not-executable");
    fs::write(&target, "#!/bin/sh\nexit 0\n").expect("write file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&target).expect("metadata").permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&target, perms).expect("chmod file");
    }

    let mut args = make_base_args(&secrets);
    args.push("./not-executable".to_string());
    let output = run_seclusor_in(dir.path(), &args);

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(!stderr.trim().is_empty());
}

#[test]
fn run_passes_secret_value_edge_cases_literally() {
    let (_dir, secrets) = temp_secrets_file();
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-fixture");
    let capture_keys = [
        "APP_SIMPLE",
        "APP_SPACES",
        "APP_SINGLE_QUOTE",
        "APP_DOUBLE_QUOTE",
        "APP_EQUALS",
        "APP_NEWLINES",
        "APP_METACHARS",
        "APP_BACKTICKS",
        "APP_DOLLARS",
        "APP_LONG",
    ];
    let output = run_dump_with_capture(
        &secrets,
        &[],
        &[fixture.display().to_string(), "dump".to_string()],
        &capture_keys,
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parsed_stdout(&output);
    assert_eq!(payload["env"]["APP_SIMPLE"], "sk-123abc");
    assert_eq!(payload["env"]["APP_SPACES"], "hello world");
    assert_eq!(payload["env"]["APP_SINGLE_QUOTE"], "it's a secret");
    assert_eq!(payload["env"]["APP_DOUBLE_QUOTE"], "say \"hello\"");
    assert_eq!(payload["env"]["APP_EQUALS"], "key=value=extra");
    assert_eq!(payload["env"]["APP_NEWLINES"], "line1\nline2");
    assert_eq!(payload["env"]["APP_METACHARS"], "$(whoami); rm -rf /");
    assert_eq!(payload["env"]["APP_BACKTICKS"], "`date`");
    assert_eq!(payload["env"]["APP_DOLLARS"], "$HOME");
    assert_eq!(
        payload["env"]["APP_LONG"].as_str().map(str::len),
        Some(65_536)
    );
}

#[test]
fn run_passes_unicode_secret_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = dir.path().join("unicode.json");
    write_unicode_secrets_fixture(&secrets);
    let fixture = compile_fixture(dir.path(), "run-fixture");

    let output = run_dump_with_capture(
        &secrets,
        &[],
        &[fixture.display().to_string(), "dump".to_string()],
        &["APP_UNICODE"],
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parsed_stdout(&output);
    assert_eq!(payload["env"]["APP_UNICODE"], "sécret_密钥_🔑");
}

#[test]
fn run_inherits_parent_env_and_injected_vars_override_parent() {
    let (_dir, secrets) = temp_secrets_file();
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-fixture");
    let args = {
        let mut base = make_base_args(&secrets);
        base.push(fixture.display().to_string());
        base.push("dump".to_string());
        base
    };

    let output = Command::new(seclusor_bin())
        .env("SECLUSOR_TEST_CAPTURE_KEYS", "PATH,APP_SIMPLE")
        .env("APP_SIMPLE", "parent-value")
        .args(&args)
        .output()
        .expect("run seclusor");

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parsed_stdout(&output);
    assert!(payload["env"]["PATH"].as_str().is_some());
    assert_eq!(payload["env"]["APP_SIMPLE"], "sk-123abc");
}

#[test]
fn run_allow_and_deny_filters_are_applied() {
    let (_dir, secrets) = temp_secrets_file();
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-fixture");
    let extra = [
        "--allow",
        "APP_*",
        "--allow",
        "DB_HOST",
        "--deny",
        "APP_DEBUG",
    ];
    let capture_keys = ["APP_SIMPLE", "APP_DEBUG", "DB_HOST"];
    let output = run_dump_with_capture(
        &secrets,
        &extra,
        &[fixture.display().to_string(), "dump".to_string()],
        &capture_keys,
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parsed_stdout(&output);
    assert_eq!(payload["env"]["APP_SIMPLE"], "sk-123abc");
    assert_eq!(payload["env"]["DB_HOST"], "db.internal");
    assert!(payload["env"]["APP_DEBUG"].is_null());
}

#[test]
fn run_allow_non_matching_pattern_injects_zero_vars_without_error() {
    let (_dir, secrets) = temp_secrets_file();
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-fixture");
    let extra = ["--allow", "NONEXISTENT_*"];
    let output = run_dump_with_capture(
        &secrets,
        &extra,
        &[fixture.display().to_string(), "dump".to_string()],
        &["APP_SIMPLE"],
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parsed_stdout(&output);
    assert!(payload["env"]["APP_SIMPLE"].is_null());
}

#[test]
fn run_child_exit_codes_are_propagated() {
    let (_dir, secrets) = temp_secrets_file();
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-fixture");

    for code in [0, 1, 127, 255] {
        let mut args = make_base_args(&secrets);
        args.push(fixture.display().to_string());
        args.push("exit".to_string());
        args.push(code.to_string());

        let output = run_seclusor(&args);
        assert_eq!(
            output.status.code(),
            Some(code),
            "unexpected exit code for {code}: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn run_unix_signal_termination_is_nonzero() {
    let (_dir, secrets) = temp_secrets_file();
    let mut args = make_base_args(&secrets);
    args.push("sh".to_string());
    args.push("-c".to_string());
    args.push("kill -TERM $$".to_string());

    let output = run_seclusor(&args);
    assert!(!output.status.success());
    assert_ne!(output.status.code(), Some(0));
}

#[test]
fn run_bundle_with_identity_file_executes_child() {
    let dir = tempfile::tempdir().expect("tempdir");
    let input = dir.path().join("input.json");
    let bundle = dir.path().join("secrets.age");
    let identity = dir.path().join("identity.txt");
    let fixture = compile_fixture(dir.path(), "run-fixture");
    write_secrets_fixture(&input);

    let generated = Command::new(seclusor_bin())
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

    let encrypted = Command::new(seclusor_bin())
        .args([
            "secrets",
            "bundle",
            "encrypt",
            "--input",
            input.to_str().expect("utf8 input"),
            "--output",
            bundle.to_str().expect("utf8 bundle"),
            "--recipient",
            recipient.trim(),
        ])
        .output()
        .expect("bundle encrypt");
    assert!(
        encrypted.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&encrypted.stderr)
    );

    let output = Command::new(seclusor_bin())
        .env("SECLUSOR_TEST_CAPTURE_KEYS", "APP_SIMPLE")
        .args([
            "secrets",
            "run",
            "--file",
            bundle.to_str().expect("utf8 bundle"),
            "--identity-file",
            identity.to_str().expect("utf8 identity"),
            "--project",
            "demo",
            fixture.to_str().expect("utf8 fixture"),
            "dump",
        ])
        .output()
        .expect("run bundle");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parsed_stdout(&output);
    assert_eq!(payload["env"]["APP_SIMPLE"], "sk-123abc");
}

#[test]
fn cli_reference_examples_cover_explicit_shell_wrapping_for_pipes() {
    let doc_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/guides/cli-reference.md");
    let doc = fs::read_to_string(&doc_path).expect("read cli reference");
    assert!(doc.contains("This does NOT work (no shell):"));
    assert!(doc.contains("seclusor secrets run"));
    assert!(doc.contains("sh -c 'echo \"$APP_API_KEY\" | base64'"));
}
