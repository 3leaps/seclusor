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

#[cfg(unix)]
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
    assert!(
        path_helper.exists(),
        "PATH helper fixture must exist: {}",
        path_helper.display()
    );
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

// ---------------------------------------------------------------------------
// Child-env chokepoint (passphrase exclusion + value guard)
// Synthetic secrets only — never assert passphrase plaintext in diagnostics.
//
// Each fixture uses a unique passphrase and env-var name so parallel tests do
// not cross-contaminate process-global ambient env via value-equality checks.
// ---------------------------------------------------------------------------

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

static PP_FIXTURE_SEQ: AtomicU64 = AtomicU64::new(1);
/// Serialize process-global env mutations across parallel integration tests.
static PP_ENV_LOCK: Mutex<()> = Mutex::new(());

struct ProtectedRunFixture {
    _dir: tempfile::TempDir,
    secrets: PathBuf,
    identity: PathBuf,
    pp_var: String,
    /// Unique synthetic passphrase for this fixture (never a real secret).
    pp_value: String,
}

#[cfg(unix)]
fn chmod_600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
}

#[cfg(not(unix))]
fn chmod_600(_path: &Path) {}

fn write_protected_run_fixture(extra_credentials: &[(&str, &str)]) -> ProtectedRunFixture {
    write_protected_run_fixture_with_suffix(extra_credentials, "")
}

fn write_protected_run_fixture_with_suffix(
    extra_credentials: &[(&str, &str)],
    passphrase_suffix: &str,
) -> ProtectedRunFixture {
    let seq = PP_FIXTURE_SEQ.fetch_add(1, Ordering::Relaxed);
    let pp_value = format!("test-child-env-pp-{seq}-not-a-real-secret{passphrase_suffix}");
    let pp_var = format!("SECLUSOR_TEST_PP_{}_{}", std::process::id(), seq);

    let dir = tempfile::tempdir().expect("tempdir");
    let identity = dir.path().join("protected-identity.txt");
    let pp = secrecy::SecretString::from(pp_value.clone());
    let gen = seclusor_keyring::generate_identity_file_with_passphrase(&identity, &pp)
        .expect("generate protected identity");
    chmod_600(&identity);

    let recipient: seclusor_crypto::Recipient = gen.recipient.parse().expect("recipient");
    // No env_prefix: credential names are exported as-is (needed for name-collision cases).
    let mut secrets_model = seclusor_core::SecretsFile::new("demo");
    secrets_model.projects[0].credentials.insert(
        "APP_SIMPLE".to_string(),
        seclusor_core::Credential::with_value("secret", "sk-sentinel-ok"),
    );
    for (k, v) in extra_credentials {
        secrets_model.projects[0].credentials.insert(
            (*k).to_string(),
            seclusor_core::Credential::with_value("secret", v),
        );
    }
    let encrypted =
        seclusor_codec::encrypt_inline(&secrets_model, std::slice::from_ref(&recipient))
            .expect("encrypt inline");
    let secrets = dir.path().join("secrets.json");
    fs::write(
        &secrets,
        serde_json::to_vec_pretty(&encrypted).expect("serialize"),
    )
    .expect("write secrets");
    chmod_600(&secrets);

    ProtectedRunFixture {
        _dir: dir,
        secrets,
        identity,
        pp_var,
        pp_value,
    }
}

fn run_protected(
    fx: &ProtectedRunFixture,
    extra_cli: &[&str],
    capture_keys: &[&str],
    fixture_cmd: &[String],
    ambient: &[(&str, Option<&str>)],
) -> Output {
    let _guard = PP_ENV_LOCK.lock().expect("pp env lock");
    // Apply ambient env for this process (restored after).
    let mut previous: Vec<(String, Option<std::ffi::OsString>)> = Vec::new();
    for (k, v) in ambient {
        previous.push(((*k).to_string(), std::env::var_os(k)));
        match v {
            Some(val) => std::env::set_var(k, val),
            None => std::env::remove_var(k),
        }
    }
    // Always set the passphrase channel var for --passphrase-env tests unless ambient overrides it.
    if !ambient.iter().any(|(k, _)| *k == fx.pp_var) {
        previous.push((fx.pp_var.clone(), std::env::var_os(&fx.pp_var)));
        std::env::set_var(&fx.pp_var, &fx.pp_value);
    }

    let mut args = vec![
        "secrets".to_string(),
        "run".to_string(),
        "--file".to_string(),
        fx.secrets.display().to_string(),
        "--project".to_string(),
        "demo".to_string(),
        "--identity-file".to_string(),
        fx.identity.display().to_string(),
        "--passphrase-env".to_string(),
        fx.pp_var.clone(),
    ];
    args.extend(extra_cli.iter().map(|s| (*s).to_string()));
    args.extend(fixture_cmd.iter().cloned());

    let output = Command::new(seclusor_bin())
        .env("SECLUSOR_TEST_CAPTURE_KEYS", capture_keys.join(","))
        .args(&args)
        .output()
        .expect("run seclusor");

    for (k, prev) in previous {
        match prev {
            Some(v) => std::env::set_var(&k, v),
            None => std::env::remove_var(&k),
        }
    }
    output
}

fn run_protected_with_stdin(fx: &ProtectedRunFixture, input: &[u8]) -> Output {
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-pp-stdin-normalization");
    let mut child = Command::new(seclusor_bin());
    child
        .env("SECLUSOR_TEST_CAPTURE_KEYS", "APP_SIMPLE")
        .args([
            "secrets",
            "run",
            "--file",
            fx.secrets.to_str().unwrap(),
            "--project",
            "demo",
            "--identity-file",
            fx.identity.to_str().unwrap(),
            "--passphrase-stdin",
            "--allow",
            "APP_SIMPLE",
            fixture.to_str().unwrap(),
            "dump",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut process = child.spawn().expect("spawn seclusor");
    {
        use std::io::Write;
        process
            .stdin
            .take()
            .expect("stdin")
            .write_all(input)
            .expect("write passphrase input");
    }
    process.wait_with_output().expect("wait")
}

#[test]
fn run_passphrase_env_var_absent_from_child_with_sentinel_present() {
    let fx = write_protected_run_fixture(&[]);
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-pp-absent");
    let capture = [fx.pp_var.as_str(), "APP_SIMPLE"];
    let output = run_protected(
        &fx,
        &["--allow", "APP_SIMPLE"],
        &capture,
        &[fixture.display().to_string(), "dump".to_string()],
        &[],
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parsed_stdout(&output);
    // Negative control: harness is live — injected sentinel must appear.
    assert_eq!(payload["env"]["APP_SIMPLE"], "sk-sentinel-ok");
    // Named passphrase channel must be absent from the child.
    assert!(
        payload["env"][&fx.pp_var].is_null(),
        "passphrase env var must not reach child: {}",
        payload["env"][&fx.pp_var]
    );
}

#[test]
fn run_passphrase_env_preserves_carriage_return_for_legacy_identity() {
    let fx = write_protected_run_fixture_with_suffix(&[], "\r");
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-pp-legacy-cr");
    let capture = [fx.pp_var.as_str(), "APP_SIMPLE"];
    let output = run_protected(
        &fx,
        &["--allow", "APP_SIMPLE"],
        &capture,
        &[fixture.display().to_string(), "dump".to_string()],
        &[],
    );
    assert!(
        output.status.success(),
        "raw environment passphrase must unlock the identity; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parsed_stdout(&output);
    assert_eq!(payload["env"]["APP_SIMPLE"], "sk-sentinel-ok");
    assert!(payload["env"][&fx.pp_var].is_null());
}

#[test]
fn run_passphrase_stdin_normalizes_crlf_first_line() {
    let fx = write_protected_run_fixture(&[]);
    let input = format!("{}\r\nignored-second-line\n", fx.pp_value);
    let output = run_protected_with_stdin(&fx, input.as_bytes());
    assert!(
        output.status.success(),
        "normalized stdin passphrase must unlock the identity; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parsed_stdout(&output);
    assert_eq!(payload["env"]["APP_SIMPLE"], "sk-sentinel-ok");
}

#[test]
fn run_passphrase_stdin_rejects_crlf_blank_first_line() {
    let fx = write_protected_run_fixture(&[]);
    let output = run_protected_with_stdin(&fx, b"\r\nignored-second-line\n");
    assert!(!output.status.success(), "blank stdin input must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("passphrase from stdin is empty"),
        "unexpected redacted diagnostic: {stderr}"
    );
}

#[test]
fn run_passphrase_env_absent_under_broad_and_overlapping_allow_deny() {
    let fx = write_protected_run_fixture(&[]);
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-pp-allow-deny");
    let capture = [fx.pp_var.as_str(), "APP_SIMPLE"];
    let output = run_protected(
        &fx,
        &["--allow", "*", "--deny", "APP_NOPE"],
        &capture,
        &[fixture.display().to_string(), "dump".to_string()],
        &[],
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parsed_stdout(&output);
    assert_eq!(payload["env"]["APP_SIMPLE"], "sk-sentinel-ok");
    assert!(payload["env"][&fx.pp_var].is_null());
}

#[test]
fn run_passphrase_env_name_collision_with_store_key_fails_closed() {
    let _guard = PP_ENV_LOCK.lock().expect("pp env lock");
    // Build fixture first so we know pp_var, then rebuild store with that name.
    // Simpler: use a dedicated unique collision name as both store key and channel.
    let seq = PP_FIXTURE_SEQ.fetch_add(1, Ordering::Relaxed);
    let collision_var = format!("SECLUSOR_TEST_PP_COLLISION_{seq}");
    // Provisional fixture to get identity/secrets structure with collision key.
    // write_protected_run_fixture also advances seq and creates its own pp_var —
    // we override the channel name to equal the store key.
    let fx = write_protected_run_fixture(&[(&collision_var, "store-value-not-pp")]);
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-pp-collision");
    let prev = std::env::var_os(&collision_var);
    std::env::set_var(&collision_var, &fx.pp_value);
    let output = Command::new(seclusor_bin())
        .args([
            "secrets",
            "run",
            "--file",
            fx.secrets.to_str().unwrap(),
            "--project",
            "demo",
            "--identity-file",
            fx.identity.to_str().unwrap(),
            "--passphrase-env",
            &collision_var,
            "--allow",
            "*",
            fixture.to_str().unwrap(),
            "dump",
        ])
        .output()
        .expect("run");
    match prev {
        Some(v) => std::env::set_var(&collision_var, v),
        None => std::env::remove_var(&collision_var),
    }
    assert!(
        !output.status.success(),
        "collision must fail closed; stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&collision_var),
        "diagnostic must name the variable: {stderr}"
    );
    assert!(
        !stderr.contains(&fx.pp_value),
        "diagnostic must not include passphrase value"
    );
    assert!(
        !stderr.contains("store-value-not-pp"),
        "diagnostic must not include store value"
    );
}

#[test]
fn run_store_value_equals_passphrase_fails_closed() {
    let leaky = "APP_LEAKY";
    // First create a unique passphrase, then put it in the store.
    // write_protected_run_fixture needs the value at construction — use a two-step:
    // generate fixture with placeholder, not ideal. Instead construct with value known.
    // We pass the passphrase value by peeking seq: call a builder that uses known value.
    let seq = PP_FIXTURE_SEQ.load(Ordering::Relaxed);
    // Build with store value equal to the *next* fixture's passphrase by using
    // a custom path: write fixture then we cannot change identity passphrase.
    // So: create fixture, then the pp_value is known — rebuild store is hard.
    // Simpler: pass extra credential with a fixed unique value we also use as passphrase.
    // write_protected_run_fixture always generates its own pp_value, so store must use that.
    // API: write_protected_run_fixture_with_pp or pass optional leak.
    // Easiest fix: after write, we only know pp_value — rebuild encrypted store.
    let fx = write_protected_run_fixture(&[]);
    // Re-encrypt secrets to include leaky key with pp_value (same recipient from identity).
    let identities = seclusor_keyring::load_identity_file_auto(
        &fx.identity,
        Some(&secrecy::SecretString::from(fx.pp_value.clone())),
    )
    .expect("load id");
    let recipient = identities[0].to_public();
    let mut secrets_model = seclusor_core::SecretsFile::new("demo");
    secrets_model.projects[0].credentials.insert(
        "APP_SIMPLE".to_string(),
        seclusor_core::Credential::with_value("secret", "sk-sentinel-ok"),
    );
    secrets_model.projects[0].credentials.insert(
        leaky.to_string(),
        seclusor_core::Credential::with_value("secret", &fx.pp_value),
    );
    let encrypted =
        seclusor_codec::encrypt_inline(&secrets_model, std::slice::from_ref(&recipient))
            .expect("encrypt");
    fs::write(
        &fx.secrets,
        serde_json::to_vec_pretty(&encrypted).expect("serialize"),
    )
    .expect("rewrite secrets");
    chmod_600(&fx.secrets);

    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-pp-value-eq");
    let output = run_protected(
        &fx,
        &["--allow", "*"],
        &[fx.pp_var.as_str(), leaky, "APP_SIMPLE"],
        &[fixture.display().to_string(), "dump".to_string()],
        &[],
    );
    assert!(!output.status.success(), "value equality must fail closed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(leaky),
        "must name offending variable: {stderr}"
    );
    assert!(
        !stderr.contains(&fx.pp_value),
        "must not leak passphrase value"
    );
    let _ = seq;
}

#[test]
fn run_ambient_alias_of_passphrase_value_fails_closed() {
    let fx = write_protected_run_fixture(&[]);
    let alias = format!("SECLUSOR_TEST_PP_ALIAS_{}", fx.pp_var);
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-pp-alias");
    let output = run_protected(
        &fx,
        &["--allow", "APP_SIMPLE"],
        &[fx.pp_var.as_str(), "APP_SIMPLE", alias.as_str()],
        &[fixture.display().to_string(), "dump".to_string()],
        &[(&alias, Some(fx.pp_value.as_str()))],
    );
    assert!(!output.status.success(), "alias must fail closed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&alias), "must name alias var: {stderr}");
    assert!(!stderr.contains(&fx.pp_value));
}

#[test]
fn run_safe_override_of_ambient_passphrase_shaped_value_ok() {
    // Ambient holds the passphrase under APP_SIMPLE; injection overrides with store value.
    let fx = write_protected_run_fixture(&[]);
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-pp-safe-override");
    let output = run_protected(
        &fx,
        &["--allow", "APP_SIMPLE"],
        &[fx.pp_var.as_str(), "APP_SIMPLE"],
        &[fixture.display().to_string(), "dump".to_string()],
        &[("APP_SIMPLE", Some(fx.pp_value.as_str()))],
    );
    assert!(
        output.status.success(),
        "safe override must not false-fail: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parsed_stdout(&output);
    assert_eq!(payload["env"]["APP_SIMPLE"], "sk-sentinel-ok");
    assert!(payload["env"][&fx.pp_var].is_null());
}

#[test]
fn run_passphrase_stdin_channel_still_value_checks_ambient_alias() {
    let _guard = PP_ENV_LOCK.lock().expect("pp env lock");
    let fx = write_protected_run_fixture(&[]);
    let alias = format!("SECLUSOR_TEST_PP_STDIN_ALIAS_{}", fx.pp_var);
    let prev = std::env::var_os(&alias);
    std::env::set_var(&alias, &fx.pp_value);
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-pp-stdin");
    let mut child = Command::new(seclusor_bin());
    child
        .args([
            "secrets",
            "run",
            "--file",
            fx.secrets.to_str().unwrap(),
            "--project",
            "demo",
            "--identity-file",
            fx.identity.to_str().unwrap(),
            "--passphrase-stdin",
            "--allow",
            "APP_SIMPLE",
            fixture.to_str().unwrap(),
            "dump",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut proc = child.spawn().expect("spawn seclusor");
    use std::io::Write;
    {
        let mut stdin = proc.stdin.take().expect("stdin");
        writeln!(stdin, "{}", fx.pp_value).expect("write passphrase");
    }
    let output = proc.wait_with_output().expect("wait");
    match prev {
        Some(v) => std::env::set_var(&alias, v),
        None => std::env::remove_var(&alias),
    }
    assert!(
        !output.status.success(),
        "stdin channel must still value-check ambient: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&alias), "must name alias: {stderr}");
    assert!(!stderr.contains(&fx.pp_value));
}

#[test]
fn run_passphrase_file_channel_still_value_checks_ambient_alias() {
    let _guard = PP_ENV_LOCK.lock().expect("pp env lock");
    let fx = write_protected_run_fixture(&[]);
    let pp_file = fx._dir.path().join("pp.txt");
    fs::write(&pp_file, format!("{}\n", fx.pp_value)).expect("write pp file");
    chmod_600(&pp_file);

    // Ambient alias still carries the value under a different name → fail closed.
    let alias = format!("SECLUSOR_TEST_PP_FILE_ALIAS_{}", fx.pp_var);
    let prev = std::env::var_os(&alias);
    std::env::set_var(&alias, &fx.pp_value);
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-pp-file");
    let output = Command::new(seclusor_bin())
        .args([
            "secrets",
            "run",
            "--file",
            fx.secrets.to_str().unwrap(),
            "--project",
            "demo",
            "--identity-file",
            fx.identity.to_str().unwrap(),
            "--passphrase-file",
            pp_file.to_str().unwrap(),
            "--allow",
            "APP_SIMPLE",
            fixture.to_str().unwrap(),
            "dump",
        ])
        .output()
        .expect("run");
    match prev {
        Some(v) => std::env::set_var(&alias, v),
        None => std::env::remove_var(&alias),
    }
    assert!(
        !output.status.success(),
        "file channel must still value-check ambient: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&alias));
    assert!(!stderr.contains(&fx.pp_value));
}

#[cfg(unix)]
#[test]
fn run_passphrase_exclusion_is_transitive_to_grandchild() {
    let _guard = PP_ENV_LOCK.lock().expect("pp env lock");
    let fx = write_protected_run_fixture(&[]);
    let prev = std::env::var_os(&fx.pp_var);
    std::env::set_var(&fx.pp_var, &fx.pp_value);
    // Grandchild shell checks the passphrase var is unset.
    let script = format!(
        "sh -c 'if [ -n \"${{{}:-}}\" ]; then exit 11; fi; if [ \"$APP_SIMPLE\" != \"sk-sentinel-ok\" ]; then exit 12; fi; exit 0'",
        fx.pp_var
    );
    let output = Command::new(seclusor_bin())
        .args([
            "secrets",
            "run",
            "--file",
            fx.secrets.to_str().unwrap(),
            "--project",
            "demo",
            "--identity-file",
            fx.identity.to_str().unwrap(),
            "--passphrase-env",
            &fx.pp_var,
            "--allow",
            "APP_SIMPLE",
            "sh",
            "-c",
            &script,
        ])
        .output()
        .expect("run");
    match prev {
        Some(v) => std::env::set_var(&fx.pp_var, v),
        None => std::env::remove_var(&fx.pp_var),
    }
    assert!(
        output.status.success(),
        "grandchild must not see passphrase env; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// Guard-only resolve regressions (unprotected estates + channel asymmetry)
// ---------------------------------------------------------------------------

#[test]
fn run_unprotected_passphrase_env_unset_is_noop() {
    let _guard = PP_ENV_LOCK.lock().expect("pp env lock");
    let (_dir, secrets) = temp_secrets_file();
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-unprot-unset");
    let unset_var = format!("SECLUSOR_TEST_PP_UNSET_{}", std::process::id());
    std::env::remove_var(&unset_var);
    let output = Command::new(seclusor_bin())
        .env("SECLUSOR_TEST_CAPTURE_KEYS", "APP_SIMPLE")
        .args([
            "secrets",
            "run",
            "--file",
            secrets.to_str().unwrap(),
            "--project",
            "demo",
            "--passphrase-env",
            &unset_var,
            "--allow",
            "APP_SIMPLE",
            fixture.to_str().unwrap(),
            "dump",
        ])
        .output()
        .expect("run");
    assert!(
        output.status.success(),
        "unset passphrase-env on unprotected estate must be no-op: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parsed_stdout(&output);
    assert_eq!(payload["env"]["APP_SIMPLE"], "sk-123abc");
}

#[test]
fn run_unprotected_passphrase_env_still_value_checks_ambient_alias() {
    let _guard = PP_ENV_LOCK.lock().expect("pp env lock");
    let (_dir, secrets) = temp_secrets_file();
    let fixture_dir = tempfile::tempdir().expect("tempdir");
    let fixture = compile_fixture(fixture_dir.path(), "run-unprot-alias");
    let pp_var = format!("SECLUSOR_TEST_PP_UNPROT_{}", std::process::id());
    let alias = format!("SECLUSOR_TEST_PP_UNPROT_ALIAS_{}", std::process::id());
    let secret = "unprot-guard-only-pp-not-real";
    let prev_pp = std::env::var_os(&pp_var);
    let prev_alias = std::env::var_os(&alias);
    std::env::set_var(&pp_var, secret);
    std::env::set_var(&alias, secret);
    let output = Command::new(seclusor_bin())
        .args([
            "secrets",
            "run",
            "--file",
            secrets.to_str().unwrap(),
            "--project",
            "demo",
            "--passphrase-env",
            &pp_var,
            "--allow",
            "APP_SIMPLE",
            fixture.to_str().unwrap(),
            "dump",
        ])
        .output()
        .expect("run");
    match prev_pp {
        Some(v) => std::env::set_var(&pp_var, v),
        None => std::env::remove_var(&pp_var),
    }
    match prev_alias {
        Some(v) => std::env::set_var(&alias, v),
        None => std::env::remove_var(&alias),
    }
    assert!(
        !output.status.success(),
        "guard-only resolve must value-check ambient: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&alias) || stderr.contains(&pp_var),
        "must name a var: {stderr}"
    );
    assert!(!stderr.contains(secret));
}

#[cfg(unix)]
#[test]
fn run_unprotected_passphrase_stdin_does_not_consume_child_stdin() {
    // All-unprotected estate: --passphrase-stdin must not read stdin so the
    // child still receives it (secrev regression pin).
    let _guard = PP_ENV_LOCK.lock().expect("pp env lock");
    let (_dir, secrets) = temp_secrets_file();
    let marker = "child-stdin-must-survive-unprotected-run";
    let mut child = Command::new(seclusor_bin());
    child
        .args([
            "secrets",
            "run",
            "--file",
            secrets.to_str().unwrap(),
            "--project",
            "demo",
            "--passphrase-stdin",
            "--allow",
            "APP_SIMPLE",
            "cat",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut proc = child.spawn().expect("spawn");
    use std::io::Write;
    {
        let mut stdin = proc.stdin.take().expect("stdin");
        write!(stdin, "{marker}").expect("write child stdin");
    }
    let output = proc.wait_with_output().expect("wait");
    assert!(
        output.status.success(),
        "unprotected + passphrase-stdin must not fail: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(marker),
        "child must receive stdin intact; got {stdout:?}"
    );
}
