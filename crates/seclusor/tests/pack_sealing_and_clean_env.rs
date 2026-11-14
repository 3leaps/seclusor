//! End-to-end process-boundary coverage for pack-sealing data-safety fixes and
//! `secrets run --clean-env` hardening:
//! 1. Refuse silent plaintext writes when recipient options are supplied.
//! 2. `secrets run --clean-env` and repeatable `--env-allow`.
//! 3. Repeatable `--recipient-file` across CLI recipient-accepting verbs.
//! 4. `secrets init --codec inline` and `secrets inline encrypt --input - --output -`.
//! 5. Fail-fast interactive passphrase preflight without a foreground controlling TTY
//!    (both detached session `setsid` and background process group `setpgid`).

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

fn seclusor_bin() -> &'static str {
    env!("CARGO_BIN_EXE_seclusor")
}

fn run_seclusor(args: &[&str]) -> Output {
    Command::new(seclusor_bin())
        .args(args)
        .output()
        .expect("run seclusor")
}

fn run_seclusor_stdin(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(seclusor_bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn seclusor");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_bytes);
    }
    child.wait_with_output().expect("wait seclusor")
}

fn generate_identity(dir: &Path, name: &str) -> (PathBuf, String) {
    let path = dir.join(name);
    let output = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        path.to_str().expect("utf8 path"),
    ]);
    assert!(
        output.status.success(),
        "identity generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (
        path,
        String::from_utf8(output.stdout)
            .expect("utf8 recipient")
            .trim()
            .to_string(),
    )
}

fn compile_run_fixture(dir: &Path, name: &str) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/run-fixture.rs");
    #[cfg(windows)]
    let output = dir.join(format!("{name}.exe"));
    #[cfg(not(windows))]
    let output = dir.join(name);

    let status = Command::new("rustc")
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .status()
        .expect("compile run-fixture");
    assert!(status.success(), "run-fixture compilation failed");
    output
}

fn assert_canary_absent_everywhere(dir: &Path, output: &Output, canary: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains(canary),
        "canary leaked to stdout: {stdout}"
    );
    assert!(
        !stderr.contains(canary),
        "canary leaked to stderr: {stderr}"
    );

    for entry in fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        if entry.file_type().expect("file type").is_file() {
            let bytes = fs::read(entry.path()).expect("read sibling file");
            assert!(
                !bytes
                    .windows(canary.len())
                    .any(|window| window == canary.as_bytes()),
                "canary leaked to file {}",
                entry.path().display()
            );
        }
    }
}

#[test]
fn plaintext_writes_refuse_recipient_options_without_persisting_canary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let plain = dir.path().join("pack.json");
    let (_, recipient) = generate_identity(dir.path(), "id.txt");
    let rfile = dir.path().join("recipients.txt");
    fs::write(&rfile, format!("{recipient}\n")).expect("write recipients");

    let init = run_seclusor(&[
        "secrets",
        "init",
        "--file",
        plain.to_str().unwrap(),
        "--project",
        "demo",
        "--env-prefix",
        "APP_",
    ]);
    assert!(init.status.success(), "plaintext init failed");
    assert_eq!(
        String::from_utf8_lossy(&init.stdout),
        format!("{}\n", plain.display())
    );
    let init_stderr = String::from_utf8_lossy(&init.stderr);
    assert!(
        init.stderr.is_empty(),
        "expected empty stderr on default plaintext init per ADR-0006, got: {init_stderr}"
    );

    // Seed one baseline non-canary credential so description-only set and unset have a target.
    let seed = run_seclusor_stdin(
        &[
            "secrets",
            "set",
            "--file",
            plain.to_str().unwrap(),
            "--project",
            "demo",
            "--key",
            "EXISTING_KEY",
            "--value-stdin",
        ],
        b"baseline-non-canary\n",
    );
    assert!(seed.status.success(), "seed set failed");

    let before = fs::read(&plain).expect("read before");
    let canary = "CANARY_PLAINTEXT_MUST_NEVER_HIT_DISK_9f4c2a";

    // 1. set --value-stdin + --recipient-file
    let out = run_seclusor_stdin(
        &[
            "secrets",
            "set",
            "--file",
            plain.to_str().unwrap(),
            "--project",
            "demo",
            "--key",
            "NEW_KEY",
            "--value-stdin",
            "--recipient-file",
            rfile.to_str().unwrap(),
        ],
        format!("{canary}\n").as_bytes(),
    );
    assert!(!out.status.success(), "set + --recipient-file must fail");
    assert_eq!(fs::read(&plain).unwrap(), before);
    assert_canary_absent_everywhere(dir.path(), &out, canary);

    // 2. set --value + --recipient
    let out = run_seclusor(&[
        "secrets",
        "set",
        "--file",
        plain.to_str().unwrap(),
        "--project",
        "demo",
        "--key",
        "NEW_KEY",
        "--value",
        canary,
        "--recipient",
        &recipient,
    ]);
    assert!(!out.status.success(), "set + --recipient must fail");
    assert_eq!(fs::read(&plain).unwrap(), before);
    assert_canary_absent_everywhere(dir.path(), &out, canary);

    // 3. set --ref + --recipient-env-var
    let out = Command::new(seclusor_bin())
        .args([
            "secrets",
            "set",
            "--file",
            plain.to_str().unwrap(),
            "--project",
            "demo",
            "--key",
            "REF_KEY",
            "--ref",
            "vault://demo/ref",
            "--recipient-env-var",
            "TEST_RECIPIENTS_ENV",
        ])
        .env("TEST_RECIPIENTS_ENV", &recipient)
        .output()
        .expect("run set ref");
    assert!(
        !out.status.success(),
        "set --ref + --recipient-env-var must fail"
    );
    assert_eq!(fs::read(&plain).unwrap(), before);

    // 4. description-only set + --recipient-file
    let out = run_seclusor(&[
        "secrets",
        "set",
        "--file",
        plain.to_str().unwrap(),
        "--project",
        "demo",
        "--key",
        "EXISTING_KEY",
        "--description",
        "updated",
        "--recipient-file",
        rfile.to_str().unwrap(),
    ]);
    assert!(
        !out.status.success(),
        "description set + --recipient-file must fail"
    );
    assert_eq!(fs::read(&plain).unwrap(), before);

    // 5. set + --allow-recipient-mismatch alone
    let out = run_seclusor_stdin(
        &[
            "secrets",
            "set",
            "--file",
            plain.to_str().unwrap(),
            "--project",
            "demo",
            "--key",
            "NEW_KEY",
            "--value-stdin",
            "--allow-recipient-mismatch",
        ],
        format!("{canary}\n").as_bytes(),
    );
    assert!(
        !out.status.success(),
        "set + --allow-recipient-mismatch on plaintext must fail"
    );
    assert_eq!(fs::read(&plain).unwrap(), before);
    assert_canary_absent_everywhere(dir.path(), &out, canary);

    // 6. import-env + --recipient-file (pass via ambient env so dotenv file doesn't hold canary)
    let out = Command::new(seclusor_bin())
        .args([
            "secrets",
            "import-env",
            "--file",
            plain.to_str().unwrap(),
            "--project",
            "demo",
            "--prefix",
            "APP_",
            "--recipient-file",
            rfile.to_str().unwrap(),
        ])
        .env("APP_IMPORTED_SECRET", canary)
        .output()
        .expect("run import-env");
    assert!(
        !out.status.success(),
        "import-env + --recipient-file must fail"
    );
    assert_eq!(fs::read(&plain).unwrap(), before);
    assert_canary_absent_everywhere(dir.path(), &out, canary);

    // 7. unset + --recipient-file
    let out = run_seclusor(&[
        "secrets",
        "unset",
        "--file",
        plain.to_str().unwrap(),
        "--project",
        "demo",
        "--key",
        "EXISTING_KEY",
        "--recipient-file",
        rfile.to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "unset + --recipient-file must fail");
    assert_eq!(fs::read(&plain).unwrap(), before);

    // Positive control: ambient SECLUSOR_RECIPIENTS without explicit CLI recipient flags
    // must NOT break intentional plaintext writes.
    let ok = Command::new(seclusor_bin())
        .args([
            "secrets",
            "set",
            "--file",
            plain.to_str().unwrap(),
            "--project",
            "demo",
            "--key",
            "INTENTIONAL_PLAIN",
            "--value",
            "plain-ok",
        ])
        .env("SECLUSOR_RECIPIENTS", &recipient)
        .output()
        .expect("run intentional plain set");
    assert!(
        ok.status.success(),
        "ambient SECLUSOR_RECIPIENTS alone must not break plaintext set: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
}

#[test]
fn run_clean_env_filters_ambient_and_preserves_passphrase_guards() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture_bin = compile_run_fixture(dir.path(), "run-fixture");
    let (id_path, recipient) = generate_identity(dir.path(), "id.txt");
    let bundle = dir.path().join("secrets.age");

    let init = run_seclusor(&[
        "secrets",
        "init",
        "--file",
        bundle.to_str().unwrap(),
        "--codec",
        "bundle",
        "--project",
        "demo",
        "--recipient",
        &recipient,
    ]);
    assert!(init.status.success(), "bundle init failed");

    let set = run_seclusor_stdin(
        &[
            "secrets",
            "set",
            "--file",
            bundle.to_str().unwrap(),
            "--project",
            "demo",
            "--key",
            "APP_INJECTED",
            "--value-stdin",
            "--identity-file",
            id_path.to_str().unwrap(),
        ],
        b"injected-value-ok\n",
    );
    assert!(set.status.success(), "bundle set failed");

    // Spawn with --clean-env and two repeatable --env-allow entries while poisoning
    // ambient env with unrelated tokens, loader vars, proxy vars, and SSH_AUTH_SOCK.
    let out = Command::new(seclusor_bin())
        .args([
            "secrets",
            "run",
            "--file",
            bundle.to_str().unwrap(),
            "--project",
            "demo",
            "--identity-file",
            id_path.to_str().unwrap(),
            "--passphrase-env",
            "CALLER_UNLOCK_PP",
            "--clean-env",
            "--env-allow",
            "CUSTOM_ALLOW_A",
            "--env-allow",
            "CUSTOM_ALLOW_B",
            "--",
            fixture_bin.to_str().unwrap(),
            "dump-all",
        ])
        .env("CALLER_UNLOCK_PP", "caller-unlock-passphrase-canary")
        .env("OTHER_SEAT_PASSPHRASE", "other-seat-secret-canary")
        .env("AWS_SECRET_ACCESS_KEY", "aws-secret-canary")
        .env("LD_LIBRARY_PATH", "/tmp/evil-lib")
        .env("DYLD_FALLBACK_LIBRARY_PATH", "/tmp/evil-dylib")
        .env("NODE_OPTIONS", "--require /tmp/evil.js")
        .env("HTTPS_PROXY", "http://proxy.internal:8080")
        .env("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock")
        .env("CUSTOM_ALLOW_A", "allow-a")
        .env("CUSTOM_ALLOW_B", "allow-b")
        .output()
        .expect("run --clean-env");

    assert!(
        out.status.success(),
        "clean-env run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let parsed: Value = serde_json::from_slice(&out.stdout).expect("parse dump-all json");
    let env_obj: BTreeMap<String, String> =
        serde_json::from_value(parsed["env"].clone()).expect("env map");

    assert_eq!(
        env_obj.get("APP_INJECTED").map(String::as_str),
        Some("injected-value-ok")
    );
    assert_eq!(
        env_obj.get("CUSTOM_ALLOW_A").map(String::as_str),
        Some("allow-a")
    );
    assert_eq!(
        env_obj.get("CUSTOM_ALLOW_B").map(String::as_str),
        Some("allow-b")
    );
    assert!(env_obj.contains_key("PATH"), "PATH baseline should survive");

    for forbidden in [
        "CALLER_UNLOCK_PP",
        "OTHER_SEAT_PASSPHRASE",
        "AWS_SECRET_ACCESS_KEY",
        "LD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "NODE_OPTIONS",
        "HTTPS_PROXY",
        "SSH_AUTH_SOCK",
    ] {
        assert!(
            !env_obj.contains_key(forbidden),
            "forbidden ambient var `{forbidden}` leaked under --clean-env"
        );
    }

    // --env-allow colliding with --passphrase-env must fail closed.
    let collision = Command::new(seclusor_bin())
        .args([
            "secrets",
            "run",
            "--file",
            bundle.to_str().unwrap(),
            "--project",
            "demo",
            "--identity-file",
            id_path.to_str().unwrap(),
            "--passphrase-env",
            "CALLER_UNLOCK_PP",
            "--clean-env",
            "--env-allow",
            "CALLER_UNLOCK_PP",
            "--",
            fixture_bin.to_str().unwrap(),
            "exit",
            "0",
        ])
        .env("CALLER_UNLOCK_PP", "caller-unlock-passphrase-canary")
        .output()
        .expect("run collision");
    assert!(
        !collision.status.success(),
        "passphrase allow collision must fail"
    );
    assert!(!String::from_utf8_lossy(&collision.stderr).contains("caller-unlock-passphrase-canary"));

    // --env-allow variable whose value aliases the passphrase must fail closed.
    let alias = Command::new(seclusor_bin())
        .args([
            "secrets",
            "run",
            "--file",
            bundle.to_str().unwrap(),
            "--project",
            "demo",
            "--identity-file",
            id_path.to_str().unwrap(),
            "--passphrase-env",
            "CALLER_UNLOCK_PP",
            "--clean-env",
            "--env-allow",
            "ALIASED_PP_COPY",
            "--",
            fixture_bin.to_str().unwrap(),
            "exit",
            "0",
        ])
        .env("CALLER_UNLOCK_PP", "caller-unlock-passphrase-canary")
        .env("ALIASED_PP_COPY", "caller-unlock-passphrase-canary")
        .output()
        .expect("run alias");
    assert!(
        !alias.status.success(),
        "aliased passphrase value must fail"
    );
    assert!(!String::from_utf8_lossy(&alias.stderr).contains("caller-unlock-passphrase-canary"));

    // --env-allow without --clean-env must be rejected at CLI parse time.
    let no_clean = run_seclusor(&[
        "secrets",
        "run",
        "--file",
        bundle.to_str().unwrap(),
        "--env-allow",
        "CUSTOM_ALLOW_A",
        "--",
        fixture_bin.to_str().unwrap(),
        "exit",
        "0",
    ]);
    assert!(!no_clean.status.success());

    // Seekable `--passphrase-stdin` must rebind child stdin to Stdio::null() so
    // the spawned child cannot `lseek(0, 0, SEEK_SET)` or read trailing stdin
    // bytes to recover unlock material.
    let protected_id = dir.path().join("protected-id.txt");
    let pp_canary = "seekable-stdin-unlock-canary-9912";
    let gen_prot = Command::new(seclusor_bin())
        .args([
            "keys",
            "age",
            "identity",
            "generate",
            "--output",
            protected_id.to_str().unwrap(),
            "--passphrase-env",
            "GEN_PP",
        ])
        .env("GEN_PP", pp_canary)
        .output()
        .expect("generate protected identity");
    assert!(
        gen_prot.status.success(),
        "protected identity generation failed: {}",
        String::from_utf8_lossy(&gen_prot.stderr)
    );
    let prot_recipient = String::from_utf8(gen_prot.stdout)
        .expect("utf8 recipient")
        .trim()
        .to_string();

    let prot_bundle = dir.path().join("protected-secrets.age");
    assert!(run_seclusor(&[
        "secrets",
        "init",
        "--file",
        prot_bundle.to_str().unwrap(),
        "--codec",
        "bundle",
        "--project",
        "demo",
        "--recipient",
        &prot_recipient,
    ])
    .status
    .success());

    let seekable_pp_path = dir.path().join("seekable-pp.txt");
    fs::write(
        &seekable_pp_path,
        format!("{pp_canary}\ntrailing-stdin-canary-8821\n"),
    )
    .expect("write seekable pp file");
    let seekable_stdin = fs::File::open(&seekable_pp_path).expect("open seekable pp file");

    let seek_out = Command::new(seclusor_bin())
        .args([
            "secrets",
            "run",
            "--file",
            prot_bundle.to_str().unwrap(),
            "--project",
            "demo",
            "--identity-file",
            protected_id.to_str().unwrap(),
            "--passphrase-stdin",
            "--clean-env",
            "--",
            fixture_bin.to_str().unwrap(),
            "probe-stdin",
        ])
        .stdin(Stdio::from(seekable_stdin))
        .output()
        .expect("run with seekable --passphrase-stdin");
    assert!(
        seek_out.status.success(),
        "seekable --passphrase-stdin run failed: {}",
        String::from_utf8_lossy(&seek_out.stderr)
    );
    let probe_json: Value = serde_json::from_slice(&seek_out.stdout).expect("parse probe-stdin");
    assert_eq!(
        probe_json["stdin"].as_str(),
        Some(""),
        "child must receive empty null stdin under --passphrase-stdin, got: {probe_json}"
    );
    let combined_out = format!(
        "{}{}",
        String::from_utf8_lossy(&seek_out.stdout),
        String::from_utf8_lossy(&seek_out.stderr)
    );
    assert!(!combined_out.contains(pp_canary));
    assert!(!combined_out.contains("trailing-stdin-canary-8821"));
}

#[test]
fn repeatable_recipient_files_and_inline_init_and_stdin_encrypt_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (id_a, rec_a) = generate_identity(dir.path(), "id-a.txt");
    let (id_b, rec_b) = generate_identity(dir.path(), "id-b.txt");
    let (id_c, rec_c) = generate_identity(dir.path(), "id-c.txt");

    let rfile_a = dir.path().join("team-a.txt");
    let rfile_b = dir.path().join("team-b.txt");
    // Include comment, blank line, and cross-file duplicate (rec_a in both).
    fs::write(&rfile_a, format!("# team a\n\n{rec_a}\n")).expect("write a");
    fs::write(&rfile_b, format!("{rec_a}\n{rec_b}\n")).expect("write b");

    // 1. secrets init --codec inline with two --recipient-file flags + --recipient
    let inline_pack = dir.path().join("pack-inline.json");
    let init = run_seclusor(&[
        "secrets",
        "init",
        "--file",
        inline_pack.to_str().unwrap(),
        "--codec",
        "inline",
        "--project",
        "demo",
        "--recipient-file",
        rfile_a.to_str().unwrap(),
        "--recipient-file",
        rfile_b.to_str().unwrap(),
        "--recipient",
        &rec_c,
    ]);
    assert!(
        init.status.success(),
        "inline init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    // Structural-only validate succeeds on 0-credential inline skeleton.
    let val_struct = run_seclusor(&[
        "secrets",
        "validate",
        "--file",
        inline_pack.to_str().unwrap(),
    ]);
    assert!(val_struct.status.success());
    assert_eq!(
        String::from_utf8_lossy(&val_struct.stdout).trim(),
        "structural-only valid"
    );

    // Seal a credential into the inline skeleton; verify no plaintext on disk and all 3 decrypt.
    let inline_canary = "INLINE_PACK_SECRET_VALUE_42";
    let set = run_seclusor_stdin(
        &[
            "secrets",
            "set",
            "--file",
            inline_pack.to_str().unwrap(),
            "--project",
            "demo",
            "--key",
            "SSH_KEY_PP",
            "--value-stdin",
            "--identity-file",
            id_a.to_str().unwrap(),
            "--recipient-file",
            rfile_a.to_str().unwrap(),
            "--recipient-file",
            rfile_b.to_str().unwrap(),
            "--recipient",
            &rec_c,
        ],
        format!("{inline_canary}\n").as_bytes(),
    );
    assert!(
        set.status.success(),
        "inline set failed: {}",
        String::from_utf8_lossy(&set.stderr)
    );
    assert_canary_absent_everywhere(dir.path(), &set, inline_canary);

    for id in [&id_a, &id_b, &id_c] {
        let get = run_seclusor(&[
            "secrets",
            "get",
            "--file",
            inline_pack.to_str().unwrap(),
            "--project",
            "demo",
            "--key",
            "SSH_KEY_PP",
            "--reveal",
            "--identity-file",
            id.to_str().unwrap(),
        ]);
        assert!(get.status.success());
        assert_eq!(String::from_utf8_lossy(&get.stdout).trim(), inline_canary);
    }

    // Unsetting down to 0 credentials preserves Inline classification (subsequent set still encrypts!).
    let unset = run_seclusor(&[
        "secrets",
        "unset",
        "--file",
        inline_pack.to_str().unwrap(),
        "--project",
        "demo",
        "--key",
        "SSH_KEY_PP",
    ]);
    assert!(unset.status.success());
    let val_after_unset = run_seclusor(&[
        "secrets",
        "validate",
        "--file",
        inline_pack.to_str().unwrap(),
    ]);
    assert!(val_after_unset.status.success());
    assert_eq!(
        String::from_utf8_lossy(&val_after_unset.stdout).trim(),
        "structural-only valid"
    );

    let set_again = run_seclusor_stdin(
        &[
            "secrets",
            "set",
            "--file",
            inline_pack.to_str().unwrap(),
            "--project",
            "demo",
            "--key",
            "SSH_KEY_PP",
            "--value-stdin",
            "--identity-file",
            id_a.to_str().unwrap(),
        ],
        format!("{inline_canary}\n").as_bytes(),
    );
    assert!(set_again.status.success());
    assert_canary_absent_everywhere(dir.path(), &set_again, inline_canary);

    // 2. rekey with multiple --recipient-file flags (+ hardlink alias check on 2nd file)
    #[cfg(unix)]
    {
        let alias_b = dir.path().join("alias-b.txt");
        fs::hard_link(&rfile_b, &alias_b).expect("hardlink b");
        let rekey_alias = run_seclusor(&[
            "secrets",
            "rekey",
            "--file",
            inline_pack.to_str().unwrap(),
            "--identity-file",
            id_a.to_str().unwrap(),
            "--recipient-file",
            rfile_a.to_str().unwrap(),
            "--recipient-file",
            rfile_b.to_str().unwrap(),
            "--write-recipients",
            alias_b.to_str().unwrap(),
            "--allow-recipient-mismatch",
        ]);
        assert!(
            !rekey_alias.status.success(),
            "hardlink alias to second --recipient-file must refuse"
        );
        assert!(String::from_utf8_lossy(&rekey_alias.stderr).contains("--recipient-file"));
    }

    // 3. secrets inline encrypt --input - --output - (zero plaintext on disk, no identity needed)
    let stream_canary = "STREAM_INLINE_ENCRYPT_CANARY_88";
    let stream_doc = serde_json::json!({
        "schema_version": "v1.0.0",
        "projects": [{
            "project_slug": "demo",
            "credentials": {
                "STREAM_KEY": {
                    "type": "secret",
                    "value": stream_canary
                }
            }
        }]
    });
    let enc_stream = run_seclusor_stdin(
        &[
            "secrets",
            "inline",
            "encrypt",
            "--input",
            "-",
            "--output",
            "-",
            "--recipient-file",
            rfile_a.to_str().unwrap(),
            "--recipient-file",
            rfile_b.to_str().unwrap(),
        ],
        serde_json::to_vec(&stream_doc).unwrap().as_slice(),
    );
    assert!(
        enc_stream.status.success(),
        "inline encrypt stdin->stdout failed: {}",
        String::from_utf8_lossy(&enc_stream.stderr)
    );
    let stdout_str = String::from_utf8(enc_stream.stdout.clone()).expect("utf8 stdout");
    assert!(!stdout_str.contains(stream_canary));
    assert!(!stdout_str.ends_with("\n-\n"));
    let parsed_enc: Value = serde_json::from_str(&stdout_str).expect("stdout must be pure JSON");
    assert_eq!(parsed_enc["schema_version"], "v1.1.0");
    assert!(
        parsed_enc["projects"][0]["credentials"]["STREAM_KEY"]["value"]
            .as_str()
            .unwrap()
            .starts_with("sec:age:v1:")
    );

    let saved_stream = dir.path().join("streamed-inline.json");
    fs::write(&saved_stream, &enc_stream.stdout).expect("save streamed json");
    let get_b = run_seclusor(&[
        "secrets",
        "get",
        "--file",
        saved_stream.to_str().unwrap(),
        "--project",
        "demo",
        "--key",
        "STREAM_KEY",
        "--reveal",
        "--identity-file",
        id_b.to_str().unwrap(),
    ]);
    assert!(get_b.status.success());
    assert_eq!(String::from_utf8_lossy(&get_b.stdout).trim(), stream_canary);

    // Malformed stdin JSON must fail closed with empty stdout and redacted stderr.
    let bad_stdin = run_seclusor_stdin(
        &[
            "secrets",
            "inline",
            "encrypt",
            "--input",
            "-",
            "--output",
            "-",
            "--recipient",
            &rec_a,
        ],
        format!("{{\"broken\": \"{stream_canary}\"").as_bytes(),
    );
    assert!(!bad_stdin.status.success());
    assert!(bad_stdin.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&bad_stdin.stderr).contains(stream_canary));

    // 4. blob encrypt with repeatable --recipient-file
    let blob_in = dir.path().join("blob.bin");
    let blob_out = dir.path().join("blob.bin.age");
    let blob_dec = dir.path().join("blob.dec");
    fs::write(&blob_in, b"blob-payload").expect("write blob");
    let blob_enc = run_seclusor(&[
        "secrets",
        "blob",
        "encrypt",
        "--input",
        blob_in.to_str().unwrap(),
        "--output",
        blob_out.to_str().unwrap(),
        "--recipient-file",
        rfile_a.to_str().unwrap(),
        "--recipient-file",
        rfile_b.to_str().unwrap(),
    ]);
    assert!(blob_enc.status.success());
    let blob_open_b = run_seclusor(&[
        "secrets",
        "blob",
        "decrypt",
        "--input",
        blob_out.to_str().unwrap(),
        "--output",
        blob_dec.to_str().unwrap(),
        "--identity-file",
        id_b.to_str().unwrap(),
    ]);
    assert!(blob_open_b.status.success());
    assert_eq!(fs::read(&blob_dec).unwrap(), b"blob-payload");
}

#[cfg(unix)]
#[test]
fn interactive_passphrase_fails_fast_when_detached_or_in_background_process_group() {
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().expect("tempdir");
    let out_id = dir.path().join("detached-id.txt");

    // Case 1: Detached session (`setsid`) — no controlling `/dev/tty`.
    let start = Instant::now();
    let mut detached = Command::new(seclusor_bin());
    detached
        .args([
            "keys",
            "age",
            "identity",
            "generate",
            "--output",
            out_id.to_str().unwrap(),
            "--passphrase",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: `setsid` is async-signal-safe between fork and exec.
    unsafe {
        detached.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let detached_out = detached.output().expect("run detached seclusor");
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(!detached_out.status.success());
    let stderr = String::from_utf8_lossy(&detached_out.stderr);
    assert!(
        stderr.contains("--passphrase-env") && stderr.contains("--passphrase-stdin"),
        "expected actionable stderr, got: {stderr}"
    );
    assert!(!out_id.exists(), "must not create partial identity file");

    // Case 2: Controlling `/dev/tty` exists on a PTY, and child calls `setpgid(0, 0)`
    // so it is in a BACKGROUND process group relative to the PTY foreground group
    // (exact reproduction of GNU `timeout` without `--foreground`). Without the
    // `tcgetpgrp(fd) == getpgrp()` check, opening `/dev/tty` and calling `tcsetattr`
    // stops the child with `SIGTTOU`!
    let mut master_fd: libc::c_int = -1;
    let mut slave_fd: libc::c_int = -1;
    // SAFETY: `openpty` initializes both descriptors on success.
    let rc = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty failed: {}", std::io::Error::last_os_error());

    // Fork a session leader that acquires `slave_fd` as its controlling terminal
    // (making the leader's pgrp the foreground pgrp of `/dev/tty`), then spawns
    // `seclusor` in its OWN background process group (`setpgid(0, 0)`) and waits
    // with `WUNTRACED` so a `SIGTTOU` stop would be caught immediately instead of hanging!
    let bg_out_id = dir.path().join("bg-id.txt");
    let mut pipe_fds = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);

    // SAFETY: single-threaded fork synchronization on `pipe_fds`; child uses only
    // async-signal-safe syscalls or exits via `_exit` on setup failure before `Command`.
    let leader_pid = unsafe { libc::fork() };
    assert!(leader_pid >= 0, "fork failed");

    if leader_pid == 0 {
        unsafe {
            libc::close(master_fd);
            libc::close(pipe_fds[0]);
            if libc::setsid() == -1 {
                libc::_exit(91);
            }
            if libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0) == -1 {
                libc::_exit(92);
            }
            libc::dup2(slave_fd, 0);
            libc::close(slave_fd);

            let mut cmd = Command::new(seclusor_bin());
            cmd.args([
                "keys",
                "age",
                "identity",
                "generate",
                "--output",
                bg_out_id.to_str().unwrap(),
                "--passphrase",
            ])
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
            let child = match cmd.spawn() {
                Ok(c) => c,
                Err(_) => libc::_exit(93),
            };
            let child_pid = child.id() as libc::pid_t;
            let mut status: libc::c_int = 0;
            if libc::waitpid(child_pid, &mut status, libc::WUNTRACED) == -1 {
                libc::_exit(94);
            }
            if libc::WIFSTOPPED(status) {
                libc::kill(child_pid, libc::SIGKILL);
                libc::_exit(95); // Stopped on SIGTTOU/SIGTTIN!
            }
            if let Some(mut child_stderr) = child.stderr {
                let mut buf = Vec::new();
                let _ = std::io::Read::read_to_end(&mut child_stderr, &mut buf);
                let _ = libc::write(pipe_fds[1], buf.as_ptr().cast(), buf.len());
            }
            libc::close(pipe_fds[1]);
            if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) != 0 {
                libc::_exit(0);
            }
            libc::_exit(96);
        }
    }

    unsafe {
        libc::close(slave_fd);
        libc::close(pipe_fds[1]);
    }
    let mut captured_stderr = Vec::new();
    {
        use std::os::fd::FromRawFd;
        let mut reader = unsafe { fs::File::from_raw_fd(pipe_fds[0]) };
        std::io::Read::read_to_end(&mut reader, &mut captured_stderr).expect("read stderr pipe");
    }
    let mut leader_status: libc::c_int = 0;
    assert_eq!(
        unsafe { libc::waitpid(leader_pid, &mut leader_status, 0) },
        leader_pid
    );
    unsafe {
        libc::close(master_fd);
    }

    assert!(
        libc::WIFEXITED(leader_status),
        "leader did not exit cleanly"
    );
    let code = libc::WEXITSTATUS(leader_status);
    assert_eq!(
        code,
        0,
        "background-pgrp child failed or stopped (code {code}); stderr={}",
        String::from_utf8_lossy(&captured_stderr)
    );
    let bg_stderr = String::from_utf8_lossy(&captured_stderr);
    assert!(
        bg_stderr.contains("--passphrase-env") && bg_stderr.contains("--passphrase-stdin"),
        "expected actionable stderr in background pgrp, got: {bg_stderr}"
    );
    assert!(!bg_out_id.exists());
}
