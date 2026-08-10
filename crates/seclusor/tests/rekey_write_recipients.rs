//! Process-boundary coverage for `secrets rekey --write-recipients`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn seclusor_bin() -> &'static str {
    env!("CARGO_BIN_EXE_seclusor")
}

fn run_seclusor(args: &[&str]) -> Output {
    Command::new(seclusor_bin())
        .args(args)
        .output()
        .expect("run seclusor")
}

fn run_seclusor_with_env(args: &[&str], name: &str, value: &Path) -> Output {
    Command::new(seclusor_bin())
        .args(args)
        .env(name, value)
        .output()
        .expect("run seclusor with env")
}

#[cfg(unix)]
fn run_seclusor_with_umask(args: &[&str], mask: libc::mode_t) -> Output {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new(seclusor_bin());
    command.args(args);
    // SAFETY: `umask` is async-signal-safe and runs in the child after fork,
    // immediately before exec. The parent test process is never modified.
    unsafe {
        command.pre_exec(move || {
            libc::umask(mask);
            Ok(())
        });
    }
    command.output().expect("run seclusor with umask")
}

fn write_plaintext_fixture(path: &Path) {
    fs::write(
        path,
        r#"{
  "schema_version": "v1.0.0",
  "projects": [
    {
      "project_slug": "demo",
      "credentials": {
        "API_KEY": {
          "type": "secret",
          "value": "sk-123"
        }
      }
    }
  ]
}
"#,
    )
    .expect("write fixture");
}

fn generate_identity(dir: &Path, name: &str) -> (PathBuf, String) {
    let path = dir.join(name);
    let output = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        path.to_str().expect("utf8 identity"),
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

#[derive(Clone, Copy)]
enum DocumentKind {
    Inline,
    Bundle,
}

impl DocumentKind {
    fn command(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Bundle => "bundle",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Inline => "json",
            Self::Bundle => "age",
        }
    }
}

struct EncryptedFixture {
    encrypted: PathBuf,
    old_identity: PathBuf,
    old_recipient: String,
}

fn prepare_encrypted(dir: &Path, kind: DocumentKind, stem: &str) -> EncryptedFixture {
    let plaintext = dir.join(format!("{stem}-plain.json"));
    write_plaintext_fixture(&plaintext);
    let (old_identity, old_recipient) = generate_identity(dir, &format!("{stem}-old-identity.txt"));
    let encrypted = dir.join(format!("{stem}.{}", kind.extension()));
    let output = run_seclusor(&[
        "secrets",
        kind.command(),
        "encrypt",
        "--input",
        plaintext.to_str().expect("utf8 plaintext"),
        "--output",
        encrypted.to_str().expect("utf8 encrypted"),
        "--recipient",
        &old_recipient,
    ]);
    assert!(
        output.status.success(),
        "encrypt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    EncryptedFixture {
        encrypted,
        old_identity,
        old_recipient,
    }
}

fn assert_decrypts_only_with(encrypted: &Path, accepted_identity: &Path, rejected_identity: &Path) {
    let accepted = run_seclusor(&[
        "secrets",
        "get",
        "--file",
        encrypted.to_str().expect("utf8 encrypted"),
        "--project",
        "demo",
        "--key",
        "API_KEY",
        "--identity-file",
        accepted_identity.to_str().expect("utf8 identity"),
        "--reveal",
    ]);
    assert!(
        accepted.status.success(),
        "new identity failed: {}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&accepted.stdout), "sk-123\n");

    let rejected = run_seclusor(&[
        "secrets",
        "get",
        "--file",
        encrypted.to_str().expect("utf8 encrypted"),
        "--project",
        "demo",
        "--key",
        "API_KEY",
        "--identity-file",
        rejected_identity.to_str().expect("utf8 identity"),
        "--reveal",
    ]);
    assert!(
        !rejected.status.success(),
        "old identity unexpectedly decrypted"
    );
    assert!(rejected.stdout.is_empty());
}

#[test]
fn explicit_refresh_is_canonical_and_never_implicit_for_inline_and_bundle() {
    for (index, kind) in [DocumentKind::Inline, DocumentKind::Bundle]
        .into_iter()
        .enumerate()
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let fixture = prepare_encrypted(dir.path(), kind, &format!("case-{index}"));
        let (new_identity_a, recipient_a) =
            generate_identity(dir.path(), &format!("new-a-{index}.txt"));
        let (_new_identity_b, recipient_b) =
            generate_identity(dir.path(), &format!("new-b-{index}.txt"));
        let recipient_file = dir.path().join("recipients.txt");
        let noncanonical = format!("{recipient_b}\n{recipient_a}\n{recipient_b}\n");
        fs::write(&recipient_file, &noncanonical).expect("seed recipient input");

        let no_refresh_output = dir
            .path()
            .join(format!("no-refresh-{index}.{}", kind.extension()));
        let no_refresh = run_seclusor(&[
            "secrets",
            "rekey",
            "--file",
            fixture.encrypted.to_str().expect("utf8 encrypted"),
            "--output",
            no_refresh_output.to_str().expect("utf8 output"),
            "--identity-file",
            fixture.old_identity.to_str().expect("utf8 old identity"),
            "--recipient-file",
            recipient_file.to_str().expect("utf8 recipients"),
            "--allow-recipient-mismatch",
        ]);
        assert!(
            no_refresh.status.success(),
            "no-refresh rekey failed: {}",
            String::from_utf8_lossy(&no_refresh.stderr)
        );
        assert_eq!(
            fs::read_to_string(&recipient_file).expect("recipient input"),
            noncanonical,
            "--recipient-file must never be rewritten implicitly"
        );

        let refreshed_output = dir
            .path()
            .join(format!("refreshed-{index}.{}", kind.extension()));
        let refreshed = run_seclusor(&[
            "secrets",
            "rekey",
            "--file",
            fixture.encrypted.to_str().expect("utf8 encrypted"),
            "--output",
            refreshed_output.to_str().expect("utf8 output"),
            "--identity-file",
            fixture.old_identity.to_str().expect("utf8 old identity"),
            "--recipient-file",
            recipient_file.to_str().expect("utf8 recipients"),
            "--write-recipients",
            recipient_file.to_str().expect("utf8 recipients"),
            "--allow-recipient-mismatch",
        ]);
        assert!(
            refreshed.status.success(),
            "refresh rekey failed: {}",
            String::from_utf8_lossy(&refreshed.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&refreshed.stdout),
            format!("{}\n", refreshed_output.display())
        );
        let stderr = String::from_utf8_lossy(&refreshed.stderr);
        assert!(stderr.contains("wrote recipient set to"));
        assert!(!stderr.contains("AGE-SECRET-KEY"));
        assert!(!stderr.contains("sk-123"));

        let mut canonical = [recipient_a, recipient_b];
        canonical.sort();
        assert_eq!(
            fs::read_to_string(&recipient_file).expect("refreshed recipient file"),
            format!("{}\n", canonical.join("\n"))
        );
        assert_decrypts_only_with(&refreshed_output, &new_identity_a, &fixture.old_identity);
    }
}

#[test]
fn dangerous_recipient_output_aliases_refuse_before_any_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = prepare_encrypted(dir.path(), DocumentKind::Inline, "alias");
    let before = fs::read(&fixture.encrypted).expect("before");

    for alias in [&fixture.encrypted, &fixture.old_identity] {
        let output = run_seclusor(&[
            "secrets",
            "rekey",
            "--file",
            fixture.encrypted.to_str().expect("utf8 encrypted"),
            "--identity-file",
            fixture.old_identity.to_str().expect("utf8 identity"),
            "--recipient",
            &fixture.old_recipient,
            "--write-recipients",
            alias.to_str().expect("utf8 alias"),
        ]);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("aliases"));
        assert_eq!(fs::read(&fixture.encrypted).expect("unchanged"), before);
    }

    let ciphertext_output = dir.path().join("rotated.json");
    let output = run_seclusor(&[
        "secrets",
        "rekey",
        "--file",
        fixture.encrypted.to_str().expect("utf8 encrypted"),
        "--output",
        ciphertext_output.to_str().expect("utf8 output"),
        "--identity-file",
        fixture.old_identity.to_str().expect("utf8 identity"),
        "--recipient",
        &fixture.old_recipient,
        "--write-recipients",
        ciphertext_output.to_str().expect("utf8 output"),
    ]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--output"));
    assert_eq!(fs::read(&fixture.encrypted).expect("unchanged"), before);
    assert!(!ciphertext_output.exists());
}

#[test]
fn discovered_identity_path_alias_refuses_before_any_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_home = dir.path().join("config");
    let seclusor_config = config_home.join("seclusor");
    fs::create_dir_all(&seclusor_config).expect("config directory");
    let identity = seclusor_config.join("identity.txt");
    let generated = run_seclusor(&[
        "keys",
        "age",
        "identity",
        "generate",
        "--output",
        identity.to_str().expect("utf8 identity"),
    ]);
    assert!(generated.status.success());
    let recipient = String::from_utf8(generated.stdout)
        .expect("utf8 recipient")
        .trim()
        .to_string();

    let plaintext = dir.path().join("plain.json");
    let encrypted = dir.path().join("secrets.json");
    write_plaintext_fixture(&plaintext);
    let encrypt = run_seclusor(&[
        "secrets",
        "inline",
        "encrypt",
        "--input",
        plaintext.to_str().expect("utf8 plaintext"),
        "--output",
        encrypted.to_str().expect("utf8 encrypted"),
        "--recipient",
        &recipient,
    ]);
    assert!(encrypt.status.success());
    let encrypted_before = fs::read(&encrypted).expect("encrypted before");
    let identity_before = fs::read(&identity).expect("identity before");

    let output = run_seclusor_with_env(
        &[
            "secrets",
            "rekey",
            "--file",
            encrypted.to_str().expect("utf8 encrypted"),
            "--identity-public-key",
            &recipient,
            "--recipient",
            &recipient,
            "--write-recipients",
            identity.to_str().expect("utf8 identity"),
        ],
        "XDG_CONFIG_HOME",
        &config_home,
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("identity source"));
    assert_eq!(
        fs::read(&encrypted).expect("encrypted after"),
        encrypted_before
    );
    assert_eq!(
        fs::read(&identity).expect("identity after"),
        identity_before
    );
}

#[test]
fn recipient_refresh_failure_reports_committed_rekey_and_empty_stdout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = prepare_encrypted(dir.path(), DocumentKind::Inline, "partial");
    let (new_identity, new_recipient) = generate_identity(dir.path(), "partial-new.txt");
    let missing_recipient_path = dir.path().join("missing-parent").join("recipients.txt");

    let output = run_seclusor(&[
        "secrets",
        "rekey",
        "--file",
        fixture.encrypted.to_str().expect("utf8 encrypted"),
        "--identity-file",
        fixture.old_identity.to_str().expect("utf8 old identity"),
        "--recipient",
        &new_recipient,
        "--write-recipients",
        missing_recipient_path.to_str().expect("utf8 recipients"),
        "--allow-recipient-mismatch",
    ]);
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "partial success keeps stdout pure"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("rekey output was committed"));
    assert!(stderr.contains("durable recipient source may remain stale"));
    assert!(!stderr.contains("AGE-SECRET-KEY"));
    assert!(!stderr.contains("sk-123"));
    assert!(!missing_recipient_path.exists());
    assert_decrypts_only_with(&fixture.encrypted, &new_identity, &fixture.old_identity);
}

#[cfg(unix)]
#[test]
fn recipient_file_modes_respect_umask_and_preserve_existing_mode() {
    use std::os::unix::fs::PermissionsExt;

    for (index, mask, expected_mode) in [(0, 0o022, 0o644), (1, 0o077, 0o600)] {
        let dir = tempfile::tempdir().expect("tempdir");
        let fixture = prepare_encrypted(dir.path(), DocumentKind::Inline, &format!("mode-{index}"));
        let recipient_file = dir.path().join("recipients.txt");
        let output = run_seclusor_with_umask(
            &[
                "secrets",
                "rekey",
                "--file",
                fixture.encrypted.to_str().expect("utf8 encrypted"),
                "--identity-file",
                fixture.old_identity.to_str().expect("utf8 identity"),
                "--recipient",
                &fixture.old_recipient,
                "--write-recipients",
                recipient_file.to_str().expect("utf8 recipients"),
            ],
            mask,
        );
        assert!(
            output.status.success(),
            "mode rekey failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mode = fs::metadata(&recipient_file)
            .expect("recipient metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, expected_mode);
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = prepare_encrypted(dir.path(), DocumentKind::Bundle, "existing-mode");
    let recipient_file = dir.path().join("recipients.txt");
    fs::write(&recipient_file, format!("{}\n", fixture.old_recipient)).expect("seed recipients");
    fs::set_permissions(&recipient_file, fs::Permissions::from_mode(0o664))
        .expect("set existing mode");
    let output = run_seclusor_with_umask(
        &[
            "secrets",
            "rekey",
            "--file",
            fixture.encrypted.to_str().expect("utf8 encrypted"),
            "--identity-file",
            fixture.old_identity.to_str().expect("utf8 identity"),
            "--recipient-file",
            recipient_file.to_str().expect("utf8 recipients"),
            "--write-recipients",
            recipient_file.to_str().expect("utf8 recipients"),
        ],
        0o077,
    );
    assert!(
        output.status.success(),
        "existing-mode rekey failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mode = fs::metadata(&recipient_file)
        .expect("recipient metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o664, "existing mode must be preserved");
}
