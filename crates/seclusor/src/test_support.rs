use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use seclusor_core::{Credential, SecretsFile};
use seclusor_crypto::Identity;

use crate::io::write_secrets_file;

pub(crate) const TEST_IDENTITY: &str =
    "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

pub(crate) fn fixture_secrets() -> SecretsFile {
    let mut secrets = SecretsFile::new("demo");
    secrets.env_prefix = Some("APP_".to_string());
    secrets.projects[0].credentials.insert(
        "API_KEY".to_string(),
        Credential::with_value("secret", "sk-123"),
    );
    secrets.projects[0].credentials.insert(
        "VAULT".to_string(),
        Credential::with_ref("ref", "vault://demo"),
    );
    secrets
}

pub(crate) fn write_fixture_secrets(path: &Path, secrets: &SecretsFile) {
    write_secrets_file(path, secrets, true).expect("write fixture secrets");
}

pub(crate) fn write_raw_json(path: &Path, json: &str) {
    let mut file = fs::File::create(path).expect("create raw json");
    file.write_all(json.as_bytes()).expect("write raw json");
}

pub(crate) fn fixture_identity() -> Identity {
    TEST_IDENTITY.parse().expect("test identity should parse")
}

pub(crate) fn fixture_recipient_string() -> String {
    fixture_identity().to_public().to_string()
}

pub(crate) fn write_identity_file(path: &Path, identity: &str) {
    let recipient = fixture_identity().to_public().to_string();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .expect("create identity file");
        writeln!(file, "# public key: {recipient}").expect("write public key comment");
        writeln!(file, "{identity}").expect("write identity");
    }

    #[cfg(not(unix))]
    {
        fs::write(path, format!("# public key: {recipient}\n{identity}\n"))
            .expect("write identity file");
    }
}

pub(crate) fn blob_fixture_identity_and_recipient(
    dir: &std::path::Path,
) -> (PathBuf, seclusor_keyring::Recipient) {
    let identity_path = dir.join("blob-identity.txt");
    let generated =
        seclusor_keyring::generate_identity_file(&identity_path).expect("generate identity");
    let recipient: seclusor_keyring::Recipient =
        generated.recipient.parse().expect("parse recipient");
    (identity_path, recipient)
}

pub(crate) fn write_inline_encrypted_file(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    let inline = dir.join("inline-encrypted.json");
    let identity_file = dir.join("inline-identity.txt");
    let secrets = fixture_secrets();
    let recipients = vec![fixture_identity().to_public()];
    let encrypted = seclusor_codec::encrypt_inline(&secrets, &recipients).expect("inline encrypt");

    write_secrets_file(&inline, &encrypted, true).expect("write inline secrets");
    write_identity_file(&identity_file, TEST_IDENTITY);

    (inline, identity_file)
}
