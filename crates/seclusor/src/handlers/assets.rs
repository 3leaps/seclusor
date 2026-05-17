use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use seclusor_sign::{
    encode_base64url, envelope_to_json_pretty, load_signing_key_file, parse_fingerprint_text,
    parse_public_key_text, sign_asset, verify_asset, SignOptions, SignerMetadata, VerifyOptions,
};

use crate::cli::{AssetSignArgs, AssetVerifyArgs};
use crate::error::{CliError, CliResult};
use crate::resolve::resolve_identities;

const MAX_SIGNATURE_FILE_BYTES: u64 = 64 * 1024;

pub(crate) fn handle_asset_sign(args: AssetSignArgs) -> CliResult<()> {
    let identities = resolve_identities(&args.identities, &args.passphrase, true)?;
    let signing_key = load_signing_key_file(&args.signing_key, &identities)?;
    let input = File::open(&args.input)?;
    let envelope = sign_asset(
        input,
        &signing_key,
        &SignOptions {
            signer: SignerMetadata {
                label: args.signer_label,
                claimed_at: args.claimed_at,
            },
        },
    )?;
    let signature_path = args
        .signature
        .unwrap_or_else(|| default_signature_path(&args.input));
    let json = envelope_to_json_pretty(&envelope)?;
    fs::write(signature_path, format!("{json}\n"))?;
    Ok(())
}

pub(crate) fn handle_asset_verify(args: AssetVerifyArgs) -> CliResult<()> {
    let signature_path = args
        .signature
        .unwrap_or_else(|| default_signature_path(&args.input));
    let signature_json = read_signature_file(&signature_path)?;
    let input = File::open(&args.input)?;
    let verification = verify_asset(
        input,
        &signature_json,
        &VerifyOptions {
            expected_public_key: args
                .public_key
                .as_deref()
                .map(parse_public_key_text)
                .transpose()?,
            expected_fingerprint: args
                .fingerprint
                .as_deref()
                .map(parse_fingerprint_text)
                .transpose()?,
            trust_embedded_key: args.trust_embedded_key,
        },
    )?;
    println!("verified=true");
    println!("public_key={}", encode_base64url(&verification.public_key));
    println!(
        "key_fingerprint={}",
        encode_base64url(&verification.key_fingerprint)
    );
    if let Some(label) = verification.signer.label {
        println!("signer_label={}", escape_line_value(&label));
    }
    if let Some(claimed_at) = verification.signer.claimed_at {
        println!("claimed_at={}", escape_line_value(&claimed_at));
    }
    Ok(())
}

fn default_signature_path(input: &Path) -> PathBuf {
    let mut out: OsString = input.as_os_str().to_owned();
    out.push(".secsig");
    PathBuf::from(out)
}

fn read_signature_file(path: &Path) -> CliResult<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut limited = std::io::Read::by_ref(&mut file).take(MAX_SIGNATURE_FILE_BYTES + 1);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_SIGNATURE_FILE_BYTES {
        return Err(CliError::Message(format!(
            "signature file exceeds maximum size of {MAX_SIGNATURE_FILE_BYTES} bytes"
        )));
    }
    Ok(buf)
}

fn escape_line_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                out.push_str("\\u{");
                out.push_str(&format!("{:x}", ch as u32));
                out.push('}');
            }
            ch => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{IdentityArgs, PassphraseArgs};
    use crate::test_support::write_identity_file;

    #[test]
    fn asset_sign_and_verify_roundtrip_with_public_key() {
        let dir = tempfile::tempdir().expect("temp dir");
        let identity = seclusor_crypto::Identity::generate();
        let recipient = identity.to_public();
        let identity_path = dir.path().join("identity.txt");
        write_identity_file(
            &identity_path,
            &seclusor_crypto::identity_to_string(&identity),
        );

        let signing_key_path = dir.path().join("release-signing.key.age");
        let generated = seclusor_sign::generate_signing_key_file(&signing_key_path, &[recipient])
            .expect("generate signing key");

        let asset = dir.path().join("asset.bin");
        fs::write(&asset, b"release asset bytes").expect("write asset");
        let signature = dir.path().join("asset.bin.secsig");

        handle_asset_sign(AssetSignArgs {
            input: asset.clone(),
            signature: Some(signature.clone()),
            signing_key: signing_key_path,
            signer_label: Some("release-signing".to_string()),
            claimed_at: Some("2026-05-17T12:00:00Z".to_string()),
            identities: IdentityArgs {
                identity_files: vec![identity_path],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("sign asset");

        handle_asset_verify(AssetVerifyArgs {
            input: asset,
            signature: Some(signature),
            public_key: Some(encode_base64url(&generated.public_key)),
            fingerprint: None,
            trust_embedded_key: false,
        })
        .expect("verify asset");
    }

    #[test]
    fn default_signature_path_appends_secsig() {
        assert_eq!(
            default_signature_path(Path::new("dist/archive.tar.gz")),
            PathBuf::from("dist/archive.tar.gz.secsig")
        );
    }

    #[test]
    fn escape_line_value_keeps_verify_output_line_oriented() {
        assert_eq!(
            escape_line_value("release\nsigning\tlabel\\x"),
            "release\\nsigning\\tlabel\\\\x"
        );
    }
}
