use napi::bindgen_prelude::*;
use napi_derive::napi;
use seclusor_codec::{decrypt_bundle_from_file, encrypt_bundle_to_file};
use seclusor_core::crud::{get_credential, list_credential_keys};
use seclusor_core::env::{export_env, EnvExportOptions};
use seclusor_core::validate::validate_strict;
use seclusor_core::SecretsFile;
use seclusor_crypto::{load_identity_file, parse_recipients};
use seclusor_keyring::generate_identity;
use serde::Serialize;

#[derive(Serialize)]
struct TsCredentialView {
    #[serde(rename = "type")]
    credential_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    reference: Option<String>,
    redacted: bool,
}

#[derive(Serialize)]
struct TsEnvVar {
    key: String,
    value: String,
}

#[derive(Serialize)]
struct TsGeneratedIdentity {
    identity: String,
    recipient: String,
}

fn parse_and_validate(input_json: &str) -> napi::Result<SecretsFile> {
    let parsed: SecretsFile = serde_json::from_str(input_json)
        .map_err(|e| Error::from_reason(format!("invalid JSON: {e}")))?;
    validate_strict(&parsed).map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(parsed)
}

#[napi]
pub fn validate_secrets_json(input_json: String) -> napi::Result<()> {
    let _ = parse_and_validate(&input_json)?;
    Ok(())
}

#[napi]
pub fn generate_identity_json() -> napi::Result<String> {
    let generated = generate_identity();
    let out = TsGeneratedIdentity {
        identity: generated.identity,
        recipient: generated.recipient,
    };
    serde_json::to_string(&out)
        .map_err(|e| Error::from_reason(format!("failed to serialize generated identity: {e}")))
}

#[napi]
pub fn list_keys(input_json: String, project: Option<String>) -> napi::Result<Vec<String>> {
    let secrets = parse_and_validate(&input_json)?;
    list_credential_keys(&secrets, project.as_deref())
        .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn get_credential_json(
    input_json: String,
    project: Option<String>,
    key: String,
    reveal: Option<bool>,
) -> napi::Result<String> {
    let secrets = parse_and_validate(&input_json)?;
    let credential = get_credential(&secrets, project.as_deref(), &key)
        .map_err(|e| Error::from_reason(e.to_string()))?;

    let reveal = reveal.unwrap_or(false);
    let value = if reveal {
        credential.value.clone()
    } else {
        None
    };

    let view = TsCredentialView {
        credential_type: credential.credential_type.clone(),
        value,
        reference: credential.reference.clone(),
        redacted: !reveal,
    };

    serde_json::to_string(&view)
        .map_err(|e| Error::from_reason(format!("failed to serialize credential view: {e}")))
}

#[napi]
pub fn export_env_json(
    input_json: String,
    project: Option<String>,
    prefix: Option<String>,
    include_refs: Option<bool>,
) -> napi::Result<String> {
    let secrets = parse_and_validate(&input_json)?;
    let options = EnvExportOptions {
        prefix,
        emit_ref: include_refs.unwrap_or(false),
        filter: Default::default(),
    };

    let vars = export_env(&secrets, project.as_deref(), &options)
        .map_err(|e| Error::from_reason(e.to_string()))?;
    let out: Vec<TsEnvVar> = vars
        .into_iter()
        .map(|entry| TsEnvVar {
            key: entry.key,
            value: entry.value,
        })
        .collect();

    serde_json::to_string(&out)
        .map_err(|e| Error::from_reason(format!("failed to serialize env export: {e}")))
}

#[napi]
pub fn encrypt_bundle(
    input_json_path: String,
    output_cipher_path: String,
    recipients_json: String,
) -> napi::Result<()> {
    let json_text = std::fs::read_to_string(&input_json_path)
        .map_err(|e| Error::from_reason(format!("failed to read input JSON file: {e}")))?;
    let secrets = parse_and_validate(&json_text)?;
    let recipients_raw: Vec<String> = serde_json::from_str(&recipients_json)
        .map_err(|e| Error::from_reason(format!("invalid recipients JSON array: {e}")))?;
    let recipients = parse_recipients(recipients_raw.iter().map(String::as_str))
        .map_err(|e| Error::from_reason(e.to_string()))?;
    encrypt_bundle_to_file(&secrets, &recipients, &output_cipher_path)
        .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn decrypt_bundle(
    input_cipher_path: String,
    output_json_path: String,
    identity_file_path: String,
) -> napi::Result<()> {
    let identities =
        load_identity_file(&identity_file_path).map_err(|e| Error::from_reason(e.to_string()))?;
    let secrets = decrypt_bundle_from_file(&input_cipher_path, &identities)
        .map_err(|e| Error::from_reason(e.to_string()))?;
    let bytes = serde_json::to_vec_pretty(&secrets)
        .map_err(|e| Error::from_reason(format!("failed to encode output JSON: {e}")))?;
    std::fs::write(output_json_path, bytes).map_err(|e| Error::from_reason(e.to_string()))
}
