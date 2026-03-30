use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use crate::constants::{INLINE_CIPHERTEXT_PREFIX, SCHEMA_VERSION};

/// A seclusor secrets file containing one or more projects.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsFile {
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub projects: Vec<Project>,
}

/// A project containing named credentials.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub project_slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(deserialize_with = "deserialize_credentials_map")]
    pub credentials: BTreeMap<String, Credential>,
}

/// A single credential with either a value or a reference.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Credential {
    #[serde(rename = "type")]
    pub credential_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ref")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl<'de> Deserialize<'de> for Credential {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["type", "value", "ref", "description"];

        enum Field {
            Type,
            Value,
            Ref,
            Description,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl Visitor<'_> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a credential field")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "type" => Ok(Field::Type),
                            "value" => Ok(Field::Value),
                            "ref" => Ok(Field::Ref),
                            "description" => Ok(Field::Description),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct CredentialVisitor;

        impl<'de> Visitor<'de> for CredentialVisitor {
            type Value = Credential;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a credential object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut credential_type = None;
                let mut value = None;
                let mut reference = None;
                let mut description = None;

                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Type => {
                            if credential_type.is_some() {
                                return Err(de::Error::duplicate_field("type"));
                            }
                            credential_type = Some(map.next_value()?);
                        }
                        Field::Value => {
                            if value.is_some() {
                                return Err(de::Error::duplicate_field("value"));
                            }
                            value = Some(map.next_value()?);
                        }
                        Field::Ref => {
                            if reference.is_some() {
                                return Err(de::Error::duplicate_field("ref"));
                            }
                            reference = Some(map.next_value()?);
                        }
                        Field::Description => {
                            if description.is_some() {
                                return Err(de::Error::duplicate_field("description"));
                            }
                            description = Some(map.next_value()?);
                        }
                    }
                }

                Ok(Credential {
                    credential_type: credential_type
                        .ok_or_else(|| de::Error::missing_field("type"))?,
                    value: value.unwrap_or(None),
                    reference: reference.unwrap_or(None),
                    description: description.unwrap_or(None),
                })
            }
        }

        deserializer.deserialize_map(CredentialVisitor)
    }
}

fn deserialize_credentials_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, Credential>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: BTreeMap<String, serde_json::Value> = BTreeMap::deserialize(deserializer)?;
    let mut credentials = BTreeMap::new();

    for (key, value) in raw {
        if !value.is_object() {
            return Err(de::Error::custom(credential_shape_message(
                &key,
                Some(value_kind(&value)),
            )));
        }

        let credential = serde_json::from_value::<Credential>(value)
            .map_err(|_| de::Error::custom(credential_shape_message(&key, None)))?;
        credentials.insert(key, credential);
    }

    Ok(credentials)
}

fn credential_shape_message(key: &str, actual_kind: Option<&str>) -> String {
    let mut message = format!(
        "credential {key:?} must be an object with \"type\" plus either \"value\" or \"ref\" string fields"
    );
    if let Some(kind) = actual_kind {
        message.push_str(&format!(", not {kind}"));
    }
    message.push_str(&format!(
        ". Use: seclusor secrets set --key {key} --value <value>"
    ));
    message
}

fn value_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

impl SecretsFile {
    /// Create a new secrets file with a single empty project.
    pub fn new(project_slug: &str) -> Self {
        SecretsFile {
            schema_version: SCHEMA_VERSION.to_string(),
            env_prefix: None,
            description: None,
            projects: vec![Project {
                project_slug: project_slug.to_string(),
                description: None,
                credentials: BTreeMap::new(),
            }],
        }
    }

    /// Returns true if any credential value is inline-encrypted.
    pub fn has_inline_ciphertext(&self) -> bool {
        self.projects
            .iter()
            .any(|p| p.credentials.values().any(|c| c.is_inline_encrypted()))
    }
}

impl Credential {
    /// Create a credential with a plaintext value.
    pub fn with_value(credential_type: &str, value: &str) -> Self {
        Credential {
            credential_type: credential_type.to_string(),
            value: Some(value.to_string()),
            reference: None,
            description: None,
        }
    }

    /// Create a credential with a reference.
    pub fn with_ref(credential_type: &str, reference: &str) -> Self {
        Credential {
            credential_type: credential_type.to_string(),
            value: None,
            reference: Some(reference.to_string()),
            description: None,
        }
    }

    /// Returns true if the value is inline-encrypted (starts with `sec:age:v1:`).
    pub fn is_inline_encrypted(&self) -> bool {
        self.value
            .as_ref()
            .is_some_and(|v| v.starts_with(INLINE_CIPHERTEXT_PREFIX))
    }

    /// Returns true if this credential is a reference (not a direct value).
    pub fn is_ref(&self) -> bool {
        self.reference.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_secrets_file() {
        let sf = SecretsFile::new("myapp");
        assert_eq!(sf.schema_version, "v1.0.0");
        assert_eq!(sf.projects.len(), 1);
        assert_eq!(sf.projects[0].project_slug, "myapp");
        assert!(sf.projects[0].credentials.is_empty());
        assert!(sf.env_prefix.is_none());
        assert!(sf.description.is_none());
    }

    #[test]
    fn serde_roundtrip_json() {
        let mut sf = SecretsFile::new("demo");
        sf.env_prefix = Some("DEMO_".to_string());
        sf.projects[0].credentials.insert(
            "API_KEY".to_string(),
            Credential::with_value("secret", "sk-123"),
        );
        sf.projects[0].credentials.insert(
            "DB_URL".to_string(),
            Credential::with_ref("dsn", "vault://db/url"),
        );

        let json = serde_json::to_string_pretty(&sf).unwrap();
        let parsed: SecretsFile = serde_json::from_str(&json).unwrap();
        assert_eq!(sf, parsed);
    }

    #[test]
    fn serde_wire_format() {
        let cred = Credential::with_value("secret", "hello");
        let json = serde_json::to_value(&cred).unwrap();
        assert_eq!(json["type"], "secret");
        assert_eq!(json["value"], "hello");
        assert!(json.get("ref").is_none());
        assert!(json.get("credential_type").is_none());
        assert!(json.get("reference").is_none());
    }

    #[test]
    fn serde_ref_wire_format() {
        let cred = Credential::with_ref("dsn", "vault://db");
        let json = serde_json::to_value(&cred).unwrap();
        assert_eq!(json["type"], "dsn");
        assert_eq!(json["ref"], "vault://db");
        assert!(json.get("value").is_none());
    }

    #[test]
    fn deny_unknown_fields() {
        let json = r#"{"type": "secret", "value": "x", "unknown": true}"#;
        let result: std::result::Result<Credential, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn reject_array_form_credentials() {
        let json = r#"["secret1", "secret2"]"#;
        let result: std::result::Result<Credential, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn bare_string_credential_error_names_key_and_hint() {
        let json = r#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"CLOUDFLARE_API_TOKEN":"cfat_example123"}}]}"#;
        let result: std::result::Result<SecretsFile, _> = serde_json::from_str(json);
        let err = result.expect_err("must fail").to_string();
        assert!(err.contains(r#"credential "CLOUDFLARE_API_TOKEN" must be an object"#));
        assert!(
            err.contains(r#"Use: seclusor secrets set --key CLOUDFLARE_API_TOKEN --value <value>"#)
        );
        assert!(!err.contains("cfat_example123"));
    }

    #[test]
    fn inline_encrypted_detection() {
        let plain = Credential::with_value("secret", "plaintext");
        assert!(!plain.is_inline_encrypted());

        let encrypted = Credential::with_value("secret", "sec:age:v1:YWdlLWVuY3J5cHRpb24=");
        assert!(encrypted.is_inline_encrypted());

        let refcred = Credential::with_ref("dsn", "vault://x");
        assert!(!refcred.is_inline_encrypted());
    }

    #[test]
    fn has_inline_ciphertext() {
        let mut sf = SecretsFile::new("app");
        assert!(!sf.has_inline_ciphertext());

        sf.projects[0]
            .credentials
            .insert("KEY".to_string(), Credential::with_value("secret", "plain"));
        assert!(!sf.has_inline_ciphertext());

        sf.projects[0].credentials.insert(
            "ENC".to_string(),
            Credential::with_value("secret", "sec:age:v1:abc123"),
        );
        assert!(sf.has_inline_ciphertext());
    }
}
