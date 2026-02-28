use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    pub credentials: BTreeMap<String, Credential>,
}

/// A single credential with either a value or a reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
