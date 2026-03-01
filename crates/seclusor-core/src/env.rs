use crate::constants::{DEFAULT_CREDENTIAL_TYPE, INLINE_CIPHERTEXT_PREFIX};
use crate::error::{Result, SeclusorError};
use crate::model::{Credential, SecretsFile};

/// Format for environment variable export output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvFormat {
    /// `KEY=VALUE` (dotenv format).
    Dotenv,
    /// `export KEY=VALUE` (shell export format).
    Export,
    /// `{"KEY": "VALUE", ...}` (JSON object format).
    Json,
}

/// A single environment variable assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

/// Options for environment variable export.
#[derive(Debug, Clone, Default)]
pub struct EnvExportOptions {
    /// Prefix to prepend to credential keys (overrides file-level env_prefix).
    pub prefix: Option<String>,
    /// Whether to export ref credentials (normally errors).
    pub emit_ref: bool,
    /// Filter to include/exclude credentials by glob pattern.
    pub filter: EnvFilter,
}

/// Glob-based filter for which credentials to export.
#[derive(Debug, Clone)]
pub struct EnvFilter {
    /// Allow patterns (defaults to `["*"]`, meaning all).
    pub allow: Vec<String>,
    /// Deny patterns (defaults to empty).
    pub deny: Vec<String>,
}

impl Default for EnvFilter {
    fn default() -> Self {
        EnvFilter {
            allow: vec!["*".to_string()],
            deny: Vec::new(),
        }
    }
}

impl EnvFilter {
    /// Check if a key passes the filter (matches an allow pattern and no deny patterns).
    pub fn matches(&self, key: &str) -> bool {
        let allowed = self.allow.iter().any(|p| glob_match(p, key));
        let denied = self.deny.iter().any(|p| glob_match(p, key));
        allowed && !denied
    }
}

/// Export credentials from a secrets file as environment variables.
///
/// Inline-encrypted values (starting with `sec:age:v1:`) must be pre-decrypted
/// before calling this function. If encountered, returns `InlineEncrypted` error.
///
/// Ref credentials are excluded by default. Set `emit_ref` to include them.
pub fn export_env(
    sf: &SecretsFile,
    project_slug: Option<&str>,
    opts: &EnvExportOptions,
) -> Result<Vec<EnvVar>> {
    let idx = crate::crud::resolve_project_index(sf, project_slug)?;
    let project = &sf.projects[idx];

    let prefix = opts
        .prefix
        .as_deref()
        .or(sf.env_prefix.as_deref())
        .unwrap_or("");
    validate_export_prefix(prefix)?;

    let mut vars = Vec::new();

    for (key, cred) in &project.credentials {
        let env_key = format!("{}{}", prefix, key);
        if !is_safe_env_key(&env_key) {
            return Err(SeclusorError::Validation(format!(
                "invalid environment variable key {:?}",
                env_key
            )));
        }

        if !opts.filter.matches(&env_key) {
            continue;
        }

        match (&cred.value, &cred.reference) {
            (Some(_), Some(_)) => {
                return Err(SeclusorError::Validation(format!(
                    "credential {env_key:?} must set exactly one of value or ref"
                )));
            }
            (Some(v), None) => {
                if v.starts_with(INLINE_CIPHERTEXT_PREFIX) {
                    return Err(SeclusorError::InlineEncrypted(env_key));
                }
                vars.push(EnvVar {
                    key: env_key,
                    value: v.clone(),
                });
            }
            (None, Some(r)) => {
                if !opts.emit_ref {
                    return Err(SeclusorError::RefNotExportable(env_key));
                }
                vars.push(EnvVar {
                    key: env_key,
                    value: r.clone(),
                });
            }
            (None, None) => {
                return Err(SeclusorError::Validation(format!(
                    "credential {env_key:?} must set exactly one of value or ref"
                )));
            }
        }
    }

    Ok(vars)
}

/// Format environment variables in the specified output format.
pub fn format_env_vars(vars: &[EnvVar], format: EnvFormat) -> String {
    match format {
        EnvFormat::Dotenv => vars
            .iter()
            .map(|v| format!("{}={}", v.key, dotenv_escape(&v.value)))
            .collect::<Vec<_>>()
            .join("\n"),
        EnvFormat::Export => vars
            .iter()
            .map(|v| format!("export {}={}", v.key, shell_quote(&v.value)))
            .collect::<Vec<_>>()
            .join("\n"),
        EnvFormat::Json => {
            let map: serde_json::Map<String, serde_json::Value> = vars
                .iter()
                .map(|v| (v.key.clone(), serde_json::Value::String(v.value.clone())))
                .collect();
            serde_json::to_string_pretty(&map).unwrap_or_else(|_| "{}".to_string())
        }
    }
}

/// Import environment variable pairs as credentials.
///
/// Returns `(key, Credential)` pairs suitable for inserting into a project.
pub fn import_env_vars(
    vars: &[(String, String)],
    credential_type: Option<&str>,
    strip_prefix: Option<&str>,
) -> Vec<(String, Credential)> {
    let cred_type = credential_type.unwrap_or(DEFAULT_CREDENTIAL_TYPE);
    vars.iter()
        .filter_map(|(key, value)| {
            let key = match strip_prefix {
                Some(prefix) => key.strip_prefix(prefix).unwrap_or(key),
                None => key,
            };
            if key.is_empty() {
                return None;
            }
            Some((key.to_string(), Credential::with_value(cred_type, value)))
        })
        .collect()
}

/// Parse a dotenv-format string into key-value pairs.
///
/// Supports:
/// - `KEY=VALUE`
/// - `export KEY=VALUE`
/// - Single and double quoted values
/// - Comments (lines starting with `#`)
/// - Empty lines (skipped)
pub fn parse_dotenv(content: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = unquote(value.trim());
            if !key.is_empty() {
                result.push((key.to_string(), value));
            }
        }
    }
    result
}

/// Shell-escape a value with double quoting.
fn shell_quote(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`");
    format!("\"{}\"", escaped)
}

/// Escape a value for dotenv format — quote only when needed.
fn dotenv_escape(value: &str) -> String {
    if needs_quoting(value) {
        shell_quote(value)
    } else {
        value.to_string()
    }
}

fn needs_quoting(value: &str) -> bool {
    value.is_empty()
        || value.contains(' ')
        || value.contains('"')
        || value.contains('\'')
        || value.contains('\\')
        || value.contains('$')
        || value.contains('`')
        || value.contains('\n')
        || value.contains('\t')
        || value.contains('#')
        || value.contains('=')
}

fn validate_export_prefix(prefix: &str) -> Result<()> {
    if prefix.is_empty() {
        return Ok(());
    }

    if !is_safe_env_key(prefix) {
        return Err(SeclusorError::Validation(format!(
            "invalid env prefix {:?}; allowed pattern: ^[A-Z_][A-Z0-9_]*$",
            prefix
        )));
    }

    Ok(())
}

fn is_safe_env_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }

    let bytes = key.as_bytes();
    let first = bytes[0];
    if !(first.is_ascii_uppercase() || first == b'_') {
        return false;
    }

    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

/// Remove surrounding quotes from a value.
fn unquote(value: &str) -> String {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        return unescape_double_quoted(&value[1..value.len() - 1]);
    }
    if value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'') {
        return value[1..value.len() - 1].to_string();
    }
    value.to_string()
}

fn unescape_double_quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                match next {
                    '\\' | '"' | '$' | '`' => out.push(next),
                    _ => {
                        out.push('\\');
                        out.push(next);
                    }
                }
            } else {
                out.push('\\');
            }
        } else {
            out.push(ch);
        }
    }

    out
}

/// Simple glob pattern matching supporting `*` and `?`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_rec(&p, &t, 0, 0)
}

fn glob_match_rec(p: &[char], t: &[char], pi: usize, ti: usize) -> bool {
    if pi == p.len() {
        return ti == t.len();
    }
    match p[pi] {
        '*' => {
            for i in ti..=t.len() {
                if glob_match_rec(p, t, pi + 1, i) {
                    return true;
                }
            }
            false
        }
        '?' => ti < t.len() && glob_match_rec(p, t, pi + 1, ti + 1),
        c => ti < t.len() && t[ti] == c && glob_match_rec(p, t, pi + 1, ti + 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SecretsFile;

    fn test_file() -> SecretsFile {
        let mut sf = SecretsFile::new("myapp");
        sf.env_prefix = Some("APP_".to_string());
        sf.projects[0].credentials.insert(
            "API_KEY".to_string(),
            Credential::with_value("secret", "sk-123"),
        );
        sf.projects[0].credentials.insert(
            "DB_URL".to_string(),
            Credential::with_value("dsn", "postgres://localhost/db"),
        );
        sf
    }

    // --- glob matching ---

    #[test]
    fn glob_match_star() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("APP_*", "APP_KEY"));
        assert!(glob_match("APP_*", "APP_"));
        assert!(!glob_match("APP_*", "OTHER_KEY"));
    }

    #[test]
    fn glob_match_question() {
        assert!(glob_match("?", "A"));
        assert!(!glob_match("?", ""));
        assert!(!glob_match("?", "AB"));
        assert!(glob_match("A?C", "ABC"));
    }

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("API_KEY", "API_KEY"));
        assert!(!glob_match("API_KEY", "API_KEYS"));
        assert!(!glob_match("API_KEY", "API_KE"));
    }

    #[test]
    fn glob_match_suffix() {
        assert!(glob_match("*_SECRET", "APP_SECRET"));
        assert!(glob_match("*_SECRET", "MY_APP_SECRET"));
        assert!(!glob_match("*_SECRET", "APP_SECRETS"));
    }

    // --- env filter ---

    #[test]
    fn filter_default_allows_all() {
        let filter = EnvFilter::default();
        assert!(filter.matches("ANYTHING"));
    }

    #[test]
    fn filter_deny_overrides_allow() {
        let filter = EnvFilter {
            allow: vec!["*".to_string()],
            deny: vec!["SECRET_*".to_string()],
        };
        assert!(filter.matches("API_KEY"));
        assert!(!filter.matches("SECRET_TOKEN"));
    }

    // --- export ---

    #[test]
    fn export_with_prefix() {
        let sf = test_file();
        let opts = EnvExportOptions::default();
        let vars = export_env(&sf, None, &opts).unwrap();
        assert!(vars
            .iter()
            .any(|v| v.key == "APP_API_KEY" && v.value == "sk-123"));
        assert!(vars
            .iter()
            .any(|v| v.key == "APP_DB_URL" && v.value == "postgres://localhost/db"));
    }

    #[test]
    fn export_override_prefix() {
        let sf = test_file();
        let opts = EnvExportOptions {
            prefix: Some("MY_".to_string()),
            ..Default::default()
        };
        let vars = export_env(&sf, None, &opts).unwrap();
        assert!(vars.iter().any(|v| v.key == "MY_API_KEY"));
    }

    #[test]
    fn export_invalid_prefix_newline_rejected() {
        let sf = test_file();
        let opts = EnvExportOptions {
            prefix: Some("BAD_\nexport PWN=1".to_string()),
            ..Default::default()
        };
        let err = export_env(&sf, None, &opts).expect_err("must fail");
        assert!(matches!(err, SeclusorError::Validation(_)));
        assert!(err.to_string().contains("invalid env prefix"));
    }

    #[test]
    fn export_invalid_prefix_shell_metachar_rejected() {
        let sf = test_file();
        let opts = EnvExportOptions {
            prefix: Some("BAD;".to_string()),
            ..Default::default()
        };
        let err = export_env(&sf, None, &opts).expect_err("must fail");
        assert!(matches!(err, SeclusorError::Validation(_)));
        assert!(err.to_string().contains("invalid env prefix"));
    }

    #[test]
    fn export_invalid_prefix_leading_digit_rejected() {
        let sf = test_file();
        let opts = EnvExportOptions {
            prefix: Some("1BAD_".to_string()),
            ..Default::default()
        };
        let err = export_env(&sf, None, &opts).expect_err("must fail");
        assert!(matches!(err, SeclusorError::Validation(_)));
        assert!(err.to_string().contains("invalid env prefix"));
    }

    #[test]
    fn export_no_prefix() {
        let mut sf = test_file();
        sf.env_prefix = None;
        let opts = EnvExportOptions::default();
        let vars = export_env(&sf, None, &opts).unwrap();
        assert!(vars.iter().any(|v| v.key == "API_KEY"));
    }

    #[test]
    fn export_inline_encrypted_error() {
        let mut sf = test_file();
        sf.projects[0].credentials.insert(
            "ENC".to_string(),
            Credential::with_value("secret", "sec:age:v1:abc"),
        );
        let opts = EnvExportOptions::default();
        let err = export_env(&sf, None, &opts).unwrap_err();
        assert!(matches!(err, SeclusorError::InlineEncrypted(_)));
    }

    #[test]
    fn export_ref_not_exportable() {
        let mut sf = test_file();
        sf.projects[0].credentials.insert(
            "VAULT".to_string(),
            Credential::with_ref("dsn", "vault://x"),
        );
        let opts = EnvExportOptions::default();
        let err = export_env(&sf, None, &opts).unwrap_err();
        assert!(matches!(err, SeclusorError::RefNotExportable(_)));
    }

    #[test]
    fn export_ref_with_emit_ref() {
        let mut sf = SecretsFile::new("app");
        sf.projects[0].credentials.insert(
            "VAULT".to_string(),
            Credential::with_ref("dsn", "vault://x"),
        );
        let opts = EnvExportOptions {
            emit_ref: true,
            ..Default::default()
        };
        let vars = export_env(&sf, None, &opts).unwrap();
        assert!(vars
            .iter()
            .any(|v| v.key == "VAULT" && v.value == "vault://x"));
    }

    #[test]
    fn export_with_filter() {
        let sf = test_file();
        let opts = EnvExportOptions {
            filter: EnvFilter {
                allow: vec!["APP_API_*".to_string()],
                deny: vec![],
            },
            ..Default::default()
        };
        let vars = export_env(&sf, None, &opts).unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].key, "APP_API_KEY");
    }

    #[test]
    fn export_invalid_credential_both_value_and_ref_errors() {
        let mut sf = test_file();
        sf.projects[0].credentials.insert(
            "BROKEN".to_string(),
            Credential {
                credential_type: "secret".to_string(),
                value: Some("v".to_string()),
                reference: Some("vault://ref".to_string()),
                description: None,
            },
        );

        let opts = EnvExportOptions::default();
        let err = export_env(&sf, None, &opts).unwrap_err();
        assert!(matches!(err, SeclusorError::Validation(_)));
        assert!(err.to_string().contains("exactly one of value or ref"));
    }

    #[test]
    fn export_invalid_credential_neither_value_nor_ref_errors() {
        let mut sf = test_file();
        sf.projects[0].credentials.insert(
            "BROKEN".to_string(),
            Credential {
                credential_type: "secret".to_string(),
                value: None,
                reference: None,
                description: None,
            },
        );

        let opts = EnvExportOptions::default();
        let err = export_env(&sf, None, &opts).unwrap_err();
        assert!(matches!(err, SeclusorError::Validation(_)));
        assert!(err.to_string().contains("exactly one of value or ref"));
    }

    // --- format ---

    #[test]
    fn format_dotenv() {
        let vars = vec![
            EnvVar {
                key: "KEY".to_string(),
                value: "value".to_string(),
            },
            EnvVar {
                key: "OTHER".to_string(),
                value: "has space".to_string(),
            },
        ];
        let out = format_env_vars(&vars, EnvFormat::Dotenv);
        assert!(out.contains("KEY=value"));
        assert!(out.contains("OTHER=\"has space\""));
    }

    #[test]
    fn format_export() {
        let vars = vec![EnvVar {
            key: "KEY".to_string(),
            value: "val".to_string(),
        }];
        let out = format_env_vars(&vars, EnvFormat::Export);
        assert_eq!(out, "export KEY=\"val\"");
    }

    #[test]
    fn format_json() {
        let vars = vec![EnvVar {
            key: "A".to_string(),
            value: "1".to_string(),
        }];
        let out = format_env_vars(&vars, EnvFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["A"], "1");
    }

    // --- import ---

    #[test]
    fn import_env_vars_basic() {
        let vars = vec![
            ("API_KEY".to_string(), "sk-123".to_string()),
            ("DB_URL".to_string(), "postgres://...".to_string()),
        ];
        let result = import_env_vars(&vars, None, None);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "API_KEY");
        assert_eq!(result[0].1.credential_type, "secret");
        assert_eq!(result[0].1.value.as_deref(), Some("sk-123"));
    }

    #[test]
    fn import_with_custom_type() {
        let vars = vec![("KEY".to_string(), "val".to_string())];
        let result = import_env_vars(&vars, Some("token"), None);
        assert_eq!(result[0].1.credential_type, "token");
    }

    #[test]
    fn import_strip_prefix() {
        let vars = vec![
            ("APP_KEY".to_string(), "val".to_string()),
            ("OTHER".to_string(), "val2".to_string()),
        ];
        let result = import_env_vars(&vars, None, Some("APP_"));
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "KEY");
        assert_eq!(result[1].0, "OTHER"); // no prefix to strip
    }

    #[test]
    fn import_skip_empty_key_after_strip() {
        let vars = vec![("APP_".to_string(), "val".to_string())];
        let result = import_env_vars(&vars, None, Some("APP_"));
        assert!(result.is_empty());
    }

    // --- parse dotenv ---

    #[test]
    fn parse_dotenv_basic() {
        let content = "KEY=value\nOTHER=123\n";
        let result = parse_dotenv(content);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], ("KEY".to_string(), "value".to_string()));
        assert_eq!(result[1], ("OTHER".to_string(), "123".to_string()));
    }

    #[test]
    fn parse_dotenv_quoted() {
        let content = "KEY=\"hello world\"\nSINGLE='quoted'\n";
        let result = parse_dotenv(content);
        assert_eq!(result[0].1, "hello world");
        assert_eq!(result[1].1, "quoted");
    }

    #[test]
    fn parse_dotenv_unescapes_double_quoted_shell_escapes() {
        let content = "KEY=\"a\\$b \\\"quoted\\\" \\\\slash \\`tick\\`\"\n";
        let result = parse_dotenv(content);
        assert_eq!(result[0].1, "a$b \"quoted\" \\slash `tick`");
    }

    #[test]
    fn dotenv_format_parse_roundtrip_preserves_dollar_sign() {
        let vars = vec![EnvVar {
            key: "KEY".to_string(),
            value: "a$b".to_string(),
        }];
        let out = format_env_vars(&vars, EnvFormat::Dotenv);
        let parsed = parse_dotenv(&out);
        assert_eq!(parsed, vec![("KEY".to_string(), "a$b".to_string())]);
    }

    #[test]
    fn parse_dotenv_export_prefix() {
        let content = "export KEY=value\n";
        let result = parse_dotenv(content);
        assert_eq!(result[0], ("KEY".to_string(), "value".to_string()));
    }

    #[test]
    fn parse_dotenv_comments_and_blanks() {
        let content = "# comment\n\nKEY=val\n  # indented comment\n";
        let result = parse_dotenv(content);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ("KEY".to_string(), "val".to_string()));
    }
}
