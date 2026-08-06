//! Child-environment construction chokepoint for `secrets run`.
//!
//! All production mutation of a child process environment (`Command::env_clear`,
//! `Command::env`, etc.) must go through [`ChildEnv::apply`]. Construction always
//! requires an explicit [`ExcludedNames`] argument so omission does not compile.
//!
//! Under [`BasePolicy::InheritAmbient`], the effective environment is **snapshotted
//! at build time** (ambient − excluded + injected) and applied with `env_clear` +
//! explicit sets. That is closed construction of an inherit-width base — not
//! 008-B clean-env (minimal base). It closes the scan-to-spawn ambient TOCTOU
//! that live inheritance would leave open.
//!
//! **Load-bearing invariant:** empty passphrases are rejected by every resolve
//! channel (`resolve.rs`) and again at [`ChildEnv::build`]. The terminal
//! value-equality assertion therefore never false-positives against
//! legitimately empty ambient variables.

use std::ffi::{OsStr, OsString};
use std::process::Command;

use seclusor_core::env::EnvVar;
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;

/// How the child base environment is formed.
///
/// `InheritAmbient` is the only policy shipped in 0.2.1. A future clean-base
/// policy is a separate base-*width* decision (not what provides the exclusion
/// guarantee).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BasePolicy {
    InheritAmbient,
}

/// Names that must never appear in the child environment.
///
/// Construct via [`ExcludedNames::none`] or [`ExcludedNames::from_names`].
/// There is no `Default` and no `Option` — callers must declare exclusion explicitly.
/// Channel-agnostic so a future library/FFI spawn helper can reuse this type
/// without a CLI/`clap` dependency.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ExcludedNames {
    names: Vec<String>,
}

impl ExcludedNames {
    /// Explicit empty exclusion set (no passphrase-env channel).
    pub(crate) fn none() -> Self {
        Self { names: Vec::new() }
    }

    /// Build an exclusion set from explicit variable names.
    pub(crate) fn from_names(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            names: names.into_iter().map(Into::into).collect(),
        }
    }

    pub(crate) fn contains_name(&self, candidate: &str) -> bool {
        self.names
            .iter()
            .any(|name| env_names_equal(name, candidate))
    }

    fn contains_os_name(&self, candidate: &OsStr) -> bool {
        match candidate.to_str() {
            Some(s) => self.contains_name(s),
            // Non-UTF-8 names cannot equal our UTF-8 excluded passphrase-env names.
            None => false,
        }
    }
}

/// Errors from child-environment construction. Diagnostics name variables only —
/// never passphrase or credential values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChildEnvError {
    /// An injected store key name equals an excluded passphrase-env name.
    PassphraseVarCollision { name: String },
    /// Some effective child env entry's value equals the resolved passphrase.
    PassphraseValueExposure { var_name: String },
    /// Resolved passphrase was empty (must be rejected by resolve channels).
    EmptyPassphrase,
}

impl std::fmt::Display for ChildEnvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PassphraseVarCollision { name } => write!(
                f,
                "refusing to inject store key `{name}`: name collides with the \
                 identity passphrase environment variable"
            ),
            Self::PassphraseValueExposure { var_name } => write!(
                f,
                "refusing to run: environment variable `{var_name}` would expose \
                 the identity passphrase to the child process"
            ),
            Self::EmptyPassphrase => {
                write!(f, "refusing to run: resolved identity passphrase is empty")
            }
        }
    }
}

impl std::error::Error for ChildEnvError {}

/// A fully verified child environment ready to apply to a `Command`.
///
/// Holds the frozen effective map so apply does not re-inherit a mutating ambient.
///
/// **No `Debug` derive** — entries hold injected credential values and ambient
/// copies; formatting must never print them.
pub(crate) struct ChildEnv {
    /// Ordered (key, value) pairs for the child after clear.
    entries: Vec<(OsString, OsString)>,
}

impl std::fmt::Debug for ChildEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildEnv")
            .field(
                "entries",
                &format_args!("[{} redacted]", self.entries.len()),
            )
            .finish()
    }
}

impl ChildEnv {
    /// Build and verify a child environment.
    ///
    /// `excluded` is a required parameter (not `Option`). Use
    /// [`ExcludedNames::none`] for an intentional empty set.
    ///
    /// When `passphrase` is `Some`, performs a terminal value-equality assertion
    /// over the **effective** child environment (snapshotted ambient under
    /// `InheritAmbient`, after exclusions and injection override precedence).
    pub(crate) fn build(
        base: BasePolicy,
        injected: &[EnvVar],
        excluded: &ExcludedNames,
        passphrase: Option<&SecretString>,
    ) -> Result<Self, ChildEnvError> {
        // Name collision: fail closed before any spawn path exists.
        for env in injected {
            if excluded.contains_name(&env.key) {
                return Err(ChildEnvError::PassphraseVarCollision {
                    name: env.key.clone(),
                });
            }
        }

        if let Some(pp) = passphrase {
            // Release-path hard check: empty rejection is load-bearing for value equality.
            if pp.expose_secret().is_empty() {
                return Err(ChildEnvError::EmptyPassphrase);
            }
        }

        let entries = match base {
            BasePolicy::InheritAmbient => snapshot_inherit_ambient(injected, excluded),
        };

        if let Some(pp) = passphrase {
            for (key, value) in &entries {
                if value_os_equals_passphrase(value, pp) {
                    return Err(ChildEnvError::PassphraseValueExposure {
                        var_name: display_env_name(key),
                    });
                }
            }
        }

        Ok(Self { entries })
    }

    /// Apply this environment to `command`. Sole production site for child
    /// env mutations (`env_clear` + `env`).
    pub(crate) fn apply(self, command: &mut Command) {
        // child-env-callsite: apply-env-clear
        command.env_clear();
        for (key, value) in &self.entries {
            // child-env-callsite: apply-env-set
            command.env(key, value);
        }
    }
}

/// Platform-correct environment name equality.
///
/// Windows: case-insensitive with **Unicode** default case mapping (not
/// ASCII-only `eq_ignore_ascii_case`). Unix: case-sensitive exact match.
pub(crate) fn env_names_equal(a: &str, b: &str) -> bool {
    #[cfg(windows)]
    {
        // Windows environment variable names are case-insensitive. Use full
        // Unicode case conversion so non-ASCII case pairs (e.g. É/é) match the
        // platform model rather than ASCII-only folding.
        a.to_uppercase() == b.to_uppercase()
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

fn display_env_name(name: &OsStr) -> String {
    match name.to_str() {
        Some(s) => s.to_owned(),
        None => "<non-utf8-name>".to_owned(),
    }
}

fn value_equals_passphrase(value: &str, passphrase: &SecretString) -> bool {
    let left = value.as_bytes();
    let right = passphrase.expose_secret().as_bytes();
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn value_os_equals_passphrase(value: &OsStr, passphrase: &SecretString) -> bool {
    match value.to_str() {
        Some(s) => value_equals_passphrase(s, passphrase),
        // Non-UTF-8 values cannot equal a UTF-8 passphrase string.
        None => false,
    }
}

fn os_name_matches_injected(name: &OsStr, injected: &[EnvVar]) -> bool {
    match name.to_str() {
        Some(s) => injected.iter().any(|env| env_names_equal(&env.key, s)),
        None => false,
    }
}

/// Snapshot ambient − excluded + injected into an explicit entry list.
fn snapshot_inherit_ambient(
    injected: &[EnvVar],
    excluded: &ExcludedNames,
) -> Vec<(OsString, OsString)> {
    let mut entries: Vec<(OsString, OsString)> = Vec::new();

    for (key, value) in std::env::vars_os() {
        if excluded.contains_os_name(&key) {
            continue;
        }
        if os_name_matches_injected(&key, injected) {
            // Injection overrides ambient; the injected value is added below.
            continue;
        }
        entries.push((key, value));
    }

    for env in injected {
        // On Windows, drop any residual ambient key that case-matches before insert.
        #[cfg(windows)]
        {
            entries.retain(|(k, _)| match k.to_str() {
                Some(s) => !env_names_equal(s, &env.key),
                None => true,
            });
        }
        entries.push((OsString::from(&env.key), OsString::from(&env.value)));
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use seclusor_core::env::EnvVar;
    use std::sync::Mutex;

    /// Process-global env mutations must not interleave across parallel tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn pp(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    fn inj(key: &str, value: &str) -> EnvVar {
        EnvVar {
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }

    #[test]
    fn excluded_names_none_is_explicit_empty() {
        assert!(!ExcludedNames::none().contains_name("ANY"));
    }

    #[test]
    fn from_names_explicit_channel() {
        let ex = ExcludedNames::from_names(["MY_PP".to_string()]);
        assert!(ex.contains_name("MY_PP"));
        #[cfg(windows)]
        assert!(ex.contains_name("my_pp"));
        #[cfg(not(windows))]
        assert!(!ex.contains_name("my_pp"));
    }

    #[test]
    fn debug_does_not_render_entry_values() {
        let child = ChildEnv::build(
            BasePolicy::InheritAmbient,
            &[inj("APP_SECRET_KEY", "super-secret-value-must-not-print")],
            &ExcludedNames::none(),
            None,
        )
        .expect("build");
        let rendered = format!("{child:?}");
        assert!(
            rendered.contains("redacted"),
            "Debug must mark entries redacted: {rendered}"
        );
        assert!(
            !rendered.contains("super-secret-value-must-not-print"),
            "Debug must not print entry values: {rendered}"
        );
        assert!(
            !rendered.contains("APP_SECRET_KEY"),
            "Debug must not print entry keys either: {rendered}"
        );
    }

    #[test]
    fn collision_fails_closed() {
        let excluded = ExcludedNames {
            names: vec!["MY_PP".to_string()],
        };
        let injected = [inj("MY_PP", "store-value")];
        let err = ChildEnv::build(
            BasePolicy::InheritAmbient,
            &injected,
            &excluded,
            Some(&pp("secret-pp")),
        )
        .expect_err("collision");
        assert!(matches!(
            err,
            ChildEnvError::PassphraseVarCollision { ref name } if name == "MY_PP"
        ));
        let rendered = err.to_string();
        assert!(rendered.contains("MY_PP"));
        assert!(!rendered.contains("secret-pp"));
        assert!(!rendered.contains("store-value"));
    }

    #[test]
    fn empty_passphrase_fails_closed_on_release_path() {
        let err = ChildEnv::build(
            BasePolicy::InheritAmbient,
            &[inj("APP_KEY", "v")],
            &ExcludedNames::none(),
            Some(&pp("")),
        )
        .expect_err("empty");
        assert!(matches!(err, ChildEnvError::EmptyPassphrase));
        // Diagnostic must not include a passphrase *value* (empty has none).
        assert!(!err.to_string().contains("secret"));
    }

    #[test]
    fn injected_value_equals_passphrase_fails_closed() {
        let excluded = ExcludedNames::none();
        let secret = "unit-test-pp-value-not-production";
        let injected = [inj("APP_KEY", secret)];
        let err = ChildEnv::build(
            BasePolicy::InheritAmbient,
            &injected,
            &excluded,
            Some(&pp(secret)),
        )
        .expect_err("value exposure");
        assert!(matches!(
            err,
            ChildEnvError::PassphraseValueExposure { ref var_name } if var_name == "APP_KEY"
        ));
        assert!(!err.to_string().contains(secret));
    }

    #[test]
    fn ambient_alias_equals_passphrase_fails_closed() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let excluded = ExcludedNames {
            names: vec!["NAMED_PP".to_string()],
        };
        let secret = "unit-test-alias-pp-value";
        let alias = "SECLUSOR_TEST_CHILD_ENV_ALIAS";
        std::env::set_var(alias, secret);
        std::env::remove_var("NAMED_PP");
        let result = ChildEnv::build(
            BasePolicy::InheritAmbient,
            &[inj("APP_KEY", "not-the-pp")],
            &excluded,
            Some(&pp(secret)),
        );
        std::env::remove_var(alias);
        let err = result.expect_err("alias must fail closed");
        match &err {
            ChildEnvError::PassphraseValueExposure { var_name } => {
                assert_eq!(var_name, alias);
            }
            other => panic!("unexpected: {other}"),
        }
        assert!(!err.to_string().contains(secret));
    }

    #[test]
    fn safe_injection_override_of_ambient_alias_does_not_false_fail() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let excluded = ExcludedNames::none();
        let secret = "unit-test-override-pp-value";
        let key = "SECLUSOR_TEST_CHILD_ENV_OVERRIDE";
        std::env::set_var(key, secret);
        let result = ChildEnv::build(
            BasePolicy::InheritAmbient,
            &[inj(key, "injected-safe-value")],
            &excluded,
            Some(&pp(secret)),
        );
        std::env::remove_var(key);
        result.expect("overridden ambient must not false-fail");
    }

    #[test]
    fn excluded_ambient_name_is_not_value_checked() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let excluded = ExcludedNames {
            names: vec!["SECLUSOR_TEST_CHILD_ENV_EXCLUDED".to_string()],
        };
        let secret = "unit-test-excluded-pp-value";
        std::env::set_var("SECLUSOR_TEST_CHILD_ENV_EXCLUDED", secret);
        let result = ChildEnv::build(
            BasePolicy::InheritAmbient,
            &[inj("APP_KEY", "ok")],
            &excluded,
            Some(&pp(secret)),
        );
        std::env::remove_var("SECLUSOR_TEST_CHILD_ENV_EXCLUDED");
        result.expect("excluded ambient name is removed, not value-checked");
    }

    #[test]
    fn build_without_passphrase_skips_value_assert() {
        let excluded = ExcludedNames {
            names: vec!["MY_PP".to_string()],
        };
        ChildEnv::build(
            BasePolicy::InheritAmbient,
            &[inj("APP_KEY", "v")],
            &excluded,
            None,
        )
        .expect("no passphrase => no value assert");
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_ambient_key_with_passphrase_value_fails_closed() {
        use std::os::unix::ffi::OsStringExt;

        let _guard = ENV_LOCK.lock().expect("env lock");
        let secret = "unit-test-nonutf8-key-pp";
        // Construct a non-UTF-8 env key with the passphrase as its value.
        let key = OsString::from_vec(vec![0xff, 0xfe, b'x']);
        // SAFETY: test-only; restored below. libc setenv for non-utf8 keys.
        // std::env::set_var requires OsStr which we have.
        std::env::set_var(&key, secret);
        let result = ChildEnv::build(
            BasePolicy::InheritAmbient,
            &[inj("APP_KEY", "ok")],
            &ExcludedNames::none(),
            Some(&pp(secret)),
        );
        std::env::remove_var(&key);
        let err = result.expect_err("non-utf8 key must still value-check");
        match &err {
            ChildEnvError::PassphraseValueExposure { var_name } => {
                assert_eq!(var_name, "<non-utf8-name>");
            }
            other => panic!("unexpected: {other}"),
        }
        assert!(!err.to_string().contains(secret));
    }

    #[test]
    fn apply_snapshots_excluded_and_injected() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let excluded = ExcludedNames {
            names: vec!["SECLUSOR_TEST_CHILD_ENV_REMOVE".to_string()],
        };
        std::env::set_var("SECLUSOR_TEST_CHILD_ENV_REMOVE", "should-not-reach-child");
        let child = ChildEnv::build(
            BasePolicy::InheritAmbient,
            &[inj("SECLUSOR_TEST_CHILD_ENV_INJECT", "sentinel-present")],
            &excluded,
            None,
        )
        .expect("build");

        #[cfg(unix)]
        let mut command = {
            let mut c = Command::new("sh");
            c.args([
                "-c",
                r#"if [ -n "${SECLUSOR_TEST_CHILD_ENV_REMOVE:-}" ]; then exit 11; fi; \
                   if [ "${SECLUSOR_TEST_CHILD_ENV_INJECT}" != "sentinel-present" ]; then exit 12; fi; \
                   if [ -z "${PATH:-}" ]; then exit 13; fi; \
                   exit 0"#,
            ]);
            c
        };
        #[cfg(windows)]
        let mut command = {
            let mut c = Command::new("cmd");
            c.args([
                "/C",
                "if defined SECLUSOR_TEST_CHILD_ENV_REMOVE (exit 11) else if not \"%SECLUSOR_TEST_CHILD_ENV_INJECT%\"==\"sentinel-present\" (exit 12) else if not defined PATH (exit 13) else (exit 0)",
            ]);
            c
        };
        child.apply(&mut command);
        let status = command.status().expect("spawn");
        std::env::remove_var("SECLUSOR_TEST_CHILD_ENV_REMOVE");
        assert!(status.success(), "status={status}");
    }

    #[cfg(windows)]
    #[test]
    fn windows_case_variant_exclusion_and_collision() {
        let excluded = ExcludedNames::from_names(["My_Pp"]);
        let err = ChildEnv::build(
            BasePolicy::InheritAmbient,
            &[inj("my_pp", "store")],
            &excluded,
            Some(&pp("win-pp-secret")),
        )
        .expect_err("case-insensitive collision");
        assert!(matches!(err, ChildEnvError::PassphraseVarCollision { .. }));
        assert!(excluded.contains_name("MY_PP"));
        assert!(excluded.contains_name("my_pp"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_non_ascii_case_variant_collision_and_exclusion() {
        // Unicode case pair (not ASCII-only folding): É / é.
        let excluded = ExcludedNames::from_names(["MY_PP_É"]);
        assert!(
            excluded.contains_name("my_pp_é"),
            "Windows must fold non-ASCII case pairs"
        );
        let err = ChildEnv::build(
            BasePolicy::InheritAmbient,
            &[inj("my_pp_é", "store")],
            &excluded,
            Some(&pp("win-unicode-pp")),
        )
        .expect_err("non-ASCII case-insensitive collision");
        assert!(matches!(err, ChildEnvError::PassphraseVarCollision { .. }));
    }

    #[cfg(windows)]
    #[test]
    fn windows_case_variant_ambient_excluded_on_apply() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        // Ambient MY_PP; exclude my_pp — snapshot must omit it.
        std::env::set_var("MY_PP", "win-case-pp-secret");
        let excluded = ExcludedNames::from_names(["my_pp"]);
        let child = ChildEnv::build(
            BasePolicy::InheritAmbient,
            &[inj("SECLUSOR_TEST_CHILD_ENV_INJECT", "sentinel-present")],
            &excluded,
            Some(&pp("win-case-pp-secret")),
        )
        .expect("build should succeed: ambient MY_PP excluded by case-insensitive name");
        let mut command = Command::new("cmd");
        command.args([
            "/C",
            "if defined MY_PP (exit 11) else if defined my_pp (exit 12) else if not \"%SECLUSOR_TEST_CHILD_ENV_INJECT%\"==\"sentinel-present\" (exit 13) else (exit 0)",
        ]);
        child.apply(&mut command);
        let status = command.status().expect("spawn");
        std::env::remove_var("MY_PP");
        assert!(status.success(), "status={status}");
    }

    #[cfg(windows)]
    #[test]
    fn windows_non_ascii_ambient_case_variant_excluded_on_apply() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let ambient = "MY_PP_É";
        let exclude = "my_pp_é";
        std::env::set_var(ambient, "win-unicode-pp-secret");
        let excluded = ExcludedNames::from_names([exclude]);
        let child = ChildEnv::build(
            BasePolicy::InheritAmbient,
            &[inj("SECLUSOR_TEST_CHILD_ENV_INJECT", "sentinel-present")],
            &excluded,
            Some(&pp("win-unicode-pp-secret")),
        )
        .expect("non-ASCII ambient must be excluded by case-insensitive name");
        // Child must not see the passphrase value under either casing.
        let mut command = Command::new("cmd");
        command.args([
            "/C",
            "if defined MY_PP_É (exit 11) else if not \"%SECLUSOR_TEST_CHILD_ENV_INJECT%\"==\"sentinel-present\" (exit 12) else (exit 0)",
        ]);
        child.apply(&mut command);
        let status = command.status().expect("spawn");
        std::env::remove_var(ambient);
        assert!(status.success(), "status={status}");
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_case_sensitive_names_are_distinct() {
        let excluded = ExcludedNames {
            names: vec!["My_Pp".to_string()],
        };
        ChildEnv::build(
            BasePolicy::InheritAmbient,
            &[inj("my_pp", "store")],
            &excluded,
            None,
        )
        .expect("unix case-sensitive: my_pp != My_Pp");
        assert!(!excluded.contains_name("my_pp"));
    }
}
