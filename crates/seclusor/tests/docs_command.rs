use std::process::Command;

fn run_seclusor(args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_seclusor");
    Command::new(bin).args(args).output().expect("run seclusor")
}

#[test]
fn docs_list_json_includes_expected_slugs() {
    let output = run_seclusor(&["docs", "list", "--format", "json"]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stderr).expect("utf8 stderr"), "");

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let rows: Vec<serde_json::Value> = serde_json::from_str(&stdout).expect("valid json");
    let slugs: Vec<String> = rows
        .iter()
        .filter_map(|row| row["slug"].as_str().map(ToOwned::to_owned))
        .collect();

    assert!(slugs.contains(&"quickstart".to_string()));
    assert!(slugs.contains(&"cli-reference".to_string()));
    assert!(slugs.contains(&"decisions/ADR-0002-age-as-default-encryption-backend".to_string()));
}

#[test]
fn docs_show_plain_returns_markdown() {
    let output = run_seclusor(&["docs", "show", "quickstart"]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stderr).expect("utf8 stderr"), "");

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.starts_with("# Quick Start\n"));
}

#[test]
fn docs_show_json_returns_content() {
    let output = run_seclusor(&["docs", "show", "--format", "json", "security"]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stderr).expect("utf8 stderr"), "");

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let row: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(row["slug"], "security");
    assert!(row["content"]
        .as_str()
        .unwrap_or_default()
        .contains("# Security Model"));
}

#[test]
fn docs_show_unknown_slug_fails() {
    let output = run_seclusor(&["docs", "show", "not-real"]);
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).expect("utf8 stdout"), "");

    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("unknown docs slug"));
}
