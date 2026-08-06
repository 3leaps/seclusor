#!/usr/bin/env bash
# Negative controls for scripts/check-child-env-chokepoint.py.
# A guard that has never been observed to reject a bypass is not proven.
set -euo pipefail

GUARD=(python3 scripts/check-child-env-chokepoint.py)
status=0
tmp="$(mktemp -d)"
probe_file="crates/seclusor/src/_child_env_guard_probe.rs"
cleanup() {
    rm -rf "$tmp"
    rm -f "$probe_file"
}
trap cleanup EXIT

log() { printf '[negative-control-child-env] %s\n' "$*" >&2; }

expect_case() {
    local name="$1" expect="$2" content="$3"
    local f="$tmp/case.rs"
    printf '%s\n' "$content" >"$f"
    set +e
    "${GUARD[@]}" --scan "$f" >/dev/null 2>&1
    local rc=$?
    set -e
    if [ "$expect" = flag ]; then
        if [ "$rc" -ne 0 ]; then
            log "$name: guard flagged it (rc $rc) [PASS]"
        else
            log "$name: guard did NOT flag a bypass [FAIL]"
            status=1
        fi
    else
        if [ "$rc" -eq 0 ]; then
            log "$name: guard accepted it [PASS]"
        else
            log "$name: guard wrongly flagged compliant code [FAIL]"
            status=1
        fi
    fi
}

# --- env mutation ---
expect_case "unscoped command.env" flag \
    'fn apply(cmd: &mut std::process::Command) {
    cmd.env("K", "V");
}'

expect_case "unscoped env_remove" flag \
    'fn scrub(cmd: &mut std::process::Command) {
    cmd.env_remove("SECRET");
}'

expect_case "unscoped env_clear" flag \
    'fn wipe(cmd: &mut std::process::Command) {
    cmd.env_clear();
}'

expect_case "unscoped UFCS Command::env" flag \
    'fn apply(command: &mut std::process::Command) {
    std::process::Command::env(command, "K", "V");
}'

expect_case "unscoped UFCS Command::env_remove" flag \
    'fn scrub(command: &mut std::process::Command) {
    Command::env_remove(command, "SECRET");
}'

expect_case "unscoped turbofish UFCS Command::env" flag \
    'fn apply(command: &mut std::process::Command) {
    Command::env::<&str, &str>(command, "K", "V");
}'

expect_case "unscoped turbofish method env" flag \
    'fn apply(command: &mut std::process::Command) {
    command.env::<&str, &str>("K", "V");
}'

expect_case "import alias Cmd::env" flag \
    'use std::process::Command as Cmd;
fn apply(command: &mut Cmd) {
    Cmd::env(command, "K", "V");
}'

expect_case "type alias ProcCmd::env" flag \
    'type ProcCmd = std::process::Command;
fn apply(command: &mut ProcCmd) {
    ProcCmd::env(command, "K", "V");
}'

expect_case "marker with wrong command" flag \
    'fn apply(cmd: &mut std::process::Command) {
    // child-env-callsite: apply-env-set
    cmd.env("other", "path");
}'

expect_case "inventoried marker in wrong file" flag \
    'fn apply(command: &mut std::process::Command, key: &OsStr, value: &OsStr) {
    // child-env-callsite: apply-env-set
    command.env(key, value);
}'

expect_case "inventoried clear marker in wrong file" flag \
    'fn apply(command: &mut std::process::Command) {
    // child-env-callsite: apply-env-clear
    command.env_clear();
}'

# --- spawn monopoly ---
expect_case "unguarded spawn, no env calls" flag \
    'fn run(prog: &str) {
    let mut c = std::process::Command::new(prog);
    let _ = c.status();
}'

expect_case "unguarded Command::new bare" flag \
    'fn run() {
    Command::new("echo");
}'

expect_case "import alias Cmd::new spawn" flag \
    'use std::process::Command as Cmd;
fn run() {
    let _ = Cmd::new("echo");
}'

expect_case "marked spawn at inventoried expected line (wrong path)" flag \
    'fn handle() {
    // child-env-callsite: run-spawn
    let mut command = Command::new(&args.command[0]);
}'

expect_case "marked spawn in wrong file with wrong body" flag \
    'fn handle() {
    // child-env-callsite: run-spawn
    let mut command = Command::new("evil");
}'

# --- cfg strip correctness ---
expect_case "cfg(test) module env mutation ignored" pass \
    'fn production() {}
#[cfg(test)]
mod tests {
    fn t(cmd: &mut std::process::Command) {
        cmd.env("X", "Y");
    }
}'

expect_case "cfg(not(test)) production env still scanned" flag \
    '#[cfg(not(test))]
fn production(cmd: &mut std::process::Command) {
    cmd.env("X", "Y");
}'

expect_case "cfg(feature=latest) production env still scanned" flag \
    '#[cfg(feature = "latest")]
fn production(cmd: &mut std::process::Command) {
    cmd.env("X", "Y");
}'

expect_case "comment only is fine" pass \
    'fn production() {
    // historical: command.env("K", "V") was here
}'

# --- full-repo probes ---
cat >"$probe_file" <<'RS'
// temporary negative-control probe — must not remain in tree
fn probe(command: &mut std::process::Command, key: &std::ffi::OsStr, value: &std::ffi::OsStr) {
    // child-env-callsite: apply-env-set
    command.env(key, value);
}
RS
set +e
python3 scripts/check-child-env-chokepoint.py >/dev/null 2>&1
probe_rc=$?
set -e
cleanup_probe() { rm -f "$probe_file"; }
cleanup_probe
if [ "$probe_rc" -ne 0 ]; then
    log "second marked site in crates/: guard flagged it (rc $probe_rc) [PASS]"
else
    log "second marked site in crates/: guard did NOT flag [FAIL]"
    status=1
fi

cat >"$probe_file" <<'RS'
fn probe(command: &mut std::process::Command) {
    std::process::Command::env(command, "K", "V");
}
RS
set +e
python3 scripts/check-child-env-chokepoint.py >/dev/null 2>&1
probe_rc=$?
set -e
cleanup_probe
if [ "$probe_rc" -ne 0 ]; then
    log "UFCS in crates/ without marker: guard flagged it (rc $probe_rc) [PASS]"
else
    log "UFCS in crates/ without marker: guard did NOT flag [FAIL]"
    status=1
fi

cat >"$probe_file" <<'RS'
fn probe() {
    let _ = std::process::Command::new("echo");
}
RS
set +e
python3 scripts/check-child-env-chokepoint.py >/dev/null 2>&1
probe_rc=$?
set -e
cleanup_probe
if [ "$probe_rc" -ne 0 ]; then
    log "unguarded spawn in crates/: guard flagged it (rc $probe_rc) [PASS]"
else
    log "unguarded spawn in crates/: guard did NOT flag [FAIL]"
    status=1
fi

cat >"$probe_file" <<'RS'
use std::process::Command as Cmd;
fn probe() {
    let _ = Cmd::new("echo");
}
RS
set +e
python3 scripts/check-child-env-chokepoint.py >/dev/null 2>&1
probe_rc=$?
set -e
cleanup_probe
if [ "$probe_rc" -ne 0 ]; then
    log "alias spawn in crates/: guard flagged it (rc $probe_rc) [PASS]"
else
    log "alias spawn in crates/: guard did NOT flag [FAIL]"
    status=1
fi

set +e
python3 scripts/check-child-env-chokepoint.py >/dev/null 2>&1
clean_rc=$?
set -e
if [ "$clean_rc" -eq 0 ]; then
    log "clean inventory after probes: [PASS]"
else
    log "clean inventory after probes: [FAIL]"
    status=1
fi

if [ "$status" -ne 0 ]; then
    log "one or more negative controls failed"
    exit 1
fi
log "all child-env guard negative controls passed"
exit 0
