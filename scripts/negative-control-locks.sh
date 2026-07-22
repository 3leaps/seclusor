#!/usr/bin/env bash
set -euo pipefail

# Negative control for lockfile enforcement (EPR-0001 conformance).
#
# A --locked build flag that has never been observed to fail is *configured*,
# not *proven*. Critically, it must be proven on the ACTUAL published-artifact
# entrypoints — not a stand-in cargo command that duplicates the flag. So this
# drives the real production build paths (the canonical artifact-build wrapper
# behind `make build-release` and `build-ffi`, and `build-native.js`), staleens
# the lock each consumes, and asserts each refuses it *at the --locked gate
# specifically* (EPR-0002 §3 — a green->red transition that trips a compile error
# or upstream fault never exercised the gate under test). Remove --locked from the
# wrapper or build-native.js and a surface below goes red. The cross-target
# workflow paths that cannot run locally (release.yml / go-bindings.yml) are
# covered by the static guard scripts/check-locked-artifact-builds.sh.
#
# For each surface it:
#   1. backs up the committed lock it consumes,
#   2. semantically staleens it (rewrites the `zeroize` package version to a
#      value the graph cannot resolve to — a real "lock out of date" condition,
#      not a TOML parse error),
#   3. runs the real build entrypoint and asserts it fails at the --locked gate,
#   4. restores the pristine lock (also on any error/interrupt via trap).
#
# `zeroize` is used as the canary because it is a security-critical shared
# component present in every surface's graph.

log() { printf '[negative-control] %s\n' "$*" >&2; }
fail() {
    printf '[negative-control][FAIL] %s\n' "$*" >&2
    exit 1
}

# Surfaces: "<label>|<lockfile it consumes>|<real production build entrypoint>"
# CLI (make build-release) and FFI/Go (the wrapper form go-bindings.yml runs)
# consume the root lock; the TS .node consumes the native lock. Each entrypoint
# enforces --locked structurally (the wrapper) or directly (build-native.js).
SURFACES=(
    "cli|Cargo.lock|make build-release"
    "ffi-go|Cargo.lock|./scripts/cargo-artifact-build.sh build -p seclusor-ffi"
    "ts-native|bindings/typescript/native/Cargo.lock|node bindings/typescript/scripts/build-native.js"
)

staleen() {
    # Rewrite the version line inside the zeroize [[package]] block.
    local lock="$1" tmp
    tmp="$(mktemp)"
    awk '
    /^\[\[package\]\]/ { iszero = 0 }
    /^name = "zeroize"$/ { iszero = 1 }
    iszero == 1 && /^version = / { print "version = \"0.0.0-stale-negative-control\""; next }
    { print }
  ' "$lock" >"$tmp"
    if cmp -s "$lock" "$tmp"; then
        rm -f "$tmp"
        return 1 # nothing changed -> canary absent, caller decides
    fi
    mv "$tmp" "$lock"
}

overall_status=0

for entry in "${SURFACES[@]}"; do
    IFS='|' read -r label lock build_cmd <<<"$entry"

    if [ ! -f "$lock" ]; then
        fail "$label: expected lockfile '$lock' not found"
    fi

    backup="$(mktemp)"
    cp "$lock" "$backup"
    # shellcheck disable=SC2064
    trap "cp '$backup' '$lock'; rm -f '$backup'" EXIT

    if ! staleen "$lock"; then
        cp "$backup" "$lock"
        rm -f "$backup"
        trap - EXIT
        fail "$label: could not staleen '$lock' (zeroize canary not found — update this control)"
    fi

    log "$label: staled '$lock'; asserting '$build_cmd' fails AT the --locked gate..."
    out="$(mktemp)"
    set +e
    # shellcheck disable=SC2086
    $build_cmd >"$out" 2>&1
    rc=$?
    set -e

    # Restore before evaluating so a nonzero assertion never leaves a dirty tree.
    cp "$backup" "$lock"
    rm -f "$backup"
    trap - EXIT

    # EPR-0002 §3 (the self-check's dual): a mere nonzero exit is not enough — the
    # build must fail *at the --locked gate's assertion*, not incidentally (a
    # compile error, an earlier gate, a network fault, a panic). Assert both the
    # nonzero exit AND that cargo refused specifically because the lock is stale.
    if [ "$rc" -eq 0 ]; then
        log "$label: locked build SUCCEEDED on a stale lock — enforcement is NOT load-bearing [FAIL]"
        overall_status=1
    elif ! grep -Eq 'passed to prevent this' "$out"; then
        log "$label: build failed (exit $rc) but NOT at the --locked gate — control inconclusive [FAIL]"
        sed 's/^/    | /' "$out" >&2
        overall_status=1
    else
        log "$label: --locked gate refused the stale lock (exit $rc; lock out of date) [PASS]"
    fi
    rm -f "$out"
done

if [ "$overall_status" -ne 0 ]; then
    fail "one or more surfaces did not enforce their committed lock"
fi

log "all surfaces enforce their committed lock [PASS]"
