#!/usr/bin/env bash
set -euo pipefail

# Negative controls for the dependency-graph parity check (SC-TASK-006 AC-4;
# EPR-0001 §4 + EPR-0002 §1/§2/§3/§4).
#
# Each control mutates a real artifact (a committed lock or the manifest), runs the
# actual check, and asserts it fails AT THE INTENDED VERDICT — crypto FAIL (2),
# REFUSE (3), or lockstep/util FAIL (4) — per EPR-0002 §3's dual, then restores to
# the pre-mutation snapshot. Coverage spans every verdict direction the review
# panel exercised: identity divergence (source AND checksum), two-way + two-
# dimensional reconciliation (component set and per-component surface scope), root
# surface entry/exit, unresolved/ambiguous edges, and the crypto/util split.

ROOT_LOCK="Cargo.lock"
TS_LOCK="bindings/typescript/native/Cargo.lock"
MANIFEST="ci/parity-manifest.toml"
CHECK=(python3 scripts/parity-check.py --manifest "$MANIFEST")

FAIL_CRYPTO=2
REFUSE=3
FAIL_UTIL=4
status=0

log() { printf '[negative-control-parity] %s\n' "$*" >&2; }

# run_case <name> <expected-exit> <target> <python-mutator>
run_case() {
    local name="$1" expected="$2" target="$3" mutator="$4"
    local backup
    backup="$(mktemp)"
    cp "$target" "$backup"
    # shellcheck disable=SC2064
    trap "cp '$backup' '$target'; rm -f '$backup'" EXIT

    python3 -c "$mutator" "$target"

    local out
    out="$(mktemp)"
    set +e
    "${CHECK[@]}" >"$out" 2>&1
    local rc=$?
    set -e

    cp "$backup" "$target"
    trap - EXIT
    if ! cmp -s "$target" "$backup"; then
        log "$name: target '$target' not restored to its pre-run state [FAIL]"
        status=1
    fi
    rm -f "$backup"

    if [ "$rc" -eq "$expected" ]; then
        log "$name: exit $rc as expected [PASS]"
    else
        log "$name: expected exit $expected, got $rc — wrong verdict [FAIL]"
        sed 's/^/    | /' "$out" >&2
        status=1
    fi
    rm -f "$out"
}

# --- mutators (each receives the target path as argv[1]) ---
MUT_CRYPTO_CHECKSUM='
import sys, re
p=sys.argv[1]; s=open(p).read()
b=re.compile(r"(\[\[package\]\]\nname = \"zeroize\"\n.*?checksum = \")([0-9a-f]{64})(\")", re.S)
s2=b.sub(lambda m: m.group(1)+"f"*64+m.group(3), s, count=1)
assert s2!=s, "zeroize checksum not mutated"; open(p,"w").write(s2)
'
MUT_CRYPTO_SOURCE='
import sys, re
p=sys.argv[1]; s=open(p).read()
b=re.compile(r"(\[\[package\]\]\nname = \"zeroize\"\nversion = \"[^\"]+\"\nsource = \")([^\"]+)(\")", re.S)
s2=b.sub(lambda m: m.group(1)+"git+https://example.invalid/zeroize#"+"a"*40+m.group(3), s, count=1)
assert s2!=s, "zeroize source not mutated"; open(p,"w").write(s2)
'
MUT_UTIL_SOURCE='
import sys, re
p=sys.argv[1]; s=open(p).read()
b=re.compile(r"(\[\[package\]\]\nname = \"serde\"\nversion = \"[^\"]+\"\nsource = \")([^\"]+)(\")", re.S)
s2=b.sub(lambda m: m.group(1)+"git+https://example.invalid/serde#"+"b"*40+m.group(3), s, count=1)
assert s2!=s, "serde source not mutated"; open(p,"w").write(s2)
'
MUT_REMOVE_ZEROIZE_PKG='
import sys, re
p=sys.argv[1]; s=open(p).read()
s2=re.sub(r"\[\[package\]\]\nname = \"zeroize\"\n.*?\n\n", "", s, count=1, flags=re.S)
assert s2!=s, "zeroize package block not removed"; open(p,"w").write(s2)
'
MUT_REMOVE_ED25519_DALEK_PKG='
import sys, re
p=sys.argv[1]; s=open(p).read()
s2=re.sub(r"\[\[package\]\]\nname = \"ed25519-dalek\"\n.*?\n\n", "", s, count=1, flags=re.S)
assert s2!=s, "ed25519-dalek package block not removed"; open(p,"w").write(s2)
'
MUT_ADD_ED25519_DALEK_PKG='
import sys
p=sys.argv[1]; s=open(p).read().rstrip()+"\n\n"
s+="[[package]]\nname = \"ed25519-dalek\"\nversion = \"2.2.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"70e796c081cee67dc755e1a36a0a172b897fab85fc3f6bc48307991f64e4eca9\"\n"
open(p,"w").write(s)
'
MUT_COLLIDE_ZEROIZE='
import sys
p=sys.argv[1]; s=open(p).read().rstrip()+"\n\n"
s+="[[package]]\nname = \"zeroize\"\nversion = \"1.9.0\"\nsource = \"git+https://example.invalid/zeroize#deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\n"
open(p,"w").write(s)
'
MUT_DANGLING_EDGE='
import sys, re
p=sys.argv[1]; s=open(p).read()
b=re.compile(r"(\[\[package\]\]\nname = \"age\"\nversion = \"[^\"]+\".*?dependencies = \[\n)", re.S)
s2=b.sub(lambda m: m.group(1)+" \"nonexistent-dangling-crate\",\n", s, count=1)
assert s2!=s, "age dependencies not mutated"; open(p,"w").write(s2)
'
# A dangling edge to an *undeclared version of a declared name*: zeroize IS declared
# (as a valid, present version), but "zeroize 9.9.9" is absent. A name-only exemption
# would swallow it; the (name,version)-keyed delegation boundary must REFUSE it.
MUT_DANGLING_VERSIONED_EDGE='
import sys, re
p=sys.argv[1]; s=open(p).read()
b=re.compile(r"(\[\[package\]\]\nname = \"age\"\nversion = \"[^\"]+\".*?dependencies = \[\n)", re.S)
s2=b.sub(lambda m: m.group(1)+" \"zeroize 9.9.9\",\n", s, count=1)
assert s2!=s, "age dependencies not mutated"; open(p,"w").write(s2)
'
MUT_UTIL_CHECKSUM='
import sys, re
p=sys.argv[1]; s=open(p).read()
b=re.compile(r"(\[\[package\]\]\nname = \"serde\"\nversion = \"[^\"]+\"\nsource = \"[^\"]+\"\nchecksum = \")([0-9a-f]{64})(\")", re.S)
s2=b.sub(lambda m: m.group(1)+"e"*64+m.group(3), s, count=1)
assert s2!=s, "serde checksum not mutated"; open(p,"w").write(s2)
'
MUT_MANIFEST_GHOST='
import sys
p=sys.argv[1]; s=open(p).read().rstrip()+"\n\n"
s+="[[crypto_components]]\nname = \"definitely-absent-crypto-canary\"\nversion = \"999.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"0000000000000000000000000000000000000000000000000000000000000000\"\nsurfaces = [\"root\"]\n"
open(p,"w").write(s)
'
MUT_MANIFEST_DROP_ZEROIZE='
import sys, re
p=sys.argv[1]; s=open(p).read()
s2=re.sub(r"\[\[crypto_components\]\]\nname = \"zeroize\"\n.*?\n\n", "", s, count=1, flags=re.S)
assert s2!=s, "zeroize crypto_components entry not removed"; open(p,"w").write(s2)
'
MUT_MANIFEST_DEMOTE_ZEROIZE='
import sys
p=sys.argv[1]; s=open(p).read()
s2=s.replace("[[crypto_components]]\nname = \"zeroize\"", "[[non_crypto_shared]]\nname = \"zeroize\"", 1)
assert s2!=s, "zeroize not demoted"; open(p,"w").write(s2)
'
MUT_MANIFEST_NARROW_CRYPTO='
import sys, re
p=sys.argv[1]; s=open(p).read()
b=re.compile(r"(\[\[crypto_components\]\]\nname = \"zeroize\"\n.*?surfaces = )\[[^\]]*\]", re.S)
s2=b.sub(lambda m: m.group(1)+"[\"root\"]", s, count=1)
assert s2!=s, "zeroize surfaces not narrowed"; open(p,"w").write(s2)
'
MUT_MANIFEST_NARROW_UTIL='
import sys, re
p=sys.argv[1]; s=open(p).read()
b=re.compile(r"(\[\[non_crypto_shared\]\]\nname = \"serde\"\n.*?surfaces = )\[[^\]]*\]", re.S)
s2=b.sub(lambda m: m.group(1)+"[\"root\"]", s, count=1)
assert s2!=s, "serde surfaces not narrowed"; open(p,"w").write(s2)
'

# --- identity divergence: security FAIL (2) / lockstep FAIL (4) ---
run_case "divergent-checksum (crypto)" "$FAIL_CRYPTO" "$TS_LOCK" "$MUT_CRYPTO_CHECKSUM"
run_case "divergent-source (crypto)" "$FAIL_CRYPTO" "$TS_LOCK" "$MUT_CRYPTO_SOURCE"
run_case "divergent-source (util)" "$FAIL_UTIL" "$TS_LOCK" "$MUT_UTIL_SOURCE"
run_case "util-drift checksum (lockstep)" "$FAIL_UTIL" "$TS_LOCK" "$MUT_UTIL_CHECKSUM"

# --- component-set reconciliation: absence FAILs, undeclared REFUSEs ---
run_case "absent-from-non-anchor (crypto)" "$FAIL_CRYPTO" "$TS_LOCK" "$MUT_REMOVE_ZEROIZE_PKG"
run_case "absent-from-anchor (crypto)" "$FAIL_CRYPTO" "$ROOT_LOCK" "$MUT_REMOVE_ZEROIZE_PKG"
run_case "ghost-declared-absent-everywhere" "$FAIL_CRYPTO" "$MANIFEST" "$MUT_MANIFEST_GHOST"
run_case "undeclared-node (dropped)" "$REFUSE" "$MANIFEST" "$MUT_MANIFEST_DROP_ZEROIZE"

# --- per-component surface-scope reconciliation (coverage cannot shrink) ---
run_case "surface-shrink (crypto -> root only)" "$REFUSE" "$MANIFEST" "$MUT_MANIFEST_NARROW_CRYPTO"
run_case "surface-shrink (util -> root only)" "$REFUSE" "$MANIFEST" "$MUT_MANIFEST_NARROW_UTIL"

# --- root surface entry/exit ---
run_case "root-removed-from-scoped-surface" "$FAIL_CRYPTO" "$ROOT_LOCK" "$MUT_REMOVE_ED25519_DALEK_PKG"
run_case "root-on-undeclared-surface (D11B)" "$REFUSE" "$TS_LOCK" "$MUT_ADD_ED25519_DALEK_PKG"

# --- edge integrity: ambiguous collision and dangling edge REFUSE ---
run_case "same-name+version-different-source" "$REFUSE" "$ROOT_LOCK" "$MUT_COLLIDE_ZEROIZE"
run_case "dangling-edge (absent target)" "$REFUSE" "$ROOT_LOCK" "$MUT_DANGLING_EDGE"
run_case "dangling-edge (undeclared version of declared name)" "$REFUSE" "$ROOT_LOCK" "$MUT_DANGLING_VERSIONED_EDGE"

# --- anti-fail-open: a core primitive cannot be parked as a utility ---
run_case "core-crypto-demoted-to-util" "$FAIL_CRYPTO" "$MANIFEST" "$MUT_MANIFEST_DEMOTE_ZEROIZE"

if [ "$status" -ne 0 ]; then
    log "one or more parity negative controls did not fire at their intended verdict"
    exit 1
fi
log "all parity negative controls fired at their intended verdict [PASS]"
