#!/usr/bin/env bash
set -euo pipefail

# Negative control for the artifact-build --locked static guard (EPR-0002 §3): a
# guard that has never been observed to reject a bypass is configured, not proven.
# Each fixture writes a synthetic workflow snippet and asserts the guard's --scan
# fail direction fires (or, for the positive cases, does not). This is the half of
# the original F0 proof the runtime stale-lock controls cannot reach: the guard is
# what covers the cross-target YAML paths.

GUARD=(python3 scripts/check-locked-artifact-builds.py)
status=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

log() { printf '[negative-control-locked-guard] %s\n' "$*" >&2; }

# expect_case <name> <expect: flag|pass> <file-content>
expect_case() {
    local name="$1" expect="$2" content="$3"
    local f="$tmp/case.yml"
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
            log "$name: guard wrongly flagged a compliant build [FAIL]"
            status=1
        fi
    fi
}

# 1. unlocked single-line raw artifact build -> flagged
expect_case "unlocked single-line raw build" flag \
    '          cargo build --release --target x86_64-apple-darwin -p seclusor-ffi'

# 2. unlocked multi-line (backslash continuation) build -> flagged (continuations joined)
expect_case "unlocked multiline raw build" flag \
    '          cargo build \
            --release -p seclusor'

# 3. bypass: raw zigbuild replacing the wrapper, no --locked -> flagged
expect_case "unlocked raw zigbuild bypass" flag \
    '          cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.17 -p seclusor-ffi'

# 4. a comment containing --locked must NOT satisfy the assertion
expect_case "commented --locked does not satisfy" flag \
    '          # build with --locked eventually
          cargo build --release -p seclusor'

# 5. bypass: YAML folded block scalar (run: >) splits an unlocked build across
#    physical lines; the runner folds it to one command, so the guard must too
expect_case "unlocked folded-scalar raw build" flag \
    '          run: >
            cargo build
            --release -p seclusor'

# 6. bypass: a cargo +toolchain selector before the subcommand -> flagged
expect_case "unlocked cargo +toolchain build" flag \
    '          cargo +stable build --release -p seclusor'

# 6b. bypass: a folded block scalar header carrying an inline comment still folds
expect_case "unlocked folded-scalar with header comment" flag \
    '          run: >- # fold with a trailing comment
            cargo build
            --release -p seclusor'

# 7. positive: the canonical wrapper call is accepted
expect_case "wrapper call accepted" pass \
    '          ./scripts/cargo-artifact-build.sh build --release --target x86_64-apple-darwin -p seclusor-ffi'

# 8. positive: a direct --locked artifact build is accepted
expect_case "direct --locked build accepted" pass \
    '          cargo build --release --locked -p seclusor'

# 9. positive: a folded-scalar build that carries --locked is accepted (folding must
#    not manufacture a false positive on a compliant multi-line command)
expect_case "folded-scalar --locked build accepted" pass \
    '          run: >
            cargo build --release
            --locked -p seclusor'

# 10. positive: a debug build (no --release) is not an artifact build
expect_case "debug build ignored" pass \
    '          cargo build --workspace'

# ---------------------------------------------------------------------------
# Closed callsite-invariant controls (the load-bearing AC-2 proof). Each mutates a
# REAL production file (workflow/Makefile), runs the guard in DEFAULT mode, asserts it
# turns red AND names the specific callsite/marker, then restores byte-for-byte. This
# is the half a `--scan` fixture cannot reach: proving the marked command must be the
# canonical wrapper INVOCATION — not merely contain its token — and that the marker
# set equals the reviewed inventory.
GUARD_DEFAULT=(python3 scripts/check-locked-artifact-builds.py)

# MUT dispatches on <kind>; it locates a callsite marker by its exact comment grammar.
#   set-cmd <id> <cmd>        replace the marked command line with <cmd>
#   set-cmd-decoy <id> <cmd>  ... and append a genuine wrapper invocation ELSEWHERE
#   remove-marker <id>        delete the marker line
#   dup-marker <id>           duplicate the marker line
#   masquerade <id>           turn the marker into executable text ending in the id
#   add-marker <id>           append a bare `# artifact-callsite: <id>` line
MUT='
import sys, re
path, kind, args = sys.argv[1], sys.argv[2], sys.argv[3:]
L = open(path).read().splitlines(keepends=True)
def marker(cid):
    rx = re.compile(r"^\s*#\s*artifact-callsite:\s*" + re.escape(cid) + r"\s*$")
    idx = [i for i, l in enumerate(L) if rx.match(l)]
    assert len(idx) == 1, "marker %s x%d" % (cid, len(idx))
    return idx[0]
def cmd_index(mi):
    j = mi + 1
    while L[j].strip() == "":
        j += 1
    return j
if kind in ("set-cmd", "set-cmd-decoy"):
    cid, newcmd = args[0], args[1]
    j = cmd_index(marker(cid))
    ind = L[j][: len(L[j]) - len(L[j].lstrip())]
    L[j] = ind + newcmd + "\n"
    if kind == "set-cmd-decoy":
        L.append(ind + "./scripts/cargo-artifact-build.sh build --workspace\n")
elif kind == "remove-marker":
    del L[marker(args[0])]
elif kind == "dup-marker":
    mi = marker(args[0]); L.insert(mi, L[mi])
elif kind == "masquerade":
    cid = args[0]; mi = marker(cid)
    ind = L[mi][: len(L[mi]) - len(L[mi].lstrip())]
    L[mi] = ind + "echo not-a-marker # artifact-callsite: " + cid + "\n"
elif kind == "add-marker":
    if L and not L[-1].endswith("\n"):
        L[-1] += "\n"
    L.append("# artifact-callsite: " + args[0] + "\n")
else:
    raise SystemExit("bad kind " + kind)
open(path, "w").writelines(L)
'

# mutate_case <name> <file> <expect-token> <kind> [mutator args...]
mutate_case() {
    local name="$1" file="$2" token="$3" kind="$4"
    shift 4
    local backup
    backup="$(mktemp)"
    cp "$file" "$backup"
    # shellcheck disable=SC2064
    trap "cp '$backup' '$file'; rm -f '$backup'; rm -rf '$tmp'" EXIT

    python3 -c "$MUT" "$file" "$kind" "$@"
    local out
    out="$(mktemp)"
    set +e
    "${GUARD_DEFAULT[@]}" >"$out" 2>&1
    local rc=$?
    set -e

    cp "$backup" "$file"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" EXIT
    if ! cmp -s "$file" "$backup"; then
        log "$name: real file '$file' not restored to its pre-run state [FAIL]"
        status=1
    fi
    rm -f "$backup"

    if [ "$rc" -ne 0 ] && grep -q -- "$token" "$out"; then
        log "$name: guard turned red and named '$token' [PASS]"
    else
        log "$name: expected nonzero naming '$token', got rc=$rc [FAIL]"
        sed 's/^/    | /' "$out" >&2
        status=1
    fi
    rm -f "$out"
}

REL=".github/workflows/release.yml"
GOB=".github/workflows/go-bindings.yml"
MK="Makefile"
ALT="bash scripts/alternate-artifact-builder.sh build --release"

# every inventoried callsite: replacing its command with an alternate builder fails
mutate_case "replace release-cli" "$REL" release-cli set-cmd release-cli "$ALT"
mutate_case "replace gobindings-ffi-linux" "$GOB" gobindings-ffi-linux set-cmd gobindings-ffi-linux "$ALT"
mutate_case "replace gobindings-ffi-darwin-amd64" "$GOB" gobindings-ffi-darwin-amd64 set-cmd gobindings-ffi-darwin-amd64 "$ALT"
mutate_case "replace gobindings-ffi-darwin-arm64" "$GOB" gobindings-ffi-darwin-arm64 set-cmd gobindings-ffi-darwin-arm64 "$ALT"
mutate_case "replace gobindings-ffi-windows-gnu" "$GOB" gobindings-ffi-windows-gnu set-cmd gobindings-ffi-windows-gnu "$ALT"
mutate_case "replace make-build-release" "$MK" make-build-release set-cmd make-build-release "$ALT"
mutate_case "replace make-build-ffi" "$MK" make-build-ffi set-cmd make-build-ffi "$ALT"

# R5 command-binding bypasses on a real callsite — a token occurrence is not an
# invocation; each must fail and name the callsite
# shellcheck disable=SC2016
mutate_case "wrapper token as data" "$REL" release-cli set-cmd release-cli \
    'echo ./scripts/cargo-artifact-build.sh build --target "${{ matrix.target }}" -p seclusor'
# shellcheck disable=SC2016
mutate_case "wrong path same basename" "$REL" release-cli set-cmd release-cli \
    './evil/cargo-artifact-build.sh build --target "${{ matrix.target }}" -p seclusor'
mutate_case "token as arg to alt builder" "$REL" release-cli set-cmd release-cli \
    'bash scripts/alternate-artifact-builder.sh cargo-artifact-build.sh'
# shellcheck disable=SC2016
mutate_case "canonical wrapper then alt builder" "$REL" release-cli set-cmd release-cli \
    './scripts/cargo-artifact-build.sh build --target "${{ matrix.target }}" -p seclusor && bash scripts/alternate-artifact-builder.sh'

# a genuine wrapper occurrence elsewhere still does not mask a replaced callsite
mutate_case "decoy wrapper does not mask" "$REL" release-cli set-cmd-decoy release-cli "$ALT"

# structural markers: masquerade, removal, duplication, unknown id, id in wrong file
mutate_case "executable masquerading as marker" "$REL" release-cli masquerade release-cli
mutate_case "remove marker" "$MK" make-build-ffi remove-marker make-build-ffi
mutate_case "duplicate marker" "$GOB" gobindings-ffi-linux dup-marker gobindings-ffi-linux
mutate_case "unknown marker id" "$MK" unknown-canary add-marker unknown-canary
mutate_case "expected id in the wrong file" "$MK" release-cli add-marker release-cli

# baseline: with every marker intact the guard finds each callsite and passes
set +e
"${GUARD_DEFAULT[@]}" >/dev/null 2>&1
brc=$?
set -e
if [ "$brc" -eq 0 ]; then
    log "baseline: every inventoried callsite present and routed through the wrapper [PASS]"
else
    log "baseline: guard failed on the pristine tree (rc $brc) [FAIL]"
    status=1
fi

if [ "$status" -ne 0 ]; then
    log "the --locked guard did not behave as required"
    exit 1
fi
log "the --locked guard rejects every bypass and accepts every compliant build [PASS]"
