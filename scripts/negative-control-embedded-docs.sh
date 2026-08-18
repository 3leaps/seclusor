#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MANIFEST="docs/embed-manifest.json"
PROBE="docs/appnotes/99-embedded-docs-negative-control.md"
CHECK=(cargo check -p seclusor)
status=0

log() { printf '[negative-control-embedded-docs] %s\n' "$*" >&2; }
fail() {
    printf '[negative-control-embedded-docs][FAIL] %s\n' "$*" >&2
    exit 1
}

if [ ! -f "$MANIFEST" ]; then
    fail "expected canonical manifest '$MANIFEST' not found"
fi
if [ -e "$PROBE" ]; then
    fail "probe path '$PROBE' already exists"
fi

manifest_backup="$(mktemp)"
cp "$MANIFEST" "$manifest_backup"
# shellcheck disable=SC2064
trap "cp '$manifest_backup' '$MANIFEST'; rm -f '$manifest_backup' '$PROBE'" EXIT

rm "$MANIFEST"
missing_out="$(mktemp)"
set +e
"${CHECK[@]}" >"$missing_out" 2>&1
missing_rc=$?
set -e

cp "$manifest_backup" "$MANIFEST"
rm -f "$manifest_backup"
trap - EXIT

if [ "$missing_rc" -eq 0 ]; then
    log "workspace build accepted a missing canonical manifest [FAIL]"
    status=1
elif ! grep -Fq "canonical embed manifest missing from workspace source" "$missing_out"; then
    log "missing-manifest build failed at the wrong assertion [FAIL]"
    sed 's/^/    | /' "$missing_out" >&2
    status=1
else
    log "workspace build refused a missing canonical manifest [PASS]"
fi
rm -f "$missing_out"

# Re-establish a successful warm build before testing directory invalidation.
"${CHECK[@]}" >/dev/null

printf '# Embedded docs negative-control probe\n' >"$PROBE"
trap "rm -f '$PROBE'" EXIT

addition_out="$(mktemp)"
set +e
"${CHECK[@]}" >"$addition_out" 2>&1
addition_rc=$?
set -e

rm -f "$PROBE"
trap - EXIT

if [ "$addition_rc" -eq 0 ]; then
    log "warm build ignored a newly matched documentation file [FAIL]"
    status=1
elif ! grep -Fq "embedded-docs.json is stale" "$addition_out"; then
    log "new-file build failed at the wrong assertion [FAIL]"
    sed 's/^/    | /' "$addition_out" >&2
    status=1
else
    log "newly matched documentation invalidated the warm build [PASS]"
fi
rm -f "$addition_out"

# Removal of the probe must also invalidate and restore the green baseline.
"${CHECK[@]}" >/dev/null

if [ "$status" -ne 0 ]; then
    fail "one or more embedded-doc controls did not fail closed"
fi

log "workspace/package distinction and directory invalidation are load-bearing [PASS]"
