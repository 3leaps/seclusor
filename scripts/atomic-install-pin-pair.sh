#!/usr/bin/env bash
# Replace dest/expected-fingerprints.{ndjson,txt} from a staging pair.
# Install-window rollback on error or INT/TERM/HUP: restore prior dest files
# or remove newly installed dest when none existed. Two dest files are not
# power-loss atomic; a crash mid-pair can still leave residue.
# Usage: atomic-install-pin-pair.sh <staging-dir> <dest-dir>
set -euo pipefail

STAGING=${1:?}
DEST=${2:?}
SRC_NDJSON="$STAGING/expected-fingerprints.ndjson"
SRC_TXT="$STAGING/expected-fingerprints.txt"
DEST_NDJSON="$DEST/expected-fingerprints.ndjson"
DEST_TXT="$DEST/expected-fingerprints.txt"
NEW_NDJSON="$DEST/expected-fingerprints.ndjson.new"
NEW_TXT="$DEST/expected-fingerprints.txt.new"
BAK_NDJSON="$DEST/expected-fingerprints.ndjson.bak"
BAK_TXT="$DEST/expected-fingerprints.txt.bak"

if [ ! -f "$SRC_NDJSON" ] || [ ! -f "$SRC_TXT" ]; then
    echo "error: staging pair incomplete" >&2
    exit 2
fi
mkdir -p "$DEST"

had_ndjson=0
had_txt=0
[ -f "$DEST_NDJSON" ] && had_ndjson=1 && cp "$DEST_NDJSON" "$BAK_NDJSON"
[ -f "$DEST_TXT" ] && had_txt=1 && cp "$DEST_TXT" "$BAK_TXT"

cp "$SRC_NDJSON" "$NEW_NDJSON"
cp "$SRC_TXT" "$NEW_TXT"

rollback() {
    # Single-shot: a signal runs this handler, then EXIT must not run it again.
    trap - EXIT INT TERM HUP
    rm -f "$NEW_NDJSON" "$NEW_TXT"
    if [ "$had_ndjson" -eq 1 ]; then
        mv -f "$BAK_NDJSON" "$DEST_NDJSON"
    else
        rm -f "$DEST_NDJSON"
    fi
    if [ "$had_txt" -eq 1 ]; then
        mv -f "$BAK_TXT" "$DEST_TXT"
    else
        rm -f "$DEST_TXT"
    fi
}

trap rollback EXIT INT TERM HUP

if ! mv -f "$NEW_NDJSON" "$DEST_NDJSON"; then
    echo "error: failed to install ndjson pin" >&2
    exit 1
fi
if [ "${SECLUSOR_TEST_KILL_AFTER_FIRST:-}" = 1 ]; then
    kill -s TERM $$
    # A handled TERM returns here; do not continue the second install.
    exit 143
fi
if [ "${SECLUSOR_TEST_FAIL_SECOND:-}" = 1 ]; then
    echo "error: failed to install txt pin; restored previous pair" >&2
    exit 1
fi
if ! mv -f "$NEW_TXT" "$DEST_TXT"; then
    echo "error: failed to install txt pin; restored previous pair" >&2
    exit 1
fi

trap - EXIT INT TERM HUP
rm -f "$BAK_NDJSON" "$BAK_TXT"
