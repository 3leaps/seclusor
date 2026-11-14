#!/usr/bin/env bash
# Copy committed fingerprint pins into dist/release before checksums.
# When `<dir>.anchor` exists, reads blobs directly from the verified tagged commit.
set -euo pipefail

ROOT="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
DIR="${1:-dist/release}"
ANCHOR="${DIR}.anchor"

mkdir -p "${DIR}"
if [ -L "${DIR}" ] || [ -L "${DIR}/expected-fingerprints.ndjson" ] || [ -L "${DIR}/expected-fingerprints.txt" ]; then
    echo "error: unsafe symlink in ${DIR}" >&2
    exit 1
fi

if [ -f "${ANCHOR}" ] && [ ! -L "${ANCHOR}" ]; then
    commit="$(awk -F= '$1 == "commit" { print $2 }' "${ANCHOR}")"
    if ! [[ "${commit}" =~ ^[0-9a-f]{40}$ ]]; then
        echo "error: malformed commit in ${ANCHOR}" >&2
        exit 1
    fi
    git -C "${ROOT}" cat-file blob "${commit}:keys/expected-fingerprints.ndjson" >"${DIR}/expected-fingerprints.ndjson"
    git -C "${ROOT}" cat-file blob "${commit}:keys/expected-fingerprints.txt" >"${DIR}/expected-fingerprints.txt"
    echo "[ok] staged fingerprint pins from ${commit} into ${DIR}"
    exit 0
fi

NDJSON="${ROOT}/keys/expected-fingerprints.ndjson"
TXT="${ROOT}/keys/expected-fingerprints.txt"

if [ ! -f "${NDJSON}" ] || [ ! -f "${TXT}" ]; then
    echo "error: missing keys/expected-fingerprints.ndjson or .txt" >&2
    echo "run: make release-insert-anchors" >&2
    exit 2
fi

cp "${NDJSON}" "${DIR}/expected-fingerprints.ndjson"
cp "${TXT}" "${DIR}/expected-fingerprints.txt"
echo "[ok] staged fingerprint pins into ${DIR}"
