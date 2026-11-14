#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <release-dir>" >&2
    exit 1
fi
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(CDPATH='' cd -- "${script_dir}/.." && pwd -P)"
# shellcheck source=scripts/release-decernor.sh
source "${script_dir}/release-decernor.sh"
decernor_bin="$(release_resolve_decernor ceremony)"
release_dir="$1"
for file in minisign.pub release-key.asc expected-fingerprints.txt expected-fingerprints.ndjson; do
    if [ ! -s "${release_dir}/${file}" ]; then
        echo "error: release public key or fingerprint anchor is missing: ${file}" >&2
        exit 1
    fi
done
for file in expected-fingerprints.txt expected-fingerprints.ndjson; do
    if ! cmp -s "${release_dir}/${file}" "${root}/keys/${file}"; then
        echo "error: staged ${file} differs from committed anchor" >&2
        exit 1
    fi
done
if grep -Eqi 'PRIVATE|SECRET|BEGIN PGP PRIVATE KEY|minisign secret key' \
    "${release_dir}/minisign.pub" "${release_dir}/release-key.asc"; then
    echo "error: exported key file appears to contain private material" >&2
    exit 1
fi
"${decernor_bin}" fingerprint verify \
    --anchors "${release_dir}/expected-fingerprints.txt" \
    --anchors-ndjson "${release_dir}/expected-fingerprints.ndjson" \
    --gpg "${release_dir}/release-key.asc" \
    --minisign "${release_dir}/minisign.pub" >/dev/null
echo "[ok] exported public keys match the committed and staged decernor anchors"
