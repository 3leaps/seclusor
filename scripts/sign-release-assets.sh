#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <release-tag> <release-dir>" >&2
    exit 1
fi

release_tag="$1"
release_dir="$2"
minisign_key="${SECLUSOR_MINISIGN_KEY:-}"
pgp_key_id="${SECLUSOR_PGP_KEY_ID:-}"
gpg_homedir="${SECLUSOR_GPG_HOMEDIR:-}"

if [ -z "$minisign_key" ]; then
    echo "error: SECLUSOR_MINISIGN_KEY is required" >&2
    exit 1
fi

if ! command -v minisign >/dev/null 2>&1; then
    echo "error: minisign is required" >&2
    exit 1
fi

for sums in SHA256SUMS SHA512SUMS; do
    file="${release_dir}/${sums}"
    if [ ! -f "$file" ]; then
        echo "error: missing checksum manifest: ${file}" >&2
        exit 1
    fi
    minisign -S -s "$minisign_key" -m "$file" -x "${file}.minisig"
done

if [ -n "$pgp_key_id" ]; then
    if ! command -v gpg >/dev/null 2>&1; then
        echo "error: gpg is required when SECLUSOR_PGP_KEY_ID is set" >&2
        exit 1
    fi

    gpg_args=(--batch --yes --armor --local-user "$pgp_key_id")
    if [ -n "$gpg_homedir" ]; then
        gpg_args+=(--homedir "$gpg_homedir")
    fi

    for sums in SHA256SUMS SHA512SUMS; do
        file="${release_dir}/${sums}"
        gpg "${gpg_args[@]}" --output "${file}.asc" --detach-sign "$file"
    done
fi

echo "[ok] Signed checksum manifests for ${release_tag}"
