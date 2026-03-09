#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <release-dir>" >&2
    exit 1
fi

release_dir="$1"
minisign_pub="${SECLUSOR_MINISIGN_PUB:-${release_dir}/minisign.pub}"
gpg_homedir="${SECLUSOR_GPG_HOMEDIR:-}"

if [ ! -f "$minisign_pub" ]; then
    echo "error: minisign public key not found at ${minisign_pub}" >&2
    exit 1
fi

if ! command -v minisign >/dev/null 2>&1; then
    echo "error: minisign is required" >&2
    exit 1
fi

for sums in SHA256SUMS SHA512SUMS; do
    file="${release_dir}/${sums}"
    sig="${file}.minisig"
    if [ -f "$sig" ]; then
        minisign -V -p "$minisign_pub" -m "$file" -x "$sig"
    else
        echo "error: missing minisign signature ${sig}" >&2
        exit 1
    fi

    asc="${file}.asc"
    if [ -f "$asc" ]; then
        if ! command -v gpg >/dev/null 2>&1; then
            echo "error: gpg signature present but gpg not installed" >&2
            exit 1
        fi
        gpg_args=(--verify "$asc" "$file")
        if [ -n "$gpg_homedir" ]; then
            gpg_args=(--homedir "$gpg_homedir" "${gpg_args[@]}")
        fi
        gpg "${gpg_args[@]}"
    fi
done

echo "[ok] Signature verification passed"
