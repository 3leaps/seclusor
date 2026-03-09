#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <release-dir>" >&2
    exit 1
fi

release_dir="$1"
mkdir -p "$release_dir"

minisign_pub="${SECLUSOR_MINISIGN_PUB:-}"
pgp_key_id="${SECLUSOR_PGP_KEY_ID:-}"
gpg_homedir="${SECLUSOR_GPG_HOMEDIR:-}"

if [ -n "$minisign_pub" ]; then
    cp "$minisign_pub" "${release_dir}/minisign.pub"
    echo "[ok] Exported minisign.pub"
else
    echo "[--] SECLUSOR_MINISIGN_PUB not set; skipping minisign public key export"
fi

if [ -n "$pgp_key_id" ]; then
    if ! command -v gpg >/dev/null 2>&1; then
        echo "error: gpg is required when SECLUSOR_PGP_KEY_ID is set" >&2
        exit 1
    fi
    gpg_args=(--armor --export "$pgp_key_id")
    if [ -n "$gpg_homedir" ]; then
        gpg_args=(--homedir "$gpg_homedir" "${gpg_args[@]}")
    fi
    gpg "${gpg_args[@]}" >"${release_dir}/release-key.asc"
    echo "[ok] Exported release-key.asc"
fi
