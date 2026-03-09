#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <release-dir>" >&2
    exit 1
fi

release_dir="$1"

for key in "${release_dir}/minisign.pub" "${release_dir}/release-key.asc"; do
    [ -f "$key" ] || continue
    if rg -n "PRIVATE|SECRET|BEGIN PGP PRIVATE KEY" "$key" >/dev/null 2>&1; then
        echo "error: key file appears to contain private material: ${key}" >&2
        exit 1
    fi
done

echo "[ok] Public key validation passed"
