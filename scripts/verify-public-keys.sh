#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <release-dir>" >&2
    exit 1
fi

release_dir="$1"

scan_for_private_material() {
    local file="$1"
    if command -v rg >/dev/null 2>&1; then
        rg -n "PRIVATE|SECRET|BEGIN PGP PRIVATE KEY" "$file" >/dev/null 2>&1
    else
        grep -En "PRIVATE|SECRET|BEGIN PGP PRIVATE KEY" "$file" >/dev/null 2>&1
    fi
}

for key in "${release_dir}/minisign.pub" "${release_dir}/release-key.asc"; do
    [ -f "$key" ] || continue
    if scan_for_private_material "$key"; then
        echo "error: key file appears to contain private material: ${key}" >&2
        exit 1
    fi
done

echo "[ok] Public key validation passed"
