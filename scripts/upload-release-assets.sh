#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <release-tag> <release-dir>" >&2
    exit 1
fi

release_tag="$1"
release_dir="$2"

if ! command -v gh >/dev/null 2>&1; then
    echo "error: gh CLI is required" >&2
    exit 1
fi

mapfile -t assets < <(find "$release_dir" -maxdepth 1 -type f | sort)
if [ "${#assets[@]}" -eq 0 ]; then
    echo "error: no assets found in ${release_dir}" >&2
    exit 1
fi

gh release upload "$release_tag" "${assets[@]}" --clobber

echo "[ok] Uploaded assets to ${release_tag}"
