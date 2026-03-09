#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <release-tag> <output-dir>" >&2
    exit 1
fi

tag="$1"
out_dir="$2"

if ! command -v gh >/dev/null 2>&1; then
    echo "error: gh CLI is required" >&2
    exit 1
fi

mkdir -p "$out_dir"

echo "Downloading assets for ${tag} into ${out_dir}..."
gh release download "$tag" --dir "$out_dir"
echo "[ok] Download complete"
