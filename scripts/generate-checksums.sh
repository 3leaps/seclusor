#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <release-dir>" >&2
    exit 1
fi

release_dir="$1"
if [ ! -d "$release_dir" ]; then
    echo "error: release dir not found: ${release_dir}" >&2
    exit 1
fi

artifacts=()
while IFS= read -r path; do
    artifacts+=("$path")
done < <(find "$release_dir" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' -o -name '*.tgz' \) | sort)
if [ "${#artifacts[@]}" -eq 0 ]; then
    echo "error: no distributable archives found in ${release_dir}" >&2
    exit 1
fi

(
    cd "$release_dir"
    files=()
    for f in "${artifacts[@]}"; do
        files+=("$(basename "$f")")
    done
    shasum -a 256 "${files[@]}" >SHA256SUMS
    shasum -a 512 "${files[@]}" >SHA512SUMS
)

echo "[ok] Wrote ${release_dir}/SHA256SUMS and ${release_dir}/SHA512SUMS"
