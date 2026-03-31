#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 <release-tag> <release-dir> [--all]" >&2
    echo "" >&2
    echo "  Default: upload provenance only (checksums, signatures, keys, notes)" >&2
    echo "  --all:   upload all assets including platform binaries" >&2
    exit 1
fi

release_tag="$1"
release_dir="$2"
upload_all="${3:-}"

if ! command -v gh >/dev/null 2>&1; then
    echo "error: gh CLI is required" >&2
    exit 1
fi

assets=()

if [ "$upload_all" = "--all" ]; then
    # Upload everything: binaries + provenance
    while IFS= read -r path; do
        assets+=("$path")
    done < <(
        find "$release_dir" -maxdepth 1 -type f \
            \( -name 'seclusor-*' \
            -o -name 'SHA256SUMS' -o -name 'SHA512SUMS' \
            -o -name 'SHA256SUMS.minisig' -o -name 'SHA512SUMS.minisig' \
            -o -name 'SHA256SUMS.asc' -o -name 'SHA512SUMS.asc' \
            -o -name '*.pub' \
            -o -name 'release-notes-*.md' \) |
            sort
    )
else
    # Provenance only: checksums, signatures, keys, notes (not binaries)
    while IFS= read -r path; do
        assets+=("$path")
    done < <(
        find "$release_dir" -maxdepth 1 -type f \
            \( -name 'SHA256SUMS' -o -name 'SHA512SUMS' \
            -o -name 'SHA256SUMS.minisig' -o -name 'SHA512SUMS.minisig' \
            -o -name 'SHA256SUMS.asc' -o -name 'SHA512SUMS.asc' \
            -o -name '*.pub' \
            -o -name 'release-notes-*.md' \) |
            sort
    )
fi

if [ "${#assets[@]}" -eq 0 ]; then
    echo "error: no publishable assets found in ${release_dir}" >&2
    exit 1
fi

echo "Uploading ${#assets[@]} assets to ${release_tag}..."
gh release upload "$release_tag" "${assets[@]}" --clobber

notes_file="${release_dir}/release-notes-${release_tag}.md"
if [ -f "$notes_file" ]; then
    gh release edit "$release_tag" --notes-file "$notes_file"
    echo "[ok] Updated release notes"
fi

echo "[ok] Uploaded assets to ${release_tag}"
