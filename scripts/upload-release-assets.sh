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

if [ ! -d "$release_dir" ] || [ -L "$release_dir" ] || [ ! -f "${release_dir}.anchor" ] || [ -L "${release_dir}.anchor" ]; then
    echo "error: missing verified release directory or ${release_dir}.anchor" >&2
    exit 1
fi

snap_root="$(mktemp -d "${TMPDIR:-/tmp}/seclusor-upload.XXXXXX")"
chmod 700 "$snap_root"
trap 'rm -rf "$snap_root"' EXIT
snap="${snap_root}/release"
mkdir -m 700 "$snap"
cp -p "${release_dir}.anchor" "${snap}.anchor"
while IFS= read -r -d '' entry; do
    if [ ! -f "$entry" ] || [ -L "$entry" ]; then
        echo "error: non-regular file in ${release_dir}: ${entry##*/}" >&2
        exit 1
    fi
    cp -p "$entry" "${snap}/${entry##*/}"
done < <(find "$release_dir" -mindepth 1 -maxdepth 1 -print0)

root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
SECLUSOR_RELEASE_TAG="${release_tag}" "${root}/scripts/release-create-draft.sh" --verify-only "${snap}"

assets=()

if [ "$upload_all" = "--all" ]; then
    # Upload everything: binaries + provenance
    while IFS= read -r path; do
        assets+=("$path")
    done < <(
        find "$snap" -maxdepth 1 -type f \
            \( -name 'seclusor-*' \
            -o -name 'SHA256SUMS' -o -name 'SHA512SUMS' \
            -o -name 'SHA256SUMS.minisig' -o -name 'SHA512SUMS.minisig' \
            -o -name 'SHA256SUMS.asc' -o -name 'SHA512SUMS.asc' \
            -o -name '*.pub' -o -name 'release-key.asc' \
            -o -name 'expected-fingerprints.txt' -o -name 'expected-fingerprints.ndjson' \
            -o -name 'release-notes-*.md' \) |
            LC_ALL=C sort
    )
else
    # Provenance only: checksums, signatures, keys, notes (not binaries)
    while IFS= read -r path; do
        assets+=("$path")
    done < <(
        find "$snap" -maxdepth 1 -type f \
            \( -name 'SHA256SUMS' -o -name 'SHA512SUMS' \
            -o -name 'SHA256SUMS.minisig' -o -name 'SHA512SUMS.minisig' \
            -o -name 'SHA256SUMS.asc' -o -name 'SHA512SUMS.asc' \
            -o -name '*.pub' -o -name 'release-key.asc' \
            -o -name 'expected-fingerprints.txt' -o -name 'expected-fingerprints.ndjson' \
            -o -name 'release-notes-*.md' \) |
            LC_ALL=C sort
    )
fi

if [ "${#assets[@]}" -eq 0 ]; then
    echo "error: no publishable assets found in ${release_dir}" >&2
    exit 1
fi

is_draft="$(gh release view "$release_tag" --repo 3leaps/seclusor --json isDraft --jq '.isDraft')"
if [ "$is_draft" != "true" ]; then
    echo "error: refusing to upload or clobber assets on non-draft release ${release_tag}" >&2
    exit 1
fi

echo "Uploading ${#assets[@]} assets to draft ${release_tag}..."
gh release upload "$release_tag" "${assets[@]}" --repo 3leaps/seclusor --clobber

notes_file="${snap}/release-notes-${release_tag}.md"
if [ -f "$notes_file" ]; then
    gh release edit "$release_tag" --repo 3leaps/seclusor --notes-file "$notes_file"
    echo "[ok] Updated release notes"
fi

echo "[ok] Uploaded assets to ${release_tag}"
