#!/usr/bin/env bash
# Install the digest-pinned decernor archive from config/release/decernor-ci-sha256.txt.
# Prints the absolute path of the extracted binary on stdout; no PATH fallback.
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(CDPATH='' cd -- "${script_dir}/.." && pwd -P)"
# shellcheck source=scripts/release-decernor.sh
source "${script_dir}/release-decernor.sh"

pin="${root}/config/release/decernor-ci-sha256.txt"
if [ ! -f "${pin}" ] || [ ! -s "${pin}" ] || [ -L "${pin}" ]; then
    echo "error: committed decernor digest pin missing: ${pin}" >&2
    exit 1
fi

read -r digest filename extra <"${pin}"
if [ -n "${extra:-}" ] || ! [[ "${digest}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "error: decernor digest pin is malformed" >&2
    exit 1
fi
if ! [[ "${filename}" =~ ^decernor_([0-9]+\.[0-9]+\.[0-9]+)_linux_amd64\.tar\.gz$ ]]; then
    echo "error: decernor archive name is malformed: ${filename}" >&2
    exit 1
fi
version="${BASH_REMATCH[1]}"

dest="${1:-}"
if [ -z "${dest}" ]; then
    dest="$(mktemp -d "${TMPDIR:-/tmp}/decernor-ci.XXXXXX")"
fi
mkdir -p "${dest}"
if [ -L "${dest}" ] || [ ! -d "${dest}" ]; then
    echo "error: decernor install destination must be a regular directory" >&2
    exit 1
fi

url="https://github.com/3leaps/decernor/releases/download/v${version}/${filename}"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 \
    "${url}" --output "${dest}/${filename}"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "${dest}" && sha256sum --check --quiet "${pin}") >&2
else
    (cd "${dest}" && shasum -a 256 --check --status "${pin}") >&2
fi

tar -xzf "${dest}/${filename}" -C "${dest}" decernor
chmod 0755 "${dest}/decernor"
resolved="$(CDPATH='' cd -- "${dest}" && pwd -P)/decernor"
if [ ! -f "${resolved}" ] || [ -L "${resolved}" ] || [ ! -x "${resolved}" ]; then
    echo "error: extracted decernor binary is not a regular executable" >&2
    exit 1
fi

SECLUSOR_DECERNOR_BIN="${resolved}" release_resolve_decernor ceremony >/dev/null
printf '%s\n' "${resolved}"
